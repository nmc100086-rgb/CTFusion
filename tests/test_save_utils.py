"""保存权限策略、提权写入与首次运行提示的测试。"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:
    from PySide6.QtWidgets import QApplication

    from core import elevate
    from ui import first_run, save_utils
except ImportError:  # pragma: no cover
    QApplication = None  # type: ignore[assignment]
    elevate = None  # type: ignore[assignment]
    first_run = None  # type: ignore[assignment]
    save_utils = None  # type: ignore[assignment]


class _FakeSettings:
    """内存版 QSettings：沙箱/CI 里注册表可能不可写。"""

    store: dict = {}

    def __init__(self, *args, **kwargs):
        pass

    def value(self, key, default=None):
        return self.store.get(key, default)

    def setValue(self, key, value):
        self.store[key] = value

    def remove(self, key):
        self.store.pop(key, None)

    def sync(self):
        return None


@unittest.skipUnless(QApplication is not None, "需要安装 PySide6")
class SavePermissionTests(unittest.TestCase):
    """保存不再限制目录；无权限时按一次性选择提权或改存。"""

    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        _FakeSettings.store.clear()
        settings_patch = patch.object(save_utils, "_settings", _FakeSettings)
        settings_patch.start()
        self.addCleanup(settings_patch.stop)
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        save_utils.set_permission_policy(save_utils.POLICY_ASK)

    def test_writes_to_any_folder_without_prompt(self):
        target = Path(self._dir.name) / "其他盘" / "题目" / "flag.png"
        self.assertTrue(save_utils.write_bytes(self, b"png", target))
        self.assertEqual(target.read_bytes(), b"png")

    def test_permission_denied_elevates_automatically(self):
        save_utils.set_allow_elevation(True)
        self.addCleanup(save_utils.set_allow_elevation, False)
        target = Path(self._dir.name) / "protected.bin"
        real_write = save_utils._write_bytes
        calls = {"elevated": 0}

        def fake_write(path, data):
            if Path(path) == target:
                raise PermissionError("denied")
            return real_write(path, data)

        def fake_elevated(parent, path, data):
            calls["elevated"] += 1
            real_write(path, data)
            return True, ""

        with patch.object(save_utils, "_write_bytes", side_effect=fake_write), \
                patch.object(save_utils, "_elevated_write",
                             side_effect=fake_elevated):
            self.assertTrue(save_utils.write_bytes(self, b"data", target))
            # 第二次仍然自动提权，不需要再确认。
            self.assertTrue(save_utils.write_bytes(self, b"data2", target))
        self.assertEqual(calls["elevated"], 2)
        self.assertEqual(target.read_bytes(), b"data2")

    def test_choose_another_location_retries_dialog(self):
        first = Path(self._dir.name) / "denied.bin"
        second = Path(self._dir.name) / "ok.bin"
        answers = iter([(str(first), ""), (str(second), "")])
        real_write = save_utils._write_bytes

        def fake_write(path, data):
            if Path(path) == first:
                raise PermissionError("denied")
            return real_write(path, data)

        with patch.object(save_utils, "_write_bytes", side_effect=fake_write), \
                patch.object(save_utils.QFileDialog, "getSaveFileName",
                             side_effect=lambda *a, **k: next(answers)), \
                patch.object(save_utils, "_handle_denied",
                             side_effect=save_utils._RetrySave):
            saved = save_utils.save_file_bytes(
                self, b"abc", str(first), title="保存文件")
        self.assertEqual(saved, str(second))
        self.assertEqual(second.read_bytes(), b"abc")

    def test_denied_falls_back_without_elevation_by_default(self):
        save_utils.set_allow_elevation(False)
        self.addCleanup(save_utils.set_allow_elevation, True)
        target = Path(self._dir.name) / "blocked.bin"
        user_dir = Path(self._dir.name) / "用户目录"
        user_dir.mkdir()
        real_write = save_utils._write_bytes

        def fake_write(path, data):
            if Path(path) == target:
                raise PermissionError("denied")
            return real_write(path, data)

        with patch.object(save_utils, "_write_bytes", side_effect=fake_write), \
                patch.object(save_utils, "user_directory",
                             return_value=str(user_dir)), \
                patch.object(save_utils, "_elevated_write",
                             side_effect=AssertionError("不应请求管理员权限")), \
                patch.object(save_utils.QFileDialog, "getSaveFileName",
                             return_value=(str(target), "")):
            self.assertFalse(save_utils.allow_elevation())
            saved = save_utils.save_file_bytes(
                self, b"payload", str(target), title="保存文件")
        self.assertEqual(saved, str(user_dir / "blocked.bin"))
        self.assertEqual(Path(saved).read_bytes(), b"payload")

    def test_remembered_drive_root_is_ignored_and_cleared(self):
        save_utils._settings().setValue(save_utils._LAST_DIR_KEY, "D:\\")
        with patch.object(save_utils, "user_directory",
                          return_value=str(self._dir.name)):
            self.assertEqual(
                save_utils.last_directory("image"), str(self._dir.name))
        self.assertNotIn(save_utils._LAST_DIR_KEY, _FakeSettings.store)

    def test_remember_directory_skips_drive_root(self):
        save_utils._remember_directory(Path("D:/flag.png"))
        self.assertNotIn(save_utils._LAST_DIR_KEY, _FakeSettings.store)

    def test_sanitize_default_moves_drive_root_to_user_folder(self):
        with patch.object(save_utils, "user_directory",
                          return_value=str(self._dir.name)):
            default = save_utils._sanitize_default("D:\\flag.png", "image")
        self.assertEqual(default, str(Path(self._dir.name) / "flag.png"))

    def test_startup_repair_clears_drive_root(self):
        save_utils._settings().setValue(save_utils._LAST_DIR_KEY, "D:\\")
        save_utils.ensure_sane_save_directory()
        self.assertNotIn(save_utils._LAST_DIR_KEY, _FakeSettings.store)

    def test_save_bytes_dialog_keeps_old_signature(self):
        target = Path(self._dir.name) / "base64.png"
        with patch.object(save_utils.QFileDialog, "getSaveFileName",
                          return_value=(str(target), "")):
            saved = save_utils.save_bytes_dialog(
                self, b"img", "base64.png", "image", "保存解码后的文件",
                "PNG (*.png)")
        self.assertEqual(saved, str(target))
        self.assertEqual(target.read_bytes(), b"img")
        self.assertEqual(save_utils.last_directory("image"),
                         str(Path(self._dir.name)))


@unittest.skipUnless(elevate is not None, "需要 Windows 提权模块")
class ElevatedTaskTests(unittest.TestCase):
    """提权辅助进程只做一次「临时文件 → 目标文件」写入。"""

    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.workdir = Path(self._dir.name)

    def _run(self, spec: dict) -> dict:
        task = self.workdir / "task.json"
        task.write_text(json.dumps(spec, ensure_ascii=False), encoding="utf-8")
        code = elevate.run_elevated_task(
            ["CTFusion", elevate.ELEVATED_FLAG, str(task)])
        self.assertIn(code, (0, 2))
        result = json.loads((self.workdir / "result.json").read_text("utf-8"))
        return result

    def test_writes_single_file(self):
        source = self.workdir / "payload.bin"
        target = self.workdir / "输出" / "flag.bin"
        source.write_bytes(b"flag{1}")
        result = self._run({"source": str(source), "target": str(target)})
        self.assertTrue(result["ok"])
        self.assertEqual(target.read_bytes(), b"flag{1}")

    def test_writes_multiple_files_in_one_task(self):
        first = self.workdir / "a.bin"
        second = self.workdir / "nested" / "b.bin"
        first.write_bytes(b"a")
        second.parent.mkdir()
        second.write_bytes(b"b")
        result = self._run({"items": [
            {"source": str(first), "target": str(self.workdir / "out-a.bin")},
            {"source": str(second), "target": str(self.workdir / "out-b.bin")},
        ]})
        self.assertTrue(result["ok"])
        self.assertEqual((self.workdir / "out-a.bin").read_bytes(), b"a")
        self.assertEqual((self.workdir / "out-b.bin").read_bytes(), b"b")

    def test_run_task_works_when_temp_dir_is_blocked(self):
        target = self.workdir / "fallback_out.bin"
        seen = {}

        def fake_runas(launcher, params, cwd):
            task = params.split('"')[-2]
            seen["task"] = task
            elevate.run_elevated_task(
                ["CTFusion", elevate.ELEVATED_FLAG, task])
            return 33, 0

        with patch("core.elevate.tempfile.mkdtemp",
                   side_effect=PermissionError("denied")), \
                patch("core.elevate._shell_execute_runas",
                      side_effect=fake_runas):
            ok, reason = elevate.write_with_elevation(target, b"data",
                                                      timeout=10)
        self.assertTrue(ok, reason)
        self.assertEqual(target.read_bytes(), b"data")
        self.assertIn("ctfusion-elev-", seen.get("task", ""))

    def test_workdir_falls_back_when_temp_is_blocked(self):
        import shutil

        with patch("core.elevate.tempfile.mkdtemp",
                   side_effect=PermissionError("denied")):
            workdir = elevate._create_workdir()
        try:
            self.assertTrue(workdir.is_dir())
            self.assertIn("ctfusion-elev-", workdir.name)
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

    def test_reports_missing_source(self):
        result = self._run({
            "source": str(self.workdir / "missing.bin"),
            "target": str(self.workdir / "out.bin"),
        })
        self.assertFalse(result["ok"])


@unittest.skipUnless(save_utils is not None, "需要保存模块")
class SaveDiagnosticsTests(unittest.TestCase):
    """保存日志与「保存权限自检」的基本行为。"""

    def test_log_event_writes_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(os.environ, {"LOCALAPPDATA": tmp}):
                save_utils.log_event("probe-entry target=D:\\x")
                log_path = save_utils.log_file()
                self.assertTrue(log_path.is_file())
                self.assertIn("probe-entry", log_path.read_text("utf-8"))

    def test_diagnose_reports_each_location(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            for name in ("Desktop", "Documents", "Pictures", "Downloads"):
                (home / name).mkdir()
            with patch.dict(os.environ, {"LOCALAPPDATA": tmp}), \
                    patch.object(save_utils.Path, "home",
                                 classmethod(lambda cls: home)):
                rows = save_utils.diagnose_save_permissions()
            labels = [row["label"] for row in rows]
            self.assertEqual(len(rows), 6)
            self.assertIn("桌面", labels)
            desktop = next(row for row in rows if row["label"] == "桌面")
            self.assertTrue(desktop["ok"], desktop["error"])
            self.assertTrue(all("error" in row for row in rows))

    def test_describe_error_keeps_winerror(self):
        exc = PermissionError(13, "denied")
        exc.winerror = 5  # type: ignore[attr-defined]
        text = save_utils.describe_error(exc)
        self.assertIn("WinError 5", text)


@unittest.skipUnless(first_run is not None, "需要首次运行提示模块")
class FirstRunTipTests(unittest.TestCase):
    def test_flag_is_written_once(self):
        _FakeSettings.store.clear()
        with patch.object(first_run, "_settings", _FakeSettings):
            self.assertFalse(first_run.shown_before())
            first_run.mark_shown()
            self.assertTrue(first_run.shown_before())
        self.assertEqual(_FakeSettings.store[first_run.FLAG_KEY], "1")


if __name__ == "__main__":
    unittest.main()
