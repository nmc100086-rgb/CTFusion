"""保存文件：允许保存到用户选择的位置，需要时按需提权。

设计目标（v2.3 起）：

1. 不做保存目录限制：用户在保存对话框里选哪里，就写哪里，包括其他磁盘、
   磁盘根目录、程序所在目录；
2. 只有 Windows 真正拒绝写入（ACL / 只读目录）时才处理：按用户的一次性
   选择，通过 ``core.elevate`` 请求一次管理员权限完成这次写入，或改存到
   用户文件夹；
3. 第一次遇到无权限时会说明情况并记住选择（``save/permission_policy``），
   之后不再重复弹窗打扰；
4. 保存对话框默认打开上次保存过的目录，减少来回切换。
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import uuid
from pathlib import Path

from PySide6.QtCore import QCoreApplication, QSettings, QStandardPaths, Qt
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QMessageBox,
    QWidget,
)

from core import elevate
from ui import i18n

_SETTINGS_ORG = "CTFusion"
_SETTINGS_APP = "CTFusion"
_POLICY_KEY = "save/permission_policy"  # ask / elevate / user
_LAST_DIR_KEY = "save/last_dir"
_ELEVATION_KEY = "save/allow_elevation"  # 默认关闭：不请求管理员权限

POLICY_ASK = "ask"
POLICY_ELEVATE = "elevate"
POLICY_USER = "user"
_POLICIES = (POLICY_ASK, POLICY_ELEVATE, POLICY_USER)


class _RetrySave(Exception):
    """用户选择「另存为…」：重新弹出保存对话框。"""


def user_directory(kind: str = "data") -> str:
    """返回一个当前用户通常可写的目录。"""
    preferred = {
        "image": QStandardPaths.PicturesLocation,
        "archive": QStandardPaths.DownloadLocation,
        "text": QStandardPaths.DocumentsLocation,
    }.get(kind, QStandardPaths.DocumentsLocation)
    home = Path.home()
    # 某些环境会把“图片/下载/文档”重定向到盘符根目录（例如 D:/），
    # 这不是一个适合默认保存的位置，避免用户误存到磁盘根目录。
    candidates: list[str] = [
        str(home / "Pictures"),
        str(home / "Downloads"),
        str(home / "Desktop"),
        str(home / "Documents"),
    ]
    for location in (preferred, QStandardPaths.DownloadLocation,
                     QStandardPaths.DesktopLocation,
                     QStandardPaths.HomeLocation):
        path = QStandardPaths.writableLocation(location)
        if path:
            candidates.append(path)
    candidates.append(str(home))
    seen: set[str] = set()
    for path in candidates:
        if not path or path in seen:
            continue
        seen.add(path)
        target = Path(path)
        if target.parent == target:  # 盘符根目录
            continue
        if target.is_dir() and os.access(target, os.W_OK):
            return path
    return str(home)


def _settings() -> QSettings:
    return QSettings(_SETTINGS_ORG, _SETTINGS_APP)


def _usable_directory(path: Path) -> bool:
    """可以作为下次默认保存目录：存在、不是盘符根、当前用户可写。"""
    try:
        if not path.is_dir():
            return False
    except OSError:
        return False
    if path.parent == path:  # 盘符根目录（D:\、C:\）
        return False
    return os.access(path, os.W_OK)


def last_directory(kind: str = "data") -> str:
    """上次成功保存的目录；记录不可用时回退到用户目录并清除记录。"""
    value = str(_settings().value(_LAST_DIR_KEY, "") or "")
    if value:
        try:
            if _usable_directory(Path(value)):
                return value
        except OSError:
            pass
        # 之前可能记成了盘符根目录（D:\ 等），必须丢掉，否则每次保存
        # 对话框都会定位到根目录并触发权限错误。
        try:
            _settings().remove(_LAST_DIR_KEY)
        except OSError:
            pass
    return user_directory(kind)


def _remember_directory(target: Path) -> None:
    parent = target.parent
    if parent.parent == parent:  # 不把盘符根目录记成下次默认位置
        return
    try:
        _settings().setValue(_LAST_DIR_KEY, str(parent))
    except OSError:
        pass


def ensure_sane_save_directory() -> None:
    """启动时清理历史遗留的无效保存目录（例如 D:\\）。"""
    value = str(_settings().value(_LAST_DIR_KEY, "") or "")
    if not value:
        return
    try:
        if _usable_directory(Path(value)):
            return
    except OSError:
        pass
    try:
        _settings().remove(_LAST_DIR_KEY)
    except OSError:
        pass


def default_save_path(filename: str, kind: str = "data") -> str:
    return str(Path(last_directory(kind)) / filename)


def permission_policy() -> str:
    value = str(_settings().value(_POLICY_KEY, POLICY_ASK) or POLICY_ASK)
    return value if value in _POLICIES else POLICY_ASK


def allow_elevation() -> bool:
    """是否允许在写入被拒时请求管理员权限（默认开启）。"""
    value = str(_settings().value(_ELEVATION_KEY, "true")).lower()
    return value not in ("0", "false", "no", "off")


def set_allow_elevation(enabled: bool) -> None:
    try:
        _settings().setValue(_ELEVATION_KEY, "true" if enabled else "false")
    except OSError:
        pass


def _reset_busy_cursor() -> None:
    """清掉残留的等待光标（保存结束后不再转圈）。"""
    app = QApplication.instance()
    if app is None:
        return
    try:
        cursor = QApplication.overrideCursor()
        while cursor is not None and cursor.shape() == Qt.WaitCursor:
            QApplication.restoreOverrideCursor()
            cursor = QApplication.overrideCursor()
        QApplication.processEvents()
    except Exception:
        pass


def set_permission_policy(policy: str) -> None:
    if policy not in _POLICIES:
        policy = POLICY_ASK
    try:
        _settings().setValue(_POLICY_KEY, policy)
    except OSError:
        pass


def _unique_path(path: Path) -> Path:
    if not path.exists():
        return path
    stem, suffix = path.stem, path.suffix
    for index in range(1, 10000):
        candidate = path.with_name(f"{stem} ({index}){suffix}")
        if not candidate.exists():
            return candidate
    return path.with_name(f"{stem} ({os.getpid()}){suffix}")


def _write_bytes(path: Path, data: bytes) -> None:
    """直接写入目标路径；父目录不存在时创建。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        handle.write(data)


# ---------------------------------------------------------------------------
# 保存诊断：日志、管理员状态、自检
# ---------------------------------------------------------------------------
def log_directory() -> Path:
    base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
    root = Path(base) if base else Path.home() / ".ctfusion"
    return root / "CTFusion"


def log_file() -> Path:
    return log_directory() / "save.log"


def ensure_log_file() -> Path:
    """确保日志文件存在（用于界面上的「打开保存日志」）。"""
    for path in _log_candidates():
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch(exist_ok=True)
            return path
        except OSError:
            continue
    return log_file()


def _log_candidates() -> list[Path]:
    """日志位置：只写用户数据目录，不在程序目录里产生文件。"""
    candidates = [log_file()]
    try:
        candidates.append(Path(tempfile.gettempdir()) / "CTFusion-save.log")
    except OSError:
        pass
    seen: set[str] = set()
    result: list[Path] = []
    for path in candidates:
        key = str(path).lower()
        if key not in seen:
            seen.add(key)
            result.append(path)
    return result


def log_event(message: str) -> None:
    """把保存相关的失败/提权记录写入本地日志；任何异常都不影响保存流程。"""
    line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}\n"
    for path in _log_candidates():
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            try:
                if path.exists() and path.stat().st_size > 1_000_000:
                    path.replace(path.with_name(path.name + ".1"))
            except OSError:
                pass
            with path.open("a", encoding="utf-8") as handle:
                handle.write(line)
            return
        except OSError:
            continue


def is_admin() -> bool:
    return elevate.is_admin()


def describe_error(exc: BaseException) -> str:
    text = str(exc)
    winerror = getattr(exc, "winerror", None)
    if winerror and str(winerror) not in text:
        text = f"{text} (WinError {winerror})"
    return text


def program_directory() -> Path:
    """打包后返回 exe 所在目录，源码运行返回当前工作目录。"""
    if getattr(sys, "frozen", False):
        try:
            return Path(sys.executable).resolve().parent
        except OSError:
            return Path(sys.executable).parent
    return Path.cwd()


def diagnose_save_permissions() -> list[dict]:
    """在常见保存位置各写一个临时文件，返回每个位置的结果。

    这是给「保存不了」准备的现场证据：能直接看出是某个目录的权限问题，
    还是安全软件拦截（例如 360 / 电脑管家 的文档保护）。
    """
    home = Path.home()
    candidates: list[tuple[str, Path]] = [
        ("桌面", home / "Desktop"),
        ("文档", home / "Documents"),
        ("图片", home / "Pictures"),
        ("下载", home / "Downloads"),
        ("程序目录", program_directory()),
        ("临时目录", Path(tempfile.gettempdir())),
    ]
    rows: list[dict] = []
    for label, folder in candidates:
        row = {"label": label, "path": str(folder), "ok": False, "error": ""}
        if not folder.is_dir():
            row.update(ok=True, error="目录不存在，已跳过")
            rows.append(row)
            continue
        target = folder / f".ctfusion_write_test_{os.getpid()}_{uuid.uuid4().hex[:6]}.tmp"
        try:
            _write_bytes(target, b"ctfusion")
            row["ok"] = target.read_bytes() == b"ctfusion"
            if not row["ok"]:
                row["error"] = "写入后读取内容不一致"
        except OSError as exc:
            row["error"] = describe_error(exc)
        finally:
            try:
                target.unlink()
            except OSError:
                pass
        rows.append(row)
    log_event("diagnose admin=%s %s" % (is_admin(), json.dumps(
        rows, ensure_ascii=False)))
    return rows


def show_diagnose_dialog(parent: QWidget | None = None) -> None:
    """显示保存权限自检结果，并给出现场处理建议。"""
    rows = diagnose_save_permissions()
    lines: list[str] = []
    for row in rows:
        mark = "✓" if row["ok"] else "✗"
        lines.append(f"{mark} {row['label']}：{row['path']}")
        if not row["ok"]:
            lines.append(f"    {row['error']}")
    failed = [row for row in rows if not row["ok"]]

    box = QMessageBox(parent)
    box.setWindowTitle(i18n.tr("保存权限自检"))
    if failed:
        box.setIcon(QMessageBox.Warning)
        box.setText(i18n.tr("有 {count} 个位置无法写入。").format(
            count=len(failed)))
        hint = i18n.tr(
            "常见原因：安全软件的文档保护（360、电脑管家、火绒等）、"
            "Windows 受控文件夹访问，或该目录的 NTFS 权限。\n"
            "请按安全软件弹窗选择「允许」，或把本程序加入信任区；"
            "也可以使用「设置 → 以管理员身份重新启动」后再试。")
    else:
        box.setIcon(QMessageBox.Information)
        box.setText(i18n.tr("常见保存位置都可以正常写入。"))
        hint = i18n.tr(
            "如果某个位置仍然保存失败，请把「帮助 → 打开保存日志」里的内容"
            "发给我们。")
    box.setInformativeText(
        "\n".join(lines) + "\n\n" + hint
        + "\n\n" + i18n.tr("保存日志：") + str(log_file()))
    box.addButton(i18n.tr("知道了"), QMessageBox.AcceptRole)
    box.exec()


def _elevated_write(parent: QWidget | None, target: Path,
                    data: bytes) -> tuple[bool, str]:
    """请求一次管理员权限写入；等待 UAC 期间保持界面响应。"""
    app = QApplication.instance()
    cursor_set = False
    if app is not None:
        QApplication.setOverrideCursor(Qt.WaitCursor)
        cursor_set = True
    try:
        ok, reason = elevate.write_with_elevation(
            target, data, timeout=120.0,
            pump=QCoreApplication.processEvents)
        log_event("elevate target=%s ok=%s reason=%s" % (target, ok, reason))
        return ok, reason
    finally:
        if cursor_set:
            QApplication.restoreOverrideCursor()
        _reset_busy_cursor()


def _save_to_user_folder(parent: QWidget | None, data: bytes, filename: str,
                         kind: str) -> str | None:
    target = _unique_path(Path(user_directory(kind)) / Path(filename).name)
    try:
        _write_bytes(target, data)
    except OSError as exc:
        log_event("user-folder failed target=%s error=%s"
                  % (target, describe_error(exc)))
        QMessageBox.warning(
            parent, i18n.tr("保存失败"),
            i18n.tr("保存到用户文件夹仍然失败：\n{error}\n\n"
                    "请检查磁盘空间或文件夹权限。\n"
                    "如果是 360、电脑管家、火绒等安全软件拦截，"
                    "请把本程序加入信任区。\n\n"
                    "保存日志：{log}").format(
                        error=describe_error(exc), log=log_file()))
        return None
    _remember_directory(target)
    return str(target)


def _sanitize_default(path: str, kind: str) -> str:
    """保存对话框的初始路径不能落在盘符根目录。"""
    target = Path(path)
    if target.parent.parent == target.parent:  # D:\xxx.png
        return default_save_path(target.name, kind)
    return path


def _ask_path(parent: QWidget | None, default: str, title: str,
              file_filter: str, kind: str = "data") -> str | None:
    default = _sanitize_default(default, kind)
    path, _ = QFileDialog.getSaveFileName(
        parent, i18n.tr(title), default, file_filter)
    return path or None


def _handle_denied(parent: QWidget | None, target: Path, data: bytes,
                   kind: str, error: str,
                   allow_redirect: bool) -> str | None:
    """处理写入被拒绝的情况。

    返回实际保存的路径；用户取消时返回 None。
    需要重新弹出保存对话框时抛出 ``_RetrySave``。

    默认不请求管理员权限：目标位置不可写时直接改存到用户目录，避免 UAC。
    只有用户在「设置」里显式允许后才走提权流程。
    """
    if not allow_elevation():
        if allow_redirect:
            log_event("fallback (no elevation) target=%s" % target)
            return _save_to_user_folder(parent, data, target.name, kind)
        QMessageBox.warning(
            parent, i18n.tr("保存失败"),
            i18n.tr("这个位置不能直接写入，请改用「另存为…」选择其他位置。")
            + "\n\n" + i18n.tr("保存日志：") + str(log_file()))
        return None

    # 已开启「保存时请求管理员权限」：直接以管理员身份写入，不再询问。
    ok, reason = _elevated_write(parent, target, data)
    if ok:
        _remember_directory(target)
        log_event("elevate ok target=%s" % target)
        return str(target)
    log_event("elevate failed target=%s reason=%s" % (target, reason))
    QMessageBox.warning(
        parent, i18n.tr("保存失败"),
        i18n.tr("管理员写入未完成：\n{error}\n\n"
                "如果 UAC 提示被取消，请重试并在提示里选择「是」。\n\n"
                "保存日志：{log}").format(error=reason, log=log_file()))
    return None


def write_bytes(parent: QWidget | None, data: bytes, path: str | Path,
                kind: str = "data") -> bool:
    """把 ``data`` 写到指定路径；被 Windows 拒绝时按策略提权后重试。

    返回是否写入成功。由于路径已经由调用方确认（例如覆盖保存、另存为），
    这里不会静默改存到其他位置；需要重新选路径时调用方应使用
    :func:`save_file_bytes`。
    """
    target = Path(path)
    try:
        _write_bytes(target, data)
        _remember_directory(target)
        return True
    except PermissionError as exc:
        log_event("write denied target=%s admin=%s error=%s"
                  % (target, is_admin(), describe_error(exc)))
        saved = _handle_denied(
            parent, target, data, kind, describe_error(exc),
            allow_redirect=False)
        log_event("write %s target=%s" % ("recovered" if saved else "failed",
                                          target))
        return bool(saved)
    except OSError as exc:
        log_event("write oserror target=%s error=%s"
                  % (target, describe_error(exc)))
        QMessageBox.warning(
            parent, i18n.tr("保存失败"),
            i18n.tr("无法写入文件：\n{error}\n\n"
                    "请检查磁盘空间、目标文件名是否合法，"
                    "或换一个位置再试。\n\n保存日志：{log}").format(
                        error=describe_error(exc), log=log_file()))
        return False
    finally:
        _reset_busy_cursor()


def write_many(parent: QWidget | None,
               items: list[tuple[str | Path, bytes]],
               kind: str = "data") -> int:
    """批量写入文件（例如“提取全部内嵌文件”）。

    先按普通权限逐个写入；只有被 Windows 拒绝的文件才合并成一次提权请求，
    因此最多只会多弹一次 UAC。返回成功写入的文件数。
    """
    written = 0
    denied: list[tuple[Path, bytes]] = []
    for path, data in items:
        target = Path(path)
        try:
            _write_bytes(target, data)
            _remember_directory(target)
            written += 1
        except PermissionError as exc:
            log_event("write-many denied target=%s error=%s"
                      % (target, describe_error(exc)))
            denied.append((target, data))
        except OSError as exc:
            log_event("write-many oserror target=%s error=%s"
                      % (target, describe_error(exc)))
            QMessageBox.warning(
                parent, i18n.tr("保存失败"),
                i18n.tr("无法写入文件：\n{error}\n\n"
                        "请检查磁盘空间、目标文件名是否合法，"
                        "或换一个位置再试。\n\n保存日志：{log}").format(
                            error=describe_error(exc), log=log_file()))
            return written
    if not denied:
        return written
    if not allow_elevation():
        QMessageBox.warning(
            parent, i18n.tr("保存失败"),
            i18n.tr("有 {count} 个文件无法写入目标文件夹。\n\n"
                    "如果不是文件夹权限问题，通常是 360、电脑管家、火绒等"
                    "安全软件的「文档保护」拦截了本程序。\n"
                    "请把 CTFusion v2.3.1.exe 加入安全软件的信任区 / 白名单，"
                    "之后普通权限就能保存，不需要管理员。\n\n"
                    "保存日志：{log}").format(
                        count=len(denied), log=log_file()))
        return written
    ok, reason = _elevated_write_many(parent, denied)
    log_event("write-many elevate count=%d ok=%s reason=%s"
              % (len(denied), ok, reason))
    if ok:
        written += len(denied)
    else:
        QMessageBox.warning(
            parent, i18n.tr("保存失败"),
            i18n.tr("管理员写入未完成：\n{error}").format(error=reason))
    return written


def _elevated_write_many(parent: QWidget | None,
                         items: list[tuple[Path, bytes]]) -> tuple[bool, str]:
    app = QApplication.instance()
    cursor_set = False
    if app is not None:
        QApplication.setOverrideCursor(Qt.WaitCursor)
        cursor_set = True
    try:
        ok, reason = elevate.write_many_with_elevation(
            items, timeout=120.0, pump=QCoreApplication.processEvents)
        log_event("elevate-many count=%d ok=%s reason=%s"
                  % (len(items), ok, reason))
        return ok, reason
    finally:
        if cursor_set:
            QApplication.restoreOverrideCursor()
        _reset_busy_cursor()


def save_file_bytes(
    parent: QWidget | None,
    data: bytes,
    suggested_path: str | None,
    kind: str = "data",
    title: str = "保存文件",
    file_filter: str = "所有文件 (*.*)",
) -> str | None:
    """弹出保存对话框并写入；返回实际保存路径，取消时返回 None。"""
    default = suggested_path or default_save_path("output.bin", kind)
    try:
        while True:
            path = _ask_path(parent, default, title, file_filter, kind)
            if not path:
                return None
            target = Path(path)
            try:
                _write_bytes(target, data)
            except PermissionError as exc:
                log_event("save denied target=%s admin=%s error=%s"
                          % (target, is_admin(), describe_error(exc)))
                try:
                    saved = _handle_denied(
                        parent, target, data, kind, describe_error(exc),
                        allow_redirect=True)
                except _RetrySave:
                    default = str(Path(last_directory(kind)) / target.name)
                    continue
                log_event("save %s target=%s"
                          % ("recovered" if saved else "failed",
                             saved or target))
                if saved:
                    return saved
                return None
            except OSError as exc:
                log_event("save oserror target=%s error=%s"
                          % (target, describe_error(exc)))
                QMessageBox.warning(
                    parent, i18n.tr("保存失败"),
                    i18n.tr("无法写入文件：\n{error}\n\n"
                            "请检查磁盘空间、目标文件名是否合法，"
                            "或换一个位置再试。\n\n保存日志：{log}").format(
                                error=describe_error(exc), log=log_file()))
                default = str(target)
                continue
            _remember_directory(target)
            log_event("save ok target=%s" % target)
            return str(target)
    finally:
        _reset_busy_cursor()


def save_bytes_dialog(
    parent: QWidget,
    data: bytes,
    filename: str,
    kind: str,
    title: str,
    file_filter: str,
    suggested_path: str | None = None,
) -> str | None:
    """兼容旧调用：保存解码出的 Base64/Hex 数据或其它二进制。"""
    return save_file_bytes(
        parent,
        data,
        suggested_path or default_save_path(filename, kind),
        kind,
        title,
        file_filter,
    )
