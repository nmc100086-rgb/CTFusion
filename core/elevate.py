"""按需提权写入：只在 Windows 拒绝普通写入时请求一次管理员权限。

工作方式（不申请常驻管理员权限，也不改系统 ACL）：

1. 普通进程把数据写到临时文件，生成一个 JSON 任务描述；
2. 用 ``ShellExecuteW(..., "runas", ...)`` 启动同一个程序，
   参数为 ``--elevated-write <task.json>``；Windows 这时弹出一次 UAC；
3. 提权后的进程只做「读临时数据 → 写目标文件 → 写结果」，不执行命令、
   不联网、不开界面，写完立即退出；
4. 普通进程轮询结果文件，拿到成功或失败原因。

因此 UAC 只在确实需要管理员权限的那一次写入时出现，程序平时仍以普通用户
权限运行；写入范围始终是用户在保存对话框里主动选择的位置。
"""

from __future__ import annotations

import ctypes
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Callable

ELEVATED_FLAG = "--elevated-write"

_TASK_NAME = "task.json"
_RESULT_NAME = "result.json"
_SUCCESS_MIN = 32  # ShellExecuteW 返回值大于 32 表示成功
_ERROR_CANCELLED = 1223


def _write_json(path: Path, payload: dict) -> None:
    """原子写 JSON，避免父进程读到写了一半的结果。"""
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, path)


def _result_path(workdir: Path) -> Path:
    return workdir / _RESULT_NAME


def program_directory() -> Path:
    """打包后是 exe 所在目录，源码运行是当前目录。"""
    if getattr(sys, "frozen", False):
        try:
            return Path(sys.executable).resolve().parent
        except OSError:
            return Path(sys.executable).parent
    return Path.cwd()


def _create_workdir() -> Path:
    """创建提权任务目录。

    安全软件可能拦截本程序写 `%TEMP%`，这时退回程序目录（通常已被允许），
    否则提权流程会在创建临时目录这一步就失败，根本走不到 UAC。
    """
    try:
        return Path(tempfile.mkdtemp(prefix="ctfusion-elev-"))
    except OSError:
        pass
    bases: list[Path] = []
    for base in (program_directory(), Path.cwd()):
        try:
            bases.append(base)
        except OSError:
            continue
    temp_env = os.environ.get("TEMP") or os.environ.get("TMP")
    if temp_env:
        bases.append(Path(temp_env))
    for base in bases:
        try:
            base.mkdir(parents=True, exist_ok=True)
            workdir = base / f".ctfusion-elev-{os.getpid()}-{int(time.time() * 1000)}"
            workdir.mkdir()
            return workdir
        except OSError:
            continue
    raise OSError("没有任何可写的临时目录")


def is_admin() -> bool:
    """当前进程是否已经拥有管理员权限。"""
    if sys.platform != "win32":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def relaunch_elevated(args: list[str] | None = None) -> tuple[bool, str]:
    """以管理员身份重新启动本程序（UAC 确认一次）。

    返回 ``(是否已启动, 失败原因)``；调用方在成功后应退出当前进程。
    """
    if sys.platform != "win32":
        return False, "当前系统不支持提权"
    launcher, script = _launcher()
    argv = list(sys.argv[1:] if args is None else args)
    if script is not None:
        argv = [script, *argv]
    params = subprocess.list2cmdline(argv)
    try:
        value, error = _shell_execute_runas(launcher, params, os.getcwd())
    except OSError as exc:
        return False, str(exc)
    if value <= _SUCCESS_MIN:
        if error == _ERROR_CANCELLED:
            return False, "已取消管理员授权"
        return False, f"无法启动管理员进程（错误码 {error or value}）"
    return True, ""


def run_elevated_task(argv: list[str]) -> int:
    """提权进程入口：执行一次「临时文件 → 目标文件」的写入。

    返回 0 表示任务已处理（无论成功还是失败，结果都写在 result.json 里）。
    """
    try:
        index = argv.index(ELEVATED_FLAG)
    except ValueError:
        return 2
    if index + 1 >= len(argv):
        return 2

    task_path = Path(argv[index + 1])
    workdir = task_path.parent
    result_path = _result_path(workdir)
    try:
        spec = json.loads(task_path.read_text(encoding="utf-8-sig"))
        items = _normalize_items(spec)
        results = []
        for source, target in items:
            try:
                data = Path(source).read_bytes()
                Path(target).parent.mkdir(parents=True, exist_ok=True)
                temp_target = Path(str(target) + ".ctfusion-tmp")
                temp_target.write_bytes(data)
                os.replace(temp_target, target)
                results.append({"ok": True, "path": str(target)})
            except Exception as exc:  # 单个文件失败不影响其余文件
                results.append({"ok": False, "target": str(target),
                                "error": str(exc)})
        ok = bool(results) and all(item.get("ok") for item in results)
        _write_json(result_path, {"ok": ok, "items": results})
    except Exception as exc:  # 兜底：把失败原因带回普通进程
        try:
            _write_json(result_path, {"ok": False, "error": str(exc)})
        except OSError:
            pass
    return 0


def _normalize_items(spec: dict) -> list[tuple[str, str]]:
    """兼容两种任务格式：单个 source/target，或 items 列表。"""
    items = spec.get("items")
    if isinstance(items, list) and items:
        normalized = []
        for item in items:
            if not isinstance(item, dict):
                raise ValueError("任务格式错误")
            normalized.append((str(item["source"]), str(item["target"])))
        return normalized
    return [(str(spec["source"]), str(spec["target"]))]


def _launcher() -> tuple[str, str | None]:
    """返回 (可执行文件, 脚本参数)；打包后脚本参数为 None。"""
    if getattr(sys, "frozen", False):
        return sys.executable, None
    python = Path(sys.executable)
    pythonw = python.with_name("pythonw.exe")
    launcher = str(pythonw) if pythonw.is_file() else str(python)
    script = Path(sys.argv[0]).resolve()
    return launcher, str(script)


def _shell_execute_runas(launcher: str, params: str, cwd: str) -> tuple[int, int]:
    """调用 ShellExecuteW("runas")；返回 (返回值, GetLastError)。"""
    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    shell32.ShellExecuteW.restype = ctypes.c_void_p
    shell32.ShellExecuteW.argtypes = [
        ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_wchar_p,
        ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_int,
    ]
    ctypes.set_last_error(0)
    result = shell32.ShellExecuteW(
        None, "runas", launcher, params, cwd, 1)  # SW_SHOWNORMAL
    error = ctypes.get_last_error()
    value = int(result or 0)
    if value > 0x7FFFFFFF:  # 极少数环境下指针被符号扩展
        value &= 0xFFFFFFFF
    return value, error


def _run_task(
    items: list[tuple[Path, bytes]],
    timeout: float = 300.0,
    pump: Callable[[], None] | None = None,
) -> tuple[bool, str]:
    if sys.platform != "win32":
        return False, "当前系统不支持提权写入"
    if not items:
        return False, "没有需要写入的文件"

    try:
        workdir = _create_workdir()
    except OSError as exc:
        return False, f"无法创建临时目录：{exc}"

    task_path = workdir / _TASK_NAME
    result_path = _result_path(workdir)
    try:
        spec_items = []
        for index, (target, data) in enumerate(items):
            payload = workdir / f"payload-{index}.bin"
            payload.write_bytes(data)
            spec_items.append(
                {"source": str(payload), "target": str(Path(target))})
        task_path.write_text(
            json.dumps({"items": spec_items}, ensure_ascii=False),
            encoding="utf-8")
        launcher, script = _launcher()
        params = (f'{ELEVATED_FLAG} "{task_path}"' if script is None
                  else f'"{script}" {ELEVATED_FLAG} "{task_path}"')
        value, error = _shell_execute_runas(launcher, params, str(workdir))
        if value <= _SUCCESS_MIN:
            if error == _ERROR_CANCELLED:
                return False, "已取消管理员授权"
            return False, f"无法启动管理员进程（错误码 {error or value}）"

        deadline = time.monotonic() + max(5.0, timeout)
        while time.monotonic() < deadline:
            if result_path.is_file():
                try:
                    result = json.loads(result_path.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    result = None
                if isinstance(result, dict):
                    return _summarize_result(result)
            if pump is not None:
                try:
                    pump()
                except Exception:  # 界面已销毁时不再阻塞等待
                    pump = None
            time.sleep(0.1)
        return False, "等待管理员写入超时"
    except OSError as exc:
        return False, f"提权写入失败：{exc}"
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def _summarize_result(result: dict) -> tuple[bool, str]:
    if result.get("ok"):
        return True, ""
    failed = [item for item in (result.get("items") or [])
              if isinstance(item, dict) and not item.get("ok")]
    if failed:
        details = "；".join(
            f"{item.get('target')}: {item.get('error')}" for item in failed[:3])
        if len(failed) > 3:
            details += f"；另有 {len(failed) - 3} 个文件失败"
        return False, details
    return False, str(result.get("error") or "管理员进程写入失败")


def write_with_elevation(
    target: Path,
    data: bytes,
    timeout: float = 300.0,
    pump: Callable[[], None] | None = None,
) -> tuple[bool, str]:
    """请求管理员权限把 ``data`` 写到 ``target``。

    返回 ``(成功, 失败原因)``。用户取消 UAC 时返回 ``(False, "已取消…")``。
    ``pump`` 用于在等待期间保持界面响应（通常传 ``QCoreApplication.processEvents``）。
    """
    return _run_task([(Path(target), data)], timeout, pump)


def write_many_with_elevation(
    items: list[tuple[Path, bytes]],
    timeout: float = 300.0,
    pump: Callable[[], None] | None = None,
) -> tuple[bool, str]:
    """一次 UAC 写入多个文件；其中任一失败时返回失败明细。"""
    return _run_task([(Path(target), data) for target, data in items],
                     timeout, pump)
