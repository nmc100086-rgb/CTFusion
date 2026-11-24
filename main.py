import ctypes
import os
import sys
import tempfile
from pathlib import Path


def _prepare_windows_qt_runtime() -> None:
    """Pin frozen Qt DLL lookup to the bundled runtime before importing PySide6."""
    if sys.platform != "win32" or not getattr(sys, "frozen", False):
        return

    root = Path(sys._MEIPASS)
    search_dirs = (
        root,
        root / "PySide6",
        root / "shiboken6",
    )
    for directory in search_dirs:
        if directory.is_dir():
            try:
                os.add_dll_directory(str(directory))
            except (AttributeError, OSError):
                pass
    os.environ["PATH"] = os.pathsep.join(
        [str(directory) for directory in search_dirs if directory.is_dir()]
        + [os.environ.get("PATH", "")]
    )

    # Qt6Core requires ICU. Some developer tools put an incompatible ICU
    # earlier on PATH; preload Windows' matching version before Qt is imported.
    system_icu = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "icuuc.dll"
    preload = [system_icu, root / "PySide6" / "Qt6Core.dll",
               root / "PySide6" / "Qt6Gui.dll"]
    for dll in preload:
        if not dll.is_file():
            continue
        try:
            ctypes.WinDLL(str(dll))
        except OSError:
            # Let Qt produce its normal, more detailed import error if this
            # particular preload path is unavailable.
            pass


_prepare_windows_qt_runtime()

from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QApplication

from core.version import __version__
from ui import i18n
from ui.main_window import MainWindow


def resource_path(relative_path: str) -> Path:
    """Resolve project assets in both source and PyInstaller builds."""
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    return base / relative_path


def _self_test() -> int:
    """Headless build check: bundled bkcrack + CRC32 inversion."""
    import zlib

    from core import (bkcrack, datatools, fileprops, mojibake, qrcode, updater,
                      zipcrack)

    info = bkcrack.bkcrack_info()
    print(f"bkcrack: {info.version or 'missing'} ({info.path})")
    if not info.available:
        print(f"ERROR: {info.error}")
        return 1
    content = b"flag"
    solved = zipcrack.crc32_preimages(
        zlib.crc32(content) & 0xFFFFFFFF, len(content))
    if content not in solved.candidates:
        print("ERROR: CRC32 inversion failed")
        return 1

    payload = datatools.decode_payload("504b0304", "hex")
    if payload.kind != "ZIP":
        print(f"ERROR: hex->ZIP check failed ({payload.kind})")
        return 1
    garbled = "测试".encode("utf-8").decode("latin-1")
    repaired = mojibake.repair(garbled)
    if repaired is None or repaired.text != "测试":
        print("ERROR: mojibake repair failed")
        return 1
    qr_ok, qr_message = qrcode.self_test()
    print(f"QR: {qr_message}")
    if not qr_ok:
        print("ERROR: QR self-test failed")
        return 1
    if updater.parse_version("v2.3.1") != (2, 3, 1):
        print("ERROR: version parser failed")
        return 1
    if not updater.check_for_update((2, 2, 0)).ignored:
        print("ERROR: update check should be ignored before v2.3")
        return 1
    icon = resource_path("assets/CTFusion.png")
    details = fileprops.shell_properties(icon) if icon.is_file() else []
    print(f"Windows properties: {len(details)} sections")
    if os.name == "nt" and not details:
        print("ERROR: Windows property system unavailable")
        return 1
    print(f"version: {__version__}")
    print("OK")
    return 0


def _prepare_working_directory() -> None:
    """把工作目录切到临时目录。

    某些输入法（如搜狗）会往当前进程的工作目录写 `debug.log`；切换工作目录
    后这类日志就不会出现在程序文件夹里。
    """
    try:
        target = Path(tempfile.gettempdir())
        if target.is_dir():
            os.chdir(target)
    except OSError:
        pass


def main() -> int:
    _prepare_working_directory()
    if "--self-test" in sys.argv:
        return _self_test()
    # 内部诊断：直接写一个文件，返回 0/1。用于判断保存失败是否由文件名
    # 或安全软件引起，不创建 QApplication。
    if "--write-probe" in sys.argv:
        try:
            index = sys.argv.index("--write-probe")
            target = Path(sys.argv[index + 1])
        except (ValueError, IndexError):
            return 2
        try:
            target.write_bytes(b"ctfusion-probe")
            return 0
        except OSError:
            return 1
    # 提权辅助进程：只做一次文件写入，不创建 QApplication，也不显示界面。
    # 由 ui.save_utils 在 Windows 拒绝普通写入时通过 ShellExecuteW("runas") 启动。
    from core.elevate import ELEVATED_FLAG, run_elevated_task
    if ELEVATED_FLAG in sys.argv:
        return run_elevated_task(sys.argv)
    app = QApplication(sys.argv)
    app.setApplicationName("CTFusion")
    app.setOrganizationName("CTFusion")
    app.setApplicationVersion(__version__)
    i18n.initialize()
    icon_path = resource_path("assets/CTFusion.png")
    if icon_path.is_file():
        app.setWindowIcon(QIcon(str(icon_path)))
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
