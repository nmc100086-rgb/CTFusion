import ctypes
import os
import sys
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

from ui.main_window import MainWindow


def resource_path(relative_path: str) -> Path:
    """Resolve project assets in both source and PyInstaller builds."""
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    return base / relative_path


def _self_test() -> int:
    """Headless build check: bundled bkcrack + CRC32 inversion."""
    import zlib

    from core import bkcrack, zipcrack

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
    print("OK")
    return 0


def main() -> int:
    if "--self-test" in sys.argv:
        return _self_test()
    app = QApplication(sys.argv)
    app.setApplicationName("CTFusion")
    app.setApplicationVersion("2.2.0")
    icon_path = resource_path("assets/CTFusion.png")
    if icon_path.is_file():
        app.setWindowIcon(QIcon(str(icon_path)))
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
