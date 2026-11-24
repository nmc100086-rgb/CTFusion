"""首次运行提示：只显示一次，之后不再出现。"""

from __future__ import annotations

from PySide6.QtCore import QSettings
from PySide6.QtWidgets import QMessageBox, QWidget

from ui import i18n

FLAG_KEY = "ui/first_run_tip_v23"


def _settings() -> QSettings:
    return QSettings("CTFusion", "CTFusion")


def shown_before() -> bool:
    value = str(_settings().value(FLAG_KEY, "") or "")
    return value.lower() in ("1", "true", "yes")


def mark_shown() -> None:
    try:
        _settings().setValue(FLAG_KEY, "1")
    except OSError:
        pass


def maybe_show(parent: QWidget | None) -> bool:
    """第一次运行时显示一次说明，返回是否本次显示过。"""
    if shown_before():
        return False
    box = QMessageBox(parent)
    box.setIcon(QMessageBox.Information)
    box.setWindowTitle(i18n.tr("首次运行提示"))
    box.setText(i18n.tr("这个提示只显示一次，之后不再出现。"))
    box.setInformativeText(i18n.tr(
        "1. 保存文件时会直接写入你选择的位置；如果 Windows 或安全软件拒绝写入，"
        "程序会自动以管理员身份再写一次（会弹一次 UAC，可在「设置 → 保存时请求"
        "管理员权限」关闭）。\n"
        "2. 如果 Windows 弹出「Windows 已保护你的电脑」，点「更多信息」→"
        "「仍要运行」即可，之后运行同一个程序不会再拦截。\n"
        "3. 保存位置、权限选择和界面语言都会被记住，不会每次运行都询问。\n"
        "4. 「帮助 → 保存权限自检」可以检查每个目录能否写入；如果仍失败，"
        "请把 CTFusion v2.3.1.exe 加入 360 / 电脑管家 的信任区。"))
    box.addButton(i18n.tr("知道了"), QMessageBox.AcceptRole)
    box.exec()
    mark_shown()
    return True
