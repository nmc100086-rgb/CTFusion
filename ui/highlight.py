"""flag / ctf / 花括号 / 零宽字符高亮。

不修改文本内容,只通过 QSyntaxHighlighter 改变显示颜色;表格类控件用
mark_item() 给命中单元格加背景色。
"""

from __future__ import annotations

import re

from PySide6.QtCore import QRegularExpression
from PySide6.QtGui import QColor, QFont, QSyntaxHighlighter, QTextCharFormat
from PySide6.QtWidgets import QPlainTextEdit, QTableWidgetItem

FLAG_RE = re.compile(r"\b(?:flag|ctf|key)\s*\{[^}\n]{0,300}\}", re.IGNORECASE)
KEYWORD_RE = re.compile(r"\b(?:flag|ctf|key)\b", re.IGNORECASE)
BRACE_RE = re.compile(r"[{}]")
HIDDEN_RE = re.compile("[\u200b-\u200f\u2060\ufeff]")

FLAG_BG = QColor("#6f5200")
FLAG_FG = QColor("#fff1a8")
KEY_FG = QColor("#ffd166")
BRACE_FG = QColor("#ff9f43")
HIDDEN_BG = QColor("#5a189a")


def has_flag(text: str) -> bool:
    return bool(FLAG_RE.search(text))


def hidden_count(text: str) -> int:
    return len(HIDDEN_RE.findall(text))


def _format(foreground: QColor | None = None, background: QColor | None = None,
            bold: bool = False) -> QTextCharFormat:
    fmt = QTextCharFormat()
    if foreground is not None:
        fmt.setForeground(foreground)
    if background is not None:
        fmt.setBackground(background)
    if bold:
        fmt.setFontWeight(QFont.Bold)
    return fmt


class FlagHighlighter(QSyntaxHighlighter):
    """高亮 flag{...}/ctf{...}、关键字、花括号和零宽字符。"""

    def __init__(self, document) -> None:
        super().__init__(document)
        self._flag_fmt = _format(FLAG_FG, FLAG_BG, True)
        self._key_fmt = _format(KEY_FG, None, True)
        self._brace_fmt = _format(BRACE_FG, None, True)
        self._hidden_fmt = _format(QColor("#ffffff"), HIDDEN_BG, True)
        self._rules: list[tuple[QRegularExpression, QTextCharFormat]] = [
            (QRegularExpression(FLAG_RE.pattern,
                                QRegularExpression.CaseInsensitiveOption),
             self._flag_fmt),
            (QRegularExpression(KEYWORD_RE.pattern,
                                QRegularExpression.CaseInsensitiveOption),
             self._key_fmt),
            (QRegularExpression(BRACE_RE.pattern), self._brace_fmt),
            (QRegularExpression(HIDDEN_RE.pattern), self._hidden_fmt),
        ]

    def highlightBlock(self, text: str) -> None:  # noqa: N802
        for regex, fmt in self._rules:
            match = regex.globalMatch(text)
            while match.hasNext():
                item = match.next()
                self.setFormat(item.capturedStart(), item.capturedLength(), fmt)


def install_flag_highlighter(edit: QPlainTextEdit) -> FlagHighlighter:
    """给 QPlainTextEdit 安装高亮器,并把引用挂在控件上防止被 GC。"""
    highlighter = FlagHighlighter(edit.document())
    edit._flag_highlighter = highlighter  # type: ignore[attr-defined]
    return highlighter


def mark_item(item: QTableWidgetItem, text: str | None = None) -> None:
    """表格单元格命中 flag 时加背景色。"""
    value = text if text is not None else item.text()
    if has_flag(value):
        item.setBackground(FLAG_BG)
        item.setForeground(FLAG_FG)
        item.setToolTip("检测到 flag/ctf 关键字")
