"""编解码器统一接口、自动注册机制与可读性评分。

新增一种编码只需两步:
1. 在任意实现模块中定义 CodecBase 子类(自动注册);
2. 在 core/codecs/__init__.py 中导入该模块。
UI 下拉框与一键智能解码会自动发现它。
"""

from __future__ import annotations

import re
from typing import ClassVar


class CodecError(Exception):
    """编解码失败。message 面向用户，直接用于弹窗提示。"""


class CodecBase:
    # ---- 元信息(子类覆盖) ----
    name: str = "未命名"
    category: str = "其他"
    description: str = ""
    one_way: bool = False        # 单向算法(如 MD5)，解码按钮禁用
    detectable: bool = True      # 是否参与一键智能解码

    # ---- 参数能力声明(UI 参数区据此动态渲染) ----
    need_key: bool = False
    key_hint: str = ""
    need_iv: bool = False
    need_alphabet: bool = False  # 支持自定义字母表/映射
    alphabet_hint: str = ""
    params: list[tuple[str, str, str]] = []   # (参数名, 界面标签, 默认值)

    registry: ClassVar[list["CodecBase"]] = []

    def __init_subclass__(cls, abstract: bool = False, **kwargs) -> None:
        super().__init_subclass__(**kwargs)
        if not abstract:
            CodecBase.registry.append(cls())

    # ---- 统一接口:输入输出均为 str;失败必须抛 CodecError ----
    def encode(self, text: str, key: str = "", iv: str = "",
               alphabet: str = "", **params: str) -> str:
        raise CodecError(f"{self.name} 不支持编码")

    def decode(self, text: str, key: str = "", iv: str = "",
               alphabet: str = "", **params: str) -> str:
        raise CodecError(f"{self.name} 不支持解码")

    # ---- 内部工具:surrogateescape 保证 bytes<->str 往返无损 ----
    @staticmethod
    def to_bytes(text: str) -> bytes:
        return text.encode("utf-8", errors="surrogateescape")

    @staticmethod
    def to_text(data: bytes) -> str:
        return data.decode("utf-8", errors="surrogateescape")


def readability(s: str) -> float:
    """文本可读性评分，供一键智能解码排序。命中 flag 格式直接高分。"""
    if not s:
        return 0.0
    sample = s[:300]
    n = len(sample)
    printable = sum(1 for c in sample if c.isprintable() or c in "\n\r\t") / n
    score = printable * 0.6
    if re.search(r"(flag|ctf|key)\{[^}\n]{0,80}\}", sample, re.IGNORECASE):
        score += 1.0
    if n >= 8:
        space_ratio = sample.count(" ") / n
        if 0.05 <= space_ratio <= 0.35:
            score += 0.15
        letters = [c for c in sample if c.isalpha()]
        # 字母太少时元音比例会失真(如 hex 串),不予评分
        if len(letters) >= 8:
            vowel = sum(1 for c in letters if c.lower() in "aeiou") / len(letters)
            if 0.25 <= vowel <= 0.55:
                score += 0.15
    elif printable >= 1.0:
        score += 0.05
    return round(min(score, 2.0), 3)
