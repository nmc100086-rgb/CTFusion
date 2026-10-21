"""编解码器协议与结果结构：所有编码模块遵守同一契约。"""

from dataclasses import dataclass
from typing import Optional, Protocol


@dataclass
class DecodeResult:
    codec: str          # 编码名称，如 "Base64"
    output: bytes       # 解码输出
    confidence: float   # 0~1，供排序
    note: str = ""      # 附加信息（如凯撒的偏移量）


class Codec(Protocol):
    """编解码器协议。每个编码一个实现类。"""

    name: str

    def detect(self, data: bytes) -> float:
        """返回 0~1 的匹配置信度，0 表示绝不可能是该编码。"""
        ...

    def decode(self, data: bytes) -> Optional[bytes]:
        """解码失败返回 None。"""
        ...
