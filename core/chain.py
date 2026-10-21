"""链式解码：单层识别 + BFS 爆破搜索解码路径。"""

from core.codecs import REGISTRY
from core.codecs.base import DecodeResult


def detect_all(data: bytes) -> list[DecodeResult]:
    """单层识别：返回所有可能的一次解码结果，按置信度降序。"""
    results: list[DecodeResult] = []
    for codec in REGISTRY:
        # TODO: detect -> decode -> 收集 DecodeResult
        ...
    return results


def decode_chain(data: bytes, max_depth: int = 3) -> list[list[DecodeResult]]:
    """BFS 爆破：返回所有解码路径，命中 flag{ 或高可读文本的排前面。"""
    # TODO: 队列 BFS，限制深度与分支数防止爆炸
    raise NotImplementedError
