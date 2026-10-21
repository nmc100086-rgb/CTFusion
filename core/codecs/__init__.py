"""编解码器包:导入实现模块即触发 __init_subclass__ 自动注册。"""

from core.codecs.base import CodecBase, CodecError  # noqa: F401

# 导入全部实现模块,触发自动注册
from core.codecs import (  # noqa: F401
    bases,
    classical,
    hashes,
    hill,
    jsfuck,
    ook,
    rot,
    symmetric,
    text_enc,
    uue,
    zerowidth,
)


def get_all() -> list[CodecBase]:
    """按分类、名称排序返回全部已注册编码器。"""
    return sorted(CodecBase.registry, key=lambda c: (c.category, c.name))
