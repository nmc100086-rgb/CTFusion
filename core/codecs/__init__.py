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
    """按分类、名称排序返回全部已注册编码器;Base85/Ascii85 挨在一起。"""
    def _sort_key(c):
        name = c.name
        # Ascii85 紧跟 Base85 后面(字母序上 'Base85 ' > 'Base85' < 'Base9')
        if name == "Ascii85":
            name = "Base85\x7f"
        return (c.category, name)

    return sorted(CodecBase.registry, key=_sort_key)
