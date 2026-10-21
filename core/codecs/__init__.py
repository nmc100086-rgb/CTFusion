"""编解码器注册表：新增编码实现后在 REGISTRY 登记，链式爆破即可自动发现。"""

from core.codecs.base import Codec

REGISTRY: list[Codec] = [
    # TODO: 实现后逐个注册，例如:
    # Base64Codec(),
    # HexCodec(),
    # MorseCodec(),
]
