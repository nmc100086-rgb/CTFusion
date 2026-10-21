"""Hill 密码:2x2 / 3x3 矩阵,模 26 运算,密钥为逗号分隔数字。"""

from __future__ import annotations

from core.codecs.base import CodecBase, CodecError

_MOD = 26


def _egcd(a: int, b: int) -> tuple[int, int, int]:
    if b == 0:
        return a, 1, 0
    g, x, y = _egcd(b, a % b)
    return g, y, x - (a // b) * y


def _modinv(a: int) -> int | None:
    g, x, _ = _egcd(a % _MOD, _MOD)
    return x % _MOD if g == 1 else None


def _det(m: list[list[int]]) -> int:
    n = len(m)
    if n == 2:
        return m[0][0] * m[1][1] - m[0][1] * m[1][0]
    return (m[0][0] * (m[1][1] * m[2][2] - m[1][2] * m[2][1])
            - m[0][1] * (m[1][0] * m[2][2] - m[1][2] * m[2][0])
            + m[0][2] * (m[1][0] * m[2][1] - m[1][1] * m[2][0]))


def _adjugate(m: list[list[int]]) -> list[list[int]]:
    n = len(m)
    if n == 2:
        return [[m[1][1], -m[0][1]], [-m[1][0], m[0][0]]]
    a, b, c = m[0]
    d, e, f = m[1]
    g, h, i = m[2]
    cof = [
        [e * i - f * h, -(d * i - f * g), d * h - e * g],
        [-(b * i - c * h), a * i - c * g, -(a * h - b * g)],
        [b * f - c * e, -(a * f - c * d), a * e - b * d],
    ]
    # 伴随 = 代数余子式矩阵的转置
    return [[cof[j][k] for j in range(3)] for k in range(3)]


def _mat_mul_vec(m: list[list[int]], v: list[int]) -> list[int]:
    return [sum(row[k] * v[k] for k in range(len(v))) % _MOD for row in m]


class HillCodec(CodecBase):
    name = "Hill 密码"
    category = "古典密码"
    description = "矩阵加密(模 26),仅处理字母;长度不足补 X"
    need_key = True
    key_hint = "2x2 或 3x3 矩阵,逗号分隔数字,如 3,3,2,5"
    detectable = False

    def _parse_key(self, key: str) -> list[list[int]]:
        raw = key.replace(" ", "")
        try:
            nums = [int(x) for x in raw.split(",") if x != ""]
        except ValueError:
            raise CodecError("Hill 密钥格式错误:需为逗号分隔的整数")
        n = {4: 2, 9: 3}.get(len(nums))
        if n is None:
            raise CodecError(f"Hill 密钥需 4 个(2x2)或 9 个(3x3)数字,当前 {len(nums)} 个")
        m = [nums[i * n:(i + 1) * n] for i in range(n)]
        det = _det(m) % _MOD
        if _modinv(det) is None:
            raise CodecError(f"密钥矩阵在模 26 下不可逆(行列式 {det} 与 26 不互素)")
        return m

    @staticmethod
    def _inverse(m: list[list[int]]) -> list[list[int]]:
        inv_det = _modinv(_det(m) % _MOD)
        adj = _adjugate(m)
        n = len(m)
        return [[(inv_det * adj[r][c]) % _MOD for c in range(n)] for r in range(n)]

    def _run(self, text: str, m: list[list[int]]) -> str:
        n = len(m)
        letters = [c for c in text.upper() if "A" <= c <= "Z"]
        if not letters:
            raise CodecError("Hill 密码仅处理英文字母")
        while len(letters) % n:
            letters.append("X")
        nums = [ord(c) - 65 for c in letters]
        out = []
        for i in range(0, len(nums), n):
            out.extend(_mat_mul_vec(m, nums[i:i + n]))
        return "".join(chr(v + 65) for v in out)

    def encode(self, text: str, key: str = "", **p) -> str:
        return self._run(text, self._parse_key(key))

    def decode(self, text: str, key: str = "", **p) -> str:
        return self._run(text, self._inverse(self._parse_key(key)))
