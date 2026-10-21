"""Hill 密码:2x2 / 3x3 矩阵,模 26 运算,密钥为逗号分隔数字。

支持两种字符模式:
- letters: 标准 Hill,只处理 A-Z,忽略其它字符;
- browser: 兼容 AmanCTF/Bugku 的浏览器版,把 {}、空格等也按
  (charCode - 65) mod 26 参与运算(等价于浏览器的模式1 A=0)。

浏览器版本身是“有损”的:{ 和 G、空格和 T、} 和 I 映射到同一个值,
所以解码时无法百分百恢复标点。restore=1 会对常见的 flag{...} 做启发式还原。
"""

from __future__ import annotations

from functools import lru_cache

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


def _bool_param(params: dict, name: str, default: bool = True) -> bool:
    raw = str(params.get(name, "1" if default else "0")).strip().lower()
    return raw not in ("0", "false", "no", "off")


# 浏览器版 flag 还原用的常见词。只用于 restore=1 的启发式,
# 找不到合适分词时会退回普通字母串。
_RESTORE_WORDS = set(
    "flag welcome come to ctf the and is of in it you that he was for on are with "
    "as his they at be this have from or one had by word but not what all were we "
    "when your can said there use an each which she do how their if will up other "
    "about out many then them these so some her would make like him into time has "
    "look two more write go see number no way could people my than first water been "
    "call who oil its now find long down day did get come made may part over new "
    "sound take only little work know place year live me back give most very after "
    "thing our just name good hello world secret key password decode encode easy hard "
    "misc ctfshow bugku".split()
)
_RESTORE_WORD_LIST = tuple(sorted(_RESTORE_WORDS, key=len, reverse=True))


def _split_browser_words(s: str) -> list[str] | None:
    """把浏览器解密后的字母串按 T(=空格) 和英文词典切成单词。"""
    if not s:
        return []
    n = len(s)

    @lru_cache(maxsize=None)
    def dfs(i: int):
        if i == n:
            return ()
        for word in _RESTORE_WORD_LIST:
            upper = word.upper()
            if not s.startswith(upper, i):
                continue
            j = i + len(upper)
            if j == n:
                return (word,)
            # 浏览器把空格也映射成 T;只有 T 才可能是词间分隔
            if s[j] == "T":
                tail = dfs(j + 1)
                if tail is not None:
                    return (word,) + tail
        return None

    result = dfs(0)
    return list(result) if result is not None else None


def _restore_browser_flag(s: str) -> str:
    """把浏览器版解出的 FLAGGWELCOMET... 尽量还原成 flag{welcome ...}。"""
    # 去掉还原用的尾部 X 填充;不命中 flag 时保持原输出不变
    trimmed = s.rstrip("X")
    if (len(trimmed) >= 6 and trimmed.startswith("FLAG")
            and trimmed[4] == "G" and trimmed.endswith("I")):
        # { -> G, } -> I
        body = trimmed[5:-1]
        words = _split_browser_words(body)
        if words:
            return "flag{" + " ".join(w.lower() for w in words) + "}"
        return "flag{" + body.lower() + "}"
    return s


class HillCodec(CodecBase):
    name = "Hill 密码"
    category = "古典密码"
    description = (
        "矩阵加密(模 26)。char_mode=browser 时与浏览器版一致,把 {}、空格等"
        "也按 charCode 参与运算;mode=1 为 A=0, mode=2 为 A=1。"
        "restore=1 会尽量还原 flag{...} 和常见英文空格。"
        "浏览器版对非字母标点是有损的,无法百分百还原;需要精确结果时请用 letters 模式"
        "并只输入 A-Z。默认解码去掉末尾填充 X(明文本身以 X 结尾时请把 strip_padding 设为 0)。"
    )
    need_key = True
    key_hint = "2x2 或 3x3 矩阵,逗号分隔数字,如 3,3,2,5"
    detectable = False
    params = [
        ("char_mode", "字符模式(letters/browser)", "browser"),
        ("mode", "模式(1=A0/2=A1)", "1"),
        ("restore", "还原flag标点(1/0)", "1"),
        ("strip_padding", "去除末尾填充X(1/0)", "1"),
    ]
    param_choices = {
        "char_mode": [
            ("浏览器(browser)", "browser"),
            ("标准字母(letters)", "letters"),
        ],
        "mode": [
            ("模式1（A=0）", "1"),
            ("模式2（A=1）", "2"),
        ],
        "restore": [
            ("开启(1)", "1"),
            ("关闭(0)", "0"),
        ],
        "strip_padding": [
            ("开启(1)", "1"),
            ("关闭(0)", "0"),
        ],
    }

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

    @staticmethod
    def _char_mode(params: dict) -> str:
        raw = str(params.get("char_mode", "browser")).strip().lower()
        aliases = {
            "letters": "letters", "letter": "letters", "字母": "letters",
            "browser": "browser", "浏览器": "browser",
        }
        mode = aliases.get(raw)
        if mode is None:
            raise CodecError("字符模式仅支持 letters 或 browser")
        return mode

    @staticmethod
    def _mode(params: dict) -> int:
        raw = str(params.get("mode", "1")).strip()
        try:
            mode = int(raw)
        except ValueError:
            raise CodecError("Hill 模式必须是 1(A=0)或 2(A=1)")
        if mode not in (1, 2):
            raise CodecError("Hill 模式必须是 1(A=0)或 2(A=1)")
        return mode

    def _run_letters(self, text: str, m: list[list[int]]) -> str:
        n = len(m)
        letters = [c for c in text.upper() if "A" <= c <= "Z"]
        if not letters:
            if not text:
                return ""
            raise CodecError("Hill 密码仅处理英文字母")
        while len(letters) % n:
            letters.append("X")
        nums = [ord(c) - 65 for c in letters]
        out = []
        for i in range(0, len(nums), n):
            out.extend(_mat_mul_vec(m, nums[i:i + n]))
        return "".join(chr(v + 65) for v in out)

    def _run_browser(self, text: str, m: list[list[int]], decrypt: bool,
                     mode: int = 1) -> str:
        """浏览器版。

        mode=1(A=0): 值 = charCode-65,输出 charCode=值+65;
        mode=2(A=1): 值 = charCode-64,输出 charCode=值+64(值 0 输出 '@')。
        """
        n = len(m)
        chars = text.upper()
        if decrypt:
            # 浏览器 mode1 输出 A-Z;mode2 输出 @-Y(值 0 是 '@')
            if mode == 1:
                chars = "".join(c for c in chars if "A" <= c <= "Z")
            else:
                chars = "".join(c for c in chars if "@" <= c <= "Z")
        if not chars:
            if not text:
                return ""
            raise CodecError("Hill 密码输入中没有可用字符")
        base_in = 65 if mode == 1 else 64
        base_out = 65 if mode == 1 else 64
        nums = [(ord(c) - base_in) % _MOD for c in chars]
        pad_value = (ord("X") - base_in) % _MOD
        while len(nums) % n:
            nums.append(pad_value)   # 浏览器用 X 填充
        out = []
        for i in range(0, len(nums), n):
            out.extend(_mat_mul_vec(m, nums[i:i + n]))
        return "".join(chr(v + base_out) for v in out)

    def encode(self, text: str, key: str = "", **params) -> str:
        m = self._parse_key(key)
        if self._char_mode(params) == "browser":
            return self._run_browser(text, m, decrypt=False, mode=self._mode(params))
        return self._run_letters(text, m)

    def decode(self, text: str, key: str = "", **params) -> str:
        m = self._inverse(self._parse_key(key))
        char_mode = self._char_mode(params)
        if char_mode == "browser":
            out = self._run_browser(text, m, decrypt=True, mode=self._mode(params))
        else:
            out = self._run_letters(text, m)
        if _bool_param(params, "strip_padding", True):
            out = out.rstrip("X")
        if char_mode == "browser" and _bool_param(params, "restore", True):
            out = _restore_browser_flag(out)
        return out
