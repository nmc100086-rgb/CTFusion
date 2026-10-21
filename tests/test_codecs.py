"""MiscKit 编解码回归测试。

运行方式(在 MiscKit 目录下):
    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import base64
import shutil
import sys
import unittest
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.chain import smart_decode  # noqa: E402
from core.codecs import get_all  # noqa: E402
from core.codecs.base import readability  # noqa: E402


def codec(name: str):
    return {c.name: c for c in get_all()}[name]


class CodecRoundTripTests(unittest.TestCase):
    def test_base_family_roundtrip(self):
        texts = ["Hello, World!", "中文测试", "flag{roundtrip}", "A", ""]
        for name in ("Base16", "Base32", "Base45", "Base58", "Base62", "Base64",
                     "Base85", "Ascii85", "Base91", "Base92", "Hex",
                     "Quoted-printable", "UUencode", "XXencode", "零宽字符"):
            c = codec(name)
            for text in texts:
                with self.subTest(name=name, text=text):
                    self.assertEqual(c.decode(c.encode(text)), text)

    def test_ascii85_preserves_angle_brackets(self):
        c = codec("Ascii85")
        self.assertEqual(c.encode("a "), "@3>")
        self.assertEqual(c.decode("@3>"), "a ")
        long_text = "The quick brown fox jumps over the lazy dog"
        self.assertEqual(c.decode(c.encode(long_text)), long_text)

    def test_ascii85_adobe_wrapper_and_z(self):
        c = codec("Ascii85")
        self.assertEqual(c.decode("<~87cURD]i,\"Ebo80~>"), "Hello World!")
        self.assertEqual(c.decode("<~z~>"), "\x00\x00\x00\x00")

    def test_base32_unpadded(self):
        self.assertEqual(codec("Base32").decode("JBSWY3DPFQQFO33SNRSCC"), "Hello, World!")

    def test_base32_custom_alphabet_padding(self):
        c = codec("Base32")
        alphabet = "abcdefghijklmnopqrstuvwxyz234567"
        encoded = c.encode("Hello, World!", alphabet=alphabet)
        self.assertEqual(c.decode(encoded.rstrip("="), alphabet=alphabet), "Hello, World!")

    def test_brainfuck_ook_non_ascii(self):
        for name in ("Brainfuck", "Ook!"):
            c = codec(name)
            for text in ("中文测试", "é", "😀", "ASCII ok"):
                with self.subTest(name=name, text=text):
                    self.assertEqual(c.decode(c.encode(text)), text)

    def test_bacon_standard_table_and_spaces(self):
        c = codec("培根密码")
        self.assertEqual(c.encode("K"), "ABAAB")
        self.assertEqual(c.encode("L"), "ABABA")
        self.assertEqual(c.encode("V"), "BAABB")
        self.assertEqual(c.encode("Z"), "BABBB")
        self.assertEqual(c.decode("ABAAB"), "K")
        self.assertEqual(c.decode(c.encode("HELLO WORLD")), "HELLO WORLD")
        self.assertEqual(c.decode(c.encode("A  B")), "A  B")

    def test_url_plus_and_percent(self):
        c = codec("URL 编码")
        self.assertEqual(c.decode("a+b"), "a b")
        self.assertEqual(c.decode("Hello%20World"), "Hello World")

    def test_ascii_leading_zero_and_surrogate(self):
        c = codec("ASCII 码")
        self.assertEqual(c.decode("065 066"), "AB")
        self.assertEqual(c.decode("0x41 0x42"), "AB")
        with self.assertRaisesRegex(Exception, "代理区"):
            c.decode("55296")

    def test_base_convert_direction(self):
        c = codec("进制转换")
        encoded = c.encode("255", from_base="10", to_base="16")
        self.assertEqual(encoded, "FF")
        self.assertEqual(c.decode(encoded, from_base="10", to_base="16"), "255")
        self.assertEqual(c.encode("FF", from_base="16", to_base="10"), "255")
        self.assertEqual(c.decode("255", from_base="16", to_base="10"), "FF")

    def test_route_and_hill_strip_padding(self):
        route = codec("曲路密码")
        self.assertEqual(route.decode(route.encode("Hello, World!", cols="5"), cols="5"),
                         "Hello, World!")

        hill = codec("Hill 密码")
        self.assertEqual(hill.decode(hill.encode("HELLO", key="3,3,2,5"), key="3,3,2,5"),
                         "HELLO")
        self.assertEqual(
            hill.decode(hill.encode("HELLO", key="3,3,2,5"), key="3,3,2,5",
                        strip_padding="0"),
            "HELLOX")

    def test_hill_letters_only_browser_compatibility(self):
        # 浏览器版 Hill 对 "FLAGWELCOMETOCFT"、key=2 5 9 5、模式1 的输出
        hill = codec("Hill 密码")
        ciphertext = "NWEEMKGFKEZBMGBK"
        self.assertEqual(hill.encode("FLAGWELCOMETOCFT", key="2,5,9,5"), ciphertext)
        self.assertEqual(hill.decode(ciphertext, key="2,5,9,5"), "FLAGWELCOMETOCFT")

    def test_hill_browser_mode_matches_and_restores_flag(self):
        # 浏览器版把 {}、空格也按 charCode 参与运算
        hill = codec("Hill 密码")
        plaintext = "flag{welcome come to ctf}"
        ciphertext = "NWEESILNWKSYWZKEZBEHWZLOBF"
        self.assertEqual(hill.encode(plaintext, key="2,5,9,5"), ciphertext)
        self.assertEqual(hill.decode(ciphertext, key="2,5,9,5"), plaintext)
        # 关掉 restore 时只能看到浏览器映射后的字母
        self.assertEqual(
            hill.decode(ciphertext, key="2,5,9,5", restore="0"),
            "FLAGGWELCOMETCOMETTOTCTFI",
        )

    def test_hill_browser_mode2_matches_browser(self):
        # 浏览器模式2(A=1)的实测向量
        hill = codec("Hill 密码")
        vectors = {
            "A": "RY",
            "B": "TH",
            "Z": "PP",
            "AB": "LS",
            "ABCD": "LS@U",
            "HELLO": "OSFLTU",
            "FLAG": "TJKR",
        }
        for plaintext, ciphertext in vectors.items():
            with self.subTest(plaintext=plaintext):
                self.assertEqual(
                    hill.encode(plaintext, key="2,5,9,5", mode="2"),
                    ciphertext,
                )
        plaintext = "flag{welcome come to ctf}"
        ciphertext = "TJKRYVRACXYLCMQRFOKUCMRBHS"
        self.assertEqual(hill.encode(plaintext, key="2,5,9,5", mode="2"), ciphertext)
        self.assertEqual(hill.decode(ciphertext, key="2,5,9,5", mode="2"), plaintext)

    def test_hill_letters_mode_keeps_standard_behavior(self):
        hill = codec("Hill 密码")
        # letters 模式只处理 A-Z,{} 和空格会被丢弃
        self.assertEqual(
            hill.decode(
                hill.encode("flag{welcome come to ctf}", key="2,5,9,5",
                            char_mode="letters"),
                key="2,5,9,5", char_mode="letters",
            ),
            "FLAGWELCOMECOMETOCTF",
        )

    def test_morse_braces_and_case(self):
        morse = codec("摩斯电码")
        plaintext = "flag{welcome come to ctf}"
        encoded = morse.encode(plaintext)
        self.assertIn("----.--", encoded)
        self.assertIn("-----.-", encoded)
        self.assertEqual(morse.decode(encoded), plaintext)
        self.assertEqual(morse.decode(encoded, letter_case="upper"), plaintext.upper())
        # 浏览器在线工具的输出(它不保留单词空格)
        browser = ("..-. .-.. .- --. ----.-- .-- . .-.. -.-. --- -- . "
                   "-.-. --- -- . - --- -.-. - ..-. -----.-")
        self.assertEqual(morse.decode(browser), "flag{welcome come to ctf}")
        self.assertEqual(morse.decode(browser, restore_spaces="0"),
                         "flag{welcomecometoctf}")
        # 兼容 Wells 扩展括号码
        wells = "..-. .-.. .- --. .--.- .-- . .-.. -.-. --- -- . .--.--"
        self.assertEqual(morse.decode(wells), "flag{welcome}")

    def test_rail_fence_standard_and_w(self):
        fence = codec("栅栏密码")
        # W 型:之字形
        self.assertEqual(
            fence.encode("HELLOWORLD", rails="3", fence_type="W"),
            "HOLELWRDLO",
        )
        # 标准型:按 i % rails 分栏后顺序读出
        self.assertEqual(
            fence.encode("HELLOWORLD", rails="3", fence_type="标准"),
            "HLODEORLWL",
        )
        self.assertEqual(
            fence.encode("THEREISACIPHER", rails="2", fence_type="标准"),
            "TEESCPEHRIAIHR",
        )
        for fence_type in ("W", "标准"):
            for text in ("HELLOWORLD", "WEAREDISCOVEREDFLEEATONCE", "中文测试ABC"):
                with self.subTest(fence_type=fence_type, text=text):
                    encoded = fence.encode(text, rails="3", fence_type=fence_type)
                    self.assertEqual(
                        fence.decode(encoded, rails="3", fence_type=fence_type),
                        text,
                    )

    def test_empty_input_consistency(self):
        for name in ("Base85", "ASCII 码", "UUencode", "XXencode", "Brainfuck",
                     "Ook!", "零宽字符", "摩斯电码", "猪圈密码", "凯撒密码",
                     "培根密码", "曲路密码", "进制转换"):
            c = codec(name)
            with self.subTest(name=name):
                self.assertEqual(c.decode(c.encode("")), "")


class SymmetricTests(unittest.TestCase):
    def test_rc4_ascii_key_is_not_auto_hex(self):
        c = codec("RC4")
        # 与 PyCryptodome 的 ASCII 密钥结果一致
        self.assertEqual(c.encode("hello", key="deadbeef", format="hex"), "687d3d9393")
        self.assertEqual(c.encode("hello", key="hex:deadbeef", format="hex"), "8bf0de69e4")
        self.assertEqual(c.encode("hello", key="deadbeef", format="hex",
                                   key_format="hex"), "8bf0de69e4")

    def test_aes_key_formats(self):
        c = codec("AES")
        key = "0123456789abcdef0123456789abcdef"  # 32 个 ASCII 字符 / 32 个 hex 字符
        utf8_ct = c.encode("hello", key=key, mode="ECB", format="hex")
        hex_ct = c.encode("hello", key=key, mode="ECB", format="hex", key_format="hex")
        self.assertNotEqual(utf8_ct, hex_ct)
        self.assertEqual(c.decode(utf8_ct, key=key, mode="ECB", format="hex"), "hello")
        self.assertEqual(c.decode(hex_ct, key=key, mode="ECB", format="hex",
                                  key_format="hex"), "hello")

    def test_aes_iv_format(self):
        c = codec("AES")
        key = "0123456789abcdef"
        iv = "0123456789abcdef0123456789abcdef"
        ct = c.encode("hello", key=key, iv=iv, mode="CBC", format="hex", iv_format="hex")
        self.assertEqual(c.decode(ct, key=key, iv=iv, mode="CBC", format="hex",
                                  iv_format="hex"), "hello")


class SmartDecodeTests(unittest.TestCase):
    def test_plain_text_has_no_noise(self):
        for text in ("HelloWorld", "This is just a normal sentence.", "monkey{bar}"):
            self.assertEqual(smart_decode(text), [])

    def test_single_word_and_ascii_decode(self):
        hits = smart_decode(codec("Base64").encode("Hello"))
        self.assertEqual([(h.path, h.output) for h in hits], [(["Base64"], "Hello")])
        hits = smart_decode(codec("ASCII 码").encode("Hello"))
        self.assertEqual([(h.path, h.output) for h in hits], [(["ASCII 码"], "Hello")])

    def test_flag_input_is_identity(self):
        hits = smart_decode("flag{already_here}")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].path, ["原文"])

    def test_common_chains_find_flag(self):
        flag = "flag{smart_decode_works}"
        cases = {
            "base64": base64.b64encode(flag.encode()).decode(),
            "base64x2": base64.b64encode(base64.b64encode(flag.encode())).decode(),
            "base32": base64.b32encode(flag.encode()).decode(),
            "hex": flag.encode().hex(),
            "url": urllib.parse.quote(flag),
            "caesar": codec("凯撒密码").encode(flag, shift="3"),
            "rail": codec("栅栏密码").encode(flag, rails="3"),
        }
        for name, encoded in cases.items():
            with self.subTest(name=name):
                hits = smart_decode(encoded)
                self.assertTrue(hits)
                self.assertEqual(hits[0].output, flag)

    def test_smart_decode_does_not_execute_jsfuck(self):
        # 即使输入是合法的 JSFuck 字符集,也不应参与一键解码(Node 执行)
        hits = smart_decode("[]")
        self.assertEqual(hits, [])

    def test_readability_flag_boundary(self):
        self.assertFalse(readability("monkey{bar}") >= 1.0)
        self.assertGreaterEqual(readability("flag{abc}"), 1.0)


@unittest.skipUnless(shutil.which("node"), "需要本机安装 Node.js")
class JsfuckTests(unittest.TestCase):
    def test_small_jsfuck(self):
        c = codec("JSFuck")
        self.assertEqual(c.decode("(![]+[])[+[]]+(![]+[])[+!+[]]"), "fa")

    def test_large_jsfuck_uses_stdin(self):
        # Windows 命令行上限约 32K;通过 stdin 传递后 35K 的代码也能执行
        code = "+".join(["![]+[]"] * 5000)  # 34999 字符,输出 25000 个 "false"
        self.assertEqual(len(codec("JSFuck").decode(code)), 25000)


if __name__ == "__main__":
    unittest.main()
