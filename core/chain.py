"""一键智能解码:多层链式 BFS + 字符集启发式剪枝 + flag 提前终止。

核心思路:
- 每层只扩展"看起来像编码数据"的节点(启发式剪枝),避免指数爆炸;
- 深度 3 足够覆盖绝大多数 CTF 套娃场景;
- 命中 flag 格式立即终止向下扩展(flag 本身不会再是编码数据);
- 凯撒通过 best_decode 走单分支(25 路太爆炸,结果合并后评分)。
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from core.codecs.base import has_flag, readability


# 各种编码的合法字符集(用于启发式剪枝)
_CHARSET = {
    "Base16": set("0123456789abcdefABCDEF"),
    "Base32": set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567="),
    "Base45": set("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"),
    "Base58": set("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"),
    "Base62": set("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"),
    "Base64": set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="),
    "Base85": set("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~"),
    "Ascii85": set("!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstu"),
    "Base91": set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\""),
    "Base92": set("!#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_abcdefghijklmnopqrstuvwxyz{|}"),
    "URL 编码": set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~%"),
    "摩斯电码": set(".-/ "),
}

# 高置信度编码(命中字符集即扩展)
_HIGH_CONFIDENCE = {"Base16", "Base32", "Base58", "Base62", "Base64", "Base85", "Ascii85", "Base91", "Base92"}


def _looks_like(text: str, codec_name: str) -> float:
    """返回 0~1 的"像这个编码"的置信度。"""
    if codec_name == "URL 编码":
        return 1.0 if re.search(r"%[0-9A-Fa-f]{2}", text) else 0.0
    if codec_name == "Quoted-printable":
        # 只有 =XX 或软换行才可能是 QP,避免把普通 Base64 的尾部 '=' 当成 QP
        return 1.0 if re.search(r"=[0-9A-Fa-f]{2}|=\r?\n", text) else 0.0
    if codec_name == "ASCII 码":
        tokens = re.split(r"[\s,]+", text.strip())
        if not tokens or tokens == [""]:
            return 0.0
        return 1.0 if all(re.fullmatch(r"(?:0[xX][0-9A-Fa-f]+|0[bB][01]+|0[oO][0-7]+|\d+)", t)
                          for t in tokens) else 0.0
    if codec_name == "零宽字符":
        return 1.0 if ("\u200b" in text or "\u200c" in text) else 0.0
    if codec_name == "摩斯电码":
        dots = sum(1 for c in text if c in ".-")
        return dots / len(text) if text else 0.0
    cs = _CHARSET.get(codec_name)
    if not cs:
        return 0.5
    cleaned = re.sub(r"\s+", "", text)
    if not cleaned:
        return 0.0
    allowed = sum(1 for c in cleaned if c in cs)
    ratio = allowed / len(cleaned)
    if codec_name in _HIGH_CONFIDENCE:
        return ratio if ratio >= 0.9 else 0.0
    return ratio * 0.8


@dataclass
class ChainHit:
    path: list[str]
    output: str
    score: float


# 这些古典密码对任何文本都能产出“看起来可读”的结果,需要更严格的提升阈值
_WEAK_CODECS = {
    "凯撒密码", "ROT13", "放射密码", "栅栏密码", "曲路密码",
    "培根密码", "摩斯电码", "猪圈密码",
}

# 这些编码解出来通常是文本,必须真的像文本才收进智能结果
_TEXT_CODECS = {
    "Hex", "URL 编码", "Quoted-printable", "ASCII 码",
    "UUencode", "XXencode", "零宽字符",
}

_COMMON_WORDS = set(
    "the and is of to in it you that he was for on are with as his they at be this "
    "have from or one had by word but not what all were we when your can said there "
    "use an each which she do how their if will up other about out many then them "
    "these so some her would make like him into time has look two more write go see "
    "number no way could people my than first water been call who oil its now find "
    "long down day did get come made may part over new sound take only little work "
    "know place year live me back give most very after thing our just name good".split()
)
_COMMON_BIGRAMS = set(
    "th he in er an re on at en nd ti es or te of ed is it al ar st to nt ng se ha "
    "as ou io le ve co me de hi ri ro ic ne ea ra ce li ch ll be ma si om ur".split()
)
_COMMON_TRIGRAMS = set(
    "the and ing her ere ent tha nth was eth for dth hat she ion tio ver est ter res "
    "all wit thi".split()
)


def _english_score(s: str) -> float:
    """简单的英文词/二元组/三元组打分,用于区分真正的凯撒解密和 Atbash 噪声。"""
    text = re.sub(r"[^a-z ]", " ", s.lower())
    words = re.findall(r"[a-z]+", text)
    if not words:
        return 0.0
    word_hits = sum(1 for w in words if w in _COMMON_WORDS)
    letters = text.replace(" ", "")
    bigram_hits = sum(1 for i in range(len(letters) - 1)
                       if letters[i:i + 2] in _COMMON_BIGRAMS)
    trigram_hits = sum(1 for i in range(len(letters) - 2)
                       if letters[i:i + 3] in _COMMON_TRIGRAMS)
    score = (word_hits * 0.15
             + (bigram_hits / max(1, len(letters) - 1)) * 2
             + (trigram_hits / max(1, len(letters) - 2)) * 3)
    return min(score, 1.0)


def _printable_ratio(s: str) -> float:
    sample = s[:300]
    if not sample:
        return 0.0
    return sum(1 for c in sample if c.isprintable() or c in "\n\r\t") / len(sample)


def _meaningful_text(s: str) -> bool:
    """判断输出是否像自然文本(中文/句子/常见英文单词)。"""
    if len(s) < 4 or _printable_ratio(s) < 0.95:
        return False
    if any(0xD800 <= ord(c) <= 0xDFFF for c in s[:300]):
        return False
    sample = s[:300]
    # 字母/空白占比太低说明只是随机符号,不是自然文本
    if sum(1 for c in sample if c.isalpha() or c.isspace()) / len(sample) < 0.75:
        return False
    if any(ord(c) > 127 for c in sample) or " " in s:
        return True
    # 单个英文单词(如 ASCII/Base 解码出的 "Hello")
    return s.isalpha() and _english_score(s) >= 0.70


def _should_record(codec_name: str, out: str, score: float, parent_score: float,
                   parent_eng: float) -> bool:
    """过滤掉“凯撒/Atbash 随便转一下”的噪声,保留真正的解码结果。"""
    if has_flag(out):
        return True
    # 解出来是乱码/二进制时不进入智能结果
    if _printable_ratio(out) < 0.90:
        return False
    if codec_name in _WEAK_CODECS:
        # 弱变换只看“像不像一句英文”:必须包含词间空白,且不应夹带数字/二进制符号。
        # 否则短单词的二元组得分很容易靠巧合冲高(如 "ESHenS8=" 也会得到 1.0)。
        if any(c.isdigit() for c in out):
            return False
        out_eng = _english_score(out)
        return (out_eng >= 0.60
                and out_eng >= parent_eng + 0.15
                and any(c.isspace() for c in out))
    if codec_name in _TEXT_CODECS:
        return _meaningful_text(out)
    if score >= max(parent_score + 0.05, 0.65):
        return True
    # Base 家族解出的短文本:可读性可能和密文接近,但内容已经是正常文本
    if (codec_name in _HIGH_CONFIDENCE and len(out) >= 4
            and _printable_ratio(out) >= 0.95 and score >= 0.70):
        return True
    return _meaningful_text(out) and score >= 0.60


def smart_decode(text: str, max_depth: int = 3, top_n: int = 30) -> list[ChainHit]:
    """多层链式智能解码。

    只返回“比原文明显更可读”或命中 flag 的结果;
    纯明文(如 HelloWorld)不会再返回一堆凯撒/Atbash 噪声。
    """
    from core.codecs import get_all

    if not text:
        return []
    # 输入本身已经是 flag 时直接返回,不必再套娃
    if has_flag(text):
        return [ChainHit(["原文"], text, readability(text))]

    input_score = readability(text)
    candidates = [c for c in get_all() if c.detectable and not c.need_key]
    hits: list[ChainHit] = []
    seen = {text}
    frontier: list[tuple[str, list[str], float]] = [(text, [], input_score)]

    for depth in range(max_depth):
        nxt: list[tuple[str, list[str], float]] = []
        for cur, path, cur_score in frontier:
            cur_eng = _english_score(cur)
            # 对所有候选编码按"看起来像"的程度排序
            scored = []
            for codec in candidates:
                conf = _looks_like(cur, codec.name)
                if conf > 0.0:
                    scored.append((conf, codec))
            scored.sort(key=lambda x: -x[0])

            for _, codec in scored:
                # 不连续套用两个弱古典变换(凯撒->Atbash 之类基本是噪声)
                if codec.name in _WEAK_CODECS and any(p in _WEAK_CODECS for p in path):
                    continue
                try:
                    if hasattr(codec, "best_decode"):
                        out = codec.best_decode(cur)
                    else:
                        out = codec.decode(cur)
                except Exception:
                    continue
                if not out or out == cur or out in seen:
                    continue
                seen.add(out)
                score = readability(out)
                new_path = path + [codec.name]
                if _should_record(codec.name, out, score, cur_score, cur_eng):
                    hits.append(ChainHit(new_path, out, score))
                # 命中 flag 格式就不向下扩展
                if has_flag(out):
                    continue
                # 古典密码通常是最外层;不再从它继续套娃,避免噪声爆炸
                if codec.name in _WEAK_CODECS:
                    continue
                # 得分低(乱码)也不扩展
                if score < 0.4:
                    continue
                nxt.append((out, new_path, score))
        frontier = nxt

    hits.sort(key=lambda h: h.score, reverse=True)
    # 一旦找到 flag,就只展示 flag 结果,不再用中间层干扰用户
    flag_hits = [h for h in hits if has_flag(h.output)]
    if flag_hits:
        hits = flag_hits
    return hits[:top_n]
