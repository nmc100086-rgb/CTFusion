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

from core.codecs.base import readability


# 各种编码的合法字符集(用于启发式剪枝)
_CHARSET = {
    "Base16": set("0123456789abcdefABCDEF"),
    "Base32": set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567="),
    "Base45": set("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"),
    "Base58": set("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"),
    "Base62": set("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"),
    "Base64": set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="),
    "Base85": set("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~"),
    "Base91": set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\""),
    "Base92": set("!#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_abcdefghijklmnopqrstuvwxyz{|}"),
    "URL 编码": set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~%"),
    "摩斯电码": set(".-/ "),
}

# 高置信度编码(命中字符集即扩展)
_HIGH_CONFIDENCE = {"Base16", "Base32", "Base58", "Base62", "Base64", "Base85", "Base91", "Base92"}


def _looks_like(text: str, codec_name: str) -> float:
    """返回 0~1 的"像这个编码"的置信度。"""
    cs = _CHARSET.get(codec_name)
    if not cs:
        return 0.5
    cleaned = re.sub(r"\s+", "", text)
    if not cleaned:
        return 0.0
    if codec_name == "URL 编码":
        return 1.0 if "%" in text else 0.0
    if codec_name == "摩斯电码":
        dots = sum(1 for c in text if c in ".-")
        return dots / len(text) if text else 0.0
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


def smart_decode(text: str, max_depth: int = 3, top_n: int = 30) -> list[ChainHit]:
    """多层链式智能解码。"""
    from core.codecs import get_all

    candidates = [c for c in get_all() if c.detectable and not c.need_key]
    hits: list[ChainHit] = []
    seen = {text}
    frontier: list[tuple[str, list[str]]] = [(text, [])]

    for depth in range(max_depth):
        nxt: list[tuple[str, list[str]]] = []
        for cur, path in frontier:
            # 对所有候选编码按"看起来像"的程度排序
            scored = []
            for codec in candidates:
                conf = _looks_like(cur, codec.name)
                if conf > 0.0:
                    scored.append((conf, codec))
            scored.sort(key=lambda x: -x[0])

            for _, codec in scored:
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
                hit = ChainHit(new_path, out, score)
                hits.append(hit)
                # 命中 flag 格式就不向下扩展
                if re.search(r"(flag|ctf|key)\{[^}\n]{0,80}\}", out, re.IGNORECASE):
                    continue
                # 得分低(乱码)也不扩展
                if score < 0.4:
                    continue
                nxt.append((out, new_path))
        frontier = nxt

    hits.sort(key=lambda h: h.score, reverse=True)
    return hits[:top_n]
