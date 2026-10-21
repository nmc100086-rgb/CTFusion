"""一键智能解码:遍历可检测编码,BFS 链式尝试,按可读性评分排序。"""

from __future__ import annotations

from dataclasses import dataclass

from core.codecs.base import readability


@dataclass
class ChainHit:
    path: list[str]   # 如 ["Base64", "Hex"]
    output: str
    score: float


def smart_decode(text: str, max_depth: int = 2, top_n: int = 20) -> list[ChainHit]:
    """对输入做 BFS 链式解码,返回按评分降序的候选结果。

    - 仅尝试 detectable 且无需密钥的编码;
    - 凯撒通过 best_decode 取最优单分支,避免 25 路爆炸;
    - 命中 flag{ 格式的结果不再向下扩展。
    """
    from core.codecs import get_all

    candidates = [c for c in get_all() if c.detectable and not c.need_key]
    hits: list[ChainHit] = []
    seen = {text}
    frontier: list[tuple[str, list[str]]] = [(text, [])]

    for depth in range(max_depth):
        nxt: list[tuple[str, list[str]]] = []
        for cur, path in frontier:
            for codec in candidates:
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
                hits.append(ChainHit(new_path, out, score))
                if score < 1.0 and depth + 1 < max_depth:
                    nxt.append((out, new_path))
        frontier = nxt

    hits.sort(key=lambda h: h.score, reverse=True)
    return hits[:top_n]
