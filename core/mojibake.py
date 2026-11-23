"""乱码检测、自动修复与编码转换。

CTF 中常见的乱码来自“字节被用错误的编码解释”：
- UTF-8 字节被当成 Latin-1/CP1252：``æµ‹è¯•``
- GBK 字节被当成 Latin-1：``²âÊÔ``
- UTF-8 字节被当成 GBK/GB18030：``娴嬭瘯``
- 上述情况叠加两层

本模块不做“猜测原文”的黑魔法，而是枚举常见的
``源编码 -> 目标编码`` 组合，按可读性、中文常用字比例和乱码特征评分，
把候选交给用户确认。这样既能自动修复，也能保留人工选择。
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

ENCODINGS: tuple[tuple[str, str], ...] = (
    ("UTF-8", "utf-8"),
    ("GB18030", "gb18030"),
    ("GBK", "gbk"),
    ("Big5", "big5"),
    ("Latin-1", "latin-1"),
    ("CP1252", "cp1252"),
)

# 常见“被错误解释”的源编码。GBK 是 GB18030 的子集，统一用 GB18030。
_SOURCE_ENCODINGS: tuple[tuple[str, str], ...] = (
    ("Latin-1", "latin-1"),
    ("CP1252", "cp1252"),
    ("GB18030", "gb18030"),
    ("Big5", "big5"),
)

_TARGET_ENCODINGS: tuple[tuple[str, str], ...] = (
    ("UTF-8", "utf-8"),
    ("GB18030", "gb18030"),
    ("Big5", "big5"),
    ("CP1252", "cp1252"),
    ("Latin-1", "latin-1"),
)

# 高频汉字。用于区分“真中文”和“UTF-8 被 GBK 解释后碰巧也是汉字”的乱码。
_COMMON_CJK = frozenset(
    "的一是不了人我在有他这为之大来以个中上们到说国和地也子时道出而要于就下得可你年生"
    "自会那后能对着事其里所去行过家十用发天如然作方成者多日都三小军二无同么经法当起与好"
    "看学进种将还分此心前面又定见只主没公从那点开问很最重并物手应战向头文体政美相见被利"
    "什二等产或新己制身果加西斯月话合回特代内信表化老给世位次度门任常先海通教儿原东声提"
    "立及比员解水名真论处走义各入几口认条平系气题活尔更别打女变四神总何电数安少报才结反"
    "受目太量再感建务做接必场件计管期市直德资命山金指克许统区保至队形社便空决治展马科司"
    "五基眼书非则听白却界达光放强即像难且权思王象完设式色路记南品住告类求据程北边死张该"
    "交规万取拉格望觉术领共确传师观清今切院让识候带导争运笑飞风步改收根干造言联持组每济"
    "车亲极林服快办议往元英士证近失转夫令准布始怎呢存未远叫台单影具罗字爱击流备兵连调深"
    "商算质团集百需价花党华城石级整府离况亚请技际约示复病息究线似官火断精满支视消越器容"
    "照须九增研写称企八功吗包片史委乎查轻易早曾除农找装广显吧阿李标谈吃图念六引历首医局"
    "突专费号尽另周较注语仅考落青随选列武红响虽推势参希古众构房半节土投某案黑维革划敌致"
    "陈律足态护七兴派孩验责营星够章音跟志底站严巴例防族供效续施留讲型料终答紧黄绝奇察母"
    "京段依批群项故按河米围江织害斗双境客纪采举杀攻父苏密低朝友诉止细愿千值仍男钱破网热"
    "助倒育属坐帝限船脸职速刻乐否刚威毛状率甚独球般普怕弹校苦创假久错承印晚兰试股拿脑预"
    "谁益阳若哪微尼继送急血惊伤素药适波夜省初喜卫源食险待述陆习置居劳财环排福纳欢雷警获"
    "模充负云停木游龙树疑层冷洲冲射略范竟句室异激汉村哈策演简卡罪判担州静退既衣您宗积余"
    "痛检差富灵协角占配征修皮挥胜降阶审沉坚善妈刘读啊超免压银买皇养伊怀执副乱抗犯追帮宣"
    "佛岁航优怪香著田铁控税左右份穿艺背阵草脚概恶块顿敢守酒岛托央户烈洋哥索胡款靠评版宝"
    "座释景顾弟登货互付伯慢欧换闻危忙核暗姐介坏讨丽良序升监临亮露永呼味野架域沙掉括舰鱼"
    "杂误湾吉减编楚肯测败屋跑梦散温困剑渐封救贵枪缺楼县尚毫移娘朋画班智亦耳恩短掌恐遗固"
    "席松秘谢鲁遇康幸均销钟诗藏赶剧票损忽巨炮旧端探湖录叶春乡附吸予礼港雨呀板庭妇归睛饭"
    "额含顺输摇招婚脱补谓督毒油聊救桌"
)

_LATIN_GARBLE = frozenset(
    "ÃÂÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞß"
    "ãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿ"
    "¡¢£¤¥¦§¨©ª«¬®¯°±²³´µ¶·¸¹º»¼½¾¿"
)

_CJK_GARBLE = frozenset(
    "锛浣犲ソ銆鈥鏄娴嬶绋锟斤拷鏂囦欢瀛楃鍥剧墖"
    "鎴愬姛澶辫触璇锋眰鏌ョ湅"
)

_REPLACEMENT = "\ufffd"
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_HEX_RE = re.compile(r"^(?:[0-9a-fA-F]{2}[\s,;:_-]*)+$")


class MojibakeError(ValueError):
    """乱码修复/编码转换失败，message 可直接展示给用户。"""


@dataclass(frozen=True)
class RepairCandidate:
    text: str
    method: str
    score: float


@dataclass(frozen=True)
class ConversionResult:
    text: str
    method: str


def _sample(text: str) -> str:
    # 评分只看前 1200 字符，避免超长文本拖慢界面；同时保留结尾用于判断。
    if len(text) <= 1200:
        return text
    return text[:1000] + text[-200:]


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    return sum(
        1 for c in text
        if c.isprintable() or c in "\n\r\t"
    ) / len(text)


def quality(text: str) -> float:
    """粗粒度可读性评分，分数越高越像正常文本。

    这不是语言模型，只用于在候选之间排序；最终仍由用户确认。
    """
    if not text:
        return -10.0
    sample = _sample(text)
    n = len(sample)
    score = _printable_ratio(sample) * 2.0

    replacements = sample.count(_REPLACEMENT)
    controls = len(_CONTROL_RE.findall(sample))
    c1 = sum(1 for c in sample if 0x80 <= ord(c) <= 0x9F)
    score -= replacements / n * 30.0
    score -= controls / n * 24.0
    score -= c1 / n * 18.0

    latin_garble = sum(1 for c in sample if c in _LATIN_GARBLE)
    cjk_garble = sum(1 for c in sample if c in _CJK_GARBLE)
    score -= latin_garble / n * 3.2
    score -= cjk_garble / n * 5.0

    cjk = [c for c in sample if "\u4e00" <= c <= "\u9fff"]
    if cjk:
        cjk_ratio = len(cjk) / n
        common_ratio = sum(1 for c in cjk if c in _COMMON_CJK) / len(cjk)
        score += min(cjk_ratio, 0.9) * 1.4
        score += common_ratio * 1.8
        score -= (1.0 - common_ratio) * 0.9
        # 汉字中间夹着片假名/半角片假名，常见于 UTF-8 被 GBK 解释。
        kana = sum(1 for c in sample if "\u3040" <= c <= "\u30ff")
        if kana and len(cjk) > kana:
            score -= kana / n * 1.5

    letters = sum(1 for c in sample if c.isascii() and c.isalpha())
    if letters:
        score += min(letters / n, 0.8)
        if " " in sample:
            score += 0.25
    # 正常标点比控制字符/私用区字符更可信。
    normal_punct = sum(1 for c in sample if c in "，。！？；：、“”‘’（）《》…—,.!?;:'\"()[]{}")
    score += min(normal_punct / n, 0.2) * 1.5
    private = sum(1 for c in sample if 0xE000 <= ord(c) <= 0xF8FF)
    score -= private / n * 8.0

    if re.search(r"(?i)flag\s*\{|ctf\s*\{|key\s*\{", sample):
        score += 2.0
    return score


def looks_garbled(text: str) -> bool:
    """快速判断是否值得尝试修复。"""
    if not text or not text.strip():
        return False
    sample = _sample(text)
    if _REPLACEMENT in sample:
        return True
    if any(0x80 <= ord(c) <= 0x9F for c in sample):
        return True
    if any(c in _LATIN_GARBLE or c in _CJK_GARBLE for c in sample):
        return True
    cjk = [c for c in sample if "\u4e00" <= c <= "\u9fff"]
    if cjk:
        common = sum(1 for c in cjk if c in _COMMON_CJK) / len(cjk)
        if len(cjk) >= 2 and common < 0.15:
            return True
    return quality(text) < 0.35


def _transform_once(text: str) -> list[tuple[str, str]]:
    """枚举一次“按源编码取字节，再按目标编码解释”的转换。"""
    out: list[tuple[str, str]] = []
    for src_label, src_codec in _SOURCE_ENCODINGS:
        try:
            raw = text.encode(src_codec)
        except (UnicodeEncodeError, LookupError):
            continue
        for dst_label, dst_codec in _TARGET_ENCODINGS:
            if src_codec == dst_codec:
                continue
            try:
                decoded = raw.decode(dst_codec)
            except (UnicodeDecodeError, LookupError):
                continue
            if decoded and decoded != text:
                out.append((decoded, f"{src_label} → {dst_label}"))
    return out


def repair_candidates(text: str, max_results: int = 12) -> list[RepairCandidate]:
    """返回按可信度排序的乱码修复候选。

    纯正常文本通常返回空列表；如果用户强制点“自动分析”，也会返回少量
    分数更高的候选，但这不代表原文一定被修复。
    """
    if not text:
        return []
    base_score = quality(text)
    seen: set[str] = {text}
    best: dict[str, RepairCandidate] = {}

    def remember(decoded: str, method: str) -> None:
        score = quality(decoded)
        # 只保留比原文有明显改善的结果，避免把正常文本转成噪声。
        if score <= base_score + 0.15:
            return
        candidate = RepairCandidate(decoded, method, round(score, 3))
        old = best.get(decoded)
        if old is None or candidate.score > old.score:
            best[decoded] = candidate

    # 第一层：所有可能的“错误解释”中间结果都保留下来。
    # 双层乱码的第一层结果可能比原文分数还低（例如 UTF-8 被当成 Latin-1
    # 后，字节又恰好是合法 Latin-1），不能在这一步就丢掉，否则永远到不了
    # 第二层。
    level_one: list[tuple[str, str, float]] = []
    for decoded, step in _transform_once(text):
        if decoded in seen:
            continue
        seen.add(decoded)
        level_one.append((decoded, step, quality(decoded)))
        remember(decoded, step)

    # 第二层：从第一层中挑最可能接近正常文本的候选继续。
    # 上限既保证双层修复的覆盖率，也避免长文本上组合爆炸。
    level_one.sort(key=lambda item: -item[2])
    for current, method, _ in level_one[:48]:
        for decoded, step in _transform_once(current):
            if decoded in seen:
                continue
            seen.add(decoded)
            remember(decoded, f"{method} → {step}")

    ranked = sorted(best.values(), key=lambda item: -item.score)
    return ranked[:max_results]


def repair(text: str) -> RepairCandidate | None:
    """返回最佳候选；没有可信候选时返回 None。"""
    candidates = repair_candidates(text, max_results=1)
    return candidates[0] if candidates else None


def repair_bytes_candidates(data: bytes, max_results: int = 12) -> list[RepairCandidate]:
    """把十六进制字节按常见编码尝试解码，返回可读性最高的结果。

    这是“输入格式 = Hex 字节”时的自动分析；它不猜测原始字节，
    只是把同一段字节按 UTF-8 / GB18030 / Big5 / CP1252 / Latin-1
    分别解释，让用户直接看到哪种编码最像正常文本。
    """
    if not data:
        return []
    found: list[RepairCandidate] = []
    for label, codec in ENCODINGS:
        try:
            text = data.decode(codec)
        except (UnicodeDecodeError, LookupError):
            continue
        if not text:
            continue
        score = quality(text)
        found.append(RepairCandidate(text, f"字节 → {label}", round(score, 3)))
    found.sort(key=lambda item: -item.score)
    # 去掉重复文本，保留分数最高/方法最短的一条。
    unique: dict[str, RepairCandidate] = {}
    for item in found:
        unique.setdefault(item.text, item)
    return list(unique.values())[:max_results]


def parse_hex_bytes(text: str) -> bytes:
    """公开的 Hex 字节解析，供 UI 在“Hex 输入”模式下复用。"""
    return _parse_hex_bytes(text)


def _parse_hex_bytes(text: str) -> bytes:
    cleaned = re.sub(r"0[xX]", "", text)
    cleaned = cleaned.replace("\\x", "").replace("\\X", "")
    cleaned = re.sub(r"[\s,;:_-]+", "", cleaned)
    if not cleaned:
        raise MojibakeError("Hex 输入为空")
    if not re.fullmatch(r"[0-9a-fA-F]+", cleaned):
        raise MojibakeError("Hex 中包含非十六进制字符")
    if len(cleaned) % 2:
        raise MojibakeError("Hex 长度必须是偶数")
    return bytes.fromhex(cleaned)


def _codec(name: str) -> str:
    for label, codec in ENCODINGS:
        if name in (label, codec):
            return codec
    raise MojibakeError(f"不支持的编码:{name}")


def convert_text(text: str, source: str, target: str,
                 input_is_hex: bool = False) -> ConversionResult:
    """按指定源/目标编码转换。

    ``input_is_hex=True`` 时，text 被视为十六进制字节，source 只用于说明
    这些字节原本的编码；最后统一按 target 解码。
    """
    if not text:
        raise MojibakeError("请输入要转换的内容")
    src = _codec(source)
    dst = _codec(target)
    if input_is_hex:
        raw = _parse_hex_bytes(text)
        method = f"Hex → {target}"
    else:
        try:
            raw = text.encode(src)
        except UnicodeEncodeError as exc:
            raise MojibakeError(f"无法按 {source} 编码输入:{exc}") from exc
        method = f"{source} → {target}"
    try:
        decoded = raw.decode(dst)
    except UnicodeDecodeError as exc:
        raise MojibakeError(
            f"按 {target} 解码失败。请尝试其他目标编码；"
            f"原始错误:{exc}") from exc
    return ConversionResult(decoded, method)


def decode_bytes(data: bytes, encoding: str) -> ConversionResult:
    """把字节按指定编码解码；失败时给出明确提示。"""
    codec = _codec(encoding)
    try:
        text = data.decode(codec)
    except UnicodeDecodeError as exc:
        raise MojibakeError(f"按 {encoding} 解码失败:{exc}") from exc
    return ConversionResult(text, f"字节 → {encoding}")


def text_stats(text: str) -> str:
    """简短统计，用于界面状态提示。"""
    if not text:
        return "0 字符"
    cjk = sum(1 for c in text if "\u4e00" <= c <= "\u9fff")
    width = sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in text)
    return f"{len(text):,} 字符 / {cjk:,} 汉字 / 约 {width:,} 列"
