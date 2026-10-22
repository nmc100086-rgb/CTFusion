"""常见文件格式的结构解析:PNG / JPG / GIF / BMP / ZIP。

每个 parse_* 返回 (节点树, 逻辑结束偏移)。逻辑结束偏移用于检测文件尾部的
附加数据 —— CTF 中最常见的考点之一。
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass, field


@dataclass
class Node:
    title: str
    offset: int
    size: int
    detail: str = ""
    children: list["Node"] = field(default_factory=list)


def _u16be(data: bytes, pos: int) -> int:
    return int.from_bytes(data[pos:pos + 2], "big")


def _u32be(data: bytes, pos: int) -> int:
    return int.from_bytes(data[pos:pos + 4], "big")


def _u16le(data: bytes, pos: int) -> int:
    return int.from_bytes(data[pos:pos + 2], "little")


def _u32le(data: bytes, pos: int) -> int:
    return int.from_bytes(data[pos:pos + 4], "little")


# ---------------------------------------------------------------- PNG
_PNG_COLOR = {0: "灰度", 2: "真彩色", 3: "索引色", 4: "灰度+Alpha", 6: "真彩色+Alpha"}


def parse_png(data: bytes) -> tuple[list[Node], int]:
    nodes: list[Node] = []
    pos = 8
    end = len(data)
    idat_total = 0
    while pos + 8 <= len(data):
        length = _u32be(data, pos)
        ctype = data[pos + 4:pos + 8]
        name = ctype.decode("latin-1")
        body_end = pos + 8 + length
        crc_end = body_end + 4
        if crc_end > len(data):
            nodes.append(Node(name, pos, len(data) - pos, "数据被截断(长度字段超出文件)"))
            return nodes, len(data)
        stored = _u32be(data, body_end)
        calc = zlib.crc32(data[pos + 4:body_end]) & 0xFFFFFFFF
        detail = "CRC 正确" if stored == calc else f"⚠ CRC 错误(存储 {stored:08X}, 实际 {calc:08X})"
        if name == "IHDR":
            w = _u32be(data, pos + 8)
            h = _u32be(data, pos + 12)
            depth = data[pos + 16]
            color = data[pos + 17]
            detail += f" | {w}x{h} 位深{depth} {_PNG_COLOR.get(color, f'类型{color}')}"
        elif name == "IDAT":
            idat_total += length
            detail += f" | 累计压缩数据 {idat_total} 字节"
        nodes.append(Node(name, pos, crc_end - pos, detail))
        pos = crc_end
        if name == "IEND":
            end = pos
            break
    if idat_total:
        nodes.append(Node("图像数据汇总", nodes[0].offset if nodes else 0, idat_total,
                          "IDAT 压缩流总量(解压后为像素数据)"))
    return nodes, end


# ---------------------------------------------------------------- JPG
_JPG_MARKERS = {
    0xC0: "SOF0 基线", 0xC1: "SOF1", 0xC2: "SOF2 渐进", 0xC3: "SOF3",
    0xC4: "DHT 哈夫曼表", 0xC8: "JPG 保留", 0xCC: "DAC",
    0xD8: "SOI 文件头", 0xD9: "EOI 文件尾", 0xDA: "SOS 扫描开始",
    0xDB: "DQT 量化表", 0xDD: "DRI 重启间隔", 0xEE: "APP14", 0xFE: "COM 注释",
}
for _i in range(16):
    _JPG_MARKERS[0xE0 + _i] = f"APP{_i}"
for _i in range(8):
    _JPG_MARKERS[0xD0 + _i] = f"RST{_i}"


def parse_jpg(data: bytes) -> tuple[list[Node], int]:
    nodes: list[Node] = []
    pos = 2 if data[:2] == b"\xff\xd8" else 0
    end = len(data)
    while pos + 1 < len(data):
        if data[pos] != 0xFF:
            pos += 1
            continue
        marker = data[pos + 1]
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
            pos += 2
            continue
        if marker == 0xD9:
            nodes.append(Node("EOI 文件尾", pos, 2, ""))
            return nodes, pos + 2
        if pos + 4 > len(data):
            break
        length = _u16be(data, pos + 2)
        seg_end = pos + 2 + length
        name = _JPG_MARKERS.get(marker, f"标记 FF{marker:02X}")
        detail = f"段长 {length}"
        if marker == 0xDA:  # SOS:后面是熵编码数据,需扫到 EOI
            scan_end = _jpg_scan_end(data, seg_end)
            nodes.append(Node(name, pos, scan_end - pos, detail + f" | 熵编码数据至 {scan_end}"))
            if scan_end >= len(data):
                return nodes, len(data)
            nodes.append(Node("EOI 文件尾", scan_end, 2, ""))
            return nodes, scan_end + 2
        if marker in (0xC0, 0xC1, 0xC2) and pos + 9 <= len(data):
            h = _u16be(data, pos + 5)
            w = _u16be(data, pos + 7)
            detail += f" | {w}x{h}"
        if marker == 0xFE and pos + 4 < len(data):
            detail += " | " + data[pos + 4:seg_end][:60].decode("utf-8", "replace")
        nodes.append(Node(name, pos, seg_end - pos, detail))
        if seg_end <= pos:
            break
        pos = seg_end
    return nodes, end


def _jpg_scan_end(data: bytes, pos: int) -> int:
    """跳过熵编码数据,返回 EOI(FFD9)的偏移;找不到则返回文件末尾。"""
    while pos + 1 < len(data):
        if data[pos] == 0xFF:
            nxt = data[pos + 1]
            if nxt == 0xD9:
                return pos
            if nxt != 0x00 and not 0xD0 <= nxt <= 0xD7:
                return pos  # 遇到下一个真实标记
        pos += 1
    return len(data)


# ---------------------------------------------------------------- GIF
def _gif_skip_subblocks(data: bytes, pos: int) -> int:
    while pos < len(data):
        size = data[pos]
        pos += 1
        if size == 0:
            return pos
        pos += size
    return len(data)


def parse_gif(data: bytes) -> tuple[list[Node], int]:
    nodes: list[Node] = []
    if len(data) < 13:
        return nodes, len(data)
    w = _u16le(data, 6)
    h = _u16le(data, 8)
    packed = data[10]
    flags = ["全局色表" if packed & 0x80 else "无全局色表"]
    if packed & 0x80:
        flags.append(f"{2 ** ((packed & 7) + 1)} 色")
    nodes.append(Node("文件头 " + data[:6].decode("latin-1"), 0, 6, "GIF87a/89a"))
    nodes.append(Node("逻辑屏幕描述符", 6, 7, f"{w}x{h} | " + " | ".join(flags)))
    pos = 13
    if packed & 0x80:
        table_size = 3 * (2 ** ((packed & 7) + 1))
        nodes.append(Node("全局颜色表", pos, table_size, f"{table_size} 字节"))
        pos += table_size
    frames = 0
    while pos < len(data):
        block = data[pos]
        if block == 0x3B:
            nodes.append(Node("文件结束符 0x3B", pos, 1, f"共 {frames} 帧"))
            return nodes, pos + 1
        if block == 0x21:
            label = data[pos + 1] if pos + 1 < len(data) else 0
            label_name = {0xFE: "注释扩展", 0xF9: "图形控制扩展", 0xFF: "应用扩展",
                          0x01: "纯文本扩展"}.get(label, f"扩展 0x{label:02X}")
            nxt = _gif_skip_subblocks(data, pos + 2)
            detail = ""
            if label == 0xF9 and pos + 6 <= len(data):
                detail = f"延迟 {_u16le(data, pos + 4) / 100:.2f}s"
            nodes.append(Node(label_name, pos, nxt - pos, detail))
            pos = nxt
            continue
        if block == 0x2C:
            if pos + 10 > len(data):
                break
            fw = _u16le(data, pos + 5)
            fh = _u16le(data, pos + 7)
            ipacked = data[pos + 9]
            nxt = _gif_skip_subblocks(data, pos + 10 + (3 * (2 ** ((ipacked & 7) + 1)) if ipacked & 0x80 else 0))
            nxt += 1  # 跳过 LZW 最小码长字节
            nxt = _gif_skip_subblocks(data, nxt)
            frames += 1
            nodes.append(Node(f"图像帧 {frames}", pos, nxt - pos, f"{fw}x{fh}"))
            pos = nxt
            continue
        pos += 1
    return nodes, len(data)


# ---------------------------------------------------------------- BMP
def parse_bmp(data: bytes) -> tuple[list[Node], int]:
    nodes: list[Node] = []
    if len(data) < 54:
        return nodes, len(data)
    bf_size = _u32le(data, 2)
    data_off = _u32le(data, 10)
    dib_size = _u32le(data, 14)
    w = int.from_bytes(data[18:22], "little", signed=True)
    h = int.from_bytes(data[22:26], "little", signed=True)
    bpp = _u16le(data, 28)
    comp = _u32le(data, 30)
    nodes.append(Node("BITMAPFILEHEADER", 0, 14,
                      f"文件总大小 {bf_size} 字节 | 像素数据偏移 {data_off}"))
    nodes.append(Node("BITMAPINFOHEADER", 14, dib_size,
                      f"{w}x{abs(h)} | {bpp} 位 | 压缩方式 {comp}"))
    if len(data) > data_off:
        nodes.append(Node("像素数据", data_off, len(data) - data_off, ""))
    end = bf_size if 0 < bf_size <= len(data) else len(data)
    return nodes, end


# ---------------------------------------------------------------- ZIP
_ZIP_LOCAL = b"PK\x03\x04"
_ZIP_CENTRAL = b"PK\x01\x02"
_ZIP_EOCD = b"PK\x05\x06"


def parse_zip(data: bytes) -> tuple[list[Node], int]:
    nodes: list[Node] = []
    eocd = data.rfind(_ZIP_EOCD)
    if eocd < 0:
        return nodes, len(data)
    total = _u16le(data, eocd + 10)
    cd_size = _u32le(data, eocd + 12)
    cd_off = _u32le(data, eocd + 16)
    comment_len = _u16le(data, eocd + 20)
    end = eocd + 22 + comment_len  # 注释属于 ZIP 本体,不算尾随数据

    # 中央目录:用于判断伪加密(本地头标记加密但中央目录未标记)
    entries: dict[str, int] = {}
    pos = cd_off
    for _ in range(min(total, 4096)):
        if data[pos:pos + 4] != _ZIP_CENTRAL or pos + 46 > len(data):
            break
        flags = _u16le(data, pos + 8)
        method = _u16le(data, pos + 10)
        csize = _u32le(data, pos + 20)
        nlen = _u16le(data, pos + 28)
        elen = _u16le(data, pos + 30)
        clen = _u16le(data, pos + 32)
        lho = _u32le(data, pos + 42)
        raw = data[pos + 46:pos + 46 + nlen]
        try:
            name = raw.decode("utf-8" if flags & 0x800 else "gbk", "replace")
        except LookupError:
            name = raw.decode("utf-8", "replace")
        entries[name] = flags
        detail = f"压缩方式 {method} | 压缩后 {csize} 字节"
        if flags & 1:
            detail += " | ⚠ 加密标志"
        nodes.append(Node(f"中央目录: {name}", pos, 46 + nlen + elen + clen, detail))
        pos += 46 + nlen + elen + clen
    nodes.append(Node("中央目录结束 EOCD", eocd, end - eocd,
                      f"{total} 个条目 | 中央目录 @ {cd_off} ({cd_size} 字节)"))

    # 本地头扫描:检测伪加密(本地置加密位但中央目录未置位)
    pos = 0
    local_count = 0
    while True:
        pos = data.find(_ZIP_LOCAL, pos, cd_off if cd_off else len(data))
        if pos < 0 or pos + 30 > len(data):
            break
        flags = _u16le(data, pos + 6)
        nlen = _u16le(data, pos + 26)
        elen = _u16le(data, pos + 28)
        raw = data[pos + 30:pos + 30 + nlen]
        try:
            name = raw.decode("utf-8" if flags & 0x800 else "gbk", "replace")
        except LookupError:
            name = raw.decode("utf-8", "replace")
        cflags = entries.get(name)
        detail = f"标志位 0x{flags:04X}"
        if flags & 1 and cflags is not None and not cflags & 1:
            detail += " | ⚠ 伪加密(本地置加密位,中央目录未置位)"
        elif not flags & 1 and cflags is not None and cflags & 1:
            detail += " | ⚠ 伪加密(中央目录置加密位,本地未置位)"
        nodes.append(Node(f"本地头: {name}", pos, 30 + nlen + elen, detail))
        local_count += 1
        pos += 30 + nlen + elen
    if local_count:
        nodes.append(Node("本地文件头汇总", 0, 0, f"共 {local_count} 个本地头"))
    return nodes, end


# ---------------------------------------------------------------- 分发
_PARSERS = {
    "PNG": parse_png,
    "JPEG": parse_jpg,
    "GIF": parse_gif,
    "BMP": parse_bmp,
    "ZIP": parse_zip,
}


def parse(kind: str, data: bytes) -> tuple[list[Node], int] | None:
    """按类型解析;不支持的格式返回 None。"""
    fn = _PARSERS.get(kind)
    if fn is None:
        return None
    try:
        return fn(data)
    except (struct.error, IndexError, ValueError):
        return None


def logical_end(kind: str, data: bytes) -> int | None:
    """文件逻辑结束偏移;用于检测尾部附加数据。"""
    result = parse(kind, data)
    if result is None:
        return None
    return result[1]
