"""常见文件格式的结构解析:PNG / JPG / GIF / BMP / ZIP。

每个 parse_* 返回 (节点树, 逻辑结束偏移)。逻辑结束偏移用于检测文件尾部的
附加数据 —— CTF 中最常见的考点之一。
"""

from __future__ import annotations

import math
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
        if marker == 0xDA:  # SOS:后面是熵编码数据,扫到下一个真实 marker
            scan_end = _jpg_scan_end(data, seg_end)
            nodes.append(Node(name, pos, scan_end - pos, detail + f" | 熵编码数据至 {scan_end}"))
            if scan_end >= len(data):
                return nodes, len(data)
            # 渐进式 JPEG 在一个 SOS 后还会出现 DHT/SOS 等 marker,
            # 不能把这里的 marker 直接当成 EOI。
            pos = scan_end
            continue
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


def _gif_image_end(data: bytes, pos: int) -> int:
    """返回图像描述符(0x2C)之后整个图像块的结束偏移。

    结构:描述符 10 字节 + 可选局部色表 + LZW 最小码长 1 字节
    + 若干 data sub-block + 0x00 结束块。
    """
    if pos + 10 > len(data):
        return len(data)
    packed = data[pos + 9]
    nxt = pos + 10
    if packed & 0x80:
        nxt += 3 * (2 ** ((packed & 7) + 1))
    nxt += 1  # LZW minimum code size
    return _gif_skip_subblocks(data, nxt)


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
            nxt = _gif_image_end(data, pos)
            frames += 1
            nodes.append(Node(f"图像帧 {frames}", pos, nxt - pos, f"{fw}x{fh}"))
            pos = nxt
            continue
        pos += 1
    return nodes, len(data)


# ---------------------------------------------------------------- BMP
def parse_bmp(data: bytes) -> tuple[list[Node], int]:
    nodes: list[Node] = []
    if len(data) < 26:
        return nodes, len(data)
    bf_size = _u32le(data, 2)
    data_off = _u32le(data, 10)
    dib_size = _u32le(data, 14)
    if dib_size == 12:  # OS/2 BITMAPCOREHEADER
        w = _u16le(data, 18)
        h = _u16le(data, 20)
        bpp = _u16le(data, 24)
        comp = 0
    else:
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


def _find_zip_eocd(data: bytes) -> int:
    """从文件尾向前寻找可信的 EOCD。

    不能简单 rfind:ZIP 注释里也可能出现 PK\\x05\\x06,必须校验
    comment length 与中央目录范围。
    """
    end = len(data)
    pos = end - 22
    while pos >= 0:
        pos = data.rfind(_ZIP_EOCD, 0, pos + 4)
        if pos < 0:
            break
        if pos + 22 <= end:
            total = _u16le(data, pos + 10)
            cd_size = _u32le(data, pos + 12)
            cd_off = _u32le(data, pos + 16)
            comment_len = _u16le(data, pos + 20)
            comment_end = pos + 22 + comment_len
            if comment_end <= end:
                zip64 = (total == 0xFFFF or cd_size == 0xFFFFFFFF
                         or cd_off == 0xFFFFFFFF)
                if zip64:
                    if _zip64_values(data, pos) is not None:
                        return pos
                    pos -= 1
                    continue
                if cd_off <= end and cd_size <= end - cd_off and cd_off + cd_size <= pos:
                    return pos
        pos -= 1
    return -1


def _zip64_values(data: bytes, eocd: int) -> tuple[int, int, int] | None:
    """读取 ZIP64 EOCD,返回 (条目数, 中央目录大小, 中央目录偏移)。"""
    locator = eocd - 20
    if locator < 0 or data[locator:locator + 4] != b"PK\x06\x07":
        return None
    off = int.from_bytes(data[locator + 8:locator + 16], "little")
    if off < 0 or off + 56 > len(data) or data[off:off + 4] != b"PK\x06\x06":
        return None
    total = int.from_bytes(data[off + 32:off + 40], "little")
    cd_size = int.from_bytes(data[off + 40:off + 48], "little")
    cd_off = int.from_bytes(data[off + 48:off + 56], "little")
    if cd_off > len(data) or cd_size > len(data) - cd_off:
        return None
    return total, cd_size, cd_off


def parse_zip(data: bytes) -> tuple[list[Node], int]:
    nodes: list[Node] = []
    eocd = _find_zip_eocd(data)
    if eocd < 0:
        return nodes, len(data)
    total = _u16le(data, eocd + 10)
    cd_size = _u32le(data, eocd + 12)
    cd_off = _u32le(data, eocd + 16)
    comment_len = _u16le(data, eocd + 20)
    zip64 = (total == 0xFFFF or cd_size == 0xFFFFFFFF or cd_off == 0xFFFFFFFF)
    if zip64:
        values = _zip64_values(data, eocd)
        if values is not None:
            total, cd_size, cd_off = values
    end = eocd + 22 + comment_len  # 注释属于 ZIP 本体,不算尾随数据
    if end > len(data):
        end = len(data)

    # 中央目录:用于判断伪加密(本地头标记加密但中央目录未标记)
    entries: dict[str, int] = {}
    pos = cd_off
    for _ in range(min(total, 4096)):
        if pos + 46 > len(data) or data[pos:pos + 4] != _ZIP_CENTRAL:
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
    eocd_detail = f"{total} 个条目 | 中央目录 @ {cd_off} ({cd_size} 字节)"
    if zip64:
        eocd_detail += " | ZIP64"
    nodes.append(Node("中央目录结束 EOCD", eocd, end - eocd, eocd_detail))
    if comment_len:
        raw_comment = data[eocd + 22:eocd + 22 + comment_len]
        try:
            comment = raw_comment.decode("utf-8")
        except UnicodeDecodeError:
            comment = raw_comment.decode("gb18030", "replace")
        comment = "".join(ch if ch.isprintable() else "." for ch in comment)
        nodes.append(Node("压缩包注释", eocd + 22, comment_len, comment[:200]))

    # 本地头扫描:检测伪加密(本地置加密位但中央目录未置位)
    pos = 0
    local_count = 0
    local_end = min(cd_off, len(data)) if cd_off else len(data)
    while True:
        pos = data.find(_ZIP_LOCAL, pos, local_end)
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


# ---------------------------------------------------------------- PNG 信息与修复
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


@dataclass
class PngChunk:
    name: str
    offset: int
    length: int
    body: bytes
    stored_crc: int | None
    calc_crc: int | None
    complete: bool

    @property
    def crc_ok(self) -> bool:
        return self.stored_crc is not None and self.stored_crc == self.calc_crc

    @property
    def total_size(self) -> int:
        return 8 + self.length + (4 if self.complete else 0)


@dataclass
class PngInfo:
    width: int = 0
    height: int = 0
    bit_depth: int = 0
    color_type: int = -1
    interlace: int = 0
    chunk_count: int = 0
    idat_size: int = 0
    crc_errors: list[PngChunk] = field(default_factory=list)
    truncated: bool = False

    @property
    def color_name(self) -> str:
        return _PNG_COLOR.get(self.color_type, f"类型{self.color_type}")

    @property
    def channels(self) -> int:
        return {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}.get(self.color_type, 1)


def png_chunks(data: bytes) -> list[PngChunk]:
    """按 chunk 拆分 PNG(含 CRC 校验结果),用于信息展示与修复。"""
    chunks: list[PngChunk] = []
    if data[:8] != PNG_SIGNATURE:
        return chunks
    pos = 8
    while pos + 8 <= len(data):
        length = _u32be(data, pos)
        name = data[pos + 4:pos + 8].decode("latin-1")
        body_end = pos + 8 + length
        if body_end + 4 > len(data):
            chunks.append(PngChunk(name, pos, max(0, len(data) - pos - 8),
                                   data[pos + 8:body_end], None, None, False))
            break
        body = data[pos + 8:body_end]
        stored = _u32be(data, body_end)
        calc = zlib.crc32(data[pos + 4:body_end]) & 0xFFFFFFFF
        chunks.append(PngChunk(name, pos, length, body, stored, calc, True))
        pos = body_end + 4
        if name == "IEND":
            break
    return chunks


@dataclass
class PngText:
    chunk: str
    keyword: str
    text: str
    offset: int


def png_text_chunks(data: bytes) -> list[PngText]:
    """解析 PNG 的 tEXt / zTXt / iTXt 文本块。"""
    rows: list[PngText] = []
    for chunk in png_chunks(data):
        try:
            if chunk.name == "tEXt":
                keyword, text = chunk.body.split(b"\x00", 1)
                rows.append(PngText("tEXt", keyword.decode("latin-1", "replace"),
                                    text.decode("latin-1", "replace"), chunk.offset))
            elif chunk.name == "zTXt":
                keyword, rest = chunk.body.split(b"\x00", 1)
                if not rest:
                    continue
                dec = zlib.decompressobj()
                text = dec.decompress(rest[1:], 16 * 1024 * 1024)
                if dec.unconsumed_tail:
                    continue
                rows.append(PngText("zTXt", keyword.decode("latin-1", "replace"),
                                    text.decode("latin-1", "replace"), chunk.offset))
            elif chunk.name == "iTXt":
                keyword, rest = chunk.body.split(b"\x00", 1)
                if len(rest) < 2:
                    continue
                compressed, _method = rest[0], rest[1]
                rest = rest[2:]
                _lang, rest = rest.split(b"\x00", 1)
                _translated, text = rest.split(b"\x00", 1)
                if compressed:
                    dec = zlib.decompressobj()
                    text = dec.decompress(text, 16 * 1024 * 1024)
                    if dec.unconsumed_tail:
                        continue
                rows.append(PngText("iTXt", keyword.decode("utf-8", "replace"),
                                    text.decode("utf-8", "replace"), chunk.offset))
            elif chunk.name == "eXIf":
                rows.append(PngText("eXIf", "", f"TIFF/EXIF {chunk.length} 字节",
                                    chunk.offset))
        except (ValueError, zlib.error):
            continue
    return rows


def png_info(data: bytes) -> PngInfo | None:
    """读取 PNG 基本参数并校验所有 chunk 的 CRC。"""
    if data[:8] != PNG_SIGNATURE:
        return None
    info = PngInfo()
    for chunk in png_chunks(data):
        info.chunk_count += 1
        if not chunk.complete:
            info.truncated = True
        if chunk.stored_crc is not None and chunk.stored_crc != chunk.calc_crc:
            info.crc_errors.append(chunk)
        if chunk.name == "IHDR" and len(chunk.body) >= 13:
            info.width = _u32be(chunk.body, 0)
            info.height = _u32be(chunk.body, 4)
            info.bit_depth = chunk.body[8]
            info.color_type = chunk.body[9]
            info.interlace = chunk.body[12]
        elif chunk.name == "IDAT":
            info.idat_size += chunk.length
    return info


def repair_png_crc(data: bytes) -> bytes:
    """重算所有 chunk 的 CRC;截断 chunk 之后的原始数据原样保留。"""
    if data[:8] != PNG_SIGNATURE:
        return data
    out = bytearray(PNG_SIGNATURE)
    consumed = 8
    for chunk in png_chunks(data):
        if not chunk.complete:
            out.extend(data[chunk.offset:])
            consumed = len(data)
            break
        out.extend(struct.pack(">I", chunk.length))
        out.extend(chunk.name.encode("latin-1"))
        out.extend(chunk.body)
        out.extend(struct.pack(">I", chunk.calc_crc or 0))
        consumed = chunk.offset + chunk.total_size
    out.extend(data[consumed:])
    return bytes(out)


def repair_png_dimensions(data: bytes, width: int, height: int) -> bytes:
    """改写 IHDR 宽高并重算 IHDR 的 CRC。"""
    if data[:8] != PNG_SIGNATURE:
        return data
    ihdr = next((c for c in png_chunks(data)
                 if c.name == "IHDR" and c.complete and c.length >= 13), None)
    if ihdr is None:
        return data
    out = bytearray(data)
    body = ihdr.offset + 8
    out[body:body + 4] = int(width).to_bytes(4, "big")
    out[body + 4:body + 8] = int(height).to_bytes(4, "big")
    crc = zlib.crc32(bytes(out[ihdr.offset + 4:ihdr.offset + 8 + ihdr.length])) & 0xFFFFFFFF
    crc_pos = ihdr.offset + 8 + ihdr.length
    out[crc_pos:crc_pos + 4] = crc.to_bytes(4, "big")
    return bytes(out)


def _png_decompressed(data: bytes) -> tuple[PngInfo, bytes] | None:
    info = png_info(data)
    if info is None or info.width <= 0 or info.height <= 0 or info.bit_depth == 0:
        return None
    if info.interlace != 0:
        return None
    compressed = bytearray()
    for chunk in png_chunks(data):
        if chunk.name == "IDAT" and chunk.complete:
            compressed.extend(chunk.body)
    if not compressed:
        return None
    try:
        dec = zlib.decompressobj()
        pixels = dec.decompress(bytes(compressed), 64 * 1024 * 1024)
        if not dec.eof or dec.unconsumed_tail:
            return None
    except zlib.error:
        return None
    if not pixels:
        return None
    return info, pixels


def _png_filters_ok(pixels: bytes, stride: int, height: int) -> bool:
    if stride <= 1 or height <= 0 or stride * height != len(pixels):
        return False
    return all(pixels[y * stride] <= 4 for y in range(height))


def png_size_candidates(data: bytes) -> list[tuple[int, int]]:
    """根据 IDAT 解压后的数据反推所有可能的 (宽, 高)。

    不信任 IHDR 宽度:枚举长度因子、过滤字节和行长度,过滤掉不可能的组合。
    """
    parsed = _png_decompressed(data)
    if parsed is None:
        return []
    info, pixels = parsed
    total = len(pixels)
    cpb = info.channels * info.bit_depth
    if cpb <= 0:
        return []
    candidates: set[tuple[int, int]] = set()
    divisors: set[int] = set()
    for d in range(1, math.isqrt(total) + 1):
        if total % d == 0:
            divisors.add(d)
            divisors.add(total // d)
    for stride in divisors:
        if stride < 2:
            continue
        # stride = 1 + ceil(width * cpb / 8)
        w_min = max(1, ((stride - 1) * 8 + cpb - 1) // cpb)
        w_max = max(w_min, (stride * 8) // cpb)
        for width in range(w_min, w_max + 1):
            if 1 + (width * cpb + 7) // 8 != stride:
                continue
            height = total // stride
            if height <= 0 or height > 0x7FFFFFFF:
                continue
            if _png_filters_ok(pixels, stride, height):
                candidates.add((width, height))
    result = list(candidates)
    # 优先保留至少一个维度与 IHDR 一致的候选,再按差异排序。
    result.sort(key=lambda wh: (
        0 if wh[0] == info.width or wh[1] == info.height else 1,
        min(abs(wh[0] - info.width), abs(wh[1] - info.height)),
        abs(wh[0] - info.width) + abs(wh[1] - info.height),
        wh[0] * wh[1],
    ))
    return result


def png_actual_size(data: bytes) -> tuple[int, int] | None:
    """解压 IDAT 推算真实像素尺寸,用于发现被篡改的 IHDR 宽高。"""
    candidates = png_size_candidates(data)
    return candidates[0] if candidates else None


# ---------------------------------------------------------------- EXIF
_EXIF_TAGS = {
    0x0100: "图像宽度", 0x0101: "图像高度", 0x010E: "图像描述",
    0x010F: "制造商", 0x0110: "型号", 0x0112: "方向",
    0x011A: "X 分辨率", 0x011B: "Y 分辨率", 0x011C: "压缩方式",
    0x0128: "分辨率单位", 0x0131: "软件", 0x0132: "修改时间",
    0x013B: "作者", 0x8298: "版权", 0x829A: "曝光时间",
    0x829D: "光圈值", 0x8822: "曝光程序", 0x8827: "ISO",
    0x9000: "Exif 版本", 0x9003: "拍摄时间", 0x9004: "数字化时间",
    0x9201: "快门速度", 0x9202: "光圈", 0x9209: "闪光灯",
    0x920A: "焦距", 0x9286: "用户注释", 0xA002: "像素宽度",
    0xA003: "像素高度",
}

_EXIF_TYPE_SIZE = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1,
                   8: 2, 9: 4, 10: 8, 11: 4, 12: 8}

_GPS_TAGS = {
    0x0000: "GPS 版本", 0x0001: "纬度参考", 0x0002: "纬度",
    0x0003: "经度参考", 0x0004: "经度", 0x0005: "海拔参考",
    0x0006: "海拔", 0x0007: "GPS 时间", 0x0008: "GPS 卫星",
    0x001D: "GPS 日期",
}


def _find_png_exif(data: bytes) -> bytes | None:
    if data[:8] != PNG_SIGNATURE:
        return None
    for chunk in png_chunks(data):
        if chunk.name == "eXIf":
            body = chunk.body
            if body.startswith(b"Exif\x00\x00"):
                body = body[6:]
            return body
    return None


def _ifd_next(tiff: bytes, offset: int, order: str) -> int:
    if offset + 2 > len(tiff):
        return 0
    count = int.from_bytes(tiff[offset:offset + 2], order)
    pos = offset + 2 + count * 12
    if pos + 4 > len(tiff):
        return 0
    return int.from_bytes(tiff[pos:pos + 4], order)


def _gps_coord(typ: int, raw: bytes, order: str) -> str:
    if typ != 5 or len(raw) < 24:
        return ""
    values = []
    for i in range(0, 24, 8):
        num = int.from_bytes(raw[i:i + 4], order)
        den = int.from_bytes(raw[i + 4:i + 8], order)
        values.append(num / den if den else 0.0)
    return f"{values[0]:.0f}°{values[1]:.0f}'{values[2]:.3f}\""


def _find_exif_tiff(data: bytes) -> bytes | None:
    pos = 2 if data[:2] == b"\xff\xd8" else 0
    while pos + 4 <= len(data):
        if data[pos] != 0xFF:
            pos += 1
            continue
        marker = data[pos + 1]
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
            pos += 2
            continue
        if marker == 0xD9:
            break
        length = _u16be(data, pos + 2)
        if pos + 2 + length > len(data):
            break
        if marker == 0xE1 and data[pos + 4:pos + 10] == b"Exif\x00\x00":
            return data[pos + 10:pos + 2 + length]
        if marker == 0xDA:
            break
        pos += 2 + length
    return None


def _read_ifd(tiff: bytes, offset: int, order: str) -> list[tuple[int, int, int, bytes]]:
    entries: list[tuple[int, int, int, bytes]] = []
    if offset + 2 > len(tiff):
        return entries
    count = int.from_bytes(tiff[offset:offset + 2], order)
    pos = offset + 2
    for _ in range(min(count, 512)):
        if pos + 12 > len(tiff):
            break
        tag = int.from_bytes(tiff[pos:pos + 2], order)
        typ = int.from_bytes(tiff[pos + 2:pos + 4], order)
        num = int.from_bytes(tiff[pos + 4:pos + 8], order)
        size = _EXIF_TYPE_SIZE.get(typ, 1) * num
        if size <= 4:
            raw = tiff[pos + 8:pos + 8 + size]
        else:
            voff = int.from_bytes(tiff[pos + 8:pos + 12], order)
            raw = tiff[voff:voff + size]
        entries.append((tag, typ, num, raw))
        pos += 12
    return entries


def _format_exif_value(typ: int, count: int, raw: bytes, order: str) -> str:
    if typ == 2:
        return raw.split(b"\x00")[0].decode("utf-8", "replace").strip()
    if typ in (3, 8):
        return ", ".join(str(int.from_bytes(raw[i:i + 2], order))
                         for i in range(0, len(raw) - 1, 2))
    if typ in (4, 9):
        return ", ".join(str(int.from_bytes(raw[i:i + 4], order))
                         for i in range(0, len(raw) - 3, 4))
    if typ == 5:
        vals = []
        for i in range(0, len(raw) - 7, 8):
            num = int.from_bytes(raw[i:i + 4], order)
            den = int.from_bytes(raw[i + 4:i + 8], order)
            vals.append(f"{num / den:g}" if den else f"{num}/0")
        return ", ".join(vals)
    return raw[:32].hex(" ")


def parse_exif(data: bytes) -> list[tuple[str, str]]:
    """解析 JPEG APP1 / PNG eXIf / TIFF 中的常用 EXIF 标签。"""
    if data[:2] in (b"II", b"MM"):
        tiff = data
    else:
        tiff = _find_png_exif(data) or _find_exif_tiff(data)
    if not tiff or len(tiff) < 8 or tiff[:2] not in (b"II", b"MM"):
        return []
    order = "little" if tiff[:2] == b"II" else "big"
    if int.from_bytes(tiff[2:4], order) != 42:
        return []
    rows: list[tuple[str, str]] = []
    ifd0_off = int.from_bytes(tiff[4:8], order)
    exif_off = 0
    gps_off = 0
    for tag, typ, num, raw in _read_ifd(tiff, ifd0_off, order):
        if tag == 0x8769:
            exif_off = int.from_bytes(raw[:4], order)
            continue
        if tag == 0x8825:
            gps_off = int.from_bytes(raw[:4], order)
            continue
        name = _EXIF_TAGS.get(tag)
        if name:
            rows.append((name, _format_exif_value(typ, num, raw, order)))
    if exif_off:
        for tag, typ, num, raw in _read_ifd(tiff, exif_off, order):
            name = _EXIF_TAGS.get(tag)
            if name:
                rows.append((name, _format_exif_value(typ, num, raw, order)))
    if gps_off:
        gps = _read_ifd(tiff, gps_off, order)
        refs: dict[int, str] = {}
        for tag, typ, num, raw in gps:
            if tag in (0x0001, 0x0003, 0x0005):
                refs[tag] = _format_exif_value(typ, num, raw, order)
        for tag, typ, num, raw in gps:
            name = _GPS_TAGS.get(tag)
            if not name:
                continue
            if tag in (0x0002, 0x0004):
                value = _gps_coord(typ, raw, order)
                if tag == 0x0002 and refs.get(0x0001):
                    value += " " + refs[0x0001]
                if tag == 0x0004 and refs.get(0x0003):
                    value += " " + refs[0x0003]
            elif tag == 0x0006:
                value = _format_exif_value(typ, num, raw, order)
                if refs.get(0x0005) == "1":
                    value = "-" + value
            else:
                value = _format_exif_value(typ, num, raw, order)
            rows.append((name, value))
    # IFD1 缩略图偏移/长度
    ifd1 = _ifd_next(tiff, ifd0_off, order)
    if ifd1:
        thumb_off = thumb_len = 0
        for tag, _typ, _num, raw in _read_ifd(tiff, ifd1, order):
            if tag == 0x0201 and len(raw) >= 4:
                thumb_off = int.from_bytes(raw[:4], order)
            elif tag == 0x0202 and len(raw) >= 4:
                thumb_len = int.from_bytes(raw[:4], order)
        if thumb_off or thumb_len:
            rows.append(("缩略图", f"offset {thumb_off},长度 {thumb_len} 字节"))
    return rows


# ---------------------------------------------------------------- GIF 帧
def gif_frame_offsets(data: bytes) -> list[int]:
    """返回每个图像描述符(帧)的偏移。"""
    offsets: list[int] = []
    if len(data) < 13 or data[:6] not in (b"GIF87a", b"GIF89a"):
        return offsets
    packed = data[10]
    pos = 13
    if packed & 0x80:
        pos += 3 * (2 ** ((packed & 7) + 1))
    while pos < len(data):
        block = data[pos]
        if block == 0x3B:
            break
        if block == 0x21:
            pos = _gif_skip_subblocks(data, pos + 2)
            continue
        if block == 0x2C:
            if pos + 10 > len(data):
                break
            offsets.append(pos)
            pos = _gif_image_end(data, pos)
            continue
        pos += 1
    return offsets


# ---------------------------------------------------------------- 图片基本信息
def image_info(kind: str, data: bytes) -> list[tuple[str, str]]:
    """按格式返回可直接展示的 (项目, 值) 列表。"""
    if kind == "PNG":
        info = png_info(data)
        if info is None:
            return []
        rows = [
            ("格式", "PNG"),
            ("尺寸", f"{info.width} x {info.height}"),
            ("位深", f"{info.bit_depth} bit/通道"),
            ("颜色类型", f"{info.color_type} ({info.color_name})"),
            ("隔行扫描", "是 (Adam7)" if info.interlace else "否"),
            ("Chunk 数量", str(info.chunk_count)),
            ("IDAT 压缩数据", f"{info.idat_size:,} 字节"),
            ("CRC 校验", f"{len(info.crc_errors)} 个 chunk 错误"
             if info.crc_errors else "全部通过"),
        ]
        if info.truncated:
            rows.append(("⚠ 截断", "存在长度字段超出文件末尾的 chunk"))
        actual = png_actual_size(data)
        if actual:
            same = actual == (info.width, info.height)
            rows.append(("实际像素尺寸", f"{actual[0]} x {actual[1]}"
                         + ("" if same else " ⚠ 与 IHDR 不符")))
        return rows
    if kind == "JPEG":
        width = height = 0
        dpi = ""
        segments = 0
        has_exif = False
        pos = 2
        while pos + 4 <= len(data):
            if data[pos] != 0xFF:
                pos += 1
                continue
            marker = data[pos + 1]
            if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
                pos += 2
                continue
            if marker == 0xD9:
                break
            length = _u16be(data, pos + 2)
            if pos + 2 + length > len(data):
                break
            segments += 1
            if marker == 0xE1 and data[pos + 4:pos + 10] == b"Exif\x00\x00":
                has_exif = True
            if marker in (0xC0, 0xC1, 0xC2) and pos + 9 <= len(data):
                height = _u16be(data, pos + 5)
                width = _u16be(data, pos + 7)
            if marker == 0xE0 and data[pos + 4:pos + 9] == b"JFIF\x00" and pos + 14 <= len(data):
                unit = data[pos + 11]
                xd = _u16be(data, pos + 12)
                if unit == 1:
                    dpi = f"{xd} DPI"
                elif unit == 2:
                    dpi = f"{xd} 像素/cm"
            if marker == 0xDA:
                break
            pos += 2 + length
        rows = [("格式", "JPEG"), ("尺寸", f"{width} x {height}" if width else "未知")]
        if dpi:
            rows.append(("分辨率", dpi))
        rows.append(("EXIF", "有" if has_exif else "无"))
        rows.append(("段数量(至 SOS)", str(segments)))
        return rows
    if kind == "GIF":
        if len(data) < 13:
            return []
        packed = data[10]
        rows = [
            ("格式", data[:6].decode("latin-1")),
            ("尺寸", f"{_u16le(data, 6)} x {_u16le(data, 8)}"),
            ("帧数", str(len(gif_frame_offsets(data)))),
            ("全局色表", f"{2 ** ((packed & 7) + 1)} 色" if packed & 0x80 else "无"),
        ]
        return rows
    if kind == "BMP":
        if len(data) < 54:
            return []
        w = int.from_bytes(data[18:22], "little", signed=True)
        h = int.from_bytes(data[22:26], "little", signed=True)
        return [
            ("格式", "BMP"),
            ("尺寸", f"{abs(w)} x {abs(h)}"),
            ("位深", f"{_u16le(data, 28)} bit"),
            ("压缩方式", str(_u32le(data, 30))),
            ("像素数据偏移", f"0x{_u32le(data, 10):X}"),
            ("文件头声明大小", f"{_u32le(data, 2):,} 字节"),
        ]
    return []


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
