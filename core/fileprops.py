"""查看文件属性：路径、大小、时间、Windows 属性、权限、类型与哈希。"""

from __future__ import annotations

import datetime as _dt
import mimetypes
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from core.analysis import digests
from core.filetype import IdentifyResult, identify


@dataclass(frozen=True)
class PropertySection:
    title: str
    rows: tuple[tuple[str, str], ...]


def human_size(size: int) -> str:
    if size < 1024:
        return f"{size:,} 字节"
    if size < 1024 * 1024:
        return f"{size:,} 字节 ({size / 1024:.2f} KiB)"
    if size < 1024 * 1024 * 1024:
        return f"{size:,} 字节 ({size / 1024 / 1024:.2f} MiB)"
    return f"{size:,} 字节 ({size / 1024 / 1024 / 1024:.2f} GiB)"


def _fmt_time(ts: float) -> str:
    try:
        local = _dt.datetime.fromtimestamp(ts).astimezone()
    except (OverflowError, OSError, ValueError):
        return "—"
    return local.strftime("%Y-%m-%d %H:%M:%S %Z")


def _fmt_utc(ts: float) -> str:
    try:
        return _dt.datetime.fromtimestamp(ts, _dt.timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC")
    except (OverflowError, OSError, ValueError):
        return "—"


def _windows_attributes(st: os.stat_result) -> list[str]:
    attrs = getattr(st, "st_file_attributes", 0)
    mapping = (
        ("只读", "FILE_ATTRIBUTE_READONLY"),
        ("隐藏", "FILE_ATTRIBUTE_HIDDEN"),
        ("系统", "FILE_ATTRIBUTE_SYSTEM"),
        ("目录", "FILE_ATTRIBUTE_DIRECTORY"),
        ("归档", "FILE_ATTRIBUTE_ARCHIVE"),
        ("临时", "FILE_ATTRIBUTE_TEMPORARY"),
        ("稀疏文件", "FILE_ATTRIBUTE_SPARSE_FILE"),
        ("重解析点/链接", "FILE_ATTRIBUTE_REPARSE_POINT"),
        ("压缩", "FILE_ATTRIBUTE_COMPRESSED"),
        ("脱机", "FILE_ATTRIBUTE_OFFLINE"),
        ("未建立内容索引", "FILE_ATTRIBUTE_NOT_CONTENT_INDEXED"),
        ("加密", "FILE_ATTRIBUTE_ENCRYPTED"),
        ("完整性流", "FILE_ATTRIBUTE_INTEGRITY_STREAM"),
        ("虚拟", "FILE_ATTRIBUTE_VIRTUAL"),
        ("不清理数据", "FILE_ATTRIBUTE_NO_SCRUB_DATA"),
    )
    names: list[str] = []
    for label, constant in mapping:
        bit = getattr(stat, constant, 0)
        if bit and attrs & bit:
            names.append(label)
    if not attrs:
        return []
    return names or ["无"]


_EXEC_EXTS = {".exe", ".dll", ".sys", ".scr", ".com", ".bat", ".cmd",
              ".ps1", ".py", ".pyw", ".jar", ".msi"}


def _permission_text(path: str) -> str:
    if os.name == "nt":
        # Windows 的 os.stat().st_mode 只是兼容字段，不能代表真实 ACL。
        return "Windows ACL（POSIX mode 不适用）"
    mode = os.stat(path).st_mode
    try:
        mode_text = stat.filemode(mode)
    except (AttributeError, ValueError):
        mode_text = oct(mode)
    access = []
    if os.access(path, os.R_OK):
        access.append("可读")
    if os.access(path, os.W_OK):
        access.append("可写")
    if os.access(path, os.X_OK):
        access.append("可执行")
    return f"{mode_text}  ({' / '.join(access) if access else '无访问权限'})"


def _executable_text(path: str) -> str:
    if os.name == "nt":
        return "是（按扩展名）" if Path(path).suffix.lower() in _EXEC_EXTS else "否（按扩展名）"
    return "是" if os.access(path, os.X_OK) else "否"


def _guess_mime(path: str, result: IdentifyResult | None) -> str:
    mime, _encoding = mimetypes.guess_type(path)
    if mime:
        return mime
    if result is not None:
        mapping = {
            "PNG": "image/png", "JPEG": "image/jpeg", "GIF": "image/gif",
            "BMP": "image/bmp", "WEBP": "image/webp", "TIFF": "image/tiff",
            "ZIP": "application/zip", "RAR": "application/vnd.rar",
            "7Z": "application/x-7z-compressed",
            "PDF": "application/pdf", "WAV": "audio/wav",
            "MP4": "video/mp4", "PE": "application/vnd.microsoft.portable-executable",
        }
        return mapping.get(result.real_name, "")
    return ""


def collect(path: str | Path, data: bytes | None = None,
            result: IdentifyResult | None = None,
            digest_rows: dict[str, str] | None = None,
            compute_hashes: bool = False) -> list[PropertySection]:
    """收集文件属性。

    ``data`` 优先使用调用方已经读入的字节，避免二次读盘；若为 None 且
    ``compute_hashes`` 为 True，则读取最多 64 MiB 用于哈希和文件头识别。
    """
    p = Path(path).expanduser().absolute()
    try:
        st = p.stat()
    except OSError as exc:
        raise OSError(f"无法读取文件属性:{exc}") from exc

    hash_limit = 64 * 1024 * 1024
    if result is None and data is None and compute_hashes:
        if st.st_size > hash_limit:
            compute_hashes = False
        else:
            try:
                data = p.read_bytes()
            except OSError:
                data = None
                compute_hashes = False
    if result is None and data is not None:
        result = identify(data, p.name)

    is_link = p.is_symlink()
    try:
        real_path = str(p.resolve(strict=False))
    except OSError:
        real_path = str(p.absolute())

    sections: list[PropertySection] = []

    path_rows = [
        ("完整路径", str(p.absolute())),
        ("真实路径", real_path),
        ("文件名", p.name),
        ("所在目录", str(p.parent)),
        ("驱动器/根", p.drive or (p.anchor or "—")),
    ]
    sections.append(PropertySection("路径", tuple(path_rows)))

    size_rows = [
        ("文件大小", human_size(st.st_size)),
        ("字节数", f"{st.st_size:,}"),
        ("逻辑类型", "目录" if p.is_dir() else ("符号链接" if is_link else "文件")),
    ]
    sections.append(PropertySection("大小 / 类型", tuple(size_rows)))

    time_rows = [
        ("创建时间", _fmt_time(getattr(st, "st_birthtime", st.st_ctime))),
        ("创建时间 (UTC)", _fmt_utc(getattr(st, "st_birthtime", st.st_ctime))),
        ("修改时间", _fmt_time(st.st_mtime)),
        ("修改时间 (UTC)", _fmt_utc(st.st_mtime)),
        ("访问时间", _fmt_time(st.st_atime)),
        ("访问时间 (UTC)", _fmt_utc(st.st_atime)),
        ("元数据变更", _fmt_time(st.st_ctime)),
    ]
    sections.append(PropertySection("时间", tuple(time_rows)))

    attrs = _windows_attributes(st)
    attr_rows = [
        ("扩展名", p.suffix or "(无)"),
        ("MIME (按扩展名)", _guess_mime(str(p), result) or "未知"),
        ("Windows 属性", "、".join(attrs) if attrs else "— (非 Windows 或无属性)"),
        ("只读", "是" if not os.access(p, os.W_OK) else "否"),
        ("可读", "是" if os.access(p, os.R_OK) else "否"),
        ("可执行", _executable_text(str(p))),
        ("权限", _permission_text(str(p))),
        ("符号链接", "是" if is_link else "否"),
    ]
    try:
        attr_rows.append(("硬链接数", str(st.st_nlink)))
    except AttributeError:
        pass
    sections.append(PropertySection("属性 / 权限", tuple(attr_rows)))

    if result is not None:
        type_rows = [
            ("真实类型", result.real_name),
            ("建议扩展名", result.real_ext or "未知"),
            ("声明扩展名", result.declared_ext or "(无)"),
            ("扩展名匹配", "是" if result.ext_ok else "否 ⚠"),
            ("前置数据", f"{result.prefix:,} 字节" if result.prefix else "无"),
            ("尾随数据", (
                f"{result.trailing.length:,} 字节 @ 0x{result.trailing.offset:X}"
                if result.trailing else "无"
            )),
        ]
        if result.matches:
            type_rows.append(("命中签名", "、".join(result.matches)))
        sections.append(PropertySection("文件类型识别", tuple(type_rows)))

    if digest_rows is None and data is not None and compute_hashes:
        digest_rows = digests(data)
    if digest_rows:
        sections.append(PropertySection(
            "哈希", tuple((name, value) for name, value in digest_rows.items())))
    elif data is not None:
        sections.append(PropertySection(
            "哈希", (("状态", "分析中…"),)))
    else:
        sections.append(PropertySection(
            "哈希", (("状态", "未计算（大文件默认不重复计算）"),)))
    return sections


def sections_to_text(sections: list[PropertySection]) -> str:
    lines: list[str] = []
    for section in sections:
        if lines:
            lines.append("")
        lines.append(f"── {section.title} ──")
        for key, value in section.rows:
            lines.append(f"{key:<12}: {value}")
    return "\n".join(lines)
