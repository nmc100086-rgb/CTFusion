"""bkcrack 已知明文攻击(KPA)的二次封装。

CTFusion 不实现 Biham-Kocher 攻击算法,而是调用 bkcrack 作者 kimci86
发布并编译好的 ``bkcrack.exe``(https://github.com/kimci86/bkcrack)。
本模块只负责:

* 从 ZIP 中按偏移取出 ZipCrypto 密文,构造 bkcrack 可读的临时 ZIP;
* 用固定参数、固定可执行文件通过 subprocess 启动 bkcrack;
* 解析 Keys、流式返回日志,并提供用密钥解密条目的封装。

这样既尊重原作者,也避免在 Python 里重复实现密码学算法。
"""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time
import zlib
from collections import deque
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Callable

from core import zipcrack

BKCrack_VERSION = "1.8.1"
BKCrack_SHA256 = "d3de2e1494c8db2a1550794cae4923956d76da9314e68198096f4b03f7f310d5"
BKCrack_URL = "https://github.com/kimci86/bkcrack"

MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_PLAINTEXT_BYTES = 64 * 1024 * 1024
MAX_EXTRA_KNOWN = 64
MAX_LOG_LINES = 4000
MIN_CONTIGUOUS = 8
MIN_TOTAL_KNOWN = 12

_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


class BkcrackError(Exception):
    """Raised when bkcrack cannot be located, started or used safely."""


@dataclass(frozen=True)
class BkcrackInfo:
    path: str
    version: str = ""
    sha256: str = ""
    verified: bool = False
    error: str = ""

    @property
    def available(self) -> bool:
        return bool(self.version and not self.error)


def resource_root() -> Path:
    """Return the directory that contains bundled resources."""
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        return Path(meipass)
    return Path(__file__).resolve().parents[1]


def bkcrack_path() -> Path:
    return resource_root() / "bin" / "bkcrack.exe"


@lru_cache(maxsize=1)
def bkcrack_info() -> BkcrackInfo:
    """Inspect the bundled executable once; never download at runtime."""
    path = bkcrack_path()
    if not path.is_file():
        return BkcrackInfo(
            path=str(path),
            error=(
                "未找到 bkcrack.exe。请将 bkcrack 1.8.1 的 "
                "bkcrack.exe 放到项目的 bin/ 目录后重新打包。"))
    try:
        size = path.stat().st_size
    except OSError as exc:
        return BkcrackInfo(path=str(path), error=f"无法读取 bkcrack.exe:{exc}")
    if not 64 * 1024 <= size <= 4 * 1024 * 1024:
        return BkcrackInfo(
            path=str(path),
            error=f"bkcrack.exe 大小异常({size:,} 字节),已拒绝调用")
    try:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        return BkcrackInfo(path=str(path), error=f"无法校验 bkcrack.exe:{exc}")

    try:
        completed = subprocess.run(
            [str(path), "--version"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
            creationflags=_creation_flags(),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return BkcrackInfo(path=str(path), sha256=digest,
                           error=f"无法启动 bkcrack.exe:{exc}")
    version = ""
    match = re.search(r"bkcrack\s+([0-9][^\s]*)", completed.stdout or "")
    if match:
        version = match.group(1)
    if not version:
        return BkcrackInfo(
            path=str(path), sha256=digest,
            error="bkcrack.exe 未返回可识别的版本信息")
    verified = digest.lower() == BKCrack_SHA256
    return BkcrackInfo(path=str(path), version=version, sha256=digest,
                       verified=verified)


def _creation_flags() -> int:
    if os.name == "nt":
        return getattr(subprocess, "CREATE_NO_WINDOW", 0)
    return 0


def _private_tempdir() -> str:
    """Create a private temp dir that also works under restricted tokens."""
    base = tempfile.gettempdir()
    mode = 0o777 if os.name == "nt" else 0o700
    for _ in range(100):
        path = os.path.join(base, "ctfusion-" + secrets.token_hex(8))
        try:
            os.makedirs(path, mode=mode)
            return path
        except FileExistsError:
            continue
    raise BkcrackError("无法创建临时目录")


@dataclass
class RunResult:
    returncode: int
    output: str
    cancelled: bool = False
    timed_out: bool = False


def _run_bkcrack(args: list[str], workdir: str, log_path: str,
                 on_output: Callable[[str], None] | None = None,
                 cancel: threading.Event | None = None,
                 timeout: float = 0.0) -> RunResult:
    """Run bkcrack with a fixed executable and a fixed argument vector.

    stdout/stderr go to a temporary log file instead of a pipe so a long
    attack can be polled and stopped without blocking on a full pipe.
    """
    info = bkcrack_info()
    if not info.available:
        raise BkcrackError(info.error or "bkcrack.exe 不可用")
    lines: deque[str] = deque(maxlen=MAX_LOG_LINES)
    buffer = ""
    position = 0
    cancelled = False
    timed_out = False

    def emit(text: str) -> None:
        text = _ANSI_RE.sub("", text).strip()
        if not text:
            return
        lines.append(text)
        if on_output is not None:
            on_output(text)

    def read_new() -> None:
        nonlocal position, buffer
        try:
            with open(log_path, "rb") as log_file:
                log_file.seek(position)
                chunk = log_file.read()
                position = log_file.tell()
        except OSError:
            return
        if not chunk:
            return
        buffer += chunk.decode("utf-8", "replace")
        parts = re.split(r"[\r\n]+", buffer)
        buffer = parts.pop()
        for part in parts:
            emit(part)

    with open(log_path, "wb") as log_file:
        try:
            process = subprocess.Popen(
                [str(bkcrack_path()), *args],
                stdin=subprocess.DEVNULL,
                stdout=log_file,
                stderr=subprocess.STDOUT,
                cwd=workdir,
                creationflags=_creation_flags(),
            )
        except OSError as exc:
            raise BkcrackError(f"无法启动 bkcrack.exe:{exc}") from exc

        started = time.monotonic()
        while True:
            returncode = process.poll()
            read_new()
            if returncode is not None:
                break
            if cancel is not None and cancel.is_set():
                cancelled = True
                _terminate(process)
                break
            if timeout and time.monotonic() - started > timeout:
                timed_out = True
                _terminate(process)
                break
            time.sleep(0.1)
        read_new()
        if buffer.strip():
            emit(buffer)
            buffer = ""
        returncode = process.poll()
        if returncode is None:
            returncode = -1
    return RunResult(returncode=returncode, output="\n".join(lines),
                     cancelled=cancelled, timed_out=timed_out)


def _terminate(process: subprocess.Popen) -> None:
    try:
        process.terminate()
        process.wait(timeout=2)
    except (OSError, subprocess.TimeoutExpired):
        try:
            process.kill()
            process.wait(timeout=2)
        except (OSError, subprocess.TimeoutExpired):
            pass


def build_synthetic_zip(entry: zipcrack.ZipEntry,
                        ciphertext: bytes) -> bytes:
    """Build a one-entry ZIP bkcrack can read, even for prefixed archives.

    The entry payload is the original encrypted bytes (including the 12-byte
    ZipCrypto header); flags/CRC/sizes/time are copied so bkcrack can infer the
    same check byte as the original archive.  In particular, bit 3 archives
    use the high byte of the DOS modification time as check byte, not the CRC
    high byte, so bit 3 and the original time/date must be preserved.
    """
    if len(ciphertext) != entry.compressed_size:
        raise BkcrackError("密文长度与 ZIP 中央目录不一致")
    if entry.size > 0xFFFFFFFF or len(ciphertext) > 0xFFFFFFFF:
        raise BkcrackError("ZIP64 条目过大,拒绝构造临时 ZIP")
    name = b"cipher"
    flags = entry.flags | 1
    method = entry.method if entry.method in (0, 8) else 0
    crc = entry.crc & 0xFFFFFFFF
    dos_time = entry.dos_time & 0xFFFF
    dos_date = entry.dos_date & 0xFFFF
    if flags & 0x08:
        # 与 data descriptor 原始 ZIP 一致:本地头 CRC/大小留 0,
        # 真实值只在中央目录中。
        local_crc = 0
        local_csize = 0
        local_usize = 0
    else:
        local_crc = crc
        local_csize = len(ciphertext)
        local_usize = entry.size
    local = struct.pack(
        "<IHHHHHIIIHH", 0x04034B50, 20, flags, method, dos_time, dos_date,
        local_crc, local_csize, local_usize, len(name), 0,
    ) + name + ciphertext
    central = struct.pack(
        "<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, flags, method,
        dos_time, dos_date, crc, len(ciphertext), entry.size,
        len(name), 0, 0, 0, 0, 0, 0,
    ) + name
    eocd = struct.pack(
        "<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, len(central), len(local), 0)
    return local + central + eocd


def _extract_ciphertext(data: bytes, entry: zipcrack.ZipEntry) -> bytes:
    if (entry.local_offset < 0 or entry.local_offset + 30 > len(data)
            or data[entry.local_offset:entry.local_offset + 4] != b"PK\x03\x04"):
        raise BkcrackError("本地文件头越界或损坏")
    name_len = int.from_bytes(
        data[entry.local_offset + 26:entry.local_offset + 28], "little")
    extra_len = int.from_bytes(
        data[entry.local_offset + 28:entry.local_offset + 30], "little")
    start = entry.local_offset + 30 + name_len + extra_len
    end = start + entry.compressed_size
    if entry.compressed_size < 12:
        raise BkcrackError("加密数据长度异常,缺少 ZipCrypto 12 字节头")
    if end > len(data):
        raise BkcrackError("加密数据越过文件末尾")
    return data[start:end]


def compress_deflate(data: bytes, level: int = 6) -> bytes:
    if not 1 <= level <= 9:
        raise BkcrackError("Deflate 压缩级别必须在 1..9")
    compressor = zlib.compressobj(level, zlib.DEFLATED, -15)
    return compressor.compress(data) + compressor.flush()


def deflate_variants(data: bytes) -> list[tuple[int, bytes]]:
    """Return compressed variants for common deflate levels."""
    variants: list[tuple[int, bytes]] = []
    for level in range(1, 10):
        try:
            variants.append((level, compress_deflate(data, level)))
        except BkcrackError:
            continue
    return variants


@dataclass
class KpaConfig:
    path: str
    entry_index: int
    plaintext: bytes = b""
    offset: int = 0
    deflate_level: int | None = None
    extra: list[tuple[int, bytes]] = field(default_factory=list)
    timeout: float = 0.0
    data: bytes = b""


@dataclass
class KpaResult:
    success: bool = False
    keys: tuple[int, int, int] | None = None
    output: str = ""
    elapsed: float = 0.0
    cancelled: bool = False
    timed_out: bool = False
    error: str = ""
    entry_name: str = ""


def parse_keys(output: str) -> tuple[int, int, int] | None:
    pattern = re.compile(
        r"Keys:?\s*([0-9a-fA-F]{8})\s+([0-9a-fA-F]{8})\s+([0-9a-fA-F]{8})",
        re.IGNORECASE,
    )
    matches = pattern.findall(output)
    if not matches:
        # bkcrack also prints a standalone "[time] Keys" line followed by
        # the three values on the next line.
        matches = re.findall(
            r"\]\s*Keys\s*\n\s*([0-9a-fA-F]{8})\s+"
            r"([0-9a-fA-F]{8})\s+([0-9a-fA-F]{8})",
            output, re.IGNORECASE)
    if not matches:
        return None
    return tuple(int(value, 16) for value in matches[-1])  # type: ignore[return-value]


def _prepare_plaintext(config: KpaConfig) -> bytes:
    plaintext = config.plaintext
    if config.deflate_level is not None:
        plaintext = compress_deflate(plaintext, config.deflate_level)
    if not plaintext:
        raise BkcrackError("已知明文不能为空")
    if len(plaintext) > MAX_PLAINTEXT_BYTES:
        raise BkcrackError("已知明文超过 64 MB 上限")
    if len(plaintext) < MIN_CONTIGUOUS:
        raise BkcrackError(
            f"bkcrack 至少需要 {MIN_CONTIGUOUS} 字节连续明文;"
            f"当前只有 {len(plaintext)} 字节")
    if len(config.extra) > MAX_EXTRA_KNOWN:
        raise BkcrackError("额外已知字节过多")
    total = len(plaintext) + 1 + sum(len(extra) for _offset, extra in config.extra)
    if total < MIN_TOTAL_KNOWN:
        raise BkcrackError(
            f"已知明文共 {total} 字节(含自动校验字节),"
            f"少于 bkcrack 要求的 {MIN_TOTAL_KNOWN} 字节")
    return plaintext


def attack(config: KpaConfig,
           on_output: Callable[[str], None] | None = None,
           cancel: threading.Event | None = None) -> KpaResult:
    started = time.monotonic()
    result = KpaResult()
    try:
        path = os.path.abspath(config.path)
        data = config.data
        if not data:
            if not os.path.isfile(path):
                raise BkcrackError("ZIP 文件不存在")
            if os.path.getsize(path) > MAX_ARCHIVE_BYTES:
                raise BkcrackError("ZIP 超过 512 MB 安全上限")
            with open(path, "rb") as archive:
                data = archive.read()
        if len(data) > MAX_ARCHIVE_BYTES:
            raise BkcrackError("ZIP 超过 512 MB 安全上限")
        info = zipcrack.inspect(data)
        if info.error:
            raise BkcrackError(info.error)
        if config.entry_index < 0 or config.entry_index >= len(info.entries):
            raise BkcrackError("请选择要攻击的加密条目")
        entry = info.entries[config.entry_index]
        result.entry_name = entry.name
        if not (entry.flags & 1):
            raise BkcrackError("该条目未加密,不需要已知明文攻击")
        if entry.aes:
            raise BkcrackError("该条目使用 AES/WinZip,不是 ZipCrypto")
        if entry.flags & 0x40:
            raise BkcrackError("该条目使用 Strong Encryption(bit 6),bkcrack 不支持")
        if entry.method not in (0, 8):
            raise BkcrackError("仅支持存储/Deflate 条目")
        if entry.pseudo:
            raise BkcrackError("该条目疑似伪加密,请先修复伪加密")
        ciphertext = _extract_ciphertext(data, entry)
        synthetic = build_synthetic_zip(entry, ciphertext)
        plaintext = _prepare_plaintext(config)
        if config.offset < 0 or config.offset > entry.compressed_size - 12:
            raise BkcrackError("已知明文偏移超出压缩数据范围")
        for offset, extra in config.extra:
            if not extra:
                raise BkcrackError("额外已知字节不能为空")
            if offset < -12 or offset > entry.compressed_size - 12:
                raise BkcrackError(f"额外已知字节偏移 {offset} 超出范围")

        temp_dir = _private_tempdir()
        try:
            zip_path = os.path.join(temp_dir, "cipher.zip")
            plain_path = os.path.join(temp_dir, "plain.bin")
            log_path = os.path.join(temp_dir, "bkcrack.log")
            with open(zip_path, "wb") as f:
                f.write(synthetic)
            with open(plain_path, "wb") as f:
                f.write(plaintext)
            args = [
                "-C", zip_path,
                "--cipher-index", "0",
                "-p", plain_path,
                "-o", str(config.offset),
            ]
            for offset, extra in config.extra:
                args.extend(["-x", str(offset), extra.hex()])
            run = _run_bkcrack(
                args, temp_dir, log_path, on_output=on_output,
                cancel=cancel, timeout=config.timeout)
            result.output = run.output
            result.cancelled = run.cancelled
            result.timed_out = run.timed_out
            result.keys = parse_keys(run.output)
            if run.cancelled:
                result.error = "已停止"
            elif run.timed_out:
                result.error = "攻击超时"
            elif result.keys is None:
                tail = "\n".join(run.output.splitlines()[-4:])
                result.error = tail or f"bkcrack 退出码 {run.returncode},未找到密钥"
            else:
                result.success = True
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
    except (BkcrackError, OSError, ValueError) as exc:
        result.error = str(exc)
    result.elapsed = time.monotonic() - started
    return result


def decrypt_entry(path: str, data: bytes, entry_index: int,
                  keys: tuple[int, int, int], output_path: str,
                  on_output: Callable[[str], None] | None = None,
                  cancel: threading.Event | None = None) -> bytes:
    """Decrypt one entry with known keys and write its plaintext."""
    if len(keys) != 3:
        raise BkcrackError("密钥格式错误")
    if os.path.abspath(output_path) == os.path.abspath(path):
        raise BkcrackError("输出文件不能覆盖原 ZIP")
    info = zipcrack.inspect(data)
    if info.error:
        raise BkcrackError(info.error)
    if entry_index < 0 or entry_index >= len(info.entries):
        raise BkcrackError("条目索引无效")
    entry = info.entries[entry_index]
    ciphertext = _extract_ciphertext(data, entry)
    temp_dir = _private_tempdir()
    try:
        cipher_path = os.path.join(temp_dir, "cipher.bin")
        plain_path = os.path.join(temp_dir, "plain.bin")
        log_path = os.path.join(temp_dir, "bkcrack.log")
        with open(cipher_path, "wb") as f:
            f.write(ciphertext)
        args = [
            "-c", cipher_path,
            "-k", *(f"{value:08x}" for value in keys),
            "-d", plain_path,
        ]
        run = _run_bkcrack(args, temp_dir, log_path, on_output=on_output,
                           cancel=cancel)
        if not os.path.isfile(plain_path):
            raise BkcrackError(run.output.splitlines()[-1] if run.output else "解密失败")
        with open(plain_path, "rb") as f:
            decrypted = f.read()
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

    if entry.method == 8:
        try:
            plain = zlib.decompress(decrypted, -15)
        except zlib.error as exc:
            raise BkcrackError(f"Deflate 解压失败:{exc}") from exc
    elif entry.method == 0:
        plain = decrypted
    else:
        plain = decrypted
    if entry.size and len(plain) != entry.size:
        raise BkcrackError(
            f"解密后大小 {len(plain)} 与 ZIP 声明 {entry.size} 不一致")
    if (zlib.crc32(plain) & 0xFFFFFFFF) != (entry.crc & 0xFFFFFFFF):
        raise BkcrackError("解密后 CRC32 校验失败,密钥或条目可能不匹配")
    with open(output_path, "wb") as f:
        f.write(plain)
    return plain


def remove_password(path: str, keys: tuple[int, int, int], output_path: str,
                    cancel: threading.Event | None = None,
                    on_output: Callable[[str], None] | None = None) -> RunResult:
    """Use bkcrack to produce a copy of the archive without encryption."""
    if len(keys) != 3:
        raise BkcrackError("密钥格式错误")
    if os.path.abspath(path) == os.path.abspath(output_path):
        raise BkcrackError("输出文件不能覆盖原 ZIP")
    temp_dir = _private_tempdir()
    try:
        log_path = os.path.join(temp_dir, "bkcrack.log")
        args = [
            "-C", os.path.abspath(path),
            "-k", *(f"{value:08x}" for value in keys),
            "-D", os.path.abspath(output_path),
        ]
        return _run_bkcrack(args, temp_dir, log_path, cancel=cancel,
                            on_output=on_output)
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def change_password(path: str, keys: tuple[int, int, int], output_path: str,
                    new_password: str,
                    cancel: threading.Event | None = None,
                    on_output: Callable[[str], None] | None = None) -> RunResult:
    """Use bkcrack to produce a copy encrypted with a new password."""
    if len(keys) != 3:
        raise BkcrackError("密钥格式错误")
    if os.path.abspath(path) == os.path.abspath(output_path):
        raise BkcrackError("输出文件不能覆盖原 ZIP")
    if not new_password or len(new_password) > 1024:
        raise BkcrackError("新密码长度必须在 1..1024 之间")
    temp_dir = _private_tempdir()
    try:
        log_path = os.path.join(temp_dir, "bkcrack.log")
        args = [
            "-C", os.path.abspath(path),
            "-k", *(f"{value:08x}" for value in keys),
            "-U", os.path.abspath(output_path), new_password,
        ]
        return _run_bkcrack(args, temp_dir, log_path, cancel=cancel,
                            on_output=on_output)
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
