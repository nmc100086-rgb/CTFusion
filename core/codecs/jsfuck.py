"""JSFuck:仅含 []()!+ 的 JavaScript 代码,解码依赖本机 Node.js 执行。"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import threading
import time

from core.codecs.base import CodecBase, CodecError

_CHARSET = set("[]()!+")

_MAX_OUTPUT = 1024 * 1024


def _run_node_limited(node: str, code: str, timeout: float = 15) -> tuple[int, bytes, bytes]:
    """Run Node with a temporary working directory and bounded captured output."""
    script = (
        "let s='';process.stdin.setEncoding('utf8');"
        "process.stdin.on('data',d=>s+=d);"
        "process.stdin.on('end',()=>{"
        "try{const r=eval(s);"
        "process.stdout.write(typeof r==='string'?r:String(r))}"
        "catch(e){process.stderr.write(String(e&&e.stack||e));process.exit(3)}});"
    )
    with tempfile.TemporaryDirectory(prefix="ctfusion_jsfuck_") as workdir:
        proc = subprocess.Popen(
            [node, "-e", script],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=workdir,
        )
        streams: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray()}
        exceeded = threading.Event()

        def drain(stream, key: str) -> None:
            assert stream is not None
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    return
                remaining = _MAX_OUTPUT - len(streams[key])
                if remaining > 0:
                    streams[key].extend(chunk[:remaining])
                if len(chunk) > remaining:
                    exceeded.set()
                    proc.kill()
                    return

        readers = [
            threading.Thread(target=drain, args=(proc.stdout, "stdout"), daemon=True),
            threading.Thread(target=drain, args=(proc.stderr, "stderr"), daemon=True),
        ]
        for reader in readers:
            reader.start()
        try:
            assert proc.stdin is not None
            proc.stdin.write(code.encode("utf-8"))
            proc.stdin.close()
        except (BrokenPipeError, OSError):
            pass

        deadline = time.monotonic() + timeout
        timed_out = False
        while proc.poll() is None:
            if time.monotonic() >= deadline:
                timed_out = True
                proc.kill()
                break
            time.sleep(0.02)
        returncode = proc.wait()
        for reader in readers:
            reader.join(timeout=1)
        for stream in (proc.stdout, proc.stderr):
            if stream is not None:
                stream.close()
        if timed_out:
            raise CodecError(f"JSFuck 执行超时({timeout:.0f}s),已终止")
        if exceeded.is_set():
            raise CodecError(f"JSFuck 输出超过 {_MAX_OUTPUT // 1024} KiB,已终止")
        return returncode, bytes(streams["stdout"]), bytes(streams["stderr"])


class JsfuckCodec(CodecBase):
    name = "JSFuck"
    category = "趣味编码"
    description = "[]()!+ 六字符 JS;解码调用本机 Node.js 执行。注意:会在本机执行任意 JS,请只对可信输入使用"
    detectable = False   # 一键智能解码不自动执行 JS

    def encode(self, text: str, **p) -> str:
        raise CodecError("JSFuck 编码依赖浏览器环境,请在浏览器控制台完成;本工具支持解码。")

    def decode(self, text: str, **p) -> str:
        code = re.sub(r"\s+", "", text)
        if not code:
            raise CodecError("请输入 JSFuck 代码")
        if not _CHARSET.issuperset(code):
            bad = sorted(set(code) - _CHARSET)
            raise CodecError(f"不是合法的 JSFuck:包含字符集之外的字符 {bad}")

        node = shutil.which("node")
        if not node:
            raise CodecError("JSFuck 解码需要本机安装 Node.js(用于执行 JS),未检测到 node 命令。")

        allowed = str(p.get("allow_execution", "0")).strip().lower()
        if allowed not in ("1", "true", "yes"):
            raise CodecError("JSFuck 会执行 JavaScript。请在界面中确认风险后再解码。")

        try:
            returncode, stdout, _stderr = _run_node_limited(node, code)
        except OSError as e:
            raise CodecError(f"调用 Node.js 失败:{e}")

        if returncode != 0:
            raise CodecError("JSFuck 执行失败,输入可能不是合法或完整的 JSFuck 代码")
        return stdout.decode("utf-8", errors="replace").rstrip("\r\n")
