"""JSFuck:仅含 []()!+ 的 JavaScript 代码,解码依赖本机 Node.js 执行。"""

from __future__ import annotations

import re
import shutil
import subprocess

from core.codecs.base import CodecBase, CodecError

_CHARSET = set("[]()!+")


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

        # 通过 stdin 传代码,避免 Windows 32K 命令行长度限制
        script = (
            "let s='';process.stdin.setEncoding('utf8');"
            "process.stdin.on('data',d=>s+=d);"
            "process.stdin.on('end',()=>{"
            "try{const r=eval(s);"
            "console.log(typeof r==='string'?r:String(r))}"
            "catch(e){process.exit(3)}});"
        )
        try:
            proc = subprocess.run(
                [node, "-e", script],
                input=code.encode("utf-8"),
                capture_output=True, timeout=15,
            )
        except subprocess.TimeoutExpired:
            raise CodecError("JSFuck 执行超时(15s),已终止")
        except OSError as e:
            raise CodecError(f"调用 Node.js 失败:{e}")

        if proc.returncode != 0:
            raise CodecError("JSFuck 执行失败,输入可能不是合法或完整的 JSFuck 代码")
        return proc.stdout.decode("utf-8", errors="replace").rstrip("\r\n")
