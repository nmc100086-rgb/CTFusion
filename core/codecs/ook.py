"""Ook! 编码:Brainfuck 的同构映射,内置极简 BF 解释器。"""

from __future__ import annotations

import re

from core.codecs.base import CodecBase, CodecError

# BF 指令 -> Ook 词对
_BF_TO_OOK = {
    ">": "Ook. Ook?", "<": "Ook? Ook.",
    "+": "Ook. Ook.", "-": "Ook! Ook!",
    ".": "Ook! Ook.", ",": "Ook. Ook!",
    "[": "Ook! Ook?", "]": "Ook? Ook!",
}
_OOK_TO_BF = {v: k for k, v in _BF_TO_OOK.items()}


def _run_bf(code: str) -> str:
    """执行 Brainfuck,返回输出。cell 0-255 循环,',' 读入 0。"""
    cmds = [c for c in code if c in "><+-.,[]"]
    # 预计算括号跳转
    jump = {}
    stack = []
    for i, c in enumerate(cmds):
        if c == "[":
            stack.append(i)
        elif c == "]":
            if not stack:
                raise CodecError("Brainfuck 括号不匹配")
            j = stack.pop()
            jump[i] = j
            jump[j] = i
    if stack:
        raise CodecError("Brainfuck 括号不匹配")

    tape = [0] * 30000
    ptr = pc = 0
    out = []
    steps = 0
    while pc < len(cmds):
        steps += 1
        if steps > 10_000_000:
            raise CodecError("Brainfuck 执行步数超限,疑似死循环")
        c = cmds[pc]
        if c == ">":
            ptr += 1
            if ptr >= len(tape):
                raise CodecError("Brainfuck 指针越界")
        elif c == "<":
            ptr -= 1
            if ptr < 0:
                raise CodecError("Brainfuck 指针越界")
        elif c == "+":
            tape[ptr] = (tape[ptr] + 1) & 0xFF
        elif c == "-":
            tape[ptr] = (tape[ptr] - 1) & 0xFF
        elif c == ".":
            out.append(chr(tape[ptr]))
        elif c == "[":
            if tape[ptr] == 0:
                pc = jump[pc]
        elif c == "]":
            if tape[ptr] != 0:
                pc = jump[pc]
        pc += 1
    return "".join(out)


def _gen_bf(text: str) -> str:
    """把文本编译为朴素 BF 程序(差值法,利用 256 回绕取最短方向)。"""
    cmds = []
    cur = 0
    for ch in text:
        target = ord(ch) & 0xFF
        diff = (target - cur) % 256
        cmds.append("+" * diff if diff <= 128 else "-" * (256 - diff))
        cmds.append(".")
        cur = target
    program = "".join(cmds)
    if len(program) % 2:  # Ook 需要偶数条指令配对,补一对无操作
        program += "+-"
    return program


class OokCodec(CodecBase):
    name = "Ook!"
    category = "趣味编码"
    description = "Ook!(Brainfuck 同构),编码为 'OokX OokY' 词对"

    def encode(self, text: str, **p) -> str:
        bf = _gen_bf(text)
        return " ".join(_BF_TO_OOK[c] for c in bf)

    def decode(self, text: str, **p) -> str:
        tokens = re.findall(r"Ook[.?!]", text)
        if not tokens:
            raise CodecError("不是合法的 Ook!:未找到任何 'Ook. / Ook? / Ook!' 词")
        if len(tokens) % 2:
            raise CodecError("不是合法的 Ook!:词数量为奇数,无法配对")
        bf = []
        for i in range(0, len(tokens), 2):
            pair = tokens[i] + " " + tokens[i + 1]
            if pair not in _OOK_TO_BF:
                raise CodecError(f"不是合法的 Ook!:无法识别的词对 {pair!r}")
            bf.append(_OOK_TO_BF[pair])
        return _run_bf("".join(bf))


class BrainfuckCodec(CodecBase):
    name = "Brainfuck"
    category = "趣味编码"
    description = "直接执行 Brainfuck 代码"

    def encode(self, text: str, **p) -> str:
        return _gen_bf(text)

    def decode(self, text: str, **p) -> str:
        if not any(c in text for c in "><+-.,[]"):
            raise CodecError("不是合法的 Brainfuck:未找到任何 BF 指令")
        return _run_bf(text)
