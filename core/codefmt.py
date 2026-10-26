"""CTF 常见代码格式化:JSON / Python / C-like / HTML / CSS。

不依赖 black/prettier/clang-format:JSON 用标准库,Python 用 ast,
其余语言用保留字符串/注释的花括号缩进器。目标是可读,不追求与
语言官方 formatter 完全一致。
"""

from __future__ import annotations

import ast
import json
import re

LANGUAGES = (
    "JSON", "Python", "JavaScript", "HTML", "CSS",
    "C", "C++", "Java", "PHP",
)

_C_LIKE = {"JavaScript", "C", "C++", "Java", "PHP", "CSS"}
_INDENT = "    "


class FormatError(ValueError):
    pass


def format_code(code: str, language: str) -> str:
    if not code.strip():
        return ""
    if language == "JSON":
        return _format_json(code)
    if language == "Python":
        return _format_python(code)
    if language == "HTML":
        return _format_html(code)
    if language in _C_LIKE:
        return _format_c_like(code, language)
    raise FormatError(f"暂不支持的语言:{language}")


def _format_json(code: str) -> str:
    try:
        value = json.loads(code)
    except json.JSONDecodeError as e:
        raise FormatError(f"JSON 解析失败:{e}") from e
    return json.dumps(value, ensure_ascii=False, indent=2) + "\n"


def _format_python(code: str) -> str:
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        raise FormatError(f"Python 语法错误:第 {e.lineno} 行 {e.msg}") from e
    # ast.unparse 会丢失注释,但能稳定规范缩进/空行/运算符空格。
    return ast.unparse(tree).strip() + "\n"


def _consume_string(code: str, i: int, quote: str) -> tuple[str, int]:
    start = i
    i += 1
    while i < len(code):
        ch = code[i]
        if ch == "\\":
            i += 2
            continue
        if ch == quote:
            i += 1
            break
        i += 1
    return code[start:i], i


def _format_c_like(code: str, language: str) -> str:
    code = code.replace("\r\n", "\n").replace("\r", "\n")
    out: list[str] = []
    line = ""
    indent = 0
    paren = 0
    i = 0
    n = len(code)

    def add(text: str) -> None:
        nonlocal line
        line += text

    def flush() -> None:
        nonlocal line
        content = line.strip()
        if content:
            out.append(_INDENT * indent + content)
        line = ""

    def trim_line() -> None:
        nonlocal line
        line = line.rstrip()

    while i < n:
        ch = code[i]
        nxt = code[i + 1] if i + 1 < n else ""

        if ch in ("'", '"', "`"):
            value, i = _consume_string(code, i, ch)
            add(value)
            continue

        if ch == "/" and nxt == "/":
            j = code.find("\n", i)
            if j < 0:
                j = n
            add(code[i:j].rstrip())
            flush()
            i = j
            continue

        if ch == "/" and nxt == "*":
            j = code.find("*/", i + 2)
            if j < 0:
                j = n - 2
            block = code[i:j + 2]
            if "\n" in block:
                flush()
                for part in block.splitlines():
                    out.append(_INDENT * indent + part.strip())
            else:
                add(block)
            i = j + 2
            continue

        if ch == "\n":
            flush()
            i += 1
            continue

        if ch == "#" and not line.strip() and language in ("C", "C++", "PHP"):
            j = code.find("\n", i)
            if j < 0:
                j = n
            out.append(code[i:j].rstrip())
            i = j
            continue

        if ch == "(":
            paren += 1
            add(ch)
            i += 1
            continue
        if ch == ")":
            paren = max(0, paren - 1)
            add(ch)
            i += 1
            continue

        if ch == "{":
            trim_line()
            if line.strip():
                add(" {")
                flush()
            else:
                out.append(_INDENT * indent + "{")
            indent += 1
            i += 1
            # 跳过紧随其后的换行
            while i < n and code[i] in " \t\n":
                i += 1
            continue

        if ch == "}":
            flush()
            indent = max(0, indent - 1)
            # 看看后面是不是 ; , ) else catch finally while
            j = i + 1
            while j < n and code[j] in " \t":
                j += 1
            tail = ""
            if j < n and code[j] in ";,":
                tail = code[j]
                j += 1
            elif j < n and code[j] == ")":
                tail = ")"
                j += 1
            else:
                word_match = re.match(r"(else|catch|finally|while)\b", code[j:])
                if word_match:
                    tail = " " + word_match.group(1)
                    j += len(word_match.group(1))
            out.append(_INDENT * indent + "}" + tail)
            i = j
            while i < n and code[i] in " \t\n":
                i += 1
            if i < n and code[i] == "{":
                out[-1] += " {"
                indent += 1
                i += 1
                while i < n and code[i] in " \t\n":
                    i += 1
            continue

        if ch == ";":
            add(";")
            if paren == 0:
                flush()
            i += 1
            continue

        if ch == ",":
            add(", ")
            i += 1
            while i < n and code[i] in " \t":
                i += 1
            continue

        if ch in " \t":
            if line and not line.endswith((" ", "\t")):
                add(" ")
            i += 1
            continue

        add(ch)
        i += 1

    flush()
    # 合并过多少量空行
    text = "\n".join(out)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip() + "\n"


def _format_html(code: str) -> str:
    code = code.replace("\r\n", "\n").replace("\r", "\n")
    token_re = re.compile(r"<!--.*?-->|<!DOCTYPE[^>]*>|<[^>]+>|[^<]+",
                          re.IGNORECASE | re.DOTALL)
    inline = {
        "a", "b", "i", "em", "strong", "span", "img", "br", "hr",
        "input", "meta", "link", "title", "label", "small", "code",
    }
    out: list[str] = []
    indent = 0
    for token in token_re.findall(code):
        if not token.strip():
            continue
        if token.startswith("<!--"):
            out.append(_INDENT * indent + token.strip())
            continue
        if token.startswith("<!DOCTYPE"):
            out.append(token.strip())
            continue
        if token.startswith("</"):
            indent = max(0, indent - 1)
            out.append(_INDENT * indent + token.strip())
            continue
        if token.startswith("<"):
            name_match = re.match(r"<\s*([a-zA-Z0-9]+)", token)
            name = name_match.group(1).lower() if name_match else ""
            self_closing = token.rstrip().endswith("/>")
            out.append(_INDENT * indent + token.strip())
            if name and name not in inline and not self_closing and not token.startswith("<!"):
                indent += 1
            continue
        text = token.strip()
        if text:
            out.append(_INDENT * indent + text)
    return "\n".join(out).strip() + "\n"
