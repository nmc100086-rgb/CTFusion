# MiscKit — CTF Misc 桌面工具箱

一个基于 **PySide6** 的本地 CTF 杂项题辅助工具。当前版本已完成「编码解码」工作台，内置 **35 种**编解码算法，并支持一键多层链式智能解码；文件分析与图片隐写、ZIP 破解两个页签为后续规划。

## 功能特性

- **35 种算法**，按「Base 家族 / 古典密码 / 哈希 / 对称密码 / 文本编码 / 趣味编码 / 进制 / 隐写编码」分类
- **动态参数区**：密钥、IV、自定义字母表、算法专属参数（如凯撒偏移量、栅栏栏数、AES 模式）随算法自动显隐
- **一键智能解码**：多层 BFS 链式尝试，自动识别套娃编码并给出 Top N 结果
- **单向算法保护**：MD5 等不可逆算法自动禁用解码按钮
- **字节级无损往返**：内部使用 `surrogateescape`，乱码输入也不会崩溃或丢字节
- **统一错误提示**：所有失败均抛 `CodecError`，界面直接显示中文原因（例如「不是合法的 Base85：包含非法字符 ','」）
- **拖放分发**：把文件拖进窗口，按类型自动跳到对应页签

## 目录结构

```
MiscKit/
├── main.py                      # 程序入口
├── requirements.txt
├── ui/
│   ├── main_window.py           # 主窗口：3 页签 + 拖放分发
│   ├── decoder_panel.py         # 编码解码工作台（已实现）
│   ├── stego_panel.py           # 文件分析 / 图片隐写（占位）
│   └── zip_panel.py             # ZIP 破解（占位）
└── core/
    ├── chain.py                 # 一键智能解码：BFS + 启发式剪枝
    ├── filetype.py / lsb.py / zipcrack.py   # 后续模块占位
    └── codecs/
        ├── __init__.py          # 导入实现模块 → 自动注册
        ├── base.py              # CodecBase 统一接口 + 可读性评分
        ├── bases.py             # Base16/32/45/58/62/64/85/Ascii85/91/92
        ├── classical.py         # 凯撒/仿射/维吉尼亚/栅栏/曲路/培根/摩斯/猪圈/ROT13/Atbash/Hill
        ├── symmetric.py         # AES(ECB/CBC)、RC4
        ├── text_enc.py          # Hex/URL/ASCII/Quoted-printable/进制转换
        ├── uue.py               # UUencode / XXencode
        ├── hashes.py            # MD5（单向）
        ├── jsfuck.py            # 走本机 Node.js 执行
        ├── ook.py               # Ook! / Brainfuck（内置解释器）
        ├── zerowidth.py         # 零宽字符
        └── hill.py / rot.py     # Hill 密码 / ROT13、Atbash
```

## 环境要求

| 依赖 | 版本 | 说明 |
|---|---|---|
| Python | 3.9+ | 需支持 `PySide6` |
| PySide6 | ≥ 6.6.0 | 图形界面 |
| pycryptodome | ≥ 3.20.0 | AES / RC4 |
| Node.js（可选） | 任意 | 仅 **JSFuck 解码** 需要 |

## 安装与运行

```bash
pip install -r requirements.txt
python main.py
```

国内网络可加镜像：

```bash
pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
```

## 支持的算法（35 种）

| 分类 | 算法 |
|---|---|
| Base 家族（10） | Base16、Base32、Base45、Base58、Base62、Base64、Base85、Ascii85、Base91、Base92 |
| 古典密码（11） | 凯撒密码、仿射密码、ROT13、Atbash、维吉尼亚、栅栏密码、曲路密码、培根密码、摩斯电码、猪圈密码、Hill 密码 |
| 文本编码（6） | Hex、URL 编码、ASCII 码、Quoted-printable、UUencode、XXencode |
| 趣味编码（3） | Brainfuck、Ook!、JSFuck |
| 对称密码（2） | AES（ECB / CBC）、RC4 |
| 哈希（1） | MD5（不可逆，仅编码方向） |
| 进制（1） | 任意 2/8/10/16 进制互转 |
| 隐写编码（1） | 零宽字符 |

### ⚠️ Base85 与 Ascii85 的区别（易混淆）

两者算法相同（4 字节 → 5 字符），**字母表不同**：

| 变体 | 字母表范围 | 是否含 `,` `.` `/` |
|---|---|---|
| **Base85**（RFC 1924，Python `base64.b85encode`） | 数字 + 字母 + `!#$%&()*+-;<=>?@^_`{\|}~` | ❌ 不含 |
| **Ascii85**（Adobe 原始，Python `base64.a85encode`） | `!`(33) ~ `u`(117) 连续 85 字符 | ✅ 含 |

遇到密文里有逗号、句号、斜杠，应选 **Ascii85**；用 Base85 解码会明确提示非法字符并给出该提示。

## 一键智能解码原理

在 `core/chain.py` 中实现，核心是「**BFS + 启发式剪枝 + 评分排序**」：

1. **字符集预判**：内置 13 种编码的合法字符集，先算「像不像这个编码」的置信度，把明显不匹配的候选直接排除，避免指数爆炸
2. **高置信度门槛**：Base 家族要求 ≥ 90% 字符命中字母表才尝试
3. **多层链式**：默认最多展开 **3 层**，覆盖绝大多数 CTF 套娃
4. **提前收敛**：解出 `flag{...}` / `ctf{...}` / `key{...}` 立即停止向下扩展
5. **乱码剪枝**：可读性评分 < 0.4 的节点不再展开
6. **评分排序**：命中 flag 格式 +1.0，再按可打印比例、空格比例、元音比例综合打分，输出 Top 30
7. **凯撒特判**：25 路移位会爆炸，改用 `best_decode()` 只取最优分支

界面中双击结果行即可把内容填入输出区。

## 新增一种编码

得益于 `__init_subclass__` 自动注册，只需两步：

```python
# 1. 在 core/codecs/ 下任意实现模块中定义子类
from core.codecs.base import CodecBase, CodecError

class MyCodec(CodecBase):
    name = "MyEncoding"
    category = "Base 家族"
    description = "一句话说明"
    need_key = False          # 声明 UI 能力：need_key / need_iv / need_alphabet
    params = []               # 动态参数：(参数名, 界面标签, 默认值)

    def encode(self, text: str, **p) -> str:
        ...
    def decode(self, text: str, **p) -> str:
        ...
```

```python
# 2. 在 core/codecs/__init__.py 中导入该模块
from core.codecs import my_module  # noqa: F401
```

下拉菜单、参数区、智能解码会自动发现新算法。

## 设计要点

- **统一接口**：`encode(text, key, iv, alphabet, **params) -> str` / `decode(...) -> str`，输入输出均为 `str`，失败必须抛 `CodecError`
- **字母表自定义**：Base16/32/58/62/64/85 支持传入自定义字母表，内部做双向映射
- **正则校验优先**：Base85 在调用标准库前逐字符校验，避免 Python `b85decode` 静默容忍非法字符后吐出乱码
- **离线优先**：除 JSFuck（依赖本机 Node.js 执行）外，全部算法本地计算，不联网

## 已知限制 / 规划

- [ ] 「文件分析 / 图片隐写」页签：文件真实类型识别、Hex 查看器、EXIF、LSB 位平面 — 目前为占位
- [ ] 「ZIP 破解」页签：伪加密修复、CRC32 爆破、字典爆破 — 目前为占位
- [ ] JSFuck 解码依赖本机 `node` 命令，未安装时给出明确提示
- [ ] PyInstaller 打包为独立 exe 尚待完成
