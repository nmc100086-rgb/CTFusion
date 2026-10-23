# MiscKit — CTF Misc 桌面工具箱

一个基于 **PySide6** 的本地 CTF 杂项题辅助工具。当前版本包含「编码解码」（**35 种**算法、一键多层链式智能解码）、「文件分析」（**类型识别 / 文件头 / 结构 / 嵌套文件 / 可编辑 Hex / 熵图 / 字符串**）、「图片隐写」（**LSB 行信息 / PNG Chunk / 通道与 XOR / PNG 修复 / EXIF / GIF 帧**）、「音频 LSB」和「ZIP 分析 / 密码恢复」页签。

## 功能特性

- **35 种算法**，按「Base 家族 / 古典密码 / 哈希 / 对称密码 / 文本编码 / 趣味编码 / 进制 / 隐写编码」分类
- **动态参数区**：密钥、IV、自定义字母表、算法专属参数（如凯撒偏移量、栅栏栏数、AES 模式）随算法自动显隐；AES/RC4 密钥和 AES IV 支持一键随机生成
- **一键智能解码**：多层 BFS 链式尝试，自动识别套娃编码并给出 Top N 结果
- **单向算法保护**：MD5 等不可逆算法自动禁用解码按钮
- **字节级无损往返**：内部使用 `surrogateescape`，乱码输入也不会崩溃或丢字节
- **统一错误提示**：所有失败均抛 `CodecError`，界面直接显示中文原因（例如「不是合法的 Base85：包含非法字符 ','」）
- **拖放分发**：按文件头而不是扩展名分发,扩展名写错或文件头前有垃圾数据也能识别
- **文件分析**：
  - magic bytes 识别 40+ 格式，检测扩展名伪造并给出修复建议；对 `BM` / `MZ` 等弱签名做结构校验，避免文本误报
  - **文件头检测**：实际前 16 字节（Hex + ASCII）与期望 magic、匹配状态、magic 偏移；支持前置垃圾数据检测
  - **文本编码**：UTF-8 / UTF-16 / GB18030 自动识别，中文文本不再被当成未知二进制
  - **图片基本信息**：宽高、位深、颜色类型、隔行、帧数、DPI、IDAT 大小、像素总数
  - 结构解析：PNG（chunk + **CRC 校验**）、JPG（含渐进式 JPEG 多扫描）、GIF（多帧）、BMP、ZIP（EOCD 校验、ZIP64、注释、伪加密标记）
  - **尾随数据检测**：文件逻辑结束后附加的隐藏内容（内嵌 ZIP/PNG、ASCII 提示）
  - **嵌套文件检测**：binwalk 风格扫描内嵌 PNG/JPEG/GIF/ZIP/PDF/ELF 等,支持单个/批量提取
  - **编码特征检测**：URL、可解码 Base64、可解码 Hex 片段及偏移
  - **可编辑 Hex 查看器**：双击改字节、撤销/重做（Ctrl+Z/Ctrl+Y）、覆盖保存/保存副本；只读文件禁止修改并提示
  - **Hex 搜索**：ASCII/Hex 下拉模式；ASCII 不区分大小写；无需先“查找全部”即可直接上一个/下一个；命中字节在 Hex/ASCII 单元格中精确高亮
  - **双击编辑**：在 Hex 表格中双击具体字节修改；只读文件禁止修改并提示
  - 数据检查器：光标处 uint8/16/32/64、int、float/double（双端序）、时间戳
  - 字符串提取（正则过滤、结果上限）、熵图、MD5/SHA1/SHA256/CRC32
- **图片隐写**：
  - 图片预览（PNG/JPG/GIF/BMP/WEBP 等），支持前置垃圾数据的图片
  - **LSB 位平面可视化**：R/G/B/A × bit 0~7 任意切换
  - **LSB 数据提取**：MSB/LSB-first、多通道（RGB/RGBA/全部）、起始像素/步长/最大长度、UTF-8/UTF-16/GB18030/Latin-1 文本预览
  - **LSB 行信息(随波逐流式)**：遍历单通道/三通道/四通道顺序,整图或逐行提取 LSB 文本,flag 行优先显示
  - **原始像素模式**：索引色保留调色板索引,16-bit 保留原始低/高字节；JPEG 给出有损警告
  - **PNG 修复**：逐个 chunk 校验 CRC、一键重算 CRC、按 IDAT 候选尺寸修复 IHDR 宽高（多候选时要求确认）
  - **PNG Chunk**：全部 chunk 列表、tEXt/zTXt/iTXt/eXIf 提取、APNG 控制块提示、文本导出
  - **EXIF 表格**：JPEG APP1 / PNG eXIf / TIFF；制造商、拍摄时间、GPS 经纬度/海拔、缩略图信息
  - **图像工具**：通道灰度图、反色、XOR、差分、RGB 直方图、结果保存
  - **StegSolve 风格工具**：Data Extract（多通道多 bit 平面、通道顺序、位序、bit 平面顺序）、Image Combiner（XOR/ADD/SUB/AND/OR/MIN/MAX/DIFF）、Stereogram 深度图、Random Color Map
  - **GIF 逐帧浏览**：顺序读入帧缓存，避免 Qt `jumpToImage` 在 GIF 上不可用的问题
- **音频 LSB**：WAV 元信息、通道/位/位序选择、采样 LSB 提取与保存
- **ZIP 分析 / 密码恢复**：条目列表、注释、伪加密检测/修复、安全解压；字典/暴力/掩码三种 ZipCrypto 密码恢复模式，带进度、速度、ETA、停止和结果复制
- **隐藏字符高亮**：flag/ctf/key、花括号、零宽字符高亮(不区分大小写),输出区显示零宽字符数量
- **双向联动**：结构树 / 字符串双击直接跳到 Hex 对应偏移

## 目录结构

```
MiscKit/
├── main.py                      # 程序入口
├── requirements.txt
├── ui/
│   ├── main_window.py           # 主窗口:5 页签 + 拖放分发
│   ├── decoder_panel.py         # 编码解码工作台
│   ├── file_panel.py            # 文件分析:概览 / 文件头 / 结构 / 嵌套 / 字符串 / 熵图
│   ├── image_panel.py           # 图片:LSB / 行信息 / PNG Chunk / 图像工具 / StegSolve / 修复 / EXIF / GIF
│   ├── stegsolve_panel.py       # StegSolve:Data Extract / Combiner / Stereogram / Color Map
│   ├── audio_panel.py           # WAV 元信息与 LSB 提取
│   ├── hex_viewer.py            # Hex 查看器(虚拟滚动 + 编辑 + 只读 + 搜索高亮)
│   ├── highlight.py             # flag/ctf/花括号/零宽字符高亮
│   └── zip_panel.py             # ZIP:结构/伪加密/字典/暴力/掩码密码恢复/安全解压
└── core/
    ├── chain.py                 # 一键智能解码:BFS + 启发式剪枝
    ├── filetype.py              # magic 识别 + 弱签名校验 + 前置数据 + 尾随数据
    ├── fileparse.py             # 结构解析 + PNG 信息/Chunk/CRC/宽高 + EXIF + GIF
    ├── filecarve.py             # 内嵌文件扫描与提取(轻量 binwalk)
    ├── detect.py                # URL / Base64 / Hex 编码特征检测
    ├── imagetools.py            # 通道 / 反色 / 组合运算 / 直方图 / 随机色 / 立体图
    ├── stegsolve.py             # StegSolve Data Extract 的位流提取
    ├── audio.py                 # WAV 元信息 + 采样 LSB
    ├── analysis.py              # 哈希 / 熵 / 字符串 / 数据解释
    ├── lsb.py                   # LSB 位平面、位序、多通道、行信息扫描
    ├── zipcrack.py              # ZIP 结构/伪加密 + ZipCrypto 密码恢复
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

## 打包为 exe

使用 PyInstaller **onedir 便携版**，带图标和版本信息：

```powershell
.\build_exe.ps1
```

如果执行策略禁止脚本：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\build_exe.ps1
```

输出：

```text
dist/MiscKit v1.0/MiscKit v1.0.exe
dist/MiscKit v1.0/_internal/
```

`MiscKit v1.0.exe` 必须和同目录的 `_internal` 一起分发。修改源码后运行 `.\rebuild.ps1` 重新打包。详见 [README_BUILD.md](README_BUILD.md)。

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
| 文本编码（6） | Hex、URL 编码、ASCII 码、Quoted-printable、UUencode、XXencode（兼容浏览器版长度标记） |
| 趣味编码（3） | Brainfuck、Ook!、JSFuck |
| 对称密码（2） | AES（ECB / CBC，PKCS7/无填充/零填充/ISO10126）、RC4（明文 string/hex/base64） |
| 哈希（1） | MD5（不可逆，输出 16/32 位、大小写四种格式） |
| 进制（1） | 任意 2/8/10/16 进制互转 |
| 隐写编码（1） | 零宽字符（输入=隐藏内容，伪装文本=载体文字） |

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

- [x] 「文件分析」页签：类型识别、弱签名校验、前置数据/文件头检测、结构解析、嵌套文件扫描与提取、编码特征检测、可编辑 Hex、字符串、熵图、尾随数据检测
- [x] 图片隐写：LSB 位平面 / 位序 / 多通道 / 行信息、原始索引/16-bit、PNG Chunk 工具箱、通道/XOR/差分/直方图、PNG CRC 与宽高候选修复、EXIF、GIF 帧浏览
- [x] Hex 支持双击改字节、撤销/重做、覆盖保存/保存副本；只读文件禁止修改；搜索支持 ASCII/Hex 下拉、大小写不敏感和高亮
- [x] 音频 LSB：WAV 元信息、通道/位/位序、采样 LSB 提取
- [x] StegSolve 风格工具：Data Extract、Image Combiner、Stereogram、Random Color Map
- [x] 「ZIP 分析」页签：条目列表、注释、伪加密检测/修复、安全解压、ZipCrypto 字典/暴力/掩码密码恢复
- [ ] Stereogram 为简化深度图算法，不等同于 StegSolve 的完整实现；复杂立体图仍建议用原工具
- [ ] EXIF 解析常用标签和 GPS/缩略图，但厂商私有标签、XMP/ICC 尚未完整覆盖
- [ ] ZIP 密码恢复目前只支持 ZipCrypto；AES/WinZip 加密 ZIP 和 RAR/7z 请使用 7-Zip、ARCHPR 或 Kali 的 `john`
- [ ] 音频频谱、PCAP、PDF/Office、二维码/OCR、完整 binwalk 签名库属于后续模块
- [ ] JSFuck 解码依赖本机 `node` 命令，未安装时给出明确提示
- [ ] PyInstaller 打包为独立 exe 尚待完成

## 与 Kali 工具的分工

以下功能需要大量外部依赖、原生库或 GPU/字典资源，**不建议塞进本工具**，建议在 Kali 里用成熟工具处理：

| 场景 | 建议工具 |
|---|---|
| 文件雕刻 / 递归提取 | `binwalk -e`、`foremost`、`scalpel` |
| ZIP/RAR 密码爆破 | `fcrackzip`、`zip2john` + `john`、`hashcat` |
| PNG 深度检查 | `pngcheck`、`pngcrush` |
| 图片隐写 | `zsteg`、`steghide`、`outguess` |
| 音频频谱 | Audacity、Sonic Visualiser、`sox` |
| PCAP | Wireshark、`tshark`、`tcpflow` |
| 二维码 / OCR | `zbarimg`、`tesseract` |
| PDF / Office | `pdf-parser`、`olevba`、`exiftool` |

本工具保留「离线、单文件、Python 依赖少」的定位；需要外部工具时，优先让用户用系统命令完成，而不是在 PySide6 里重写一遍。
