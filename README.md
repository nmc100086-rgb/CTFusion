# CTFusion v2.2

CTFusion 是一个基于 PySide6 的本地 CTF 综合工具箱，覆盖编码解码、文件分析、图片与音频隐写、ZIP 密码恢复 / CRC32 反查 / bkcrack 已知明文攻击、JWT 和代码格式化。工具离线运行，不依赖在线服务。

> v2.2 ZIP 页签新增 **CRC 爆破** 与 **已知明文攻击 (KPA)**。KPA 是对 [kimci86/bkcrack](https://github.com/kimci86/bkcrack) 的二次封装，攻击算法由原作者实现，CTFusion 只负责准备数据、启动进程和展示结果。

## 主要功能

### 编码解码

- 35 种算法：Base 家族、古典密码、哈希、AES/RC4、文本编码、趣味编码、进制转换和零宽字符。
- 多层智能解码：BFS 链式尝试、启发式剪枝、凯撒最优分支和结果评分。
- 智能结果分类：可识别 Flag、路径、凭据、疑似密码、URL、邮箱、哈希和普通文本，并支持按类型筛选。
- 动态参数：密钥、IV、自定义字母表、AES 模式、填充方式等按算法自动显示。
- 字节级无损往返：无法显示的输出可使用“复制 Hex”取出原始字节。
- JSFuck 默认禁止执行；界面必须显式确认风险，且有超时和输出大小限制。

### 文件分析

- 根据 magic bytes 识别 40 多种格式，校验弱签名并检测扩展名伪造。
- 支持前置垃圾数据、尾随数据、嵌套文件和编码特征检测。
- PNG/JPG/GIF/BMP/ZIP 结构解析；PNG 支持 Chunk、CRC 和尺寸修复。
- 可编辑 Hex：搜索高亮、精确字节复制、撤销/重做、覆盖保存和另存副本。
- 字符串、熵图、MD5/SHA1/SHA256/CRC32。
- 大文件分析在工作线程执行；界面先展示文件，再逐步填充哈希、字符串和结构结果。
- Hex 搜索限制最大命中数量，并使用区间高亮，避免高频单字符搜索耗尽内存。

### 图片隐写

- LSB 位平面、位序、多通道、起始像素、步长和最大长度。
- LSB 行扫描，`FLAG{...}`、`CTF{...}`、`KEY{...}` 不区分大小写并优先高亮。
- 原始索引色和 16-bit 像素处理，JPEG 有损提示。
- PNG Chunk、CRC 修复、IDAT 宽高候选修复、EXIF、GIF 逐帧浏览。
- StegSolve Data Extract、Image Combiner、Stereogram 和 Random Color Map。
- GIF 帧缓存有内存预算，避免大尺寸多帧文件无限占用内存。

### 音频 LSB

- WAV 元信息、通道、bit、位序和最大提取长度。
- 提取结果支持文本自动识别、Flag 高亮和二进制保存。

### ZIP 分析与密码恢复

- 支持带前置垃圾数据的 ZIP，条目、注释、伪加密检测和修复均使用正确偏移。
- ZipCrypto 字典、暴力和掩码恢复；显示进度、速度、ETA、停止和密码复制。
- 掩码中的每个裸 `?` 都使用多选下拉菜单中的字符集：小写字母、大写字母、数字、大写 HEX、小写 HEX、特殊符号。
- 选择“所有可打印字符”时会自动取消其他选项，不允许与其他字符集同时选择。
- 已移除 `?l ?u ?d ?H ?h ?s ?a` 固定掩码写法；只保留裸 `?` 多选菜单，`\?` 表示字面问号。
- **CRC32 反查 / CRC 爆破**：针对极小 ZipCrypto 条目（ZIP ≤ 1 MiB、明文 ≤ 6 字节、候选 ≤ 65,536），用存储的 CRC32 反推出明文。只读分析，不修改原 ZIP。
- **已知明文攻击 (KPA)**：调用随包发布的 `bkcrack.exe`，支持存储 / Deflate 条目、明文文件或 HEX、偏移、额外已知字节（`-x`）、Deflate 自动压缩，以及用恢复出的密钥解密当前条目、移除密码或修改密码另存。
- 解压前检查条目数、总大小、单文件大小和压缩比；高风险压缩包默认取消。
- 解压工作线程继续执行硬上限和逐块写入检查，防止伪造的 ZIP 大小字段绕过限制。
- 越界路径会被拒绝，不会将文件写到目标目录之外。

#### CRC 爆破的安全边界

- 只接受 **≤ 1 MiB** 的 ZIP、条目数 ≤ 256、明文长度 **0~6 字节**，且必须是已加密、非 AES、非伪加密的存储 / Deflate 条目。
- 枚举空间上限 65,536；超过上限直接拒绝，不会无限占用 CPU。
- 反查过程在后台线程运行，可停止；不会执行或解压反查结果。
- 结果只表示“CRC32 与长度都匹配的候选明文”。CRC32 只有 32 位，条目越小越可能唯一；用于 bkcrack 时仍需至少 8 字节连续明文和总计 12 字节已知字节。

#### bkcrack KPA 说明

- 可执行文件：`bin/bkcrack.exe`（开发目录）→ 打包后位于 `_internal/bin/bkcrack.exe`。
- 固定版本：**bkcrack 1.8.1 (win64)**，SHA-256 `d3de2e1494c8db2a1550794cae4923956d76da9314e68198096f4b03f7f310d5`。
- CTFusion 不实现 Biham-Kocher 攻击算法；只按偏移取出密文、构造 bkcrack 可读的临时单条目 ZIP、以固定参数调用子进程并解析 `Keys`。
- 不使用 shell，不拼接用户命令；条目名不会进入命令行。所有临时文件在结束后删除。
- 带前置垃圾数据的 ZIP 也能攻击：CTFusion 用本地头偏移提取密文并重建临时 ZIP，绕开 bkcrack 对非标准偏移的限制。
- Deflate 条目的已知明文必须是**压缩后的字节**；如果提供的是原始文件内容，请勾选“先按 Deflate 压缩”。压缩级别必须与原 ZIP 一致才可能匹配。

### JWT 与代码格式化

- JWT Header/Payload/Signature 解析，HS256/384/512、`none` 和 RS256 生成/验证。
- 严格校验 Base64URL 和 JSON 类型；Header、Payload 必须是 JSON 对象。
- 支持 JSON、Python、JavaScript、HTML、CSS、C、C++、Java、PHP 格式化。

## 界面与文件管理

- 主窗口包含 7 个功能页签和顶部多文件栏。
- 文件分析、图片、音频和 ZIP 页面中的“打开文件”统一进入顶部文件栏。
- 另存为或修复伪加密后，文件栏路径会同步更新。
- 关闭最后一个文件页签时，会清空各分析页面的旧文件状态。
- 切换文件时，不兼容的图片、音频和 ZIP 页面会被清空。

## 安装与运行

要求 Python 3.9+。

```powershell
pip install -r requirements.txt
python main.py
```

源码运行时，KPA 会查找 `bin/bkcrack.exe`；该文件已随项目提供，无需额外安装。若缺失，界面会显示明确提示。

运行测试：

```powershell
python -m unittest discover -s tests -v
```

测试中的 bkcrack 集成用例需要 `bin/bkcrack.exe`；缺失时会自动跳过。

## 打包 EXE

安装构建依赖：

```powershell
pip install -r requirements.txt -r requirements-build.txt
```

执行：

```powershell
.\build_exe.ps1
```

如果 PowerShell 禁止脚本：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\build_exe.ps1
```

输出：

```text
dist\CTFusion v2.2\CTFusion v2.2.exe
dist\CTFusion v2.2\_internal\
dist\CTFusion v2.2\_internal\bin\bkcrack.exe
```

这是 PySide6/PyInstaller **onedir** 版本。分发时必须保留整个 `dist\CTFusion v2.2` 目录，不能只复制 EXE。构建脚本会检查 `bin\bkcrack.exe` 是否存在，并用 `--self-test` 验证打包后的 bkcrack 与 CRC 反查。

## 项目结构

```text
CTFusion/
├── main.py
├── assets/
│   ├── CTFusion.ico
│   ├── CTFusion.png
│   └── CTFusion-logo-source.png
├── bin/
│   ├── bkcrack.exe              # 第三方程序,打包后位于 _internal/bin
│   ├── bkcrack-license.txt      # 原作者 zlib 许可证
│   ├── bkcrack-readme.md        # 原作者说明
│   └── bkcrack-version.txt      # 版本 / 来源 / SHA-256
├── core/
│   ├── codecs/
│   ├── analysis.py
│   ├── bkcrack.py               # bkcrack KPA 子进程封装
│   ├── chain.py
│   ├── fileparse.py
│   ├── filetype.py
│   ├── jwt_tool.py
│   ├── sensitive.py
│   ├── lsb.py
│   └── zipcrack.py              # ZIP 结构 / ZipCrypto / CRC32 反查
├── ui/
│   ├── main_window.py
│   ├── decoder_panel.py
│   ├── file_panel.py
│   ├── image_panel.py
│   ├── audio_panel.py
│   ├── zip_panel.py
│   ├── zip_attack_panels.py     # CRC 爆破 / KPA 页签
│   └── hex_viewer.py
├── tests/
├── packaging/
├── build_exe.ps1
├── requirements.txt
└── requirements-build.txt
```

## 安全说明

- JSFuck 会在本机 Node.js 中执行输入代码。只处理可信来源，并在界面中确认后再运行。
- ZIP 解压会执行多层资源限制。用户确认高风险压缩包后，仍受工作线程硬上限保护。
- CRC 爆破有 1 MiB ZIP、6 字节明文、65,536 候选和后台线程限制；只做只读计算。
- KPA 只调用随包发布的 `bkcrack.exe`，使用固定参数和子进程参数数组，不经过 shell；条目名不进入命令行；临时目录结束后删除。
- 运行 KPA 前会检查 bkcrack 是否存在、大小是否正常，并记录 SHA-256；版本不符时仅提示，不下载、不联网。
- 本工具不会联网；除 JSFuck 调用的本机 Node.js 和本地 bkcrack.exe 外，所有分析均在本地完成。

## 已知限制

- ZIP 密码恢复 / CRC 反查 / KPA 只支持 ZipCrypto，不支持 AES/WinZip、RAR 或 7z。
- CRC 反查只适用于极小条目（≤ 6 字节）；更大的条目请使用字典、掩码或 bkcrack。
- Deflate 条目的 bkcrack 已知明文必须是压缩后的字节，且压缩级别 / 压缩器需与原 ZIP 一致；CTFusion 提供按 1~9 级重新压缩的辅助，但不能保证匹配所有压缩器。
- bkcrack 可能被部分杀毒软件误报为黑客工具；这是第三方程序的常见误报，请在可信环境中使用。
- 带前置垃圾数据的 ZIP 可以攻击单条目；`移除密码另存` / `修改密码另存` 依赖 bkcrack 对整包的重建，非标准偏移可能失败，此时请使用“解密当前条目”。
- EXIF 覆盖常用标签，不包含完整厂商私有标签、XMP 和 ICC。
- Stereogram 是简化实现，复杂立体图建议使用 StegSolve。
- 工具不内置 PCAP 深度分析、PDF/Office 引擎、OCR 或二维码解码。

## 第三方组件与致谢

### bkcrack

- 项目：[kimci86/bkcrack](https://github.com/kimci86/bkcrack)
- 版本：1.8.1 (win64)
- 作者：kimci86 及贡献者
- 许可证：zlib/png license，全文见 `bin/bkcrack-license.txt`
- 用途：ZipCrypto 已知明文攻击（KPA）

CTFusion 对 bkcrack 只做**二次封装**：准备密文 / 明文、构造临时 ZIP、通过 `subprocess` 启动 `bkcrack.exe`、解析输出并展示结果。攻击算法、密钥恢复和 ZIP 重写均由 bkcrack 完成，版权归原作者所有。请在使用和再分发时保留 `bin/bkcrack-license.txt` 与 `bin/bkcrack-readme.md`。

## Logo

当前版本使用 `assets/CTFusion-logo-source.png`（轨道聚合方案）。应用运行时图标为 `assets/CTFusion.png`，Windows 多尺寸图标为 `assets/CTFusion.ico`。
