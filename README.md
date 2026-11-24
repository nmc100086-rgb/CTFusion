# CTFusion v2.3.1

CTFusion 是一个基于 PySide6 的本地 CTF 综合工具箱，覆盖编码解码、文件分析、图片与音频分析、ZIP 密码恢复 / CRC32 反查 / bkcrack 已知明文攻击、二维码识别、乱码修复、Base64/Hex 文件互转、JWT 和代码格式化。除可选的 GitHub 更新检查外，所有分析都在本地完成，不依赖在线服务。

> **v2.3**：文件属性页会读取 Windows 属性系统的全部元数据（说明、来源、图像、照相机、高级照片、GPS、音频、视频等）；保存失败会写入本地日志；提供「帮助 → 保存权限自检…」和「设置 → 以管理员身份重新启动」，并附带 `以管理员身份运行.cmd`。
>
> v2.3 新增 **多语言界面**（简体中文、英语、日语、韩语、西班牙语、法语、德语、俄语、葡萄牙语、阿拉伯语）、**左侧分组导航**、**GitHub 更新检查**、**二维码 / 条码扫描（结果可复制）**、**乱码自动修复与编码转换**、**Base64 / Hex 与图片、ZIP 等文件互转**、**文件属性查看**。界面中的第三方工具名称已改为通用功能名称；更新检查从 v2.3 起启用，只提示新版本并打开 GitHub，不自动下载。
>
> v2.2 ZIP 页签新增 **CRC 爆破** 与 **已知明文攻击 (KPA)**。KPA 是对 [kimci86/bkcrack](https://github.com/kimci86/bkcrack) 的二次封装，攻击算法由原作者实现，CTFusion 只负责准备数据、启动进程和展示结果。

## 主要功能

### 编码解码

- 35 种算法：Base 家族、古典密码、哈希、AES/RC4、文本编码、趣味编码、进制转换和零宽字符。
- 多层智能解码：BFS 链式尝试、启发式剪枝、凯撒最优分支和结果评分。
- 智能结果分类：可识别 Flag、路径、凭据、疑似密码、URL、邮箱、哈希和普通文本，并支持按类型筛选。
- 动态参数：密钥、IV、自定义字母表、AES 模式、填充方式等按算法自动显示。
- 字节级无损往返：无法显示的输出可使用“复制 Hex”取出原始字节。
- JSFuck 默认禁止执行；界面必须显式确认风险，且有超时和输出大小限制。

### 杂项工具（二维码 / 乱码 / Base64·Hex 文件）

- **二维码 / 条码扫描**：基于 zxing-cpp，支持二维码、Micro QR、Data Matrix、Aztec、PDF417 和常见一维条码；可从文件、剪贴板或拖放读取图片。
- 一张图片可包含多个条码，结果表格显示格式、内容预览、纠错级别和方向；选中后可复制文本、复制原始字节 Hex，或一次复制全部结果。
- **乱码修复**：自动枚举 UTF-8 / GB18030 / GBK / Big5 / Latin-1 / CP1252 的错误解释组合，按可读性和中文常用字比例排序，双击候选填入结果。
- 支持双层乱码（如 `Ã¤Â½...`）、GBK 被当 Latin-1、UTF-8 被当 GBK 等常见 CTF 场景；也支持手动“源编码 → 目标编码”转换和 Hex 字节输入。
- QPlainTextEdit 会吞掉 U+00A0，本页使用 `QTextDocument.toRawText()` 保留原始字节，避免 UTF-8 被 Latin-1 解释后的乱码在输入阶段再次损坏。
- **Base64 / Hex → 文件**：自动识别 Base64、Data URI、URL-safe Base64，以及带 `0x` / 空格 / 逗号分隔的 Hex；识别真实文件头后给出建议扩展名。
- Base64 图片会直接预览；ZIP 等二进制可保存为文件，或“保存并分析”直接送进对应页签。十六进制转 ZIP 即“Hex → 文件 → 保存为 .zip”。
- **文件 → Base64 / Hex**：任意文件转连续 Base64 或 Hex 文本，可复制或保存。
- 解码输入和输出都有大小上限，避免误贴超大内容导致界面卡死。

### 文件分析

- 根据 magic bytes 识别 40 多种格式，校验弱签名并检测扩展名伪造。
- 支持前置垃圾数据、尾随数据、嵌套文件和编码特征检测。
- PNG/JPG/GIF/BMP/ZIP 结构解析；PNG 支持 Chunk、CRC 和尺寸修复。
- 可编辑 Hex：搜索高亮、鼠标拖选字节、Ctrl+C / 右键复制（Hex 列复制 HEX，ASCII 列复制 ASCII 文本）、撤销/重做、覆盖保存和另存副本。
- 字符串、熵图、MD5/SHA1/SHA256/CRC32。
- **文件属性**页签：完整路径、真实路径、大小、创建/修改/访问时间（本地与 UTC）、Windows 只读/隐藏/系统/归档等属性、可读可写状态、MIME、真实类型和哈希；支持一键复制全部属性。
- 同时通过 Windows 属性系统读取资源管理器「详细信息」里的全部元数据，按 **文件 / 说明 / 来源 / 图像 / 照相机 / 高级照片 / GPS / 音频 / 视频 / 音乐 / 文档 / 其他** 分组显示：标题、主题、分级、标记、备注、作者、拍摄日期、程序名称、获取日期、版权、图像尺寸与分辨率、位深度、相机型号、光圈、曝光时间、ISO、焦距、35mm 焦距、镜头、闪光灯、Exif 版本等；属性只依赖系统属性处理程序，不做额外联网或写入。
- 菜单「文件 → 查看文件属性…」（`Alt+Enter`）可直接跳到当前文件的属性页。
- 大文件分析在工作线程执行；界面先展示文件，再逐步填充哈希、字符串和结构结果。
- Hex 搜索限制最大命中数量，并使用区间高亮，避免高频单字符搜索耗尽内存。

### 图片隐写

- LSB 位平面、位序、多通道、起始像素、步长和最大长度。
- LSB 行扫描，`FLAG{...}`、`CTF{...}`、`KEY{...}` 不区分大小写并优先高亮。
- 原始索引色和 16-bit 像素处理，JPEG 有损提示。
- PNG 数据块、CRC 修复、IDAT 宽高候选修复、EXIF、GIF 逐帧浏览。
- 扩展分析：数据提取、图像合成、立体图和随机颜色映射。
- 图片页右上角「识别二维码」会把当前图片直接送到实用工具，不必重新选文件。
- 图片页的「通道 / 直方图」只保留通道预览、反色和直方图；异或、相加、相减、按位与、按位或、取小、取大和差分统一到「扩展分析 → 图像合成」，避免重复入口。
- GIF 帧缓存有内存预算，避免大尺寸多帧文件无限占用内存。

### 音频 LSB

- WAV 元信息、通道、bit、位序和最大提取长度。
- 提取结果支持文本自动识别、Flag 高亮和二进制保存。

### ZIP 分析与密码恢复

- 支持带前置垃圾数据的 ZIP，条目、注释、伪加密检测和修复均使用正确偏移。
- 支持部分压缩工具常见的 bit 3 / data descriptor 流式 ZIP：密码恢复按 DOS 时间高字节校验；KPA 会保留 bit 3、DOS 时间和本地头零大小，保证 bkcrack 使用与原包一致的校验字节。
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

## 多语言与更新检查

- 支持 10 种界面语言：简体中文、英语、日语、韩语、西班牙语、法语、德语、俄语、葡萄牙语、阿拉伯语。
- 可在左侧导航底部或「设置 → 语言」中切换；切换会立即应用到已打开界面，并保存选择。
- 中文界面尽量使用中文功能名称；旧版界面中的第三方工具名已移除或改为通用功能名。`Base64`、`Hex`、`CRC`、`JWT`、`IHDR`、`IDAT` 等技术表示保留。
- 阿拉伯语界面自动使用从右到左布局。
- 更新检查从 **v2.3** 起启用；v2.3 之前的版本不会请求更新接口。
- 启动后最多每 24 小时自动检查一次 GitHub 最新版本；也可以在「设置 → 检查更新…」手动检查。
- 发现新版本时提示：`发现新版本，请到github官网更新，https://github.com/nmc100086-rgb/CTFusion`，并提供「打开 GitHub」按钮；不会自动下载或替换当前程序。
- 更新检查只读取 GitHub 的公开 release / tag 信息；网络失败时自动检查保持静默，手动检查会给出错误提示。

## 界面与文件管理

- 主窗口使用 **左侧分组导航**：文本处理、文件与压缩包、图像与音频、识别与转换。
- 侧边栏可收起/展开（`Ctrl+B`），收起后内容区自动扩展，适合小屏幕或专注查看结果。
- 顶部「☰」按钮、菜单「视图 → 显示侧边栏」都可以控制侧边栏。
- `Ctrl+F` 打开当前页面查找栏，支持文本框、表格和树形结果；继续按 Enter 或「下一个」循环查找。
- 查找不到时显示友好提示，并提示换关键词或切换到包含文本的页签；空页面会提示先打开文件。
- 文件分析页的 Hex 区域获得焦点时，`Ctrl+F` 会优先聚焦 Hex 查看器自带的搜索框。
- 主窗口包含 8 个功能页面和顶部多文件栏。
- 文件分析、图片、音频和 ZIP 页面中的“打开文件”统一进入顶部文件栏。
- 另存为或修复伪加密后，文件栏路径会同步更新。
- 关闭最后一个文件页签时，会清空各分析页面的旧文件状态。
- 切换文件时，不兼容的图片、音频和 ZIP 页面会被清空。
- 对空输入、空结果、未载入文件、复制空内容、保存失败等常见操作补充了状态提示；查找无结果、乱码无候选、二维码无识别结果都会给出下一步建议。

## 安装与运行

要求 Python 3.9+。二维码识别需要 Pillow 与 zxing-cpp（已在 `requirements.txt` 中）。

```powershell
pip install -r requirements.txt
python main.py
```

源码运行时，KPA 会查找 `bin/bkcrack.exe`；该文件已随项目提供，无需额外安装。若缺失，界面会显示明确提示。

> 建议把打包后的整个 `CTFusion v2.3.1` 文件夹放在普通目录（例如 `D:\CTFusion`、桌面）再运行。放在受限的工程/沙箱目录里时，系统或安全软件可能只允许它写该目录，导致保存需要管理员权限。

### 第一次运行（只提示一次）

- 第一次启动会显示一次「首次运行提示」，说明保存规则和 Windows 拦截的处理方式；之后不再出现。
- 如果 Windows 弹出 **「Windows 已保护你的电脑」/「仍要运行」**（未签名程序的 SmartScreen 提示），点 **「更多信息」→「仍要运行」** 即可。同一个 exe 只会被拦截一次；如果每次重新下载/解压都被拦，先右键下载的 zip → 属性 → 勾选「解除锁定」，或运行压缩包里的 `首次运行-解除Windows拦截.cmd`（先 `Unblock-File` 再启动程序）。
- 保存到 `D:\`、`C:\` 根目录或 `Program Files` 等受保护位置时，Windows 可能拒绝普通写入；程序会自动以管理员身份再写一次（UAC 确认一次），保存按钮文字不变。
- 如果仍然保存失败：
  - 「帮助 → 保存权限自检…」会依次在桌面、文档、图片、下载、程序目录和临时目录各写一个临时文件，直接显示哪个位置失败、错误码是什么；
  - 「帮助 → 打开保存日志」可查看 `%LOCALAPPDATA%\CTFusion\save.log`，里面记录了每次失败的目标路径、错误码和提权结果；
  - 360、电脑管家、火绒等安全软件的「文档保护」会拦截未签名程序：请把 `CTFusion v2.3.1.exe` 加入它们的信任区 / 白名单，之后**普通权限即可保存，不需要管理员**；
  - 需要写入盘根或受保护目录时，程序会自动提权（默认开启）；不想弹 UAC 可在「设置 → 保存时请求管理员权限」关闭，关闭后改为保存到用户目录。
- **拖拽只在普通权限下可用**：Windows 不允许普通权限的资源管理器把文件拖进管理员窗口（UIPI 限制，代码无法绕过）。管理员模式下请用「文件 → 打开文件…」、顶部「+」按钮，或「文件 → 从剪贴板打开文件」（资源管理器里 `Ctrl+C` 复制，程序里 `Ctrl+Shift+V` 打开）。
- 保存日志只记录路径、错误码和权限状态，不记录文件内容。

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
dist\CTFusion v2.3.1\CTFusion v2.3.1.exe
dist\CTFusion v2.3.1\_internal\
dist\CTFusion v2.3.1\_internal\bin\bkcrack.exe
```

这是 PySide6/PyInstaller **onedir** 版本。分发时必须保留整个 `dist\CTFusion v2.3.1` 目录，不能只复制 EXE。构建脚本会检查 `bin\bkcrack.exe` 是否存在，并用 `--self-test` 验证打包后的 bkcrack、CRC 反查、Hex→ZIP、乱码修复、二维码识别和更新检查基础逻辑；同时在输出目录生成 `首次运行-解除Windows拦截.cmd`（第一次运行解除“下载文件”标记并启动）和 `以管理员身份运行.cmd`（以完整权限启动，便于写入受保护位置）。

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
│   ├── bkcrack-version.txt      # 版本 / 来源 / SHA-256
│   ├── zxingcpp-license.txt     # zxing-cpp Apache-2.0
│   ├── zxingcpp-version.txt
│   ├── Pillow-license.txt       # Pillow HPND
│   └── Pillow-version.txt
├── core/
│   ├── codecs/
│   ├── analysis.py
│   ├── bkcrack.py               # bkcrack KPA 子进程封装
│   ├── chain.py
│   ├── datatools.py             # Base64 / Hex <-> 文件
│   ├── fileprops.py             # 文件属性
│   ├── fileparse.py
│   ├── filetype.py
│   ├── jwt_tool.py
│   ├── mojibake.py              # 乱码检测 / 修复 / 编码转换
│   ├── qrcode.py                # zxing-cpp 二维码封装
│   ├── sensitive.py
│   ├── lsb.py
│   ├── updater.py               # GitHub 版本检查
│   ├── version.py               # 版本号 / 更新起始版本
│   └── zipcrack.py              # ZIP 结构 / ZipCrypto / CRC32 反查
├── ui/
│   ├── main_window.py
│   ├── decoder_panel.py
│   ├── file_panel.py
│   ├── image_panel.py
│   ├── image_analysis_panel.py  # 数据提取 / 图像合成 / 立体图 / 颜色映射
│   ├── audio_panel.py
│   ├── misc_panel.py            # 二维码 / 乱码 / Base64·Hex 文件
│   ├── i18n.py                  # 多语言界面
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
- 二维码识别在本地完成，不调用在线 API；图片最多解码 1.2 亿像素，图片文件上限 128 MB。
- Base64/Hex 解码上限 128 MB；保存前先识别 magic，不会自动执行解码出的文件。
- 保存位置由用户决定：解码结果、LSB 提取数据、图片/PNG/ZIP 修复结果、内嵌文件等都可以保存到任意可选位置。
- 写入被拒绝时（受保护目录或安全软件拦截），程序会自动以管理员身份再写一次；提权进程只写用户选定的文件，写完立即退出。
- 不需要提权时可在「设置 → 保存时请求管理员权限」关闭；关闭后遇到拒绝会改存到用户目录，并在状态栏和「已保存」提示里给出实际路径。
- 「设置 → 以管理员身份重新启动」和发布包里的 `以管理员身份运行.cmd` 仍然保留，供需要完整权限时手动使用。
- 程序不会在后台静默写入用户没有选择的路径，不会修改系统 ACL，也不会常驻管理员权限；提权进程写完一个（批）文件后立即退出。
- 乱码修复只是枚举候选并按可读性排序，不会执行文本；若字节已经被替换字符（`�`）覆盖，原始内容无法恢复。
- 更新检查只向 GitHub 公开 API 读取 release / tag 信息，不发送文件、路径或分析内容；不自动下载，也不会执行远端文件。
- 除更新检查、JSFuck 调用的本机 Node.js 和本地 bkcrack.exe 外，所有分析均在本地完成。

## 已知限制

- ZIP 密码恢复 / CRC 反查 / KPA 只支持 ZipCrypto，不支持 AES、RAR 或 7z。
- CRC 反查只适用于极小条目（≤ 6 字节）；更大的条目请使用字典、掩码或 bkcrack。
- Deflate 条目的 bkcrack 已知明文必须是压缩后的字节，且压缩级别 / 压缩器需与原 ZIP 一致；CTFusion 提供按 1~9 级重新压缩的辅助，但不能保证匹配所有压缩器。
- bkcrack 可能被部分杀毒软件误报为黑客工具；这是第三方程序的常见误报，请在可信环境中使用。
- 带前置垃圾数据的 ZIP 可以攻击单条目；`移除密码另存` / `修改密码另存` 依赖 bkcrack 对整包的重建，非标准偏移可能失败，此时请使用“解密当前条目”。
- EXIF 覆盖常用标签，不包含完整厂商私有标签、XMP 和 ICC。
- 立体图解析是简化实现，复杂立体图可尝试调整偏移范围。
- 二维码 / 条码识别依赖 zxing-cpp；极端低分辨率、强透视或大面积遮挡的码可能无法识别。
- 乱码修复提供候选排序，不保证百分之百还原；如果原文已经写入 `�` 或经过有损转换，缺失字节无法凭空恢复。
- 工具不内置 PCAP 深度分析、PDF/Office 引擎或 OCR。

## 第三方组件与致谢

### zxing-cpp

- 项目：[zxing-cpp/zxing-cpp](https://github.com/zxing-cpp/zxing-cpp)
- Python 包：`zxing-cpp 3.0.0`
- 许可证：Apache License 2.0，全文见 `bin/zxingcpp-license.txt`
- 用途：二维码、Micro QR、Data Matrix、Aztec、PDF417 和常见一维条码识别

CTFusion 只负责读取图片、调用 zxing-cpp 并展示结果；条码检测与解码算法由 zxing-cpp 完成。

### Pillow

- 项目：[python-pillow/Pillow](https://github.com/python-pillow/Pillow)
- 版本：`12.1.0`
- 许可证：HPND，全文见 `bin/Pillow-license.txt`
- 用途：二维码扫描前的图片解码与尺寸检查

### bkcrack

- 项目：[kimci86/bkcrack](https://github.com/kimci86/bkcrack)
- 版本：1.8.1 (win64)
- 作者：kimci86 及贡献者
- 许可证：zlib/png license，全文见 `bin/bkcrack-license.txt`
- 用途：ZipCrypto 已知明文攻击（KPA）

CTFusion 对 bkcrack 只做**二次封装**：准备密文 / 明文、构造临时 ZIP、通过 `subprocess` 启动 `bkcrack.exe`、解析输出并展示结果。攻击算法、密钥恢复和 ZIP 重写均由 bkcrack 完成，版权归原作者所有。请在使用和再分发时保留 `bin/bkcrack-license.txt` 与 `bin/bkcrack-readme.md`。

## Logo

当前版本使用 `assets/CTFusion-logo-source.png`（轨道聚合方案）。应用运行时图标为 `assets/CTFusion.png`，Windows 多尺寸图标为 `assets/CTFusion.ico`。
