"""界面多语言支持。

中文是源语言；其他语言通过“原文 -> 译文”的映射在运行时替换控件文本。
为了让几十个现有面板不用逐个改写，本模块在导入时包装 Qt 的常见文本
设置方法（QLabel/QPushButton/QTabWidget/QComboBox/表头/菜单等）。
映射表只按完整字符串匹配，不会误改文件名、哈希、路径等用户数据。

支持语言：简体中文、英语、日语、韩语、西班牙语、法语、德语、俄语、
葡萄牙语、阿拉伯语。非英语语言缺失的条目回退到英语；技术缩写
（Base64、Hex、AES、CRC、JWT、bkcrack 等）保持原样。
"""

from __future__ import annotations

from PySide6.QtCore import QSettings, Qt
from PySide6.QtWidgets import (
    QAbstractButton,
    QApplication,
    QComboBox,
    QGroupBox,
    QLabel,
    QLineEdit,
    QListWidget,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QTabWidget,
    QTableWidget,
    QTextEdit,
    QTreeWidget,
    QWidget,
)
from PySide6.QtGui import QAction

LANGUAGES: tuple[tuple[str, str], ...] = (
    ("zh_CN", "简体中文"),
    ("en", "英语"),
    ("ja", "日语"),
    ("ko", "韩语"),
    ("es", "西班牙语"),
    ("fr", "法语"),
    ("de", "德语"),
    ("ru", "俄语"),
    ("pt", "葡萄牙语"),
    ("ar", "阿拉伯语"),
)

_LANGUAGE_LABELS = dict(LANGUAGES)
_SETTINGS_KEY = "ui/language"
_current = "zh_CN"
_TRANSLATING = False


_EN: dict[str, str] = {
    # 语言名称
    "简体中文": "Simplified Chinese",
    "英语": "English",
    "日语": "Japanese",
    "韩语": "Korean",
    "西班牙语": "Spanish",
    "法语": "French",
    "德语": "German",
    "俄语": "Russian",
    "葡萄牙语": "Portuguese",
    "阿拉伯语": "Arabic",
    # 导航 / 主界面
    "无法保存文件": "Cannot Save File",
    "当前用户没有写入这个位置的权限。":
        "The current user does not have write permission for this location.",
    "目标位置：\n{path}\n\n"
    "请选择「图片」「下载」「文档」或桌面等用户目录。\n"
    "程序不会绕过 Windows 权限，也不会请求管理员权限。\n\n"
    "原始错误：{error}":
        "Target location:\n{path}\n\n"
        "Choose a user folder such as Pictures, Downloads, Documents or Desktop.\n"
        "The app will not bypass Windows permissions or request administrator rights.\n\n"
        "Original error: {error}",
    "图片": "Pictures",
    "下载": "Downloads",
    "文档": "Documents",
    "保存到{folder}文件夹": "Save to {folder}",
    "选择其他位置…": "Choose Another Location…",
    "保存到用户文件夹仍然失败：\n{error}\n\n"
    "请检查磁盘空间或文件夹权限。":
        "Saving to the user folder also failed:\n{error}\n\n"
        "Check free disk space or folder permissions.",
    "无法写入文件：\n{error}\n\n"
    "请检查磁盘空间、目标文件夹是否存在，或换一个用户目录。":
        "Cannot write the file:\n{error}\n\n"
        "Check free disk space, whether the target folder exists, "
        "or choose a user folder.",
    "保存未完成：已取消，或目标文件夹不可写。"
    "请选择图片/下载/文档等用户目录。":
        "Save was not completed: it was cancelled, or the target folder "
        "is not writable. Choose a user folder such as Pictures, Downloads "
        "or Documents.",
    # 保存权限（v2.3：任意位置 + 按需提权）
    "Windows 拒绝写入这个位置。":
        "Windows refused to write to this location.",
    "可以让程序请求一次管理员权限，只写入这个文件；\n"
    "也可以改存到「{folder}」等用户文件夹。":
        "The app can request administrator rights once to write only this "
        "file, or you can save it into a user folder such as “{folder}”.",
    "可以让程序请求一次管理员权限，只写入这个文件。":
        "The app can request administrator rights once to write only this file.",
    "目标位置：\n{path}\n\n{hint}\n\n原始错误：{error}":
        "Target location:\n{path}\n\n{hint}\n\nOriginal error: {error}",
    "以管理员身份保存": "Save as Administrator",
    "记住我的选择，不再询问": "Remember my choice and do not ask again",
    "管理员写入未完成：\n{error}":
        "The administrator write did not complete:\n{error}",
    "这个位置不能直接写入，请改用「另存为…」选择其他位置。":
        "This location cannot be written directly. Use “Save As…” to choose "
        "another location.",
    "无法写入文件：\n{error}\n\n"
    "请检查磁盘空间、目标文件名是否合法，或换一个位置再试。":
        "Cannot write the file:\n{error}\n\n"
        "Check free disk space, whether the target file name is valid, or "
        "choose another location.",
    "首次运行提示": "First Run Notice",
    "这个提示只显示一次，之后不再出现。":
        "This notice is shown only once.",
    "1. 保存文件时会直接写入你选择的位置，包括其他磁盘、磁盘根目录和"
    "程序所在目录；只有 Windows 拒绝写入时，才会请求一次管理员权限。\n"
    "2. 如果 Windows 弹出「Windows 已保护你的电脑」，点「更多信息」→"
    "「仍要运行」即可，之后运行同一个程序不会再拦截。\n"
    "3. 保存位置、权限选择和界面语言都会被记住，不会每次运行都询问。":
        "1. Files are saved exactly where you choose, including other drives, "
        "drive roots and the program folder. Administrator rights are only "
        "requested when Windows actually refuses the write.\n"
        "2. If Windows shows “Windows protected your PC”, click “More info” → "
        "“Run anyway”; the same program will not be blocked again.\n"
        "3. The save location, permission choice and interface language are "
        "remembered, so you are not asked on every run.",
    "知道了": "Got it",
    "保存未完成：已取消，或目标位置不能写入。可以换一个位置重试。":
        "Save was not completed: it was cancelled, or the location cannot be "
        "written. Try another location.",
    # 保存诊断 / 管理员模式（v2.3.1）
    "保存权限自检": "Save Permission Check",
    "保存权限自检…": "Save Permission Check…",
    "打开保存日志": "Open Save Log",
    "以管理员身份重新启动": "Restart as Administrator",
    "以管理员权限重新打开程序，可写入任何 Windows 允许的位置":
        "Reopen the app with administrator rights to write anywhere Windows "
        "allows.",
    "检查桌面/文档/图片/下载/程序目录能否正常写入":
        "Check whether Desktop, Documents, Pictures, Downloads and the program "
        "folder are writable.",
    "有 {count} 个位置无法写入。":
        "{count} locations cannot be written.",
    "常见原因：安全软件的文档保护（360、电脑管家、火绒等）、"
    "Windows 受控文件夹访问，或该目录的 NTFS 权限。\n"
    "请按安全软件弹窗选择「允许」，或把本程序加入信任区；"
    "也可以使用「设置 → 以管理员身份重新启动」后再试。":
        "Common causes: document protection in security software (360, PC "
        "Manager, Huorong), Windows Controlled Folder Access, or NTFS "
        "permissions on that folder.\nAllow the app in the security software "
        "popup or add it to the trust list; you can also try “Settings → "
        "Restart as Administrator”.",
    "常见保存位置都可以正常写入。":
        "All common save locations are writable.",
    "如果某个位置仍然保存失败，请把「帮助 → 打开保存日志」里的内容"
    "发给我们。":
        "If a location still fails, send us the content from “Help → Open "
        "Save Log”.",
    "保存日志：": "Save log: ",
    "当前已经是管理员权限，可以直接保存到任何位置。":
        "Already running as administrator; you can save anywhere.",
    "无法以管理员身份重新启动：\n{error}":
        "Cannot restart as administrator:\n{error}",
    "目标位置：\n{path}\n\n{hint}\n\n"
    "如果是 360、电脑管家、火绒等安全软件拦截，"
    "请在它们的弹窗里选择「允许」，或把本程序加入信任区。\n\n"
    "原始错误：{error}\n保存日志：{log}":
        "Target location:\n{path}\n\n{hint}\n\n"
        "If security software such as 360, PC Manager or Huorong blocks the "
        "write, choose “Allow” in its popup or add this app to its trust "
        "list.\n\nOriginal error: {error}\nSave log: {log}",
    "保存到用户文件夹仍然失败：\n{error}\n\n"
    "请检查磁盘空间或文件夹权限。\n\n"
    "保存日志：{log}":
        "Saving to the user folder also failed:\n{error}\n\n"
        "Check free disk space or folder permissions.\n\nSave log: {log}",
    "无法写入文件：\n{error}\n\n"
    "请检查磁盘空间、目标文件名是否合法，"
    "或换一个位置再试。\n\n保存日志：{log}":
        "Cannot write the file:\n{error}\n\n"
        "Check free disk space, whether the target file name is valid, or "
        "choose another location.\n\nSave log: {log}",
    "工具导航": "Tools",
    "视图": "View",
    "显示侧边栏": "Show sidebar",
    "查找当前页面": "Find in Current Page",
    "查找:": "Find:",
    "在当前页面查找（不区分大小写）":
        "Find in the current page (case-insensitive)",
    "收起/展开侧边栏（Ctrl+B）": "Collapse/expand sidebar (Ctrl+B)",
    "找到 {count} 个结果，当前 {index} / {count}":
        "Found {count} results, showing {index} / {count}",
    "没有找到“{query}”。可以试试：换一个关键词、检查拼写，"
    "或切换到包含文本的页签。":
        "No matches for “{query}”. Try another keyword, check the spelling, "
        "or switch to a tab that contains text.",
    "当前页面没有可搜索的文本内容。请先打开文件，"
    "或切换到文本/表格页签。":
        "There is no searchable text on this page. Open a file first, "
        "or switch to a text/table tab.",
    "文本处理": "Text",
    "文件与压缩包": "Files & Archives",
    "图像与音频": "Images & Audio",
    "识别与转换": "Recognition & Conversion",
    "文本编解码": "Text Codec",
    "JWT 解析": "JWT Parser",
    "代码格式化": "Code Formatter",
    "文件分析": "File Analysis",
    "压缩包分析": "Archive Analysis",
    "图像分析": "Image Analysis",
    "音频分析": "Audio Analysis",
    "实用工具": "Utilities",
    "文件": "File",
    "设置": "Settings",
    "帮助": "Help",
    "语言": "Language",
    "检查更新…": "Check for Updates…",
    "关于": "About",
    "打开一个或多个文件": "Open one or more files",
    "打开文件(可多选)": "Open Files",
    "打开文件…": "Open File…",
    "关闭当前文件": "Close Current File",
    "查看文件属性…": "File Properties…",
    "退出": "Exit",
    "发现新版本": "New Version Available",
    "发现新版本，请到github官网更新，https://github.com/nmc100086-rgb/CTFusion":
        "A new version is available. Please update from the official GitHub page: "
        "https://github.com/nmc100086-rgb/CTFusion",
    "当前版本": "Current version",
    "最新版本": "Latest version",
    "打开 GitHub": "Open GitHub",
    "稍后": "Later",
    "已是最新版本。": "You are using the latest version.",
    "检查更新失败：": "Update check failed:",
    "正在检查更新…": "Checking for updates…",
    "检查更新": "Check for Updates",
    "未知错误": "Unknown error",
    "提示": "Notice",
    "确定": "OK",
    "取消": "Cancel",
    "关闭": "Close",
    "保存": "Save",
    "保存…": "Save…",
    "保存文件…": "Save File…",
    "保存并分析": "Save and Analyze",
    "另存为…": "Save As…",
    "保存副本…": "Save Copy…",
    "打开": "Open",
    "复制": "Copy",
    "清空": "Clear",
    "刷新": "Refresh",
    "浏览…": "Browse…",
    "转换": "Convert",
    "开始": "Start",
    "停止": "Stop",
    "撤销": "Undo",
    "重做": "Redo",
    "上一个": "Previous",
    "下一个": "Next",
    "查找全部": "Find All",
    "全部": "All",
    "是": "Yes",
    "否": "No",
    "无": "None",
    "值": "Value",
    "类型": "Type",
    "结果": "Result",
    "说明": "Description",
    "格式": "Format",
    "名称": "Name",
    "属性": "Property",
    "路径": "Path",
    "大小": "Size",
    "偏移": "Offset",
    "长度": "Length",
    "内容": "Content",
    "评分": "Score",
    "方向": "Direction",
    "纠错": "EC level",
    "项目": "Item",
    "字段": "Field",
    "结构": "Structure",
    "检查项": "Check",
    "文件名": "File name",
    "方法": "Method",
    "加密": "Encrypted",
    "伪加密": "Pseudo-encrypted",
    "原始大小": "Original size",
    "压缩后": "Compressed",
    "存储 CRC": "Stored CRC",
    "实际 CRC": "Actual CRC",
    "内容预览": "Preview",
    "修复方式": "Repair method",
    "结果预览": "Result preview",
    "明文": "Plaintext",
    "数据块": "Chunk",
    "PNG 数据块": "PNG Chunks",
    "通道": "Channel",
    "位": "Bit",
    "位序": "Bit order",
    "输入": "Input",
    "输入:": "Input:",
    "输出:": "Output:",
    "输出": "Output",
    "模式:": "Mode:",
    "格式:": "Format:",
    "通道:": "Channel:",
    "位:": "Bit:",
    "位序:": "Bit order:",
    "帧:": "Frame:",
    "搜索:": "Search:",
    "跳转:": "Go to:",
    "最大长度:": "Max length:",
    "最小长度:": "Min length:",
    "最大偏移:": "Max offset:",
    "最小偏移:": "Min offset:",
    "起始像素:": "Start pixel:",
    "步长:": "Step:",
    "最多字节:": "Max bytes:",
    "每行最多字节:": "Max bytes per row:",
    "过滤(正则):": "Filter (regex):",
    "随机种子:": "Random seed:",
    "运算:": "Operation:",
    "攻击模式:": "Attack mode:",
    "密码编码:": "Password encoding:",
    "算法:": "Algorithm:",
    "密钥:": "Key:",
    "密钥/私钥:": "Key / private key:",
    "IV:": "IV:",
    "自定义字母表:": "Custom alphabet:",
    "参数设置": "Parameters",
    "字典文件:": "Dictionary file:",
    "字符集:": "Character set:",
    "级别:": "Level:",
    "明文偏移:": "Plaintext offset:",
    "新密码:": "New password:",
    # 页签
    "编码解码": "Codec",
    "概览": "Overview",
    "文件头": "Header",
    "嵌套": "Embedded",
    "字符串": "Strings",
    "文件属性": "Properties",
    "基本信息": "Basic Info",
    "LSB 隐写": "LSB Steganography",
    "LSB 行信息": "LSB Row Scan",
    "图片修复": "Image Repair",
    "通道 / 直方图": "Channels / Histogram",
    "扩展分析": "Extended Analysis",
    "数据提取": "Data Extraction",
    "图像合成": "Image Combine",
    "立体图": "Stereogram",
    "颜色映射": "Color Map",
    "GIF 帧": "GIF Frames",
    "结构 / 伪加密": "Structure / Pseudo-encryption",
    "密码恢复": "Password Recovery",
    "CRC 爆破": "CRC Attack",
    "已知明文 (KPA)": "Known Plaintext (KPA)",
    "二维码 / 条码": "QR / Barcode",
    "乱码修复": "Mojibake Repair",
    "Base64 / Hex ↔ 文件": "Base64 / Hex ↔ File",
    "Base64 / Hex → 文件": "Base64 / Hex → File",
    "文件 → Base64 / Hex": "File → Base64 / Hex",
    "头部": "Header",
    "载荷": "Payload",
    "签名": "Signature",
    # 常用按钮 / 状态
    "识别二维码": "Scan QR Code",
    "从剪贴板读取": "Read Clipboard",
    "重新识别": "Scan Again",
    "解码并预览": "Decode and Preview",
    "自动分析乱码": "Analyze Mojibake",
    "按编码转换": "Convert Encoding",
    "选择文件…": "Choose File…",
    "选择另一张图…": "Choose Another Image…",
    "开始恢复": "Start Recovery",
    "开始 CRC 爆破": "Start CRC Attack",
    "开始已知明文攻击": "Start Known-Plaintext Attack",
    "停止": "Stop",
    "复制结果": "Copy Result",
    "复制全部结果": "Copy All Results",
    "复制原始字节 Hex": "Copy Raw Hex",
    "复制全部属性": "Copy All Properties",
    "复制选中结果": "Copy Selected",
    "复制选中 HEX": "Copy Selected Hex",
    "复制选中明文": "Copy Selected Plaintext",
    "复制密码": "Copy Password",
    "复制密钥": "Copy Keys",
    "复制 Token": "Copy Token",
    "复制生成结果": "Copy Generated",
    "复制输出": "Copy Output",
    "复制 Hex": "Copy Hex",
    "复制解码后 Hex": "Copy Decoded Hex",
    "粘贴或拖入不规则代码": "Paste or drop irregular code",
    "粘贴 JWT 令牌（头部.载荷.签名）":
        "Paste a JWT token (header.payload.signature)",
    "等待开始。": "Waiting to start.",
    "已复制 ✓": "Copied ✓",
    "已复制到剪贴板": "Copied to clipboard",
    "已复制到剪贴板。": "Copied to clipboard.",
    "已清空。": "Cleared.",
    "保存失败": "Save failed",
    "保存失败:": "Save failed:",
    "读取失败:": "Read failed:",
    "读取文件失败:": "Failed to read file:",
    "读取图片失败:": "Failed to read image:",
    "无法解码该图片": "Cannot decode this image",
    "无法预览该图片": "Cannot preview this image",
    "两张图片尺寸必须相同": "The two images must have the same size",
    "未选择文件": "No file selected",
    "转换结果": "Conversion result",
    "解码失败": "Decode failed",
    "图片预览": "Image Preview",
    "未找到": "Not found",
    "分析记录": "Analysis log",
    "恢复日志": "Recovery log",
    "修复操作记录": "Repair log",
    "正在检查更新…": "Checking for updates…",
    "当前版本": "Current version",
    "最新版本": "Latest version",
    "打开 GitHub": "Open GitHub",
    "稍后": "Later",
    # 编码分类
    "文本编码": "Text encoding",
    "Base 家族": "Base family",
    "古典密码": "Classical ciphers",
    "哈希": "Hashes",
    "对称密码": "Symmetric ciphers",
    "进制": "Numeral systems",
    "趣味编码": "Esoteric encodings",
    "隐写编码": "Steganographic encodings",
    "其他": "Other",
    # 面板按钮 / 标签
    "打开图片…": "Open Image…",
    "打开 ZIP…": "Open ZIP…",
    "打开 WAV…": "Open WAV…",
    "打开代码…": "Open Code…",
    "拖入 WAV 开始分析": "Drop a WAV file to analyze",
    "拖入 ZIP 文件开始分析": "Drop a ZIP file to analyze",
    "拖入任意文件开始分析": "Drop any file to analyze",
    "拖入图片开始分析": "Drop an image to analyze",
    "拖入图片，或点击「打开图片…」\n也可以直接从剪贴板读取截图":
        "Drop an image, or click “Open Image…”\nYou can also read a screenshot from the clipboard",
    "点击「扫描 LSB 行信息」": "Click “Scan LSB Rows”",
    "点击「提取 LSB 数据」后显示文本或 Hex 预览":
        "Click “Extract LSB Data” to show text or a Hex preview",
    "载入 GIF 后可逐帧查看": "Load a GIF to browse frames",
    "载入 ZIP 后选择条目。": "Load a ZIP and select an entry.",
    "载入 ZIP 后选择模式开始恢复；仅支持 ZipCrypto，不支持 AES。":
        "Load a ZIP and choose a mode; only ZipCrypto is supported, not AES.",
    "载入 ZIP 并选择加密条目。": "Load a ZIP and select an encrypted entry.",
    "载入文件后显示类型、哈希与检测结论":
        "Load a file to show its type, hashes and findings",
    "勾选每个通道要提取的位平面：": "Select bit planes for each channel:",
    "位平面顺序：": "Bit-plane order:",
    "选择位平面后点击“提取”": "Select bit planes, then click Extract",
    "仅 PNG 支持数据块列表与文本块提取":
        "Chunk listing and text-chunk extraction are PNG-only",
    "导出文本数据块…": "Export Text Chunks…",
    "扫描内嵌的 PNG/JPEG/GIF/ZIP/PDF/ELF 等文件":
        "Scan embedded PNG/JPEG/GIF/ZIP/PDF/ELF files",
    "JWT 令牌：": "JWT token:",
    "复制令牌": "Copy Token",
    "生成令牌": "Generate Token",
    "JWT 头部 JSON：": "JWT header JSON:",
    "JWT 载荷 JSON：": "JWT payload JSON:",
    "HMAC 密钥，或 RS256 PEM 私钥": "HMAC key, or RS256 PEM private key",
    "WAV LSB：每个采样点取指定的二进制位":
        "WAV LSB: read the selected bit from each sample",
    "JWT 头部": "JWT header",
    "JWT 载荷": "JWT payload",
    "JWT 签名": "JWT signature",
    # 算法显示名（仅界面，不改变内部名称）
    "Hill 密码": "Hill Cipher",
    "仿射密码": "Affine Cipher",
    "凯撒密码": "Caesar Cipher",
    "培根密码": "Bacon Cipher",
    "摩斯电码": "Morse Code",
    "曲路密码": "Route Cipher",
    "栅栏密码": "Rail Fence Cipher",
    "猪圈密码": "Pigpen Cipher",
    "维吉尼亚": "Vigenère Cipher",
    "进制转换": "Base Conversion",
    "零宽字符": "Zero-width Characters",
    "ASCII 码": "ASCII Codes",
    "URL 编码": "URL Encoding",
    "编码 ▶": "Encode ▶",
    "◀ 解码": "◀ Decode",
    "一键智能解码": "Smart Decode",
    "提取": "Extract",
    "全部结果": "All results",
    "格式化": "Format",
    "跳转": "Go",
    "已知明文": "Known plaintext",
    "文本": "Text",
    "语言:": "Language:",
    "解码路径": "Decode path",
    "解码后会显示真实文件类型、大小和建议扩展名。\n图片会直接预览；ZIP/PE 等可保存后打开。":
        "After decoding, the real file type, size and suggested extension appear here.\n"
        "Images are previewed directly; ZIP/PE files can be saved and opened.",
    "路径、时间、Windows 属性、权限、文件类型和哈希；大文件哈希在后台分析完成后填入。":
        "Path, timestamps, Windows attributes, permissions, file type and hashes; "
        "large-file hashes appear after background analysis.",
    "遍历 R/G/B/A 通道顺序,提取 LSB 文本;flag 行会排在最前并高亮。":
        "Scan R/G/B/A channel orders and extract LSB text; flag lines are shown first and highlighted.",
    "熵图(越高越接近加密/压缩)":
        "Entropy chart (higher means closer to encrypted/compressed)",
    "提取结果(文本/Hex)": "Extraction result (text/Hex)",
    "粘贴 HEX(可带空格)或文本;CRC 爆破结果可直接导入此处":
        "Paste HEX (spaces allowed) or text; CRC attack results can be imported here",
    "仅用于极小的 ZipCrypto 条目:ZIP ≤ 1 MiB、明文 ≤ 6 字节。CRC32 只有 32 位,通常只能唯一确定 4 字节左右的明文。":
        "For very small ZipCrypto entries only: ZIP ≤ 1 MiB, plaintext ≤ 6 bytes. "
        "CRC32 is only 32 bits, so usually only about 4 bytes can be determined uniquely.",
    "恢复不出来时依次检查：①「结构」页看是否 AES 加密（本工具不支持）；②密码是否确实在字典/掩码范围内；③中文密码把编码改为 GBK 或自动；④掩码写 ???? 并在下拉菜单勾选字符集，?d/?l 固定写法已移除；⑤0 字节加密条目无法可靠校验密码。":
        "If recovery fails, check: (1) the Structure tab for AES encryption (unsupported); "
        "(2) that the password is inside the dictionary/mask; (3) use GBK or Auto for Chinese passwords; "
        "(4) use ???? masks and select character sets in the menu; (5) empty entries cannot be verified reliably.",
    "每个裸 ? 都使用上方下拉菜单多选的字符集;?l/?u/?d 等固定写法已移除。例如 4 位数字:掩码写 ????，下拉勾选“数字”。字面问号请写 \\?。":
        "Each bare ? uses the character sets selected above; fixed codes such as ?l/?u/?d are removed. "
        "For 4 digits, write ???? and select “Digits”. Use \\? for a literal question mark.",
    "XOR / ADD / SUB / AND / OR / MIN / MAX / DIFF 已统一到 「扩展分析 → 图像合成」，避免重复入口；本页保留通道预览、反色和直方图。":
        "XOR / ADD / SUB / AND / OR / MIN / MAX / DIFF are centralized in "
        "“Extended Analysis → Image Combine”. This page keeps channel preview, invert and histogram.",
    "小写字母 + 大写字母 + 数字 (62 字符)":
        "Lowercase + uppercase + digits (62 characters)",
    "低位优先 (LSB)": "LSB first",
    "高位优先 (MSB)": "MSB first",
    "异或 (XOR)": "XOR",
    "相加": "Add",
    "相减": "Subtract",
    "按位与": "Bitwise AND",
    "按位或": "Bitwise OR",
    "取小": "Minimum",
    "取大": "Maximum",
    "差分": "Difference",
    "异或 / 相加 / 相减 / 按位与 / 按位或 / 取小 / 取大 / 差分":
        "XOR / Add / Subtract / AND / OR / Min / Max / Difference",
    "异或 / 相加 / 相减 / 按位与 / 按位或 / 取小 / 取大 / 差分 已统一到 「扩展分析 → 图像合成」，避免重复入口；本页保留通道预览、反色和直方图。":
        "XOR / Add / Subtract / AND / OR / Min / Max / Difference are centralized in "
        "“Extended Analysis → Image Combine”. This page keeps channel preview, invert and histogram.",
    "头部": "Header",
    "载荷": "Payload",
    "签名": "Signature",
    "解析成功，可修改载荷后重新生成/伪造":
        "Parsed successfully; edit the payload to regenerate or forge",
    "请先粘贴 JWT 令牌": "Paste a JWT token first",
    "验证失败：令牌无法解析": "Verification failed: cannot parse the token",
    "已生成": "Generated",
    # 面板按钮 / 标签
    "打开 WAV…": "Open WAV…",
    "打开 ZIP…": "Open ZIP…",
    "打开代码…": "Open Code…",
    "打开图片…": "Open Image…",
    "拖入 WAV 开始分析": "Drop a WAV file to analyze",
    "拖入 ZIP 文件开始分析": "Drop a ZIP file to analyze",
    "拖入任意文件开始分析": "Drop any file to analyze",
    "拖入图片开始分析": "Drop an image to analyze",
    "拖入图片，或点击「打开图片…」\n也可以直接从剪贴板读取截图":
        "Drop an image, or click “Open Image…”\nYou can also read a screenshot from the clipboard",
    "点击「提取 LSB 数据」后显示文本或 Hex 预览":
        "Click “Extract LSB Data” to show text or a Hex preview",
    "点击「扫描 LSB 行信息」": "Click “Scan LSB Rows”",
    "载入 GIF 后可逐帧查看": "Load a GIF to browse frames",
    "载入 ZIP 后选择条目。": "Load a ZIP and select an entry.",
    "载入 ZIP 后选择模式开始恢复;仅支持 ZipCrypto,不支持 AES。":
        "Load a ZIP and choose a mode; only ZipCrypto is supported, not AES.",
    "载入 ZIP 并选择加密条目。": "Load a ZIP and select an encrypted entry.",
    "载入文件后显示类型、哈希与检测结论":
        "Load a file to show its type, hashes and findings",
    "选择 bit 平面后点击提取": "Select bit planes, then click Extract",
    "勾选每个通道要提取的 bit 平面:": "Select bit planes for each channel:",
    "bit 平面顺序:": "Bit-plane order:",
    "位平面预览": "Bit-plane preview",
    "通道 / 反色 / 直方图结果预览": "Channel / invert / histogram preview",
    "自动立体图深度图": "Automatic stereogram depth map",
    "同色像素映射为同一随机色,用于打乱调色板看轮廓":
        "Map equal pixels to one random color to reveal outlines",
    "单通道最低位容量:—": "Single-channel LSB capacity: —",
    "提取结果": "Extraction result",
    "提取结果:": "Extraction result:",
    "修复结果:": "Repair result:",
    "显示:": "Show:",
    "智能解码结果(双击填入输出区):": "Smart decode results (double-click to use):",
    "手动转换:": "Manual conversion:",
    "源编码": "Source encoding",
    "目标编码": "Target encoding",
    "快捷字符集:": "Preset character sets:",
    "裸 ? 代表:": "Bare ? means:",
    "掩码:": "Mask:",
    "加密条目:": "Encrypted entry:",
    "密码:—": "Password: —",
    "密钥:—": "Key: —",
    "压缩包注释:(无)": "Archive comment: (none)",
    "输入格式:": "Input format:",
    "文本编码:": "Text encoding:",
    "通道顺序:": "Channel order:",
    "整图通道顺序": "Whole-image channel order",
    "逐行扫描": "Row-by-row scan",
    "低位→高位": "Low to high",
    "高位→低位": "High to low",
    "全部可打印": "All printable",
    "小写": "Lowercase",
    "大写": "Uppercase",
    "数字": "Digits",
    "小写+数字": "Lowercase + digits",
    "字典攻击": "Dictionary attack",
    "暴力破解": "Brute force",
    "掩码攻击": "Mask attack",
    "自动": "Auto",
    "自动识别": "Auto detect",
    "明文文件": "Plaintext file",
    "HEX / 文本": "HEX / Text",
    "Hex 字节": "Hex bytes",
    "UTF-8 文本": "UTF-8 text",
    "ASCII 文本(忽略大小写)": "ASCII text (case-insensitive)",
    "CRC 爆破日志": "CRC attack log",
    "bkcrack 输出": "bkcrack output",
    "保存提取数据…": "Save Extracted Data…",
    "保存结果…": "Save Result…",
    "保存文本…": "Save Text…",
    "导出文本 Chunk…": "Export Text Chunks…",
    "删除选中": "Remove Selected",
    "添加一行": "Add Row",
    "生成": "Generate",
    "生成 Token": "Generate Token",
    "生成随机颜色映射": "Generate Random Color Map",
    "解析": "Parse",
    "解析立体图": "Parse Stereogram",
    "验证签名": "Verify Signature",
    "修改密码另存…": "Change Password and Save As…",
    "移除密码另存…": "Remove Password and Save As…",
    "解密当前条目…": "Decrypt Current Entry…",
    "导入已知明文攻击 →": "Send to Known-Plaintext Attack →",
    "覆盖保存": "Overwrite",
    "选择已知明文文件": "Choose a known-plaintext file",
    "选择一行一个密码的 txt 字典": "Choose a TXT dictionary, one password per line",
    "保存提取数据…": "Save Extracted Data…",
    "复制选区": "Copy Selection",
    "反色": "Invert",
    "直方图": "Histogram",
    "预览通道": "Preview Channel",
    "显示位平面": "Show Bit Plane",
    "提取 LSB 数据": "Extract LSB Data",
    "提取 LSB": "Extract LSB",
    "扫描 LSB 行信息": "Scan LSB Rows",
    "提取选中…": "Extract Selected…",
    "全部提取…": "Extract All…",
    "扫描嵌套文件": "Scan Embedded Files",
    "按 IDAT 自动推算宽高…": "Infer Size from IDAT…",
    "修复全部 CRC 并另存…": "Repair All CRCs and Save As…",
    "按上述宽高修复并另存…": "Repair with Size Above and Save As…",
    "修复伪加密并另存…": "Repair Pseudo-encryption and Save As…",
    "安全解压…": "Safe Extract…",
    "仅 PNG 支持 CRC 与宽高校验/修复":
        "CRC and dimension checks/repair are PNG-only",
    "仅 PNG 支持 Chunk 列表与文本块提取":
        "Chunk listing and text-chunk extraction are PNG-only",
    "宽:": "Width:",
    "高:": "Height:",
    "支持二维码、Micro QR、Data Matrix、Aztec、PDF417 和常见一维条码。":
        "Supports QR, Micro QR, Data Matrix, Aztec, PDF417 and common 1D barcodes.",
    "支持 data:image/png;base64,...、URL 安全 Base64、0x/空格/逗号分隔的 Hex。":
        "Supports data:image/png;base64,..., URL-safe Base64, and Hex separated by 0x, spaces or commas.",
    "在此粘贴明文或密文,支持乱码输入……":
        "Paste plaintext or ciphertext here; garbled input is supported…",
    "自动分析或手动转换后显示结果":
        "The result appears after automatic analysis or manual conversion",
    "识别结果会显示在这里；可直接选中复制。":
        "Results appear here; select and copy directly.",
    "粘贴 Base64 或 Hex，例如：\niVBORw0KGgoAAAANSUhEUg...（Base64 图片）\n504b0304...（Hex ZIP）":
        "Paste Base64 or Hex, e.g.:\niVBORw0KGgoAAAANSUhEUg... (Base64 image)\n504b0304... (Hex ZIP)",
    "粘贴乱码，例如：æµ‹è¯• / 娴嬭瘯 / ÄãºÃ£¬ÊÀ½ç\n输入格式选「Hex 字节」时，粘贴 c4e3bac3 这类连续 Hex。":
        "Paste garbled text, e.g. æµ‹è¯• / 娴嬭瘯 / ÄãºÃ£¬ÊÀ½ç\n"
        "For “Hex bytes”, paste continuous Hex such as c4e3bac3.",
    "选择任意文件，转换成 Base64 或 Hex 文本。":
        "Choose any file and convert it to Base64 or Hex text.",
    "自动枚举 UTF-8 / GB18030 / Big5 / Latin-1 / CP1252 的错误解释组合；候选按可读性排序，双击填入结果。":
        "Tries UTF-8 / GB18030 / Big5 / Latin-1 / CP1252 misinterpretations, ranks candidates by readability, and fills the result on double-click.",
    "选择已知明文文件": "Choose a known-plaintext file",
    "选择已知明文文件": "Choose a known-plaintext file",
    "偏移(支持 0x1A / 26)": "Offset (0x1A / 26 supported)",
    "如 flag|ctf": "e.g. flag|ctf",
    "例如 qctf2026????": "e.g. qctf2026????",
    "默认 6": "Default 6",
    "明文是原始文件内容,先按 Deflate 压缩":
        "Plaintext is original file content; compress with Deflate first",
    "额外已知字节(可选,对应 bkcrack -x)":
        "Extra known bytes (optional, bkcrack -x)",
    "生成 / 伪造": "Generate / Forge",
    "生成结果": "Generated result",
    "留空使用标准 16 字符字母表": "Leave empty for the standard 16-character alphabet",
    "普通文本": "Plain text",
    "疑似密码": "Suspected password",
    "凭据": "Credential",
    "显示:": "Show:",
    "附件": "Attachment",
}
_JA: dict[str, str] = {
    "文本处理": "テキスト", "文件与压缩包": "ファイルと圧縮", "图像与音频": "画像と音声",
    "识别与转换": "認識と変換", "文本编解码": "テキスト変換", "JWT 解析": "JWT 解析",
    "代码格式化": "コード整形", "文件分析": "ファイル分析", "压缩包分析": "圧縮ファイル分析",
    "图像分析": "画像分析", "音频分析": "音声分析", "实用工具": "便利ツール",
    "语言": "言語", "设置": "設定", "帮助": "ヘルプ", "检查更新…": "更新を確認…",
    "打开文件…": "ファイルを開く…", "关闭当前文件": "現在のファイルを閉じる",
    "查看文件属性…": "ファイルのプロパティ…", "退出": "終了",
    "发现新版本": "新しいバージョンがあります",
    "发现新版本，请到github官网更新，https://github.com/nmc100086-rgb/CTFusion":
        "新しいバージョンがあります。GitHub の公式ページから更新してください："
        "https://github.com/nmc100086-rgb/CTFusion",
    "当前版本": "現在のバージョン", "最新版本": "最新バージョン",
    "打开 GitHub": "GitHub を開く", "稍后": "後で",
    "已是最新版本。": "最新バージョンです。", "检查更新失败：": "更新の確認に失敗しました：",
    "提示": "お知らせ", "确定": "OK", "取消": "キャンセル", "关闭": "閉じる",
    "保存": "保存", "打开": "開く", "复制": "コピー", "清空": "クリア",
    "刷新": "更新", "浏览…": "参照…", "转换": "変換", "开始": "開始", "停止": "停止",
    "编码解码": "コード変換", "文件分析": "ファイル分析", "图片隐写": "画像ステガノ",
    "图片分析": "画像分析", "音频 LSB": "音声 LSB", "压缩包": "圧縮ファイル",
    "实用工具": "便利ツール", "概览": "概要", "文件头": "ファイルヘッダ",
    "结构": "構造", "嵌套": "埋め込み", "字符串": "文字列", "文件属性": "プロパティ",
    "基本信息": "基本情報", "LSB 隐写": "LSB ステガノ", "LSB 行信息": "LSB 行走査",
    "图片修复": "画像修復", "PNG 数据块": "PNG チャンク", "扩展分析": "拡張分析",
    "二维码 / 条码": "QR / バーコード", "乱码修复": "文字化け修復",
    "密码恢复": "パスワード復元", "CRC 爆破": "CRC 攻撃", "已知明文 (KPA)": "既知平文 (KPA)",
    "复制": "コピー", "保存": "保存", "取消": "キャンセル", "关闭": "閉じる",
}
_KO: dict[str, str] = {
    "文本处理": "텍스트", "文件与压缩包": "파일 및 압축", "图像与音频": "이미지 및 오디오",
    "识别与转换": "인식 및 변환", "文本编解码": "텍스트 변환", "JWT 解析": "JWT 분석",
    "代码格式化": "코드 정리", "文件分析": "파일 분석", "压缩包分析": "압축 파일 분석",
    "图像分析": "이미지 분석", "音频分析": "오디오 분석", "实用工具": "도구",
    "语言": "언어", "设置": "설정", "帮助": "도움말", "检查更新…": "업데이트 확인…",
    "打开文件…": "파일 열기…", "关闭当前文件": "현재 파일 닫기",
    "查看文件属性…": "파일 속성…", "退出": "종료",
    "发现新版本": "새 버전이 있습니다",
    "发现新版本，请到github官网更新，https://github.com/nmc100086-rgb/CTFusion":
        "새 버전이 있습니다. GitHub 공식 페이지에서 업데이트하세요: "
        "https://github.com/nmc100086-rgb/CTFusion",
    "当前版本": "현재 버전", "最新版本": "최신 버전",
    "打开 GitHub": "GitHub 열기", "稍后": "나중에",
    "已是最新版本。": "최신 버전입니다.", "检查更新失败：": "업데이트 확인 실패:",
    "提示": "알림", "确定": "확인", "取消": "취소", "关闭": "닫기",
    "保存": "저장", "打开": "열기", "复制": "복사", "清空": "지우기",
    "刷新": "새로고침", "浏览…": "찾아보기…", "转换": "변환", "开始": "시작", "停止": "중지",
    "编码解码": "코드 변환", "图片隐写": "이미지 스테가노", "图片分析": "이미지 분석",
    "音频 LSB": "오디오 LSB", "压缩包": "압축 파일", "实用工具": "도구",
    "概览": "개요", "文件头": "파일 헤더", "结构": "구조", "嵌套": "내장",
    "字符串": "문자열", "文件属性": "속성", "基本信息": "기본 정보",
    "LSB 隐写": "LSB 스테가노", "LSB 行信息": "LSB 행 스캔", "图片修复": "이미지 복구",
    "PNG 数据块": "PNG 청크", "扩展分析": "확장 분석", "二维码 / 条码": "QR / 바코드",
    "乱码修复": "깨진 문자 복구", "密码恢复": "비밀번호 복구",
    "CRC 爆破": "CRC 공격", "已知明文 (KPA)": "기지 평문 (KPA)",
}
_ES: dict[str, str] = {
    "文本处理": "Texto", "文件与压缩包": "Archivos y comprimidos", "图像与音频": "Imagen y audio",
    "识别与转换": "Reconocimiento y conversión", "文本编解码": "Códec de texto",
    "JWT 解析": "Analizador JWT", "代码格式化": "Formateador de código",
    "文件分析": "Análisis de archivos", "压缩包分析": "Análisis de comprimidos",
    "图像分析": "Análisis de imágenes", "音频分析": "Análisis de audio",
    "实用工具": "Utilidades", "语言": "Idioma", "设置": "Ajustes", "帮助": "Ayuda",
    "检查更新…": "Buscar actualizaciones…", "打开文件…": "Abrir archivo…",
    "关闭当前文件": "Cerrar archivo actual", "查看文件属性…": "Propiedades del archivo…",
    "退出": "Salir", "发现新版本": "Nueva versión disponible",
    "发现新版本，请到github官网更新，https://github.com/nmc100086-rgb/CTFusion":
        "Hay una nueva versión. Actualiza desde la página oficial de GitHub: "
        "https://github.com/nmc100086-rgb/CTFusion",
    "当前版本": "Versión actual", "最新版本": "Última versión",
    "打开 GitHub": "Abrir GitHub", "稍后": "Más tarde",
    "已是最新版本。": "Ya tienes la última versión.", "检查更新失败：": "Error al buscar actualizaciones:",
    "提示": "Aviso", "确定": "Aceptar", "取消": "Cancelar", "关闭": "Cerrar",
    "保存": "Guardar", "打开": "Abrir", "复制": "Copiar", "清空": "Limpiar",
    "刷新": "Actualizar", "浏览…": "Examinar…", "转换": "Convertir", "开始": "Iniciar",
    "停止": "Detener", "编码解码": "Códec", "图片隐写": "Esteganografía",
    "图片分析": "Análisis de imágenes", "音频 LSB": "Audio LSB", "压缩包": "Comprimidos",
    "实用工具": "Utilidades", "概览": "Resumen", "文件头": "Cabecera",
    "结构": "Estructura", "嵌套": "Incrustado", "字符串": "Cadenas",
    "文件属性": "Propiedades", "基本信息": "Información básica", "LSB 隐写": "LSB",
    "LSB 行信息": "Escaneo LSB por filas", "图片修复": "Reparación de imagen",
    "PNG 数据块": "Bloques PNG", "扩展分析": "Análisis extendido",
    "二维码 / 条码": "QR / Código de barras", "乱码修复": "Reparar texto dañado",
    "密码恢复": "Recuperar contraseña", "CRC 爆破": "Ataque CRC",
    "已知明文 (KPA)": "Texto conocido (KPA)",
}
_FR: dict[str, str] = {
    "文本处理": "Texte", "文件与压缩包": "Fichiers et archives", "图像与音频": "Images et audio",
    "识别与转换": "Reconnaissance et conversion", "文本编解码": "Codec de texte",
    "JWT 解析": "Analyse JWT", "代码格式化": "Formateur de code",
    "文件分析": "Analyse de fichiers", "压缩包分析": "Analyse d’archives",
    "图像分析": "Analyse d’images", "音频分析": "Analyse audio",
    "实用工具": "Utilitaires", "语言": "Langue", "设置": "Paramètres", "帮助": "Aide",
    "检查更新…": "Vérifier les mises à jour…", "打开文件…": "Ouvrir un fichier…",
    "关闭当前文件": "Fermer le fichier", "查看文件属性…": "Propriétés du fichier…",
    "退出": "Quitter", "发现新版本": "Nouvelle version disponible",
    "发现新版本，请到github官网更新，https://github.com/nmc100086-rgb/CTFusion":
        "Une nouvelle version est disponible. Mettez à jour depuis la page GitHub officielle : "
        "https://github.com/nmc100086-rgb/CTFusion",
    "当前版本": "Version actuelle", "最新版本": "Dernière version",
    "打开 GitHub": "Ouvrir GitHub", "稍后": "Plus tard",
    "已是最新版本。": "Vous avez déjà la dernière version.", "检查更新失败：": "Échec de la vérification :",
    "提示": "Information", "确定": "OK", "取消": "Annuler", "关闭": "Fermer",
    "保存": "Enregistrer", "打开": "Ouvrir", "复制": "Copier", "清空": "Effacer",
    "刷新": "Actualiser", "浏览…": "Parcourir…", "转换": "Convertir", "开始": "Démarrer",
    "停止": "Arrêter", "编码解码": "Codec", "图片隐写": "Stéganographie",
    "图片分析": "Analyse d’images", "音频 LSB": "Audio LSB", "压缩包": "Archives",
    "实用工具": "Utilitaires", "概览": "Aperçu", "文件头": "En-tête",
    "结构": "Structure", "嵌套": "Intégré", "字符串": "Chaînes",
    "文件属性": "Propriétés", "基本信息": "Informations", "LSB 隐写": "LSB",
    "LSB 行信息": "Analyse LSB par ligne", "图片修复": "Réparation d’image",
    "PNG 数据块": "Blocs PNG", "扩展分析": "Analyse étendue",
    "二维码 / 条码": "QR / Code-barres", "乱码修复": "Réparer le texte corrompu",
    "密码恢复": "Récupération du mot de passe", "CRC 爆破": "Attaque CRC",
    "已知明文 (KPA)": "Texte connu (KPA)",
}
_DE: dict[str, str] = {
    "文本处理": "Text", "文件与压缩包": "Dateien & Archive", "图像与音频": "Bilder & Audio",
    "识别与转换": "Erkennung & Konvertierung", "文本编解码": "Text-Codec",
    "JWT 解析": "JWT-Analyse", "代码格式化": "Code-Formatierung",
    "文件分析": "Dateianalyse", "压缩包分析": "Archivanalyse",
    "图像分析": "Bildanalyse", "音频分析": "Audioanalyse",
    "实用工具": "Werkzeuge", "语言": "Sprache", "设置": "Einstellungen", "帮助": "Hilfe",
    "检查更新…": "Nach Updates suchen…", "打开文件…": "Datei öffnen…",
    "关闭当前文件": "Aktuelle Datei schließen", "查看文件属性…": "Dateieigenschaften…",
    "退出": "Beenden", "发现新版本": "Neue Version verfügbar",
    "发现新版本，请到github官网更新，https://github.com/nmc100086-rgb/CTFusion":
        "Eine neue Version ist verfügbar. Bitte über die offizielle GitHub-Seite aktualisieren: "
        "https://github.com/nmc100086-rgb/CTFusion",
    "当前版本": "Aktuelle Version", "最新版本": "Neueste Version",
    "打开 GitHub": "GitHub öffnen", "稍后": "Später",
    "已是最新版本。": "Sie verwenden bereits die neueste Version.",
    "检查更新失败：": "Updateprüfung fehlgeschlagen:",
    "提示": "Hinweis", "确定": "OK", "取消": "Abbrechen", "关闭": "Schließen",
    "保存": "Speichern", "打开": "Öffnen", "复制": "Kopieren", "清空": "Leeren",
    "刷新": "Aktualisieren", "浏览…": "Durchsuchen…", "转换": "Konvertieren",
    "开始": "Starten", "停止": "Stoppen", "编码解码": "Codec",
    "图片隐写": "Steganografie", "图片分析": "Bildanalyse", "音频 LSB": "Audio-LSB",
    "压缩包": "Archive", "实用工具": "Werkzeuge", "概览": "Übersicht",
    "文件头": "Dateikopf", "结构": "Struktur", "嵌套": "Eingebettet",
    "字符串": "Zeichenketten", "文件属性": "Eigenschaften", "基本信息": "Basisinfo",
    "LSB 隐写": "LSB", "LSB 行信息": "LSB-Zeilenscan", "图片修复": "Bildreparatur",
    "PNG 数据块": "PNG-Blöcke", "扩展分析": "Erweiterte Analyse",
    "二维码 / 条码": "QR / Barcode", "乱码修复": "Textreparatur",
    "密码恢复": "Passwortwiederherstellung", "CRC 爆破": "CRC-Angriff",
    "已知明文 (KPA)": "Bekannter Klartext (KPA)",
}
_RU: dict[str, str] = {
    "文本处理": "Текст", "文件与压缩包": "Файлы и архивы", "图像与音频": "Изображения и звук",
    "识别与转换": "Распознавание и преобразование", "文本编解码": "Кодек текста",
    "JWT 解析": "Анализ JWT", "代码格式化": "Форматирование кода",
    "文件分析": "Анализ файлов", "压缩包分析": "Анализ архивов",
    "图像分析": "Анализ изображений", "音频分析": "Анализ звука",
    "实用工具": "Инструменты", "语言": "Язык", "设置": "Настройки", "帮助": "Справка",
    "检查更新…": "Проверить обновления…", "打开文件…": "Открыть файл…",
    "关闭当前文件": "Закрыть текущий файл", "查看文件属性…": "Свойства файла…",
    "退出": "Выход", "发现新版本": "Доступна новая версия",
    "发现新版本，请到github官网更新，https://github.com/nmc100086-rgb/CTFusion":
        "Доступна новая версия. Обновитесь со страницы GitHub: "
        "https://github.com/nmc100086-rgb/CTFusion",
    "当前版本": "Текущая версия", "最新版本": "Последняя версия",
    "打开 GitHub": "Открыть GitHub", "稍后": "Позже",
    "已是最新版本。": "У вас последняя версия.", "检查更新失败：": "Ошибка проверки обновлений:",
    "提示": "Уведомление", "确定": "ОК", "取消": "Отмена", "关闭": "Закрыть",
    "保存": "Сохранить", "打开": "Открыть", "复制": "Копировать", "清空": "Очистить",
    "刷新": "Обновить", "浏览…": "Обзор…", "转换": "Преобразовать", "开始": "Начать",
    "停止": "Остановить", "编码解码": "Кодек", "图片隐写": "Стеганография",
    "图片分析": "Анализ изображений", "音频 LSB": "Аудио LSB", "压缩包": "Архивы",
    "实用工具": "Инструменты", "概览": "Обзор", "文件头": "Заголовок",
    "结构": "Структура", "嵌套": "Вложенные", "字符串": "Строки",
    "文件属性": "Свойства", "基本信息": "Основное", "LSB 隐写": "LSB",
    "LSB 行信息": "LSB-сканирование", "图片修复": "Восстановление изображения",
    "PNG 数据块": "Блоки PNG", "扩展分析": "Расширенный анализ",
    "二维码 / 条码": "QR / Штрихкод", "乱码修复": "Исправление текста",
    "密码恢复": "Восстановление пароля", "CRC 爆破": "Атака CRC",
    "已知明文 (KPA)": "Известный текст (KPA)",
}
_PT: dict[str, str] = {
    "文本处理": "Texto", "文件与压缩包": "Arquivos e compactados", "图像与音频": "Imagem e áudio",
    "识别与转换": "Reconhecimento e conversão", "文本编解码": "Codec de texto",
    "JWT 解析": "Analisador JWT", "代码格式化": "Formatador de código",
    "文件分析": "Análise de arquivos", "压缩包分析": "Análise de compactados",
    "图像分析": "Análise de imagens", "音频分析": "Análise de áudio",
    "实用工具": "Utilitários", "语言": "Idioma", "设置": "Configurações", "帮助": "Ajuda",
    "检查更新…": "Verificar atualizações…", "打开文件…": "Abrir arquivo…",
    "关闭当前文件": "Fechar arquivo atual", "查看文件属性…": "Propriedades do arquivo…",
    "退出": "Sair", "发现新版本": "Nova versão disponível",
    "发现新版本，请到github官网更新，https://github.com/nmc100086-rgb/CTFusion":
        "Há uma nova versão. Atualize pela página oficial do GitHub: "
        "https://github.com/nmc100086-rgb/CTFusion",
    "当前版本": "Versão atual", "最新版本": "Última versão",
    "打开 GitHub": "Abrir GitHub", "稍后": "Depois",
    "已是最新版本。": "Você já está na versão mais recente.",
    "检查更新失败：": "Falha ao verificar atualizações:",
    "提示": "Aviso", "确定": "OK", "取消": "Cancelar", "关闭": "Fechar",
    "保存": "Salvar", "打开": "Abrir", "复制": "Copiar", "清空": "Limpar",
    "刷新": "Atualizar", "浏览…": "Procurar…", "转换": "Converter", "开始": "Iniciar",
    "停止": "Parar", "编码解码": "Codec", "图片隐写": "Esteganografia",
    "图片分析": "Análise de imagens", "音频 LSB": "Áudio LSB", "压缩包": "Compactados",
    "实用工具": "Utilitários", "概览": "Visão geral", "文件头": "Cabeçalho",
    "结构": "Estrutura", "嵌套": "Embutido", "字符串": "Strings",
    "文件属性": "Propriedades", "基本信息": "Informações básicas", "LSB 隐写": "LSB",
    "LSB 行信息": "Varredura LSB por linha", "图片修复": "Reparo de imagem",
    "PNG 数据块": "Blocos PNG", "扩展分析": "Análise estendida",
    "二维码 / 条码": "QR / Código de barras", "乱码修复": "Reparar texto corrompido",
    "密码恢复": "Recuperação de senha", "CRC 爆破": "Ataque CRC",
    "已知明文 (KPA)": "Texto conhecido (KPA)",
}
_AR: dict[str, str] = {
    "文本处理": "النصوص", "文件与压缩包": "الملفات والأرشيفات", "图像与音频": "الصور والصوت",
    "识别与转换": "التعرف والتحويل", "文本编解码": "ترميز النصوص", "JWT 解析": "تحليل JWT",
    "代码格式化": "تنسيق الشيفرة", "文件分析": "تحليل الملفات", "压缩包分析": "تحليل الأرشيفات",
    "图像分析": "تحليل الصور", "音频分析": "تحليل الصوت", "实用工具": "أدوات",
    "语言": "اللغة", "设置": "الإعدادات", "帮助": "مساعدة", "检查更新…": "التحقق من التحديثات…",
    "打开文件…": "فتح ملف…", "关闭当前文件": "إغلاق الملف الحالي",
    "查看文件属性…": "خصائص الملف…", "退出": "خروج",
    "发现新版本": "إصدار جديد متاح",
    "发现新版本，请到github官网更新，https://github.com/nmc100086-rgb/CTFusion":
        "يتوفر إصدار جديد. يرجى التحديث من صفحة GitHub الرسمية: "
        "https://github.com/nmc100086-rgb/CTFusion",
    "当前版本": "الإصدار الحالي", "最新版本": "أحدث إصدار",
    "打开 GitHub": "فتح GitHub", "稍后": "لاحقًا",
    "已是最新版本。": "لديك أحدث إصدار.", "检查更新失败：": "فشل التحقق من التحديثات:",
    "提示": "تنبيه", "确定": "موافق", "取消": "إلغاء", "关闭": "إغلاق",
    "保存": "حفظ", "打开": "فتح", "复制": "نسخ", "清空": "مسح",
    "刷新": "تحديث", "浏览…": "استعراض…", "转换": "تحويل", "开始": "بدء",
    "停止": "إيقاف", "编码解码": "الترميز", "图片隐写": "إخفاء في الصور",
    "图片分析": "تحليل الصور", "音频 LSB": "صوت LSB", "压缩包": "الأرشيفات",
    "实用工具": "أدوات", "概览": "نظرة عامة", "文件头": "ترويسة الملف",
    "结构": "البنية", "嵌套": "مضمّن", "字符串": "النصوص",
    "文件属性": "الخصائص", "基本信息": "معلومات أساسية", "LSB 隐写": "LSB",
    "LSB 行信息": "فحص LSB بالأسطر", "图片修复": "إصلاح الصور",
    "PNG 数据块": "كتل PNG", "扩展分析": "تحليل موسع",
    "二维码 / 条码": "QR / الباركود", "乱码修复": "إصلاح النص التالف",
    "密码恢复": "استعادة كلمة المرور", "CRC 爆破": "هجوم CRC",
    "已知明文 (KPA)": "نص معروف (KPA)",
}

_LANGUAGE_TABLES = {
    "ja": _JA,
    "ko": _KO,
    "es": _ES,
    "fr": _FR,
    "de": _DE,
    "ru": _RU,
    "pt": _PT,
    "ar": _AR,
}


def language() -> str:
    return _current


def language_label(code: str) -> str:
    return _LANGUAGE_LABELS.get(code, code)


def tr(text: str) -> str:
    """翻译完整字符串；找不到时回退英语，再回退原文。"""
    if not isinstance(text, str) or not text or _current == "zh_CN":
        return text
    table = _LANGUAGE_TABLES.get(_current)
    if table and text in table:
        return table[text]
    if _current != "en" and text in _EN:
        return _EN[text]
    if _current == "en" and text in _EN:
        return _EN[text]
    return text


def initialize() -> None:
    """读取保存的语言；在 QApplication 创建之后调用。"""
    settings = QSettings("CTFusion", "CTFusion")
    code = str(settings.value(_SETTINGS_KEY, "zh_CN") or "zh_CN")
    if code not in _LANGUAGE_LABELS:
        code = "zh_CN"
    _current = code
    _apply_layout_direction()


def set_language(code: str) -> None:
    global _current
    if code not in _LANGUAGE_LABELS:
        code = "zh_CN"
    _current = code
    QSettings("CTFusion", "CTFusion").setValue(_SETTINGS_KEY, code)
    _apply_layout_direction()


def _apply_layout_direction() -> None:
    app = QApplication.instance()
    if app is not None:
        app.setLayoutDirection(
            Qt.RightToLeft if _current == "ar" else Qt.LeftToRight)


# ---------------------------------------------------------------------------
# Qt 文本 setter 包装
# ---------------------------------------------------------------------------
_ORIG = {}
_PATCHED = False


def _install_patches() -> None:
    global _PATCHED
    if _PATCHED:
        return
    _PATCHED = True

    _ORIG["QLabel.setText"] = QLabel.setText

    def label_set(self, text):
        if not _TRANSLATING:
            self._i18n_src = text
        _ORIG["QLabel.setText"](self, tr(text))

    QLabel.setText = label_set

    _ORIG["QAbstractButton.setText"] = QAbstractButton.setText

    def button_set(self, text):
        if not _TRANSLATING:
            self._i18n_src = text
        _ORIG["QAbstractButton.setText"](self, tr(text))

    QAbstractButton.setText = button_set

    _ORIG["QGroupBox.setTitle"] = QGroupBox.setTitle

    def group_set(self, text):
        if not _TRANSLATING:
            self._i18n_src = text
        _ORIG["QGroupBox.setTitle"](self, tr(text))

    QGroupBox.setTitle = group_set

    _ORIG["QWidget.setWindowTitle"] = QWidget.setWindowTitle

    def window_set(self, text):
        if not _TRANSLATING:
            self._i18n_src = text
        _ORIG["QWidget.setWindowTitle"](self, tr(text))

    QWidget.setWindowTitle = window_set

    _ORIG["QTabWidget.addTab"] = QTabWidget.addTab

    def tab_add(self, *args):
        pos = None
        if len(args) >= 2 and isinstance(args[1], str):
            pos = 1
        elif len(args) >= 3 and isinstance(args[2], str):
            pos = 2
        if pos is None:
            return _ORIG["QTabWidget.addTab"](self, *args)
        label = args[pos]
        sources = list(getattr(self, "_i18n_tabs", []))
        sources.append(label)
        self._i18n_tabs = sources
        changed = list(args)
        changed[pos] = tr(label)
        return _ORIG["QTabWidget.addTab"](self, *changed)

    QTabWidget.addTab = tab_add

    _ORIG["QTabWidget.setTabText"] = QTabWidget.setTabText

    def tab_set(self, index, text):
        sources = list(getattr(self, "_i18n_tabs", []))
        while len(sources) <= index:
            sources.append("")
        sources[index] = text
        self._i18n_tabs = sources
        _ORIG["QTabWidget.setTabText"](self, index, tr(text))

    QTabWidget.setTabText = tab_set

    _ORIG["QComboBox.addItem"] = QComboBox.addItem

    def combo_add(self, *args):
        pos = None
        if args and isinstance(args[0], str):
            pos = 0
        elif len(args) >= 2 and isinstance(args[1], str):
            pos = 1
        if pos is None:
            return _ORIG["QComboBox.addItem"](self, *args)
        label = args[pos]
        sources = list(getattr(self, "_i18n_items", []))
        sources.append(label)
        self._i18n_items = sources
        changed = list(args)
        changed[pos] = tr(label)
        return _ORIG["QComboBox.addItem"](self, *changed)

    QComboBox.addItem = combo_add

    _ORIG["QComboBox.setItemText"] = QComboBox.setItemText

    def combo_set(self, index, text):
        sources = list(getattr(self, "_i18n_items", []))
        while len(sources) <= index:
            sources.append("")
        sources[index] = text
        self._i18n_items = sources
        _ORIG["QComboBox.setItemText"](self, index, tr(text))

    QComboBox.setItemText = combo_set

    _ORIG["QComboBox.clear"] = QComboBox.clear

    def combo_clear(self):
        self._i18n_items = []
        _ORIG["QComboBox.clear"](self)

    QComboBox.clear = combo_clear

    _ORIG["QTableWidget.setHorizontalHeaderLabels"] = (
        QTableWidget.setHorizontalHeaderLabels)

    def table_headers(self, labels):
        self._i18n_headers = list(labels)
        _ORIG["QTableWidget.setHorizontalHeaderLabels"](
            self, [tr(label) for label in labels])

    QTableWidget.setHorizontalHeaderLabels = table_headers

    _ORIG["QTreeWidget.setHeaderLabels"] = QTreeWidget.setHeaderLabels

    def tree_headers(self, labels):
        self._i18n_headers = list(labels)
        _ORIG["QTreeWidget.setHeaderLabels"](
            self, [tr(label) for label in labels])

    QTreeWidget.setHeaderLabels = tree_headers

    _ORIG["QLineEdit.setPlaceholderText"] = QLineEdit.setPlaceholderText

    def line_placeholder(self, text):
        self._i18n_placeholder = text
        _ORIG["QLineEdit.setPlaceholderText"](self, tr(text))

    QLineEdit.setPlaceholderText = line_placeholder

    _ORIG["QPlainTextEdit.setPlaceholderText"] = QPlainTextEdit.setPlaceholderText

    def plain_placeholder(self, text):
        self._i18n_placeholder = text
        _ORIG["QPlainTextEdit.setPlaceholderText"](self, tr(text))

    QPlainTextEdit.setPlaceholderText = plain_placeholder

    _ORIG["QTextEdit.setPlaceholderText"] = QTextEdit.setPlaceholderText

    def text_placeholder(self, text):
        self._i18n_placeholder = text
        _ORIG["QTextEdit.setPlaceholderText"](self, tr(text))

    QTextEdit.setPlaceholderText = text_placeholder

    _ORIG["QAction.setText"] = QAction.setText

    def action_set(self, text):
        if not _TRANSLATING:
            self._i18n_src = text
        _ORIG["QAction.setText"](self, tr(text))

    QAction.setText = action_set

    _ORIG["QMenu.setTitle"] = QMenu.setTitle

    def menu_set(self, text):
        if not _TRANSLATING:
            self._i18n_src = text
        _ORIG["QMenu.setTitle"](self, tr(text))

    QMenu.setTitle = menu_set

    _patch_message_boxes()


def _patch_message_boxes() -> None:
    for name in ("information", "warning", "question", "critical"):
        original = getattr(QMessageBox, name)
        _ORIG[f"QMessageBox.{name}"] = original

        def wrapper(parent, title, text, *args, _orig=original, **kwargs):
            return _orig(parent, tr(title), tr(text), *args, **kwargs)

        setattr(QMessageBox, name, staticmethod(wrapper))


def _retranslate_widget(widget: QWidget) -> None:
    if isinstance(widget, QLabel):
        source = getattr(widget, "_i18n_src", None)
        if source is None:
            source = widget.text()
            widget._i18n_src = source
        _ORIG["QLabel.setText"](widget, tr(source))
    elif isinstance(widget, QAbstractButton):
        source = getattr(widget, "_i18n_src", None)
        if source is None:
            source = widget.text()
            widget._i18n_src = source
        _ORIG["QAbstractButton.setText"](widget, tr(source))
    elif isinstance(widget, QGroupBox):
        source = getattr(widget, "_i18n_src", None)
        if source is None:
            source = widget.title()
            widget._i18n_src = source
        _ORIG["QGroupBox.setTitle"](widget, tr(source))

    if isinstance(widget, QLineEdit):
        source = getattr(widget, "_i18n_placeholder", None)
        if source is not None:
            _ORIG["QLineEdit.setPlaceholderText"](widget, tr(source))
    elif isinstance(widget, QPlainTextEdit):
        source = getattr(widget, "_i18n_placeholder", None)
        if source is not None:
            _ORIG["QPlainTextEdit.setPlaceholderText"](widget, tr(source))
    elif isinstance(widget, QTextEdit):
        source = getattr(widget, "_i18n_placeholder", None)
        if source is not None:
            _ORIG["QTextEdit.setPlaceholderText"](widget, tr(source))

    if isinstance(widget, QTabWidget):
        sources = getattr(widget, "_i18n_tabs", None)
        if sources is None:
            sources = [widget.tabText(i) for i in range(widget.count())]
            widget._i18n_tabs = sources
        for index, source in enumerate(sources):
            if index < widget.count():
                _ORIG["QTabWidget.setTabText"](widget, index, tr(source))

    if isinstance(widget, QComboBox):
        sources = getattr(widget, "_i18n_items", None)
        if sources is None:
            sources = [widget.itemText(i) for i in range(widget.count())]
            widget._i18n_items = sources
        for index, source in enumerate(sources):
            if index < widget.count():
                _ORIG["QComboBox.setItemText"](widget, index, tr(source))

    if isinstance(widget, (QTableWidget, QTreeWidget)):
        sources = getattr(widget, "_i18n_headers", None)
        if sources is None:
            if isinstance(widget, QTableWidget):
                sources = [
                    widget.horizontalHeaderItem(i).text()
                    if widget.horizontalHeaderItem(i) else ""
                    for i in range(widget.columnCount())
                ]
            else:
                header = widget.headerItem()
                sources = (
                    [header.text(i) for i in range(header.columnCount())]
                    if header else [])
            widget._i18n_headers = sources
        if isinstance(widget, QTableWidget):
            for index, source in enumerate(sources):
                item = widget.horizontalHeaderItem(index)
                if item is not None:
                    item.setText(tr(source))
        else:
            header = widget.headerItem()
            if header is not None:
                for index, source in enumerate(sources):
                    if index < header.columnCount():
                        header.setText(index, tr(source))

    if isinstance(widget, QListWidget):
        for row in range(widget.count()):
            item = widget.item(row)
            source = item.data(Qt.UserRole + 100)
            if source:
                item.setText(tr(str(source)))

    source_title = getattr(widget, "_i18n_src", None)
    if source_title is not None and widget.isWindow():
        _ORIG["QWidget.setWindowTitle"](widget, tr(source_title))


def apply_language(root: QWidget) -> None:
    """把当前语言应用到已经创建的控件树。"""
    global _TRANSLATING
    _TRANSLATING = True
    try:
        widgets = [root]
        widgets.extend(root.findChildren(QWidget))
        for widget in widgets:
            _retranslate_widget(widget)
        for action in root.findChildren(QAction):
            source = getattr(action, "_i18n_src", None)
            if source is None:
                source = action.text()
                action._i18n_src = source
            _ORIG["QAction.setText"](action, tr(source))
        for menu in root.findChildren(QMenu):
            source = getattr(menu, "_i18n_src", None)
            if source is None:
                source = menu.title()
                menu._i18n_src = source
            _ORIG["QMenu.setTitle"](menu, tr(source))
    finally:
        _TRANSLATING = False


_install_patches()
