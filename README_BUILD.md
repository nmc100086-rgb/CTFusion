# CTFusion 源码 / 重新打包

项目源码就在当前目录。

## 重新打包

```powershell
.\rebuild.ps1
```

如果系统禁止运行脚本：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\rebuild.ps1
```

输出：

```text
dist\CTFusion v2.3\CTFusion v2.3.exe
dist\CTFusion v2.3\_internal\bin\bkcrack.exe
```

这是 PyInstaller **onedir 便携版**：`CTFusion v2.3.exe` 必须和同目录的 `_internal` 文件夹放在一起，整个 `dist\CTFusion v2.3` 目录一起分发。

之所以不再使用 onefile：onefile 每次启动都要把 100MB+ 运行库解压到临时目录，在带杀软的机器上启动会非常慢；onedir 实测启动约 3~5 秒。

## 依赖

```powershell
pip install -r requirements.txt -r requirements-build.txt
```

- `PySide6`：图形界面
- `pycryptodome`：AES / RC4
- `Pillow`：二维码图片解码
- `zxing-cpp`：二维码 / 条码识别
- `pyinstaller`：仅重新打包时需要

## 说明

- 修改源码后必须重新运行 `rebuild.ps1`，已经生成的 exe 不会自动更新。
- JSFuck 解码仍依赖系统里的 `node` 命令。
- ZIP 密码恢复支持 ZipCrypto；AES 加密 ZIP 请使用支持 AES 的解压工具。
- ZipCrypto 四位纯数字密码在当前实现下通常 1 秒内完成。
- `bin\bkcrack.exe` 是第三方程序（bkcrack 1.8.1, kimci86, zlib license），打包脚本会把它放到 `_internal\bin\bkcrack.exe`；缺少时会直接报错。
- 打包脚本最后会运行 `CTFusion v2.3.exe --self-test`，验证 bkcrack、CRC32 反查、Hex→ZIP、乱码修复、二维码识别和版本号解析正常。
- 打包脚本会在输出目录生成 `首次运行-解除Windows拦截.cmd`：第一次运行时先解除“下载文件”标记（`Unblock-File`）再启动程序，之后 Windows 不再重复拦截未签名 exe。
- 保存文件时不再限制目录；只有 Windows 真正拒绝写入时才会请求一次管理员权限（`core/elevate.py`，通过 `--elevated-write` 启动同一个 exe 写单个/单批文件）。提权进程不加载 Qt、不显示界面，写完即退出。
- 更新检查从 v2.3 起启用；打包后的程序只读取 GitHub 公开版本信息，不会自动下载；同一个新版本只会提示一次。
- `bin\zxingcpp-license.txt` 与 `bin\Pillow-license.txt` 会一并打包到 `_internal\bin`，再分发时请保留。
