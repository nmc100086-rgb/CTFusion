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
dist\CTFusion v2.0\CTFusion v2.0.exe
```

这是 PyInstaller **onedir 便携版**：`CTFusion v2.0.exe` 必须和同目录的 `_internal` 文件夹放在一起，整个 `dist\CTFusion v2.0` 目录一起分发。

之所以不再使用 onefile：onefile 每次启动都要把 100MB+ 运行库解压到临时目录，在带杀软的机器上启动会非常慢；onedir 实测启动约 3~5 秒。

## 依赖

```powershell
pip install -r requirements.txt -r requirements-build.txt
```

- `PySide6`：图形界面
- `pycryptodome`：AES / RC4
- `pyinstaller`：仅重新打包时需要

## 说明

- 修改源码后必须重新运行 `rebuild.ps1`，已经生成的 exe 不会自动更新。
- JSFuck 解码仍依赖系统里的 `node` 命令。
- ZIP 密码恢复支持 ZipCrypto；AES/WinZip 加密 ZIP 请使用 7-Zip 或 ARCHPR。
- ZipCrypto 四位纯数字密码在当前实现下通常 1 秒内完成。
