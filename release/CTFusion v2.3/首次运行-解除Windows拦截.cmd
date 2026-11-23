@echo off
rem Unblock downloaded files (Mark-of-the-Web) and start CTFusion.
set "APPDIR=%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-ChildItem -LiteralPath '%APPDIR%' -Recurse -File -Force -ErrorAction SilentlyContinue | Unblock-File -ErrorAction SilentlyContinue"
start "" "%APPDIR%CTFusion v2.3.exe"