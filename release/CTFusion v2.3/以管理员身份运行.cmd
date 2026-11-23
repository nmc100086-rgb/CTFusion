@echo off
rem Start CTFusion with administrator rights (UAC prompt).
set "APPDIR=%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%APPDIR%CTFusion v2.3.exe' -Verb RunAs"