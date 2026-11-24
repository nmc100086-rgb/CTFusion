param(
    [switch]$NoClean,
    [string]$OutputRoot = ""
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    throw "Python not found. Install Python 3.10+ and add it to PATH."
}

$bkcrack = Join-Path $PSScriptRoot "bin\bkcrack.exe"
if (-not (Test-Path -LiteralPath $bkcrack)) {
    throw "Missing bin\bkcrack.exe. Download bkcrack 1.8.1 win64 from https://github.com/kimci86/bkcrack/releases and put bkcrack.exe in bin\."
}
$expectedHash = "D3DE2E1494C8DB2A1550794CAE4923956D76DA9314E68198096F4B03F7F310D5"
$actualHash = (Get-FileHash -LiteralPath $bkcrack -Algorithm SHA256).Hash
if ($actualHash -ne $expectedHash) {
    Write-Warning "bin\bkcrack.exe SHA-256 differs from the tested 1.8.1 build; packaging will continue."
}

$name = "CTFusion v2.3.1"
$distRoot = if ($OutputRoot) {
    Join-Path $PSScriptRoot $OutputRoot
} else {
    Join-Path $PSScriptRoot "dist"
}
$argsList = @(
    "-m", "PyInstaller",
    "--noconfirm",
    "--onedir",
    "--windowed",
    "--name", $name,
    "--icon", "assets\CTFusion.ico",
    "--add-data", "assets\CTFusion.png;assets",
    "--add-binary", "bin\bkcrack.exe;bin",
    "--add-data", "bin\bkcrack-license.txt;bin",
    "--add-data", "bin\bkcrack-readme.md;bin",
    "--add-data", "bin\bkcrack-version.txt;bin",
    "--add-data", "bin\zxingcpp-license.txt;bin",
    "--add-data", "bin\zxingcpp-version.txt;bin",
    "--add-data", "bin\Pillow-license.txt;bin",
    "--add-data", "bin\Pillow-version.txt;bin",
    "--hidden-import", "zxingcpp",
    "--hidden-import", "PIL.Image",
    "--hidden-import", "PIL.PngImagePlugin",
    "--hidden-import", "PIL.JpegImagePlugin",
    "--hidden-import", "PIL.GifImagePlugin",
    "--hidden-import", "win32com",
    "--hidden-import", "win32com.propsys",
    "--hidden-import", "pythoncom",
    "--hidden-import", "pywintypes",
    "--version-file", "packaging\version_info.txt",
    "--distpath", $distRoot,
    "--workpath", (Join-Path $PSScriptRoot "build"),
    "--specpath", $PSScriptRoot,
    "--exclude-module", "PySide6.QtNetwork",
    "--exclude-module", "PySide6.QtQml",
    "--exclude-module", "PySide6.QtQuick",
    "--exclude-module", "PySide6.QtPdf",
    "--exclude-module", "PySide6.QtOpenGL",
    "--exclude-module", "PySide6.QtSvg",
    "--exclude-module", "PySide6.QtXml"
)
if (-not $NoClean) {
    $argsList += "--clean"
}
$argsList += "main.py"

python @argsList
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

$exe = Join-Path $distRoot "$name\$name.exe"
if (-not (Test-Path -LiteralPath $exe)) {
    throw "Output not found: $exe"
}

Write-Host "Running packaged self-test..."
$test = Start-Process -FilePath $exe -ArgumentList "--self-test" -Wait -PassThru
if ($test.ExitCode -ne 0) {
    throw "Packaged self-test failed with exit code $($test.ExitCode)"
}

# First-run helper: clear the Mark-of-the-Web, then start the program, so
# SmartScreen only appears the first time. The Chinese file name is decoded
# from UTF-8 bytes to keep this script ASCII-only (Windows PowerShell 5.1
# reads BOM-less scripts with the ANSI code page).
$launcherName = [Text.Encoding]::UTF8.GetString(
    [Convert]::FromBase64String(
        '6aaW5qyh6L+Q6KGMLeino+mZpFdpbmRvd3Pmi6bmiKouY21k'))
$launcher = Join-Path (Split-Path -Path $exe -Parent) $launcherName
$launcherBody = @"
@echo off
rem Unblock downloaded files (Mark-of-the-Web) and start CTFusion.
set "APPDIR=%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-ChildItem -LiteralPath '%APPDIR%' -Recurse -File -Force -ErrorAction SilentlyContinue | Unblock-File -ErrorAction SilentlyContinue"
start "" "%APPDIR%$name.exe"
"@
Set-Content -LiteralPath $launcher -Value $launcherBody -Encoding ASCII -NoNewline

# Administrator launcher: full write access (UAC prompt on each start).
$adminName = [Text.Encoding]::UTF8.GetString(
    [Convert]::FromBase64String(
        '5Lul566h55CG5ZGY6Lqr5Lu96L+Q6KGMLmNtZA=='))
$adminLauncher = Join-Path (Split-Path -Path $exe -Parent) $adminName
$adminBody = @"
@echo off
rem Start CTFusion with administrator rights (UAC prompt).
set "APPDIR=%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%APPDIR%$name.exe' -Verb RunAs"
"@
Set-Content -LiteralPath $adminLauncher -Value $adminBody -Encoding ASCII -NoNewline

Remove-Item -LiteralPath (Join-Path $PSScriptRoot "build") -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $PSScriptRoot "CTFusion.spec") -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $PSScriptRoot "$name.spec") -Force -ErrorAction SilentlyContinue
Get-ChildItem -LiteralPath $PSScriptRoot -Recurse -Directory -Filter "__pycache__" -ErrorAction SilentlyContinue |
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "Done: $exe"
Write-Host "Ship this whole folder: $(Split-Path $exe -Parent)"
exit 0
