param(
    [switch]$NoClean
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    throw "Python not found. Install Python 3.10+ and add it to PATH."
}

$name = "CTFusion v2.0"
$distRoot = Join-Path $PSScriptRoot "dist"
$argsList = @(
    "-m", "PyInstaller",
    "--noconfirm",
    "--onedir",
    "--windowed",
    "--name", $name,
    "--icon", "assets\CTFusion.ico",
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

Remove-Item -LiteralPath (Join-Path $PSScriptRoot "build") -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $PSScriptRoot "CTFusion.spec") -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $PSScriptRoot "CTFusion v2.0.spec") -Force -ErrorAction SilentlyContinue
Get-ChildItem -LiteralPath $PSScriptRoot -Recurse -Directory -Filter "__pycache__" |
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "Done: $exe"
Write-Host "Ship this whole folder: $(Split-Path $exe -Parent)"
