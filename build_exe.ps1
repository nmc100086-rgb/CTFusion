param(
    [switch]$NoClean
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

$name = "CTFusion v2.2"
$distRoot = Join-Path $PSScriptRoot "dist"
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

Remove-Item -LiteralPath (Join-Path $PSScriptRoot "build") -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $PSScriptRoot "CTFusion.spec") -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $PSScriptRoot "$name.spec") -Force -ErrorAction SilentlyContinue
Get-ChildItem -LiteralPath $PSScriptRoot -Recurse -Directory -Filter "__pycache__" |
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "Done: $exe"
Write-Host "Ship this whole folder: $(Split-Path $exe -Parent)"
exit 0
