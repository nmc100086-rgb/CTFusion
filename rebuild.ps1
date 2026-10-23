param(
    [switch]$NoClean
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

& (Join-Path $PSScriptRoot "build_exe.ps1") @PSBoundParameters
