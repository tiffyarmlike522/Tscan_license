$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

if (-not (Test-Path ".\.venv\Scripts\python.exe")) {
    python -m venv .venv
}

.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install pyinstaller

Get-Process -Name TSpaceScan -ErrorAction SilentlyContinue | Stop-Process -Force

.\.venv\Scripts\pyinstaller.exe `
    --clean `
    --noconfirm `
    --onefile `
    --windowed `
    --name TSpaceScan `
    --paths src `
    --add-data "data\license_rules.json;data" `
    run_app.py

$exe = Join-Path $Root "dist\TSpaceScan.exe"
if (-not (Test-Path $exe)) {
    throw "Build failed: $exe was not created."
}

Write-Host "Built $exe"
Get-FileHash -Algorithm SHA256 $exe
