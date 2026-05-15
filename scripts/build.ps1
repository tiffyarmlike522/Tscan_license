param(
    [switch]$Portable
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

if (-not (Test-Path ".\.venv\Scripts\python.exe")) {
    python -m venv .venv
}

.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install pyinstaller

Get-Process -Name TscanLicense -ErrorAction SilentlyContinue | Stop-Process -Force
Get-Process -Name TSpaceScan -ErrorAction SilentlyContinue | Stop-Process -Force

foreach ($target in @(
    (Join-Path $Root "dist\TscanLicense"),
    (Join-Path $Root "dist\TscanLicense.exe"),
    (Join-Path $Root "dist\TscanLicensePortable.exe"),
    (Join-Path $Root "dist\TscanLicenseSetup.exe"),
    (Join-Path $Root "dist\TscanLicense.exe.sha256.txt"),
    (Join-Path $Root "dist\TscanLicensePortable.exe.sha256.txt"),
    (Join-Path $Root "dist\TscanLicenseSetup.exe.sha256.txt")
)) {
    if (Test-Path -LiteralPath $target) {
        Remove-Item -LiteralPath $target -Recurse -Force
    }
}

$commonArgs = @(
    "--clean",
    "--noconfirm",
    "--windowed",
    "--name",
    "TscanLicense",
    "--paths",
    "src",
    "--add-data",
    "data\license_rules.json;data",
    "run_app.py"
)

.\.venv\Scripts\pyinstaller.exe @commonArgs

$exe = Join-Path $Root "dist\TscanLicense\TscanLicense.exe"
if (-not (Test-Path $exe)) {
    throw "Build failed: $exe was not created."
}

Write-Host "Built installed app $exe"
Get-FileHash -Algorithm SHA256 $exe

if ($Portable) {
    .\.venv\Scripts\pyinstaller.exe `
    --clean `
    --noconfirm `
    --onefile `
    --windowed `
    --name TscanLicensePortable `
    --paths src `
    --add-data "data\license_rules.json;data" `
    run_app.py

    $portableExe = Join-Path $Root "dist\TscanLicensePortable.exe"
    if (-not (Test-Path $portableExe)) {
        throw "Build failed: $portableExe was not created."
    }

    Write-Host "Built portable app $portableExe"
    Get-FileHash -Algorithm SHA256 $portableExe
}

$iscc = Get-Command iscc.exe -ErrorAction SilentlyContinue
$isccPath = if ($iscc) { $iscc.Source } else { "" }
if (-not $isccPath) {
    foreach ($candidate in @(
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
        "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
        "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
    )) {
        if ($candidate -and (Test-Path -LiteralPath $candidate)) {
            $isccPath = $candidate
            break
        }
    }
}

if ($isccPath) {
    & $isccPath ".\installer\TscanLicense.iss"
    $setup = Join-Path $Root "dist\TscanLicenseSetup.exe"
    if (Test-Path $setup) {
        Write-Host "Built $setup"
        Get-FileHash -Algorithm SHA256 $setup
    }
} else {
    Write-Host "Inno Setup compiler not found; skipped installer build."
}
