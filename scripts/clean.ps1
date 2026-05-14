$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

foreach ($path in @("build", "dist", ".pytest_cache", ".mypy_cache")) {
    if (Test-Path -LiteralPath $path) {
        Remove-Item -LiteralPath $path -Recurse -Force
    }
}

Get-ChildItem -Path . -Recurse -Directory -Filter __pycache__ | ForEach-Object {
    Remove-Item -LiteralPath $_.FullName -Recurse -Force
}

Get-ChildItem -Path . -Filter "*.spec" | Remove-Item -Force
