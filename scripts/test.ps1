$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
python -m unittest discover -s tests
python -m compileall src run_app.py tests
python .\run_app.py --smoke-test
