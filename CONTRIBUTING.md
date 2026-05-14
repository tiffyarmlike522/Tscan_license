# Contributing

Thanks for helping improve T-Space Scan.

## Development Setup

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install pyinstaller
```

Run tests:

```powershell
python -m unittest discover -s tests
python -m compileall src run_app.py tests
```

Run the app:

```powershell
python .\run_app.py
```

Build the Windows executable:

```powershell
.\scripts\build.ps1
```

## Rule Contributions

License classification rules live in:

```text
data/license_rules.json
```

Rules should be conservative. If a license cannot be determined reliably, prefer `Unknown` over guessing.

## Safety Guidelines

- Do not add crack, bypass, keygen, or activation-circumvention functionality.
- Do not collect software license keys.
- Do not upload reports without explicit user/admin configuration.
- Avoid high-confidence claims unless the signal is strong and explainable.
