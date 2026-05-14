# Tscan License

Windows desktop beta for installed-software inventory, license classification, and license-compliance risk signaling.

Tscan License helps IT admins inventory Windows software, separate free/open-source/runtime/driver components from license-review applications, and export reports for software asset management.

Download beta builds from [GitHub Releases](https://github.com/hntngoctu1/Tscan_license/releases).

> Beta notice: findings are risk indicators, not proof of unauthorized software. Always verify license status with vendor portals, procurement records, contracts, or internal entitlement systems.

## What The Professional Prototype Does

- Scans Windows uninstall Registry keys under HKLM and HKCU.
- Supplements entries from Program Files, AppData top-level folders, and Start Menu shortcuts.
- Collects software name, publisher, version, install date, install path, executable path, website, estimated size, and install type.
- Classifies license type with offline JSON rules and local license files.
- Verifies executable digital signatures through Windows Authenticode/PowerShell when enabled.
- Detects risk signals such as suspicious keywords, hosts-file activation blocking, missing publisher metadata, signature anomalies, blacklist policy matches, and missing license evidence for commercial software.
- Stores scan sessions, software items, findings, settings, whitelist, and blacklist in SQLite.
- Provides a desktop UI with dashboard charts, search, filters, sorting, detail panel, scan history, session compare, settings, whitelist/blacklist management, dark mode, and CSV/JSON/PDF/XLSX export.
- Adds app grouping so review-needed apps, free/open-source apps, freemium apps, developer runtimes, drivers, system tools, and helper shortcuts are separated while still listing all installed software.
- Shows a scan progress animation/status while inventory collection is running.
- Writes debug logs to `%LOCALAPPDATA%\T-SpaceScan\logs\tspace_scan.log`.

The scanner reports signals, not proof of piracy. It intentionally does not crack, bypass, remove activation, generate keys, or alter third-party software.

## Run

Download `TSpaceScan.exe` from GitHub Releases, or run from source:

```powershell
python .\run_app.py
```

or:

```powershell
.\scripts\run.ps1
```

The local database and default reports are stored under:

```text
%LOCALAPPDATA%\T-SpaceScan\
```

## Test

```powershell
python -m unittest discover -s tests
python -m compileall src run_app.py tests
python .\run_app.py --smoke-test
```

or:

```powershell
.\scripts\test.ps1
```

## Project Layout

```text
data/license_rules.json             Offline classification rules
docs/TECHNICAL_DESIGN.md            Product and engineering design A-N
run_app.py                          Direct launcher
scripts/build.ps1                   Windows executable build
scripts/test.ps1                    Test and smoke-test runner
scripts/run.ps1                     PowerShell launcher
src/tspace_scan/app_classifier.py   App grouping and priority classification
src/tspace_scan/database.py         SQLite schema and persistence
src/tspace_scan/filesystem_scanner.py
src/tspace_scan/license_classifier.py
src/tspace_scan/registry_scanner.py
src/tspace_scan/reports.py
src/tspace_scan/risk_analyzer.py
src/tspace_scan/scanner.py          Scanner orchestration
src/tspace_scan/ui.py               Tkinter desktop UI
tests/test_scoring.py               Focused classifier/risk tests
```

## Packaging Direction

Build the Windows executable:

```powershell
.\scripts\build.ps1
```

The built file is:

```text
dist\TSpaceScan.exe
```

For a commercial product, prefer a signed installer, auto-update, MSIX/MSI packaging, and enterprise policy support.

## Privacy And Safety

- No telemetry is uploaded by default.
- Scan history is stored locally in `%LOCALAPPDATA%\T-SpaceScan\`.
- Reports may contain software names, publishers, paths, machine/user metadata, and risk findings.
- The tool does not collect license keys and must not be extended to crack, bypass, patch, or hide software activation.
