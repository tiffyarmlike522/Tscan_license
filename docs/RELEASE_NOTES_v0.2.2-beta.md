# Tscan License v0.2.2-beta

Free Windows software license scanner for installed-software inventory, software asset management, and license-compliance risk review.

## Download

- `TscanLicenseSetup.exe` - recommended one-file installer with Start Menu shortcut and uninstaller.

No Python or terminal is required for normal users.

## Why This Release Uses An Installer

This release uses a normal installer built from a PyInstaller `onedir` application instead of publishing a PyInstaller `onefile` portable executable as the primary download. This is intended to reduce antivirus false positives from self-extracting one-file executables.

## Highlights

- Installed software inventory from Windows Registry, Program Files, AppData, and Start Menu shortcuts.
- License classification for free, open-source, freemium, trial, paid, subscription, and unknown software.
- Risk score from 0 to 100 with explainable findings.
- Digital signature checks for executable files.
- Dashboard, filters, scan history, comparison, details panel, dark mode, whitelist, and blacklist.
- PDF, Excel, CSV, and JSON exports.

## Privacy And Safety

- No telemetry is uploaded by default.
- Reports are exported only when the user chooses an export action.
- Findings are risk indicators, not legal conclusions.
- The project does not crack software, generate keys, bypass activation, or collect license keys.

## Known Limitation

This beta build is not code-signed yet, so Windows SmartScreen or antivirus products may still warn until the project builds reputation or the binaries are code-signed.
