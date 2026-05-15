# Antivirus False Positives

Tscan License is a software inventory and license-risk review tool. It must not include antivirus evasion, packer tricks, obfuscation, bypass behavior, or activation-circumvention functionality.

## Why A Beta Build May Be Flagged

Windows Defender and other security products may flag new unsigned executables, especially when they are:

- Built with Python-to-exe packagers.
- Distributed as a PyInstaller `--onefile` self-extracting executable.
- Rare or newly published with little reputation.
- Unsigned.
- Running system inventory logic.
- Launching PowerShell or other system utilities.

## Legitimate Mitigations

Recommended actions:

- Prefer the Inno Setup installer built from the PyInstaller `onedir` app instead of a PyInstaller `onefile` portable executable.
- Do not use UPX or executable obfuscators.
- Code-sign the installer and application executable with a trusted certificate.
- Keep the source public and release checksums.
- Submit false-positive samples to Microsoft Security Intelligence and other vendors.
- Avoid suspicious command-line flags such as `ExecutionPolicy Bypass`.
- Keep all scan behavior transparent and documented.

## What Not To Do

Do not add code intended to hide from antivirus, disable Defender, bypass security policy, evade detection, or mislead users.
