# Security Policy

## Scope

Tscan License is a local Windows software inventory and license-risk scanner. It is designed to collect installed-software metadata and risk indicators for IT/software asset management.

The tool must not be used to crack, bypass, patch, remove activation, harvest license keys, or hide unauthorized software.

## Data Handling

The desktop app stores scan history locally under:

```text
%LOCALAPPDATA%\T-SpaceScan\
```

Current builds do not upload telemetry or reports automatically. Exports are created only when the user chooses an export action.

Reports may contain:

- Computer/user metadata
- Installed software names
- Publishers and versions
- Install paths
- Executable paths
- Digital signature metadata
- License classification signals
- Risk findings

Reports should be treated as internal IT/security data.

## Reporting Vulnerabilities

Please open a GitHub Security Advisory or a private issue with:

- Affected version or commit
- Reproduction steps
- Expected and actual behavior
- Any relevant logs from `%LOCALAPPDATA%\T-SpaceScan\logs`

Do not post secrets, production reports, or private company inventory data in public issues.

## Token Hygiene

Never commit GitHub tokens, API keys, software license keys, or private report exports. Rotate any token that was pasted into a chat, issue, terminal transcript, or log.
