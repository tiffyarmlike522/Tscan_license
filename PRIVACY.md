# Privacy

Tscan License is designed as a local-first Windows desktop tool.

## Default Behavior

- The app does not upload telemetry by default.
- The app does not send scan reports to the developer by default.
- The app does not collect or store software license keys.
- Scan history, settings, logs, and the local SQLite database are stored on the user's computer.

Default local data location:

```text
%LOCALAPPDATA%\T-SpaceScan\
```

## Data The App May Display Or Export

When a user scans a computer or exports a report, the data may include:

- Computer and user metadata available to the local Windows account
- Installed software names
- Publishers and versions
- Install paths and executable paths
- Digital signature metadata
- License classification results
- Risk indicators and recommendations

Exported reports should be treated as internal IT/security documents because they may reveal installed software, folder paths, and business tooling.

## Network Access

Current beta builds do not require network access for scanning. Future optional integrations, such as vulnerability lookup or reputation services, should require explicit user/admin configuration.

## Enterprise Use

IT administrators should inform users before collecting software inventory from company devices. If reports are centralized in the future, the transport, retention policy, and access control should be documented clearly before deployment.
