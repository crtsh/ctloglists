# ctloglists

Tracker for CT Log Lists and logs' Accepted Roots

## Features

- Bundles and parses the following CT Log Lists:
  - For Server Authentication Certificates:
    - Chrome [all_logs_list.json](https://googlechrome.github.io/CertificateTransparency/log_lists.html)
    - Apple [current_log_list.json](https://support.apple.com/en-us/103214)
    - Mozilla [Known CT Logs](https://wiki.mozilla.org/SecurityEngineering/Certificate_Transparency#Known_CT_Logs)
  - For Mark Certificates:
    - BIMIGroup [Approved CT Logs (see Appendix F)](https://bimigroup.org/resources/VMC_Requirements_latest.pdf).
  - Also:
    - crt.sh [logs.json?include=all](https://crt.sh/v3/logs.json?include=all)
    - Chrome ["log mimics"](https://googlechrome.github.io/CertificateTransparency/3p_libraries.html#freezing-log-lists-and-adding-mimic-logs)

- Bundles and parses logs' Accepted Roots.

- Automated handling of Log List updates and Accepted Roots updates, via GitHub Actions.

## Versioning

The latest Log Lists and Accepted Roots are fetched hourly by a GitHub Action. Any changes are automatically committed. If one or more Log Lists have been updated, a Release is tagged using a [Scalable Calendar Versioning](https://www.reddit.com/r/golang/comments/1jzucpw/scalable_calendar_versioning_calver_semver/) format (`v1.YYYYMMDD.HHMMSS`).

## API

### `LoadLogLists() error`
Loads and parses all bundled CT Log Lists.

### `LoadAcceptedRoots() error`
Loads and parses all bundled Accepted Roots data.

### `OldestTimestampForLogListWithEnforcementCutOff() time.Time`
Returns the oldest `LogListTimestamp` among the supported log lists that are known to have a corresponding 70-day enforcement cut-off (Chrome, Apple, Mozilla). Log lists with an omitted or zero timestamp are ignored.

### Exported Variables

| Variable | Description |
|----------|-------------|
| `GstaticV3All` | Chrome's all_logs_list.json |
| `AppleCurrent` | Apple's current_log_list.json |
| `CrtshV3All` | crt.sh all logs |
| `CrtshV3Active` | crt.sh active logs |
| `MozillaV3Known` | Mozilla's known_logs_list.json |
| `BimiV3Approved` | BIMI approved_logs_list.json |
| `LogMimics` | Chrome log mimics |
| `LogSignatureVerifierMap` | Map of log ID → signature verifier |
| `TemporalIntervalMap` | Map of log ID → temporal interval |
| `AcceptedRootsMap` | Map of roots list hash → PEM cert pool |
| `LogAcceptedRootsMap` | Map of log ID → accepted roots list hash |

## Used by

- [ctlint](https://github.com/crtsh/ctlint): CT compliance linter.
- [ctsubmit](https://github.com/crtsh/ctsubmit): CT submission proxy.