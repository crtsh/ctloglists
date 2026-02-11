# ctloglists

CT log list tracker

## Features

- Bundles and parses the following log lists:
  - For Server Authentication Certificates:
    - Chrome [all_logs_list.json](https://googlechrome.github.io/CertificateTransparency/log_lists.html)
    - Apple [current_log_list.json](https://support.apple.com/en-us/103214)
    - Mozilla [Known CT Logs](https://wiki.mozilla.org/SecurityEngineering/Certificate_Transparency#Known_CT_Logs)
  - For Mark Certificates:
    - BIMIGroup [Approved CT Logs (see Appendix F)](https://bimigroup.org/resources/VMC_Requirements_latest.pdf).
  - Also:
    - crt.sh [logs.json?include=all](https://crt.sh/v3/logs.json?include=all)
    - Chrome ["log mimics"](https://groups.google.com/a/chromium.org/g/ct-policy/c/qY3aOKr5-sU/m/P4nzWuNHCwAJ)

- Automated handling of log list updates, via GitHub Actions.

## Used by

- [ctlint](https://github.com/crtsh/ctlint): CT compliance linter.
- [ctsubmit](https://github.com/crtsh/ctsubmit): CT submission proxy.