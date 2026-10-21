# ATT&CK coverage

![coverage map](coverage.svg)

| Branch | Technique | Name | Status | Rules |
|---|---|---|---|---|
| Identity | T1566 | Phishing | gap | - |
| Identity | T1528 | Steal Application Access Token | tested | Entra ID Sign-In Using Device Code Flow, Entra ID User Consent Granted to an Application |
| Identity | T1539 | Steal Web Session Cookie | gap | - |
| Identity | T1550.004 | Use Alternate Auth Material: Web Session Cookie | tested | Entra ID User Session Active From Multiple IPs Within One Hour |
| Identity | T1078.004 | Valid Accounts: Cloud Accounts | tested | Entra ID User Session Active From Multiple IPs Within One Hour |
| Data | T1213.002 | Data from Info Repositories: SharePoint | gap | - |
| Data | T1530 | Data from Cloud Storage | gap | - |
| Data | T1567 | Exfiltration Over Web Service | gap | - |
| AWS | T1552.001 | Unsecured Credentials: Credentials In Files | gap | - |
| AWS | T1098.003 | Account Manipulation: Additional Cloud Roles | gap | - |
| AWS | T1537 | Transfer Data to Cloud Account | gap | - |
