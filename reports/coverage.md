# ATT&CK coverage

![coverage map](coverage.svg)

| Branch | Technique | Name | Status | Rules |
|---|---|---|---|---|
| Identity | T1566 | Phishing | gap | - |
| Identity | T1528 | Steal Application Access Token | tested | Entra ID Sign-In Using Device Code Flow, Entra ID User Consent Granted to an Application |
| Identity | T1539 | Steal Web Session Cookie | gap | - |
| Identity | T1550.004 | Use Alternate Auth Material: Web Session Cookie | tested | Entra ID User Session Active From Multiple IPs Within One Hour |
| Identity | T1078.004 | Valid Accounts: Cloud Accounts | tested | Data Access Within One Hour of a Multi-IP Entra Session, Entra ID User Session Active From Multiple IPs Within One Hour |
| Data | T1213.002 | Data from Info Repositories: SharePoint | tested | M365 Search for Credential or Payroll Terms |
| Data | T1530 | Data from Cloud Storage | tested | Data Access Within One Hour of a Multi-IP Entra Session, M365 Mass File Access or Download by One User, M365 File Download With Rclone User Agent |
| Data | T1114.002 | Email Collection: Remote Email Collection | tested | Data Access Within One Hour of a Multi-IP Entra Session |
| Data | T1567 | Exfiltration Over Web Service | tested | M365 Mass File Access or Download by One User, M365 File Download With Rclone User Agent |
| AWS | T1552.001 | Unsecured Credentials: Credentials In Files | gap | - |
| AWS | T1098.003 | Account Manipulation: Additional Cloud Roles | gap | - |
| AWS | T1537 | Transfer Data to Cloud Account | gap | - |
