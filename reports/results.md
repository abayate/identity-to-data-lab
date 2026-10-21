# Replay results

| Rule | Events | Hits | TP | FP | Auto-closed | FP rate | FP rate after triage |
|---|---|---|---|---|---|---|---|
| AWS Burst of Access-Denied API Calls by One Identity | 1333 | 2 | 2 | 0 | 0 | 0.0% | 0.0% |
| AWS Access Key Created for a Different IAM User | 1333 | 56 | 28 | 28 | 23 | 73.7% | 13.2% |
| AWS EBS Snapshot Shared With Another Account or Made Public | 1333 | 6 | 6 | 0 | 0 | 0.0% | 0.0% |
| AWS IAM Policy Version Set as Default With Wildcard Actions | 1333 | 3 | 3 | 0 | 0 | 0.0% | 0.0% |
| AWS IAM Role Created Trusting Any Principal or a Whole Account | 1333 | 2 | 2 | 0 | 0 | 0.0% | 0.0% |
| AWS S3 Mass Object Download by One Identity | 1333 | 1 | 1 | 0 | 0 | 0.0% | 0.0% |
| Data Access Within One Hour of a Multi-IP Entra Session | 332 | 1 | 1 | 0 | 0 | 0.0% | 0.0% |
| M365 Mass File Access or Download by One User | 289 | 4 | 4 | 0 | 0 | 0.0% | 0.0% |
| M365 File Download With Rclone User Agent | 289 | 58 | 58 | 0 | 0 | 0.0% | 0.0% |
| M365 Search for Credential or Payroll Terms | 289 | 12 | 12 | 0 | 0 | 0.0% | 0.0% |
| Entra ID Sign-In Using Device Code Flow | 43 | 1 | 1 | 0 | 0 | 0.0% | 0.0% |
| Entra ID User Consent Granted to an Application | 5 | 1 | 1 | 0 | 0 | 0.0% | 0.0% |
| Entra ID User Session Active From Multiple IPs Within One Hour | 43 | 3 | 3 | 0 | 0 | 0.0% | 0.0% |

**Malicious events caught by at least one rule:** 1563 / 1611
