# Detections

Every rule is a Sigma file in `detections/`, tested by `tests/test_detections.py`
against the labeled public-dataset logs in `data/sample-logs/`. Each section below
gives what the rule catches, why it works, a KQL equivalent for Microsoft Sentinel,
how to tune it, and its result in this lab.

**How to read the results:** the numbers come from `python harness/replay.py`. A rule
"fires" when it raises an alert. An alert is a true positive (TP) if it contains a
malicious event, and a false positive (FP) if it is all benign. The benign baseline
in this lab is small (21 events, see `data/sample-logs/README.md`), so **0 FP here
means "no false positives on the data available," not "won't be noisy in production."**
Each rule's tuning notes say where production noise would come from.

## Rule index

| Rule | File | Log source | ATT&CK | TP alerts | FP alerts |
|---|---|---|---|---|---|
| Entra ID Sign-In Using Device Code Flow | `detections/entra/entra_device_code_signin.yml` | SigninLogs | T1528 | 1 | 0 |
| Entra ID User Consent Granted to an Application | `detections/entra/entra_oauth_consent_granted.yml` | AuditLogs | T1528 | 1 | 0 |
| Entra ID User Session Active From Multiple IPs Within One Hour | `detections/entra/entra_user_signin_multiple_ips.yml` | SigninLogs | T1550.004, T1078.004 | 3 | 0 |
| M365 Mass File Access or Download by One User | `detections/data/m365_mass_file_access.yml` | OfficeActivity | T1530, T1567 | 4 | 0 |
| M365 File Download With Rclone User Agent | `detections/data/m365_rclone_download.yml` | OfficeActivity | T1567, T1530 | 58 | 0 |
| M365 Search for Credential or Payroll Terms | `detections/data/m365_sensitive_term_search.yml` | OfficeActivity | T1213.002 | 12 | 0 |
| Data Access Within One Hour of a Multi-IP Entra Session | `detections/data/identity_to_data_access_after_multi_ip_session.yml` | SigninLogs + OfficeActivity | T1530, T1114.002, T1078.004 | 1 | 0 |

**Whole chain:** 274 of 316 malicious events (87%) are part of at least one alert.

## Entra identity detections

### Entra ID Sign-In Using Device Code Flow

**Catches:** device-code phishing. The attacker starts the device authorization flow,
sends the victim the code ("enter this at microsoft.com/devicelogin"), and when the
victim completes it, the attacker's device receives the victim's tokens.

**Why it works:** the token-issuing sign-in is logged with
`AuthenticationProtocol = deviceCode`. Ordinary users almost never use this flow; it's
meant for TVs, CLIs and meeting-room devices.

**Sigma logic:** `AuthenticationProtocol: deviceCode`

```kql
SigninLogs
| where AuthenticationProtocol == "deviceCode"
| project TimeGenerated, UserPrincipalName, IPAddress, AutonomousSystemNumber,
          AppDisplayName, ResultType, UserAgent
```

**Tuning:** expect hits from admins using Azure CLI / PowerShell and from shared
devices. Add a `known_benign.yml` entry per sanctioned app or admin group. The
stronger control is a Conditional Access policy that blocks device-code flow for
everyone except a named group; then any success outside that group is high severity.

**Lab result:** 1 TP alert (the device-code token issue in `device_code_phishing`),
0 FP. The victim's 8 normal sign-ins in the same file did not trigger it.

### Entra ID User Consent Granted to an Application

**Catches:** illicit consent grant / consent phishing. The victim approves an
attacker's multi-tenant app, which gets delegated access (mail, files) through tokens
the attacker holds. No password is stolen, so a password reset doesn't remove access.

**Why it works:** every user consent writes an `AuditLogs` event with
`OperationName = "Consent to application"`.

**Sigma logic:** `OperationName: Consent to application` and `Result: success`

```kql
AuditLogs
| where OperationName == "Consent to application" and Result =~ "success"
| extend User = tostring(InitiatedBy.user.userPrincipalName),
         App = tostring(TargetResources[0].displayName)
| project TimeGenerated, User, App, CorrelationId
```

**Tuning:** legitimate app consents are common where users are allowed to consent.
Restrict user consent to verified publishers and low-risk permissions, and every
remaining consent becomes rare enough to review. A stricter variant alerts only when
the granted scopes include `Mail.Read`, `Files.Read.All` or `offline_access`.

**Lab result:** 1 TP alert (`oauth_consent_grant`), 0 FP. The benign MFA-registration
audit event in the same file did not trigger it.

### Entra ID User Session Active From Multiple IPs Within One Hour

**Catches:** AiTM session-cookie replay. An adversary-in-the-middle proxy (Evilginx in
the public dataset) relays the victim's real login, MFA included, and captures the
session cookie. The attacker then imports the cookie into their own browser. MFA was
already satisfied, so the replay looks like a normal sign-in except that it comes from
a different IP while the session is still active.

**Why it works:** the same user shows successful sign-ins from two or more IPs within a
short window. This is a **correlation rule** (Sigma v2 `value_count`): a base rule picks
successful user sign-ins, then the correlation counts distinct `IPAddress` values per
`UserPrincipalName` within one hour.

**Why not "same session token from two IPs"?** That's the sharper signal, but the
public datasets don't include `SessionId`, and token identifiers are unique per event.
With a live tenant, group by `SessionId` instead of user (see `05-go-live.md`).

```kql
let window = 1h;
union SigninLogs, AADNonInteractiveUserSignInLogs
| where ResultType == "0" and isnotempty(UserPrincipalName)
| summarize IPs = make_set(IPAddress), IPCount = dcount(IPAddress),
            FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
    by UserPrincipalName, bin(TimeGenerated, window)
| where IPCount > 1
```

Note: KQL's `bin()` makes fixed hourly buckets, while the lab matcher uses a sliding
window. Two sign-ins at 09:55 and 10:05 are caught by the lab version, but fall in
different buckets in this KQL. A production version can use `row_window_session()` or
a self-join on a time range to get sliding behavior.

**Tuning:** this is the noisiest rule. Users roam (Wi-Fi to hotspot, VPN on/off), and
one device can show both IPv4 and IPv6 addresses. `tests/test_detections.py` includes
a hand-made roaming user that trips the rule, to keep that limitation visible. Tune
with `known_benign.yml` entries for corporate egress and VPN ranges, or compare ASN or
country instead of raw IP.

**Lab result:** 3 TP alerts: both Evilginx datasets, plus the device-code victim, whose
sign-ins from a second IP during the phish are also caught. 0 FP on the available
benign data, but see the roaming caveat above.

## Data-layer detections

These rules read M365 audit events (Sentinel table `OfficeActivity`). Field names
follow the Office 365 Management API, which Sentinel mostly keeps; a few columns get
renamed on ingestion (for example `SiteUrl` becomes `Site_Url`). Run
`OfficeActivity | getschema` on your workspace to confirm before deploying.

**Dataset caveat:** the SharePoint exfiltration and search datasets come from a
different test tenant than the sign-in datasets, so their users never sign in in our
logs. The full identity-to-data chain exists in one dataset (the Evilginx M365 one),
which is what the last rule below is tested on.

### M365 Mass File Access or Download by One User

**Catches:** bulk collection from SharePoint / OneDrive by any method. The public
dataset shows four: browser access (51 files in 6 seconds), zip download (58 files),
the sync client pulling a whole library (66 files), and rclone (58 files).

**Why it works:** speed and volume. Someone reading documents opens a few files in ten
minutes; a thief with a stolen session takes everything before access is cut off. In
the dataset, the twelve normal users each opened one file.

**Sigma logic:** correlation, `event_count` > 20 per `UserId` in 10 minutes, over
`FileAccessed`, `FilePreviewed`, `FileDownloaded` and `FileSyncDownloadedFull`.

```kql
OfficeActivity
| where Operation in ("FileAccessed", "FilePreviewed", "FileDownloaded", "FileSyncDownloadedFull")
| summarize Files = count(), FileNames = make_set(SourceFileName, 50), IPs = make_set(ClientIP)
    by UserId, bin(TimeGenerated, 10m)
| where Files > 20
```

**Tuning:** the classic FP is a user setting up a new laptop, whose OneDrive sync
downloads a whole library at once. A test (`test_mass_file_rule_known_false_positive_new_laptop_sync`)
keeps that visible. Backup, migration and eDiscovery accounts belong in
`known_benign.yml`. A stronger production version compares each user against their
own 30-day baseline instead of a fixed 20.

**Lab result:** 4 TP alerts (one per attacker account, every method), 0 FP; none of
the 12 normal users came close.

### M365 File Download With Rclone User Agent

**Catches:** exfiltration with rclone, a sync tool data-theft crews like because it
copies cloud libraries quickly and can send them straight to attacker storage.

**Sigma logic:** `Operation: FileDownloaded` and `UserAgent|contains: rclone`

```kql
OfficeActivity
| where Operation == "FileDownloaded" and UserAgent contains "rclone"
| project TimeGenerated, UserId, ClientIP, SourceFileName, Site_Url, UserAgent
```

**Tuning:** rare in business use, so high confidence when it fires. Two caveats: IT
staff may use rclone for sanctioned migrations, and the user agent is chosen by the
client, so an attacker can change it. That's why the mass-file rule exists alongside it.

**Lab result:** 58 TP alerts (one per downloaded file), 0 FP. In Sentinel, alert
grouping would roll these into one incident per user; the lab counts each event.

### M365 Search for Credential or Payroll Terms

**Catches:** an intruder searching the file store or mailbox for valuable content
(passwords, VPN access, payroll and direct-deposit details) before downloading it.

**Sigma logic:** search operations (`SearchQueryPerformed`, `SearchQueryInitiatedSharePoint`,
`SearchQueryInitiatedExchange`) whose query text (`SearchQueryText` or `QueryText`,
depending on the operation) contains a sensitive term.

```kql
OfficeActivity
| where Operation in ("SearchQueryPerformed", "SearchQueryInitiatedSharePoint", "SearchQueryInitiatedExchange")
| extend Query = tostring(coalesce(column_ifexists("SearchQueryText", ""), column_ifexists("QueryText", "")))
| where Query matches regex @"(?i)password|passwd|credential|secret|vpn|payroll|direct deposit"
| project TimeGenerated, UserId, ClientIP, Operation, Query
```

**Tuning:** HR searches for payroll and help-desk staff search for password-reset
guides as part of their jobs. Exclude those groups. Search auditing (the `SearchQuery*`
events) must be enabled in Purview first.

**Lab result:** 12 TP alerts (the searches that used a listed term; 27 others, such as
"ceo" or "money", did not match), 0 FP.

### Data Access Within One Hour of a Multi-IP Entra Session

**Catches:** the identity-to-data step, where a likely-stolen session is used to read
data. This is the rule that ties the lab's two halves together.

**Why it works:** each half alone is ambiguous: roaming users trip the multi-IP rule,
and everyone reads files and mail. Together, "this session looks replayed AND it's
reading data" is the moment an identity incident becomes a data breach.

**Sigma logic:** a `temporal` correlation over two rules from different log sources:
`entra_user_session_multiple_ips` (itself a correlation) and `m365_user_data_access`
(`FileAccessed`, `FileDownloaded`, `FileSyncDownloadedFull`, `MailItemsAccessed`).
Both must fire for the same user within one hour. The user field is called
`UserPrincipalName` in sign-ins and `UserId` in M365 audit, so the rule uses Sigma
`aliases` to treat them as one `user` field, compared case-insensitively.

```kql
let window = 1h;
let multi_ip_users =
    union SigninLogs, AADNonInteractiveUserSignInLogs
    | where ResultType == "0" and isnotempty(UserPrincipalName)
    | summarize IPCount = dcount(IPAddress), SessionStart = min(TimeGenerated),
                SessionEnd = max(TimeGenerated)
        by User = tolower(UserPrincipalName), bin(TimeGenerated, window)
    | where IPCount > 1;
OfficeActivity
| where Operation in ("FileAccessed", "FileDownloaded", "FileSyncDownloadedFull", "MailItemsAccessed")
| extend User = tolower(UserId)
| join kind=inner multi_ip_users on User
| where TimeGenerated between ((SessionStart - window) .. (SessionEnd + window))
| summarize DataEvents = count(), Operations = make_set(Operation)
    by User, SessionStart, SessionEnd, IPCount
```

**Tuning:** inherits the multi-IP rule's roaming FPs, but only when the roaming user
also reads data in that hour, so it's much quieter than the multi-IP rule alone, and
it gets better as that rule is tuned. Tests check that it needs **both** halves within
the hour (`test_identity_to_data_rule_needs_both_halves_in_time`).

**Lab result:** 1 TP alert: the Evilginx M365 victim, whose mailbox was read from the
replaying IP 33 seconds after its first sign-in from that second IP. 0 FP.

## AWS detections

_Phase 4._

## GuardDuty vs. custom rules

_Phase 4._
