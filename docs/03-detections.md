# Detections

Every rule is a Sigma file in `detections/`, tested by `tests/test_detections.py`
against the labeled public-dataset logs in `data/sample-logs/`. Each section below
gives what the rule catches, why it works, a KQL equivalent for Microsoft Sentinel,
how to tune it, and its result in this lab.

**How to read the results:** the numbers come from `python harness/replay.py`. A rule
"fires" when it raises an alert. An alert is a true positive (TP) if it contains a
malicious event, and a false positive (FP) if it is all benign. "Open FP" is what is
left after `harness/enrich.py` auto-closes documented known-benign patterns. The benign
baseline in this lab is small (59 events: 21 identity / M365 and 38 AWS, see
`data/sample-logs/README.md`), so **0 FP here means "no false positives on the data
available," not "won't be noisy in production."** Each rule's tuning notes say where
production noise would come from.

## Rule index

| Rule | File | Log source | ATT&CK | TP alerts | FP alerts | Open FP after triage |
|---|---|---|---|---|---|---|
| Entra ID Sign-In Using Device Code Flow | `detections/entra/entra_device_code_signin.yml` | SigninLogs | T1528 | 1 | 0 | 0 |
| Entra ID User Consent Granted to an Application | `detections/entra/entra_oauth_consent_granted.yml` | AuditLogs | T1528 | 1 | 0 | 0 |
| Entra ID User Session Active From Multiple IPs Within One Hour | `detections/entra/entra_user_signin_multiple_ips.yml` | SigninLogs | T1550.004, T1078.004 | 3 | 0 | 0 |
| M365 Mass File Access or Download by One User | `detections/data/m365_mass_file_access.yml` | OfficeActivity | T1530, T1567 | 4 | 0 | 0 |
| M365 File Download With Rclone User Agent | `detections/data/m365_rclone_download.yml` | OfficeActivity | T1567, T1530 | 58 | 0 | 0 |
| M365 Search for Credential or Payroll Terms | `detections/data/m365_sensitive_term_search.yml` | OfficeActivity | T1213.002 | 12 | 0 | 0 |
| Data Access Within One Hour of a Multi-IP Entra Session | `detections/data/identity_to_data_access_after_multi_ip_session.yml` | SigninLogs + OfficeActivity | T1530, T1114.002, T1078.004 | 1 | 0 | 0 |
| AWS Burst of Access-Denied API Calls by One Identity | `detections/aws/aws_access_denied_burst.yml` | CloudTrail | T1580, T1078.004 | 2 | 0 | 0 |
| AWS Access Key Created for a Different IAM User | `detections/aws/aws_access_key_created_for_other_user.yml` | CloudTrail | T1098.001 | 28 | 28 | 5 |
| AWS IAM Policy Version Set as Default With Wildcard Actions | `detections/aws/aws_policy_version_grants_wildcard.yml` | CloudTrail | T1098.003, T1078.004 | 3 | 0 | 0 |
| AWS IAM Role Created Trusting Any Principal or a Whole Account | `detections/aws/aws_role_trust_wildcard_or_account.yml` | CloudTrail | T1098.003 | 2 | 0 | 0 |
| AWS S3 Mass Object Download by One Identity | `detections/aws/aws_s3_mass_getobject.yml` | CloudTrail | T1530 | 1 | 0 | 0 |
| AWS EBS Snapshot Shared With Another Account or Made Public | `detections/aws/aws_ebs_snapshot_shared.yml` | CloudTrail | T1537 | 6 | 0 | 0 |

**Whole chain:** 1,563 of 1,611 malicious events (97%) are part of at least one alert.

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

These rules read CloudTrail with AWS's own field names (`eventName`, `userIdentity.arn`,
`requestParameters...`), which is what Sigma's `aws/cloudtrail` rules, Athena and
CloudTrail Lake use. The KQL targets Sentinel's `AWSCloudTrail` table, which flattens
and renames them (`EventName`, `UserIdentityArn`, `RequestParameters` as a JSON string).

**The chain:** a leaked key is used to look around (discovery), to gain more rights
(privilege escalation and persistence), then to take data (S3 and snapshot exfiltration).
The step where the key leaks (T1552.001, e.g. a key committed to GitHub) happens outside
AWS and leaves no CloudTrail event, so it stays a gap in the coverage map. See the
GuardDuty comparison for what covers it.

**Dataset caveat:** each AWS dataset comes from a different Splunk test account and run,
so no single identity walks the whole chain. The rules are tested step by step. A
cross-step correlation (e.g. "discovery burst, then privilege escalation by the same key")
is the natural next rule once a live run produces a connected trail (see `05-go-live.md`).

### AWS Burst of Access-Denied API Calls by One Identity

**Catches:** someone enumerating an account with a key they shouldn't have. The dataset
shows the scanners CloudSploit and CloudMapper running as low-privilege users: 1,150 calls
across dozens of services in two hours, nearly all refused.

**Sigma logic:** correlation, `event_count` > 20 of `errorCode` in (`AccessDenied`,
`UnauthorizedOperation`, `Client.UnauthorizedOperation`) per `userIdentity.arn` in 10 minutes.

```kql
AWSCloudTrail
| where ErrorCode in ("AccessDenied", "UnauthorizedOperation", "Client.UnauthorizedOperation")
| summarize Denied = count(), Services = make_set(EventSource), Calls = make_set(EventName, 25),
            IPs = make_set(SourceIpAddress)
    by UserIdentityArn, bin(TimeGenerated, 10m)
| where Denied > 20
```

**Tuning:** the dataset itself shows the main FP: a sanctioned posture scanner whose
read-only policy doesn't cover every service looks exactly like this. Allow-list scanner
identities in `known_benign.yml`. Expect a burst after a deployment breaks permissions too.

**Lab result:** 2 TP alerts (one per scanner identity), 0 FP.

### AWS Access Key Created for a Different IAM User

**Catches:** privilege escalation / persistence by minting a key for another user
(Stratus Red Team: `aws.persistence.iam-backdoor-user`).

**Sigma logic:** `CreateAccessKey` where `requestParameters.userName` is present and is
**not** the caller. Comparing two fields of one event uses Sigma v2's `|fieldref` modifier:
`requestParameters.userName|fieldref: userIdentity.userName`.

```kql
AWSCloudTrail
| where EventSource == "iam.amazonaws.com" and EventName == "CreateAccessKey"
| extend TargetUser = tostring(parse_json(RequestParameters).userName)
| where isnotempty(TargetUser) and TargetUser !~ UserIdentityUserName
// known-benign: federated admins provisioning keys from the console
| where not(UserIdentityType == "AssumedRole"
            and UserIdentityArn contains ":assumed-role/okta_adm_role/"
            and UserAgent == "console.amazonaws.com")
| project TimeGenerated, UserIdentityArn, TargetUser, SourceIpAddress, UserAgent
```

**Tuning (the triage story):** this is the one rule the public data makes noisy, because
the dataset includes months of the lab team's real admin work. Raw: 28 TP and **28 FP
(73.7% of benign events)**. 23 of the 28 FPs are admins who signed in through Okta into
`okta_adm_role` and created keys in the console: an approved workflow. One documented
`known_benign.yml` entry auto-closes exactly those, and **the analyst-facing FP rate drops
to 13.2%** (5 open). The remaining 5 are IAM users creating keys from the CLI or with
long-lived credentials; they stay open on purpose, because that's how a real attacker with
a stolen admin key would look. Tests check that the entry never closes a true positive
and cap open FPs at 5, so any drift fails CI.

**Lab result:** 28 TP alerts (Atomic Red Team's target user, plus Rhino-style escalation
attempts), 28 FP raw, 23 auto-closed, 5 open.

### AWS IAM Policy Version Set as Default With Wildcard Actions

**Catches:** the classic "rewrite my own policy to admin" escalation.

**Sigma logic:** `CreatePolicyVersion`, `setAsDefault: true`, and the policy document
has `"*"` or `"iam:*"` as an action, either alone or anywhere in an action list
(regex, whitespace-tolerant).

```kql
AWSCloudTrail
| where EventSource == "iam.amazonaws.com" and EventName == "CreatePolicyVersion"
| extend Params = parse_json(RequestParameters)
| where tobool(Params.setAsDefault)
    and tostring(Params.policyDocument) matches regex @'"Action"\s*:\s*(\[[^\]]*)?"(\*|iam:\*)"'
| project TimeGenerated, UserIdentityArn, PolicyArn = tostring(Params.policyArn), SourceIpAddress
```

**Tuning:** rare in production. Watch for sandbox / break-glass accounts. An earlier
version only checked the first entry of an action list, so `["s3:GetObject", "*"]` slipped
through. The regex now scans the whole list, and `test_policy_wildcard_regex_cases` pins
that down. Still not covered: service-wide grants like `"s3:*"` (a different, noisier rule).

**Lab result:** 3 TP alerts (including one failed attempt, which is still worth seeing), 0 FP.

### AWS IAM Role Created Trusting Any Principal or a Whole Account

**Catches:** a backdoor role that an attacker's own account can assume
(Stratus Red Team: `aws.persistence.iam-create-backdoor-role`).

**Sigma logic:** `CreateRole` whose trust policy has `"AWS": "*"` or
`"AWS": "arn:aws:iam::<12 digits>:root"`.

```kql
AWSCloudTrail
| where EventSource == "iam.amazonaws.com" and EventName == "CreateRole"
| extend Trust = tostring(parse_json(RequestParameters).assumeRolePolicyDocument)
| where Trust matches regex @'"AWS"\s*:\s*"(\*|arn:aws:iam::\d{12}:root)"'
| extend TrustedAccount = extract(@"arn:aws:iam::(\d{12}):root", 1, Trust)
| where TrustedAccount != RecipientAccountId   // KQL can do what Sigma can't: drop same-account trust
| project TimeGenerated, UserIdentityArn, TrustedAccount, Trust
```

**Tuning:** Sigma can't compare the account inside the policy with `recipientAccountId`
(a value inside a string vs. another field), so the Sigma version also fires on
same-account trusts. The KQL version removes those. Legitimate cross-account roles
(security tooling, CI/CD, partners) need an allow-list. AWS IAM Access Analyzer is the
native control for "who outside my account can assume this".

**Lab result:** 2 TP alerts (one wildcard, one external account), 0 FP.

### AWS S3 Mass Object Download by One Identity

**Catches:** bulk copying of a bucket by one identity: the AWS twin of the M365 mass-download rule.

**Sigma logic:** correlation, `event_count` > 50 `GetObject` per `userIdentity.arn` in 10 minutes.

```kql
AWSCloudTrail
| where EventSource == "s3.amazonaws.com" and EventName == "GetObject"
| summarize Objects = count(), Buckets = make_set(tostring(parse_json(RequestParameters).bucketName)),
            IPs = make_set(SourceIpAddress)
    by UserIdentityArn, bin(TimeGenerated, 10m)
| where Objects > 50
```

**Tuning:** requires **CloudTrail S3 data events**, which are off by default and billed
per event. Without them this rule is blind. Apps, ETL and analytics roles read many
objects by design, so scope the rule to human identities or sensitive buckets, or baseline per role.

**Lab result:** 1 TP alert (100 objects in one second), 0 FP.

### AWS EBS Snapshot Shared With Another Account or Made Public

**Catches:** exfiltrating a whole disk by sharing its snapshot
(Stratus Red Team: `aws.exfiltration.ec2-share-ebs-snapshot`; one run in the dataset
carries the Stratus user agent).

**Sigma logic:** `ModifySnapshotAttribute` that **adds** create-volume permission for an
account id or for group `all`. The permission is a list inside the event
(`requestParameters.createVolumePermission.add.items[]`), which the matcher walks.

```kql
AWSCloudTrail
| where EventSource == "ec2.amazonaws.com" and EventName == "ModifySnapshotAttribute"
| extend Added = parse_json(RequestParameters).createVolumePermission.add.items
| mv-expand Added
| where isnotempty(tostring(Added.userId)) or tostring(Added.group) == "all"
| project TimeGenerated, UserIdentityArn, SourceIpAddress,
          SharedWith = iff(tostring(Added.group) == "all", "PUBLIC", tostring(Added.userId))
```

**Tuning:** backup / DR tooling that copies snapshots to a dedicated backup account should
be allow-listed by destination account. Public sharing should always be reviewed.

**Lab result:** 6 TP alerts, 0 FP. The 3 malicious events not alerted on are the
attack's setup (`CreateSnapshot`), its cleanup (removing public access), and an empty
"add" call. None of them shares anything.

## GuardDuty vs. custom rules

Amazon GuardDuty is AWS's managed threat-detection service. It combines threat
intelligence (known-bad IPs, Tor, known-compromised keys) with a machine-learning model
that baselines each identity and flags `AnomalousBehavior`. The question for each step
is what each approach would flag, and why you'd want both.

**How this was built:** the public datasets contain no GuardDuty findings, so this table
is reasoning from AWS's published finding types
([IAM](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html),
[S3](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html)),
not measured output. Running GuardDuty against a live Stratus Red Team detonation to fill
in an "actually fired?" column is a go-live step (`05-go-live.md`).

| Attack step | Custom rule here | GuardDuty finding(s) that could fire | Who wins, and why |
|---|---|---|---|
| Key leaks (T1552.001) | **None:** the leak happens outside AWS, no CloudTrail event | `CredentialAccess:IAMUser/CompromisedCredentials` (key flagged by Amazon threat intel, then used) | **GuardDuty.** It has intel we can't see. A custom rule only sees what the key does next. |
| Discovery with the key (T1580) | Access-denied burst (> 20 in 10 min) | `Discovery:IAMUser/AnomalousBehavior` (low severity); `Recon:IAMUser/MaliciousIPCaller` / `TorIPCaller` if the IP is on a list; `PenTest:IAMUser/KaliLinux` from Kali | **Both.** Ours catches the noisy failed burst on day one with no learning period. GuardDuty can also catch *quiet, successful* recon that produces no errors, which ours misses. |
| Key minted for another user (T1098.001) | `CreateAccessKey` with target ≠ caller (`fieldref`) + known-benign triage | `Persistence:IAMUser/AnomalousBehavior` (AWS lists `CreateAccessKey` as an example API) | **Different trade-offs.** GuardDuty's baseline would likely ignore routine admins (fewer FPs), but it also skips an attacker whose activity fits the stolen identity's normal pattern. Ours is deterministic and explainable, but needed tuning (73.7% → 13.2% FP). |
| Policy rewritten to admin (T1098.003) | `CreatePolicyVersion` + wildcard action | `PrivilegeEscalation:IAMUser/AnomalousBehavior` (policy, role and user changes) | **Custom.** Ours checks *what the policy grants*. AWS describes the GuardDuty finding in terms of how unusual the API call is, not the permissions in the document. |
| Backdoor role trusting another account (T1098.003) | `CreateRole` with `*` / account-root trust | No dedicated finding; possibly `Persistence:` / `PrivilegeEscalation:` AnomalousBehavior | **Custom (plus IAM Access Analyzer).** GuardDuty has no "external trust" finding. Access Analyzer is the AWS-native control for external access. |
| Mass S3 download (T1530) | > 50 `GetObject` in 10 min | `Exfiltration:S3/AnomalousBehavior`, `Exfiltration:S3/MaliciousIPCaller` (need **S3 Protection**) | **GuardDuty, slightly.** Both need S3 data-event visibility, but GuardDuty baselines per identity and bucket, so a role that always reads a lot isn't flagged. Ours needs data events in your own trail (paid) and a fixed threshold. |
| Snapshot shared out (T1537) | `ModifySnapshotAttribute` adding an account / `all` | `Exfiltration:IAMUser/AnomalousBehavior` (AWS lists snapshot APIs), only if unusual for the caller | **Custom.** Sharing a snapshot outside the account is worth an alert every time, anomalous or not. Ours fires deterministically. |

**Takeaway:** GuardDuty is strongest where you can't write a rule: threat intel, leaked-key
reputation, and "this identity has never done that before." Custom rules are strongest
where the *content* of the call is the signal (what a policy grants, who a role trusts,
where a snapshot goes), and where you need deterministic, CI-tested behavior with a written
reason for every suppression. Run both, and send GuardDuty findings into the same triage
pipeline (`harness/enrich.py`) so analysts see one queue.
