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

_Phase 3._

## AWS detections

_Phase 4._

## GuardDuty vs. custom rules

_Phase 4._
