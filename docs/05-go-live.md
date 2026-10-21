# Go-Live: Real Entra Tenant and AWS Account

How to run this lab's rules against real telemetry. Everything here is done by a
person in their **own** test tenant and **own** throwaway AWS account. Never use an
employer's environment.

## Prerequisites

- A Microsoft Entra ID tenant you control. The free Microsoft 365 Developer Program
  sandbox works, if you qualify. Sign-in logs need at least Entra ID P1 licensing.
- An Azure subscription for a Log Analytics workspace + Microsoft Sentinel (there's
  a free trial period for new workspaces; watch the ingestion cost).
- An AWS account used only for this lab, with billing alerts turned on.
- Azure CLI (`az`) and AWS CLI (`aws`) installed and logged in.
- Optional: `sigma-cli` with the Microsoft backend for converting rules
  (`pip install sigma-cli pysigma-backend-microsoft365defender` or the Kusto/Sentinel backend).

## Microsoft Entra ID / Sentinel

1. **Create the workspace.** Azure portal → Log Analytics workspaces → Create.
   Then Microsoft Sentinel → Add → choose that workspace.
2. **Send Entra logs to it.** Entra admin center → Monitoring & health → Diagnostic
   settings → Add diagnostic setting → tick `SignInLogs`, `NonInteractiveUserSignInLogs`,
   and `AuditLogs` → Send to Log Analytics workspace. Logs appear in the `SigninLogs`,
   `AADNonInteractiveUserSignInLogs`, and `AuditLogs` tables within ~15 minutes.
3. **Send M365 file activity** (for the data-layer rules): Sentinel → Content hub →
   install the Microsoft 365 solution → connect it with SharePoint/OneDrive enabled.
   File events land in `OfficeActivity`.
4. **Check the field names line up.** Run `SigninLogs | take 10` and compare the
   columns with `simulations/entra_aitm/schema.py`. The synthetic logs copy these
   names, so the KQL in `03-detections.md` should run unchanged. Note any differences
   here. `AutonomousSystemNumber` appears in `SigninLogs` as `AutonomousSystemNumber`
   on current schemas; if not present in yours, derive it from `IPAddress` with a
   lookup.
5. **Create the analytics rules.** Sentinel → Analytics → Create → Scheduled query
   rule. Paste each rule's KQL from `03-detections.md`, set the schedule (e.g. every
   5 min looking back 1 hour), map entities (Account → `UserPrincipalName`,
   IP → `IPAddress`), and set severity from the Sigma `level`.
   Or convert the Sigma YAML directly: `sigma convert -t kusto detections/entra/<rule>.yml`.
6. **Recreate the auto-close logic.** Each `known_benign.yml` entry becomes either a
   `where not(...)` clause in the KQL or a Sentinel **automation rule** that closes
   matching incidents with the same written reason as its comment.

## AWS (CloudTrail, GuardDuty)

1. **Turn on CloudTrail.** A trail for all regions with management events, plus S3
   data events for the lab bucket (needed to see `GetObject` for exfil detection).
   Deliver to an S3 bucket; optionally CloudTrail Lake for SQL queries.
2. **Turn on GuardDuty** in the same region(s). It's needed for the
   GuardDuty-vs-custom comparison in `03-detections.md`.
3. **Run the emulations** with Stratus Red Team (github.com/DataDog/stratus-red-team)
   in the lab account only. Use `stratus list` to pick techniques, then
   `stratus detonate <technique>` and `stratus cleanup <technique>` afterwards.
   Record which technique ran, and when, so events can be labeled.
4. **Export the events** for that window (CloudTrail console → Event history →
   download as JSON, or query CloudTrail Lake). Label them `lab_label: malicious`,
   convert to JSON Lines, and save as `data/sample-logs/cloudtrail_<technique>.jsonl`.
5. **Get the matching GuardDuty findings** (`aws guardduty list-findings` /
   `get-findings`) and save them as `data/sample-logs/guardduty_<technique>.jsonl`
   for the comparison table.
6. **Deploy the rules:** convert the Sigma CloudTrail rules to your query engine
   (Athena / CloudTrail Lake SQL, or a SIEM), or send CloudTrail into Sentinel with
   the AWS connector and reuse the Sentinel workflow above.
7. **Tear down:** `stratus cleanup --all`, delete the trail bucket if you don't need
   it, and check the billing dashboard.

## Validation

A rule counts as **validated live** when all three hold:

1. **Fires on the real attack:** after the emulation, the Sentinel/SQL rule produces
   an alert for the emulated activity.
2. **Quiet on real normal use:** over at least a few days of ordinary sign-ins and
   file use in the test tenant, it produces no alerts, or only alerts covered by a
   documented known-benign entry.
3. **Matches the lab result:** export the real events to `data/sample-logs/`, run
   `python harness/replay.py`, and confirm the harness agrees with what the SIEM did.

Record results per rule in the table below and copy them into the README.

| Rule | Fired on emulation? | Alerts in N days of normal use | Harness agrees? | Notes |
|---|---|---|---|---|
| _(fill in per rule)_ | | | | |
