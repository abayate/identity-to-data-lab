"""Converts the raw public datasets into labeled sample logs in data/sample-logs/.

Run from the repo root (no internet needed; it reads the committed raw files):

    python -m simulations.public_datasets.generate

For every dataset in sources.yml it:
  1. Reads the raw file (one JSON event per line; unreadable lines are skipped and counted).
  2. Labels each event benign / malicious (or excludes it) using the dataset's
     labeling rules, checked against the RAW event.
  3. Converts the event to the field names of the Sentinel table it belongs to:
       - Azure Monitor sign-in exports nest most fields under "properties" with
         camelCase names; Sentinel's SigninLogs flattens them into PascalCase
         columns (properties.ipAddress -> IPAddress). We do the same.
       - Azure Monitor audit exports become AuditLogs columns.
       - Office 365 Management API events are kept as-is (OfficeActivity uses
         nearly the same names) plus a TimeGenerated field.
       - AWS CloudTrail events are kept as-is (Sigma's CloudTrail rules use AWS's
         own field names) plus a TimeGenerated field.
  4. Writes entra_signins_<name>.jsonl, entra_audit_<name>.jsonl,
     m365_audit_<name>.jsonl and/or cloudtrail_<name>.jsonl, sorted by time,
     plus a README summarizing the counts.

The output is deterministic: same raw input, byte-identical output.
"""

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from harness.evaluate import selection_matches  # noqa: E402
from simulations.public_datasets.fetch import RAW_DIR, load_sources, raw_log_path  # noqa: E402

OUT_DIR = REPO_ROOT / "data" / "sample-logs"


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def to_utc_iso(text):
    """Normalize the timestamp styles in these datasets to 2023-08-03T21:59:28.123456Z.

    Seen in the raw data: "...T22:00:48.7263711Z" (7 fractional digits, which Python
    can't parse), "...+00:00", and "2024-12-10T16:13:47" (no zone; the Office 365
    Management API always means UTC).
    """
    text = text.replace("Z", "+00:00")
    text = re.sub(r"(\.\d{6})\d+", r"\1", text)  # keep at most 6 fractional digits
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def read_raw_events(path):
    """Read a raw JSON Lines file. Returns (events, number_of_unreadable_lines)."""
    events, unreadable = [], 0
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                unreadable += 1  # e.g. a line truncated in the published file
    return events, unreadable


def any_selection(event, selections):
    """True if the event matches any of the given Sigma-style selections."""
    return any(selection_matches(event, selection) for selection in selections or [])


def label_event(event, dataset):
    """Return "malicious", "benign", or None (excluded) for one RAW event."""
    if any_selection(event, dataset.get("exclude_when")):
        return None
    if any_selection(event, dataset.get("malicious_when")):
        return "malicious"
    if any_selection(event, dataset.get("benign_when")):
        return "benign"
    return dataset["default_label"]


# ---------------------------------------------------------------------------
# Recognizing and converting each kind of raw event
# ---------------------------------------------------------------------------

def event_kind(event):
    """Work out which log type a raw event is: 'signin', 'audit', 'm365' or 'cloudtrail'."""
    if "eventSource" in event and "eventTime" in event:
        return "cloudtrail"                             # AWS CloudTrail
    if "Operation" in event and "CreationTime" in event:
        return "m365"                                   # Office 365 Management API
    if event.get("category") == "AuditLogs":
        return "audit"                                  # Azure Monitor audit export
    if "properties" in event or "createdDateTime" in event:
        return "signin"                                 # Azure Monitor or Graph sign-in
    raise ValueError(f"unrecognized event shape: {sorted(event)[:8]}")


def convert_signin(event):
    """Flatten a sign-in event into SigninLogs column names."""
    # Azure Monitor exports wrap the sign-in in "properties"; Graph exports don't.
    props = event.get("properties", event)
    status = props.get("status") or {}
    location = props.get("location") if isinstance(props.get("location"), dict) else {}
    if "category" in event:
        category = event["category"]
    else:
        category = "SignInLogs" if props.get("isInteractive") else "NonInteractiveUserSignInLogs"
    return {
        "TimeGenerated": to_utc_iso(event.get("time") or props["createdDateTime"]),
        "Category": category,
        "UserPrincipalName": props.get("userPrincipalName"),
        "UserId": props.get("userId"),
        "AppDisplayName": props.get("appDisplayName"),
        "AppId": props.get("appId"),
        "IPAddress": props.get("ipAddress"),
        "AutonomousSystemNumber": props.get("autonomousSystemNumber"),
        "Location": location.get("countryOrRegion"),
        "LocationDetails": location or None,
        "UserAgent": props.get("userAgent"),
        "ClientAppUsed": props.get("clientAppUsed"),
        "AuthenticationProtocol": props.get("authenticationProtocol"),
        "AuthenticationRequirement": props.get("authenticationRequirement"),
        "IncomingTokenType": props.get("incomingTokenType"),
        "ResultType": str(status.get("errorCode", event.get("resultType", ""))),
        "ResultDescription": status.get("failureReason"),
        "ConditionalAccessStatus": props.get("conditionalAccessStatus"),
        "RiskLevelDuringSignIn": props.get("riskLevelDuringSignIn"),
        "IsInteractive": props.get("isInteractive"),
        "DeviceDetail": props.get("deviceDetail"),
        "ResourceDisplayName": props.get("resourceDisplayName"),
        "UniqueTokenIdentifier": props.get("uniqueTokenIdentifier"),
        "SessionId": props.get("sessionId"),
        "ServicePrincipalName": props.get("servicePrincipalName"),
        "CorrelationId": props.get("correlationId") or event.get("correlationId"),
    }


def convert_audit(event):
    """Flatten an audit event into AuditLogs column names."""
    props = event["properties"]
    return {
        "TimeGenerated": to_utc_iso(event["time"]),
        "OperationName": props.get("activityDisplayName") or event.get("operationName"),
        "Category": props.get("category"),
        "Result": props.get("result"),
        "CorrelationId": props.get("correlationId") or event.get("correlationId"),
        "InitiatedBy": props.get("initiatedBy") or {},
        "TargetResources": props.get("targetResources") or [],
        "LoggedByService": props.get("loggedByService"),
        "AdditionalDetails": props.get("additionalDetails"),
    }


def convert_m365(event):
    """Office 365 Management API events keep their own names; add TimeGenerated."""
    converted = dict(event)
    converted["TimeGenerated"] = to_utc_iso(event["CreationTime"])
    return converted


def convert_cloudtrail(event):
    """CloudTrail events keep AWS's field names; add TimeGenerated."""
    converted = dict(event)
    converted["TimeGenerated"] = to_utc_iso(event["eventTime"])
    return converted


CONVERTERS = {"signin": convert_signin, "audit": convert_audit, "m365": convert_m365,
              "cloudtrail": convert_cloudtrail}
FILE_PREFIX = {"signin": "entra_signins", "audit": "entra_audit", "m365": "m365_audit",
               "cloudtrail": "cloudtrail"}


# ---------------------------------------------------------------------------
# Whole datasets
# ---------------------------------------------------------------------------

def convert_dataset(dataset, raw_dir=RAW_DIR):
    """Convert one dataset. Returns ({file_prefix: [records]}, stats dict)."""
    events, unreadable = read_raw_events(raw_log_path(dataset, raw_dir))
    outputs = {}
    stats = {"name": dataset["name"], "technique": dataset["technique"], "malicious": 0,
             "benign": 0, "excluded": 0, "unreadable": unreadable}
    for event in events:
        label = label_event(event, dataset)
        if label is None:
            stats["excluded"] += 1
            continue
        stats[label] += 1
        kind = event_kind(event)
        record = CONVERTERS[kind](event)
        record["lab_label"] = label
        record["lab_scenario"] = dataset["scenario"]
        record["lab_source"] = f"splunk/attack_data:{dataset['path']}"
        outputs.setdefault(FILE_PREFIX[kind], []).append(record)
    for records in outputs.values():
        records.sort(key=lambda record: record["TimeGenerated"])
    return outputs, stats


def write_jsonl(path, records):
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True) + "\n")


def provenance_readme(all_stats, sources):
    """A human-readable summary of where every sample log came from and how it was labeled."""
    lines = [
        "# Sample logs",
        "",
        "Generated by `python -m simulations.public_datasets.generate`. Do not edit by hand.",
        "",
        "Source: [splunk/attack_data](https://github.com/splunk/attack_data) (Apache-2.0),",
        "raw copies in `data/raw/splunk_attack_data/`. Labeling rules and evidence:",
        "`simulations/public_datasets/sources.yml`.",
        "",
        "| Dataset | Technique | Malicious | Benign | Excluded | Unreadable lines |",
        "|---|---|---|---|---|---|",
    ]
    for s in all_stats:
        lines.append(f"| {s['name']} | {s['technique']} | {s['malicious']} | {s['benign']} | "
                     f"{s['excluded']} | {s['unreadable']} |")
    totals = {key: sum(s[key] for s in all_stats) for key in ("malicious", "benign", "excluded", "unreadable")}
    lines.append(f"| **Total** | | **{totals['malicious']}** | **{totals['benign']}** | "
                 f"**{totals['excluded']}** | **{totals['unreadable']}** |")
    lines.append("")
    return "\n".join(lines)


def main(out_dir=OUT_DIR, raw_dir=RAW_DIR):
    sources = load_sources()
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    # Remove previous output so a renamed or deleted dataset doesn't leave stale files behind.
    for old in out_dir.glob("*.jsonl"):
        old.unlink()
    all_stats = []
    for dataset in sources["datasets"]:
        outputs, stats = convert_dataset(dataset, raw_dir)
        for prefix, records in outputs.items():
            write_jsonl(out_dir / f"{prefix}_{dataset['name']}.jsonl", records)
        all_stats.append(stats)
        print(f"{dataset['name']}: {stats['malicious']} malicious, {stats['benign']} benign, "
              f"{stats['excluded']} excluded, {stats['unreadable']} unreadable")
    # newline="\n" so the file is identical on Windows and Linux.
    with open(out_dir / "README.md", "w", encoding="utf-8", newline="\n") as handle:
        handle.write(provenance_readme(all_stats, sources))
    return 0


if __name__ == "__main__":
    sys.exit(main())
