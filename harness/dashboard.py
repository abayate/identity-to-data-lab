"""Builds the interactive dashboard (reports/dashboard/index.html) from a replay run.

The terminal table says *how many* alerts fired. The dashboard shows *what happened*:
every real log event on a timeline, which rule fired on it and why (field by field),
the alert queue an analyst would work, the triage decisions with their reasons, and the
ATT&CK coverage. It is one self-contained HTML file: the data is embedded as JSON and
the page needs no server, so it works from disk and on GitHub Pages.

replay.py calls write_dashboard() at the end of every run. The page itself lives in
harness/dashboard_template.html; this module only prepares the data it displays.
"""

import json
import re
from pathlib import Path

import yaml

from harness.evaluate import explain_match, get_field, window_meets_condition

REPO_ROOT = Path(__file__).resolve().parent.parent
TEMPLATE_PATH = Path(__file__).resolve().parent / "dashboard_template.html"
DETECTIONS_DOC = REPO_ROOT / "docs" / "03-detections.md"
SOURCES_PATH = REPO_ROOT / "simulations" / "public_datasets" / "sources.yml"
RAW_DIR = REPO_ROOT / "data" / "raw" / "splunk_attack_data"

MAX_VALUE_CHARS = 240  # long values (policy documents, user agents) are shortened in explanations

# Sample-log file prefixes = log types (same list as replay.SERVICE_TO_FILE_PREFIX values).
LOG_TYPES = ["entra_signins", "entra_audit", "m365_audit", "cloudtrail", "guardduty"]


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def short(value):
    """Make a value safe and small enough to show in an explanation table."""
    if isinstance(value, (dict, list)):
        value = json.dumps(value, sort_keys=True)
    if isinstance(value, str) and len(value) > MAX_VALUE_CHARS:
        return value[:MAX_VALUE_CHARS] + "…"
    return value


def log_type(record):
    """Which log type a record came from, e.g. 'entra_signins', from its source file name."""
    source = record.get("_source_file", "")
    return next((prefix for prefix in LOG_TYPES if source.startswith(prefix)), source)


def event_summary(record):
    """Who / what / where for one event, whatever log type it is."""
    who = (record.get("UserPrincipalName") or record.get("UserId")
           or get_field(record, "userIdentity.arn") or get_field(record, "InitiatedBy.user.userPrincipalName")
           or get_field(record, "InitiatedBy.app.displayName") or record.get("ServicePrincipalName") or "?")
    what = (record.get("Operation") or record.get("eventName") or record.get("OperationName")
            or ("Sign-in: " + str(record.get("AppDisplayName") or record.get("AppId") or "?")))
    where = record.get("IPAddress") or record.get("ClientIP") or record.get("sourceIPAddress") or ""
    return str(who), str(what), str(where)


def kql_for(title, doc_text):
    """The first ```kql block under '### <title>' in docs/03-detections.md, or ''."""
    heading = f"\n### {title}\n"
    if heading not in doc_text:
        return ""
    section = doc_text.split(heading, 1)[1].split("\n### ", 1)[0].split("\n## ", 1)[0]
    match = re.search(r"```kql\n(.*?)```", section, re.DOTALL)
    return match.group(1).rstrip() if match else ""


def display_path(path):
    try:
        return Path(path).resolve().relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return Path(path).name


# ---------------------------------------------------------------------------
# Explaining alerts
# ---------------------------------------------------------------------------

def detection_parts(rule):
    """The detection logic to explain for a rule, as (part name, rule-with-detection) pairs.

    A plain rule or a count correlation explains its own detection (part = None). A temporal
    correlation has no detection of its own, so each linked rule is explained instead,
    labeled with its name (e.g. "m365_user_data_access").
    """
    if "detection" in rule:
        return [(None, rule)]
    return [(base.get("name"), base) for base in rule.get("_bases", []) if "detection" in base]


def describe_alert(rule, events):
    """One plain-English sentence saying why this alert fired."""
    correlation = rule.get("correlation")
    if not correlation:
        return "This single event matched the rule's condition."
    kind = correlation["type"]
    span = correlation["timespan"]
    if kind == "temporal":
        names = " and ".join(correlation["rules"])
        return f"Every linked rule ({names}) fired for the same user within {span}."
    condition = correlation["condition"]
    threshold = ", ".join(f"{op} {value}" for op, value in condition.items() if op != "field")
    group = ", ".join(correlation.get("group-by", []))
    if kind == "value_count":
        field = condition["field"]
        values = sorted({str(get_field(e, field)) for e in events if get_field(e, field) is not None})
        return (f"{len(values)} different {field} values for one {group} within {span} "
                f"(rule threshold: {threshold}): {', '.join(values[:8])}")
    return f"{len(events)} matching events for one {group} within {span} (rule threshold: {threshold})."


def trigger_position(rule, events):
    """Index (in time order) of the event at which the alert would first have fired.

    Used by the replay animation. For a single-event rule it is that event. For a
    correlation it is the first event at which the events seen so far meet the condition
    (temporal: once events from every linked log type have arrived). Approximate by design:
    it ignores events outside this alert.
    """
    correlation = rule.get("correlation")
    if not correlation:
        return 0
    if correlation["type"] == "temporal":
        seen = set()
        for index, event in enumerate(events):
            seen.add(log_type(event))
            if len(seen) >= 2:
                return index
        return len(events) - 1
    for index in range(len(events)):
        if window_meets_condition(events[: index + 1], correlation):
            return index
    return len(events) - 1


# ---------------------------------------------------------------------------
# Building the data bundle
# ---------------------------------------------------------------------------

def dataset_info(sources):
    """Dataset cards: name, technique, scenario, evidence, and the upstream description."""
    datasets = []
    for dataset in sources["datasets"]:
        description = ""
        metadata = RAW_DIR / f"{dataset['name']}.metadata.yml"
        if metadata.is_file():
            with open(metadata, encoding="utf-8") as handle:
                description = str((yaml.safe_load(handle) or {}).get("description", "")).strip()
        datasets.append({
            "name": dataset["name"],
            "technique": dataset["technique"],
            "related": dataset.get("related_techniques", []),
            "scenario": dataset["scenario"],
            "evidence": " ".join(str(dataset.get("evidence", "")).split()),
            "description": " ".join(description.split()),
            "source": f"https://github.com/splunk/attack_data/tree/master/datasets/attack_techniques/"
                      f"{dataset['path'].rsplit('/', 1)[0]}",
            "lab_source": f"splunk/attack_data:{dataset['path']}",
        })
    return datasets


def build_data(rules, results, logs, coverage, caught, total_malicious, sources):
    """Everything the page shows, as plain JSON-ready Python data."""
    doc_text = DETECTIONS_DOC.read_text(encoding="utf-8") if DETECTIONS_DOC.is_file() else ""
    datasets = dataset_info(sources)
    by_lab_source = {d["lab_source"]: d["name"] for d in datasets}

    # Number every event once, in a stable order (log type, then time), so the page can refer to it.
    all_records = sorted((r for records in logs.values() for r in records),
                         key=lambda r: (r.get("_source_file", ""), r.get("TimeGenerated", "")))
    index_of = {id(record): index for index, record in enumerate(all_records)}
    events = []
    for record in all_records:
        who, what, where = event_summary(record)
        events.append({
            "t": record.get("TimeGenerated", ""),
            "who": who, "what": what, "where": where,
            "log": log_type(record),
            "ds": by_lab_source.get(record.get("lab_source"), ""),
            "label": record.get("lab_label"),
            "scenario": record.get("lab_scenario"),
            "raw": {k: v for k, v in record.items() if not k.startswith("lab_") and not k.startswith("_")},
        })

    rule_cards, alerts, explanations = [], [], {}
    for rule, result in zip(rules, results):
        key = display_path(rule["_path"])
        rule_cards.append({
            "key": key,
            "title": rule["title"],
            "level": rule.get("level", ""),
            "description": " ".join(str(rule.get("description", "")).split()),
            "tags": rule.get("tags", []),
            "techniques": sorted(result["techniques"]),
            "type": rule["correlation"]["type"] if "correlation" in rule else "single event",
            "falsepositives": rule.get("falsepositives", []),
            "sigma": Path(rule["_path"]).read_text(encoding="utf-8"),
            "kql": kql_for(rule["title"], doc_text),
            "stats": {k: result[k] for k in ("events_checked", "hits", "true_positives", "false_positives",
                                              "auto_closed", "fp_rate", "fp_rate_after_triage")},
        })
        for triaged in result["open_alerts"] + result["closed_alerts"]:
            ordered = sorted(triaged["events"], key=lambda e: e.get("TimeGenerated", ""))
            alerts.append({
                "id": len(alerts),
                "rule": key,
                "status": triaged["status"],
                "events": [index_of[id(e)] for e in ordered],
                "trigger": index_of[id(ordered[trigger_position(rule, ordered)])],
                "why": describe_alert(rule, ordered),
                "context": {k: short(v) for k, v in triaged.get("context", {}).items()},
                "reason": triaged.get("reason", ""),
                "truth": "true_positive" if any(e.get("lab_label") == "malicious" for e in ordered)
                         else "false_positive",
            })
        # Field-by-field explanations for every event a rule's detection logic touched,
        # including the building-block rules a temporal correlation links together.
        for part, logic in detection_parts(rule):
            for record in result["records"]:
                why = explain_match(logic, record)
                # Skip events where only a filter_* (an exclusion) matched: that says nothing useful.
                if why["matched"] or any(sel["matched"] for name, sel in why["selections"].items()
                                         if not name.startswith("filter")):
                    for selection in why["selections"].values():
                        for check in selection["checks"]:
                            check["actual"] = short(check["actual"])
                            check["expected"] = short(check["expected"])
                    explanations.setdefault(index_of[id(record)], []).append({"rule": key, "part": part, **why})

    benign_total = sum(1 for e in events if e["label"] == "benign")
    return {
        "summary": {
            "events": len(events),
            "malicious": total_malicious,
            "benign": benign_total,
            "caught": caught,
            "rules": len(rule_cards),
            "alerts": len(alerts),
            "open": sum(1 for a in alerts if a["status"] == "open"),
            "auto_closed": sum(1 for a in alerts if a["status"] == "auto_closed"),
            "techniques_tested": sum(1 for c in coverage if c["status"] == "tested"),
            "techniques_planned": len(coverage),
        },
        "datasets": datasets,
        "events": events,
        "rules": rule_cards,
        "alerts": alerts,
        "explanations": {str(k): v for k, v in sorted(explanations.items())},
        "coverage": coverage,
    }


def write_dashboard(out_dir, rules, results, logs, coverage, caught, total_malicious, sources=None):
    """Write reports/dashboard/index.html: the template with the data embedded."""
    if sources is None:
        with open(SOURCES_PATH, encoding="utf-8") as handle:
            sources = yaml.safe_load(handle)
    data = build_data(rules, results, logs, coverage, caught, total_malicious, sources)
    # "</" inside a <script> block would end it early, so escape it.
    payload = json.dumps(data, sort_keys=True, default=str).replace("</", "<\\/")
    html = TEMPLATE_PATH.read_text(encoding="utf-8").replace("/*__DASHBOARD_DATA__*/null", payload)
    out_dir = Path(out_dir) / "dashboard"
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "index.html"
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(html)
    return path
