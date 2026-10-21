"""Feeds the committed sample logs (or freshly generated simulation output) through every detection rule.

Run it from the repo root:

    python harness/replay.py              # replay the committed sample logs
    python harness/replay.py --regenerate # first re-run every simulations/*/generate.py

What it does, in order:
  1. Loads every log file in data/sample-logs/ (JSON Lines, one event per line).
  2. Loads every Sigma rule in detections/.
  3. Runs each rule only against the log type it is written for (its `logsource`).
  4. Scores each rule (true / false positives) and triages its hits with enrich.py.
  5. Prints a summary table and writes reports/ (results.md, results.json,
     coverage.md, coverage.svg).
  6. If running in GitHub Actions, also adds the summary to the run's summary page.
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

# Allow `python harness/replay.py` (not just `python -m harness.replay`) by putting
# the repo root on the import path.
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from harness.coverage import build_coverage, coverage_markdown, coverage_svg, techniques_in_rule  # noqa: E402
from harness.enrich import load_known_benign, triage  # noqa: E402
from harness.evaluate import find_hits, load_rules  # noqa: E402

# A rule's `logsource: service:` decides which log files it runs against.
# Log files are named <prefix>*.jsonl in data/sample-logs/.
SERVICE_TO_FILE_PREFIX = {
    "signinlogs": "entra_signins",
    "auditlogs": "entra_audit",
    "m365": "m365_audit",
    "cloudtrail": "cloudtrail",
    "guardduty": "guardduty",
}


def load_jsonl(path):
    """Read a JSON Lines file into a list of dicts, tagging each with the file it came from."""
    records = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                record = json.loads(line)
                record["_source_file"] = path.name
                records.append(record)
    return records


def load_logs_by_prefix(log_dir):
    """Group every record in log_dir by the file prefix it belongs to."""
    logs = {prefix: [] for prefix in SERVICE_TO_FILE_PREFIX.values()}
    for path in sorted(Path(log_dir).glob("*.jsonl")):
        for prefix in logs:
            if path.name.startswith(prefix):
                logs[prefix].extend(load_jsonl(path))
    return logs


def records_for_rule(rule, logs):
    """Return the log records a rule should be run against, based on its logsource."""
    service = str(rule.get("logsource", {}).get("service", "")).lower()
    prefix = SERVICE_TO_FILE_PREFIX.get(service)
    return logs.get(prefix, []) if prefix else []


def regenerate_simulations():
    """Re-run every simulations/<name>/generate.py so the sample logs are rebuilt from code."""
    for script in sorted((REPO_ROOT / "simulations").glob("*/generate.py")):
        module = f"simulations.{script.parent.name}.generate"
        print(f"Regenerating logs: python -m {module}")
        subprocess.run([sys.executable, "-m", module], cwd=REPO_ROOT, check=True)


def evaluate_all(rules, logs, known_benign):
    """Run every rule, score it, and triage its hits. Returns one result dict per rule."""
    results = []
    for rule in rules:
        records = records_for_rule(rule, logs)
        hits = find_hits(rule, records)
        alerts = triage(rule, hits, records, known_benign)
        benign_total = sum(1 for r in records if r.get("lab_label") == "benign")
        false_positives = sum(1 for r in hits if r.get("lab_label") == "benign")
        open_false_positives = sum(
            1 for a in alerts if a["status"] == "open" and a["record"].get("lab_label") == "benign"
        )
        results.append({
            "rule": rule.get("title", rule["_path"]),
            "path": rule["_path"],
            "techniques": techniques_in_rule(rule),
            "events_checked": len(records),
            "hits": len(hits),
            "true_positives": sum(1 for r in hits if r.get("lab_label") == "malicious"),
            "false_positives": false_positives,
            "auto_closed": sum(1 for a in alerts if a["status"] == "auto_closed"),
            "fp_rate": false_positives / benign_total if benign_total else 0.0,
            "fp_rate_after_triage": open_false_positives / benign_total if benign_total else 0.0,
            "caught_ids": {id(a["record"]) for a in alerts if a["record"].get("lab_label") == "malicious"},
            "open_alerts": [a for a in alerts if a["status"] == "open"],
        })
    return results


def chain_coverage(logs, results):
    """How many malicious events were caught by at least one rule, out of all malicious events."""
    malicious = [r for records in logs.values() for r in records if r.get("lab_label") == "malicious"]
    caught = set().union(*(result["caught_ids"] for result in results)) if results else set()
    return sum(1 for r in malicious if id(r) in caught), len(malicious)


def results_markdown(results, caught, total_malicious):
    """Render the per-rule results as a markdown table plus a one-line chain summary."""
    lines = [
        "| Rule | Events | Hits | TP | FP | Auto-closed | FP rate | FP rate after triage |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in results:
        lines.append(
            f"| {r['rule']} | {r['events_checked']} | {r['hits']} | {r['true_positives']} | "
            f"{r['false_positives']} | {r['auto_closed']} | {r['fp_rate']:.1%} | "
            f"{r['fp_rate_after_triage']:.1%} |"
        )
    if not results:
        lines.append("| (no rules in detections/ yet) | - | - | - | - | - | - | - |")
    lines.append("")
    lines.append(f"**Malicious events caught by at least one rule:** {caught} / {total_malicious}")
    return "\n".join(lines) + "\n"


def write_reports(out_dir, results, coverage, caught, total_malicious):
    """Write results and coverage files into out_dir. Returns the results markdown."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    table = results_markdown(results, caught, total_malicious)
    (out_dir / "results.md").write_text("# Replay results\n\n" + table, encoding="utf-8")
    (out_dir / "coverage.md").write_text(
        "# ATT&CK coverage\n\n![coverage map](coverage.svg)\n\n" + coverage_markdown(coverage),
        encoding="utf-8",
    )
    (out_dir / "coverage.svg").write_text(coverage_svg(coverage), encoding="utf-8")
    # JSON for machines: drop the internal fields that can't be serialized.
    serializable = [
        {key: (sorted(value) if key == "techniques" else value)
         for key, value in r.items() if key not in ("caught_ids", "open_alerts")}
        for r in results
    ]
    (out_dir / "results.json").write_text(
        json.dumps({"rules": serializable, "chain_caught": caught, "chain_total": total_malicious,
                    "coverage": coverage}, indent=2),
        encoding="utf-8",
    )
    return table


def main(argv=None):
    parser = argparse.ArgumentParser(description="Replay sample logs through every detection rule.")
    parser.add_argument("--logs", default=REPO_ROOT / "data" / "sample-logs", type=Path)
    parser.add_argument("--rules", default=REPO_ROOT / "detections", type=Path)
    parser.add_argument("--known-benign", default=REPO_ROOT / "harness" / "known_benign.yml", type=Path)
    parser.add_argument("--out", default=REPO_ROOT / "reports", type=Path)
    parser.add_argument("--regenerate", action="store_true", help="re-run simulations first")
    args = parser.parse_args(argv)

    if args.regenerate:
        regenerate_simulations()

    logs = load_logs_by_prefix(args.logs)
    rules = load_rules(args.rules)
    results = evaluate_all(rules, logs, load_known_benign(args.known_benign))
    caught, total_malicious = chain_coverage(logs, results)
    coverage = build_coverage(results)
    table = write_reports(args.out, results, coverage, caught, total_malicious)

    print(f"Loaded {sum(len(v) for v in logs.values())} log events and {len(rules)} rules.\n")
    print(table)
    print(coverage_markdown(coverage))
    print(f"Reports written to {args.out}")

    # GitHub Actions sets this variable to a file; anything appended shows on the run's summary page.
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_file:
        with open(summary_file, "a", encoding="utf-8") as handle:
            handle.write("## Detection replay\n\n" + table + "\n## ATT&CK coverage\n\n"
                         + coverage_markdown(coverage))
    return 0


if __name__ == "__main__":
    sys.exit(main())
