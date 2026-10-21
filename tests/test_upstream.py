"""Tests for rules prepared for upstream contribution (upstream/sigmahq/).

These are the SigmaHQ-formatted copies of lab rules. Formatting is validated with
SigmaHQ's own tools (see upstream/sigmahq/README.md); these tests prove the copy still
detects the same attack data, and stays quiet on the same benign data, as the lab rule.
"""

from pathlib import Path

import pytest

from harness.evaluate import alert_is_true_positive, find_alerts, load_rule
from harness.replay import load_logs_by_prefix, records_for_rule

REPO_ROOT = Path(__file__).resolve().parent.parent
UPSTREAM_DIR = REPO_ROOT / "upstream" / "sigmahq" / "rules"
LOGS = load_logs_by_prefix(REPO_ROOT / "data" / "sample-logs")

# upstream file -> (lab rule it was derived from, scenario it must catch)
UPSTREAM_RULES = {
    "cloud/aws/cloudtrail/aws_iam_policy_version_wildcard_actions_set_default.yml":
        ("aws/aws_policy_version_grants_wildcard.yml", "aws_privilege_escalation"),
}


def test_every_upstream_rule_is_registered():
    found = {p.relative_to(UPSTREAM_DIR).as_posix() for p in UPSTREAM_DIR.rglob("*.yml")}
    assert found == set(UPSTREAM_RULES)


@pytest.mark.parametrize("relative_path", sorted(UPSTREAM_RULES))
def test_upstream_rule_matches_lab_rule_behaviour(relative_path):
    lab_path, scenario = UPSTREAM_RULES[relative_path]
    upstream = load_rule(UPSTREAM_DIR / relative_path)
    lab = load_rule(REPO_ROOT / "detections" / lab_path)
    records = records_for_rule(upstream, LOGS)
    upstream_alerts = find_alerts(upstream, records)
    # Fires on its attack...
    assert any(e["lab_scenario"] == scenario and e["lab_label"] == "malicious"
               for alert in upstream_alerts for e in alert)
    # ...is quiet on benign...
    assert all(alert_is_true_positive(alert) for alert in upstream_alerts)
    # ...and raises exactly the same alerts as the lab version.
    lab_ids = [[id(e) for e in a] for a in find_alerts(lab, records)]
    assert [[id(e) for e in a] for a in upstream_alerts] == lab_ids


def test_upstream_rule_uses_sigmahq_style():
    for path in UPSTREAM_DIR.rglob("*.yml"):
        text = path.read_text(encoding="utf-8")
        assert "\n    " in text and "\n  - " not in text, f"{path.name}: SigmaHQ uses 4-space indentation"
        assert "lab_" not in text and "identity-to-data-lab" not in text, f"{path.name}: lab-only content"
        rule = load_rule(path)
        assert all("_" not in tag.split(".", 1)[1] for tag in rule["tags"] if not tag.startswith("attack.t")), (
            "SigmaHQ tactic tags use hyphens, e.g. attack.privilege-escalation")
