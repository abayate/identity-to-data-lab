"""Tests for the harness. For now, a smoke test that the Phase 0 scaffold is in place."""

import importlib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

EXPECTED_DIRS = [
    "docs",
    "detections/entra",
    "detections/data",
    "detections/aws",
    "simulations/entra_aitm",
    "simulations/data_exfil",
    "simulations/aws_keyleak",
    "data/sample-logs",
    "harness",
    "tests",
]


@pytest.mark.parametrize("relative_path", EXPECTED_DIRS)
def test_scaffold_directory_exists(relative_path):
    assert (REPO_ROOT / relative_path).is_dir()


@pytest.mark.parametrize("module", ["replay", "evaluate", "enrich", "coverage"])
def test_harness_module_imports(module):
    imported = importlib.import_module(f"harness.{module}")
    assert imported.__doc__, f"harness/{module}.py needs a docstring"


# ---------------------------------------------------------------------------
# enrich.py, coverage.py and replay.py, tested end to end on made-up data.
# The data lives in a temporary folder so these tests never depend on (or change)
# the real sample logs and rules.
# ---------------------------------------------------------------------------

import json
import xml.etree.ElementTree as ET

from harness import coverage, enrich, replay

TOY_RULE = """
title: Toy rule - sign-in from test network
logsource:
  product: azure
  service: signinlogs
tags:
  - attack.initial_access
  - attack.t1078.004
detection:
  selection:
    IPAddress|startswith: '203.0.113.'
  condition: selection
"""

TOY_KNOWN_BENIGN = """
- name: test-scanner
  reason: The internal scanner account is expected to sign in from the test network.
  match:
    UserPrincipalName: scanner@contoso.example
"""

TOY_EVENTS = [
    {"UserPrincipalName": "alice@contoso.example", "IPAddress": "198.51.100.10", "lab_label": "benign"},
    {"UserPrincipalName": "alice@contoso.example", "IPAddress": "203.0.113.5", "lab_label": "malicious"},
    {"UserPrincipalName": "scanner@contoso.example", "IPAddress": "203.0.113.9", "lab_label": "benign"},
    {"UserPrincipalName": "bob@contoso.example", "IPAddress": "198.51.100.11", "lab_label": "benign"},
]


@pytest.fixture
def toy_lab(tmp_path):
    """Build a tiny rules/logs/known-benign layout in a temp folder and return its paths."""
    (tmp_path / "rules").mkdir()
    (tmp_path / "rules" / "toy.yml").write_text(TOY_RULE, encoding="utf-8")
    (tmp_path / "logs").mkdir()
    with open(tmp_path / "logs" / "entra_signins_toy.jsonl", "w", encoding="utf-8") as handle:
        for event in TOY_EVENTS:
            handle.write(json.dumps(event) + "\n")
    (tmp_path / "known_benign.yml").write_text(TOY_KNOWN_BENIGN, encoding="utf-8")
    return tmp_path


def run_toy_replay(lab):
    return replay.main([
        "--logs", str(lab / "logs"), "--rules", str(lab / "rules"),
        "--known-benign", str(lab / "known_benign.yml"), "--out", str(lab / "reports"),
    ])


def test_replay_writes_all_reports(toy_lab):
    assert run_toy_replay(toy_lab) == 0
    for name in ("results.md", "results.json", "coverage.md", "coverage.svg"):
        assert (toy_lab / "reports" / name).is_file()


def test_replay_scores_and_triages(toy_lab):
    run_toy_replay(toy_lab)
    results = json.loads((toy_lab / "reports" / "results.json").read_text(encoding="utf-8"))
    rule = results["rules"][0]
    assert rule["hits"] == 2
    assert rule["true_positives"] == 1
    assert rule["false_positives"] == 1   # the scanner
    assert rule["auto_closed"] == 1       # ...which the known-benign list closes
    assert rule["fp_rate"] == pytest.approx(1 / 3)
    assert rule["fp_rate_after_triage"] == 0.0
    assert (results["chain_caught"], results["chain_total"]) == (1, 1)


def test_replay_marks_technique_tested(toy_lab):
    run_toy_replay(toy_lab)
    results = json.loads((toy_lab / "reports" / "results.json").read_text(encoding="utf-8"))
    status = {item["id"]: item["status"] for item in results["coverage"]}
    assert status["T1078.004"] == "tested"
    assert status["T1530"] == "gap"


def test_coverage_svg_is_valid_xml(toy_lab):
    run_toy_replay(toy_lab)
    ET.parse(toy_lab / "reports" / "coverage.svg")  # raises if the SVG is malformed


def test_rule_ignores_other_log_types(toy_lab):
    # A CloudTrail file must not be fed to a sign-in rule, even if a field happens to match.
    with open(toy_lab / "logs" / "cloudtrail_toy.jsonl", "w", encoding="utf-8") as handle:
        handle.write(json.dumps({"IPAddress": "203.0.113.1", "lab_label": "benign"}) + "\n")
    run_toy_replay(toy_lab)
    results = json.loads((toy_lab / "reports" / "results.json").read_text(encoding="utf-8"))
    assert results["rules"][0]["events_checked"] == len(TOY_EVENTS)


def test_enrich_context_flags_new_ip():
    rule = {"title": "any"}
    hit = TOY_EVENTS[1]  # alice from a network she has not used before
    alerts = enrich.triage(rule, [[hit]], TOY_EVENTS, entries=[])
    assert alerts[0]["status"] == "open"
    assert alerts[0]["context"]["user"] == "alice@contoso.example"
    assert alerts[0]["context"]["new_IPAddress_for_user"] is True


def test_known_benign_entry_can_be_limited_to_rules():
    entries = [{"name": "x", "reason": "y", "rules": ["Other rule"],
                "match": {"UserPrincipalName": "scanner@contoso.example"}}]
    assert enrich.find_known_benign(TOY_EVENTS[2], {"title": "Toy"}, entries) is None
    assert enrich.find_known_benign(TOY_EVENTS[2], {"title": "Other rule"}, entries) is not None


def test_known_benign_entry_needs_a_reason(tmp_path):
    path = tmp_path / "kb.yml"
    path.write_text("- name: x\n  match: {A: b}\n", encoding="utf-8")
    with pytest.raises(ValueError):
        enrich.load_known_benign(path)


def test_real_known_benign_file_loads():
    assert isinstance(enrich.load_known_benign(), list)


def test_technique_tags_parsed():
    rule = {"tags": ["attack.initial_access", "attack.t1078.004", "attack.T1530", "cve.2024.1"]}
    assert coverage.techniques_in_rule(rule) == {"T1078.004", "T1530"}
