"""Tests that each detection rule fires on its true-positive sample and stays silent on benign traffic.

Four kinds of checks:
  1. Quality bar: every rule has the metadata a reviewer (or SigmaHQ) expects.
  2. No cheating: rules never read the answer key, or the values used to make it.
  3. Fires on its attack: each rule raises at least one alert containing a
     malicious event from the scenario it was written for.
  4. Quiet on benign: no rule raises an alert made only of benign events.

The rule -> scenario mapping lives HERE, in the test, not in the rule. Rules must
not know which events are malicious.
"""

import re
from pathlib import Path

import pytest
import yaml

from harness.evaluate import alert_is_true_positive, find_alerts, load_rule, load_rules
from harness.replay import SERVICE_TO_FILE_PREFIX, load_logs_by_prefix, records_for_rule, rule_services
from simulations.public_datasets.fetch import load_sources

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = REPO_ROOT / "detections"
RULE_FILES = sorted(RULES_DIR.rglob("*.yml"))
LOGS = load_logs_by_prefix(REPO_ROOT / "data" / "sample-logs")
DETECTIONS_DOC = (REPO_ROOT / "docs" / "03-detections.md").read_text(encoding="utf-8")

# Which scenario(s) each rule is expected to catch (the answer key, kept out of the rules).
EXPECTED_SCENARIOS = {
    "data/identity_to_data_access_after_multi_ip_session.yml": {"aitm_cookie_replay"},
    "data/m365_mass_file_access.yml": {"sharepoint_exfiltration"},
    "data/m365_rclone_download.yml": {"sharepoint_exfiltration"},
    "data/m365_sensitive_term_search.yml": {"sharepoint_recon"},
    "entra/entra_device_code_signin.yml": {"device_code_phishing"},
    "entra/entra_oauth_consent_granted.yml": {"oauth_consent_grant"},
    "entra/entra_user_signin_multiple_ips.yml": {"aitm_cookie_replay"},
}


def rule_id(path):
    return Path(path).relative_to(RULES_DIR).as_posix()


# Load all rules together: a correlation may refer to a rule defined in another file.
RULES = {rule_id(rule["_path"]): rule for rule in load_rules(RULES_DIR)}


# --- 1. Quality bar ---

def test_every_rule_has_an_expected_scenario():
    assert set(RULES) == {rule_id(p) for p in RULE_FILES}, "each file must hold exactly one top-level rule"
    assert set(RULES) == set(EXPECTED_SCENARIOS), (
        "add new rules to EXPECTED_SCENARIOS (and remove deleted ones)")


@pytest.mark.parametrize("path", RULE_FILES, ids=rule_id)
def test_rule_metadata(path):
    rule = RULES[rule_id(path)]
    for key in ("title", "id", "status", "description", "falsepositives", "level", "tags"):
        assert rule.get(key), f"{rule_id(path)} is missing {key}"
    assert re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", rule["id"])
    assert rule_services(rule) and rule_services(rule) <= set(SERVICE_TO_FILE_PREFIX)
    assert any(re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", tag) for tag in rule["tags"]), (
        "rule needs at least one ATT&CK technique tag")
    assert rule["level"] in {"informational", "low", "medium", "high", "critical"}


def test_rule_ids_are_unique():
    ids = []
    for path in RULE_FILES:
        with open(path, encoding="utf-8") as handle:
            ids += [doc["id"] for doc in yaml.safe_load_all(handle) if doc and "id" in doc]
    assert len(ids) == len(set(ids))


@pytest.mark.parametrize("path", RULE_FILES, ids=rule_id)
def test_rule_is_documented_with_kql(path):
    title = RULES[rule_id(path)]["title"]
    heading = f"\n### {title}\n"
    assert heading in DETECTIONS_DOC, f"docs/03-detections.md needs a '### {title}' section"
    section = DETECTIONS_DOC.split(heading, 1)[1].split("\n### ", 1)[0].split("\n## ", 1)[0]
    assert "```kql" in section, f"the {title!r} section needs a KQL equivalent"


# --- 2. No cheating ---

def labeling_values():
    """Every literal value sources.yml uses to decide labels (IPs, account prefixes...)."""
    values = set()
    for dataset in load_sources()["datasets"]:
        for key in ("malicious_when", "benign_when", "exclude_when"):
            for selection in dataset.get(key) or []:
                values.update(str(v).lower() for v in selection.values())
    return values


@pytest.mark.parametrize("path", RULE_FILES, ids=rule_id)
def test_rule_does_not_read_the_answer_key(path):
    text = path.read_text(encoding="utf-8").lower()
    assert "lab_" not in text, "rules must not read lab_ fields"
    for value in labeling_values():
        assert value not in text, f"rule uses {value!r}, a value the labels were built from"


# --- 3 and 4. Behaviour on the sample logs ---

@pytest.mark.parametrize("path", RULE_FILES, ids=rule_id)
def test_rule_fires_on_its_attack(path):
    rule = RULES[rule_id(path)]
    alerts = find_alerts(rule, records_for_rule(rule, LOGS))
    caught = {event["lab_scenario"] for alert in alerts for event in alert
              if event["lab_label"] == "malicious"}
    missing = EXPECTED_SCENARIOS[rule_id(path)] - caught
    assert not missing, f"{rule['title']} did not catch: {missing}"


@pytest.mark.parametrize("path", RULE_FILES, ids=rule_id)
def test_rule_is_quiet_on_benign(path):
    rule = RULES[rule_id(path)]
    false_alerts = [alert for alert in find_alerts(rule, records_for_rule(rule, LOGS))
                    if not alert_is_true_positive(alert)]
    assert not false_alerts, f"{rule['title']} raised {len(false_alerts)} all-benign alert(s)"


def test_every_log_type_with_rules_has_benign_events():
    # A "quiet on benign" result means nothing if there was no benign traffic to be quiet on.
    for rule in load_rules(RULES_DIR):
        records = records_for_rule(rule, LOGS)
        assert any(r["lab_label"] == "benign" for r in records), (
            f"{rule['title']} has no benign events to be tested against")


# --- Known limitations, written down as tests so they stay visible ---

def test_multi_ip_rule_known_false_positive_roaming_user():
    """A normal user hopping from office Wi-Fi to a phone hotspot also trips the rule.

    The public data has no such user, so this hand-made pair documents the gap. In
    production this is tuned with known_benign.yml entries for corporate/VPN ranges.
    """
    rule = RULES["entra/entra_user_signin_multiple_ips.yml"]
    roaming = [
        {"UserPrincipalName": "pat@contoso.example", "IPAddress": "198.51.100.20",
         "ResultType": "0", "TimeGenerated": "2026-10-01T09:00:00Z", "lab_label": "benign"},
        {"UserPrincipalName": "pat@contoso.example", "IPAddress": "203.0.113.50",
         "ResultType": "0", "TimeGenerated": "2026-10-01T09:40:00Z", "lab_label": "benign"},
    ]
    assert len(find_alerts(rule, roaming)) == 1


def test_mass_file_rule_known_false_positive_new_laptop_sync():
    """A user setting up a new laptop syncs a whole library at once and trips the rule.

    Documented as a test for the same reason as the roaming user: the public data has
    no such user, so the 0% FP result would otherwise hide it.
    """
    rule = RULES["data/m365_mass_file_access.yml"]
    sync = [{"UserId": "pat@contoso.example", "Operation": "FileSyncDownloadedFull",
             "TimeGenerated": f"2026-10-01T09:00:{second:02d}Z", "lab_label": "benign"}
            for second in range(25)]  # 25 files in 25 seconds
    assert len(find_alerts(rule, sync)) == 1


# --- The identity -> data link needs BOTH halves ---

def chain_events(include_second_ip=True, include_data_access=True,
                 access_time="2026-10-01T09:15:00Z"):
    """A user's sign-ins (optionally from a second IP) and an optional later mailbox read."""
    events = [{"UserPrincipalName": "Pat@Contoso.example", "IPAddress": "198.51.100.20",
               "ResultType": "0", "TimeGenerated": "2026-10-01T09:00:00Z", "lab_label": "benign"}]
    if include_second_ip:
        events.append({"UserPrincipalName": "pat@contoso.example", "IPAddress": "203.0.113.50",
                       "ResultType": "0", "TimeGenerated": "2026-10-01T09:05:00Z", "lab_label": "benign"})
    if include_data_access:
        events.append({"UserId": "pat@contoso.example", "Operation": "MailItemsAccessed",
                       "TimeGenerated": access_time,
                       "lab_label": "benign"})
    return events


def test_identity_to_data_rule_fires_when_both_halves_present():
    rule = RULES["data/identity_to_data_access_after_multi_ip_session.yml"]
    alerts = find_alerts(rule, chain_events())
    assert len(alerts) == 1
    # The alias joined two differently-named, differently-cased user fields into one group.
    assert {"Operation" in e for e in alerts[0]} == {True, False}


@pytest.mark.parametrize("kwargs", [
    {"include_second_ip": False},          # data access, but no suspicious session
    {"include_data_access": False},        # suspicious session, but no data access
    {"access_time": "2026-10-01T10:30:00Z"},  # data access more than an hour after both sign-ins
])
def test_identity_to_data_rule_needs_both_halves_in_time(kwargs):
    rule = RULES["data/identity_to_data_access_after_multi_ip_session.yml"]
    assert find_alerts(rule, chain_events(**kwargs)) == []
