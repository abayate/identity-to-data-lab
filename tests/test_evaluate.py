"""Unit tests for the minimal Sigma matcher in harness/evaluate.py.

These use tiny made-up rules and records so each Sigma feature is tested on its
own. The real detection rules get their own tests in test_detections.py.
"""

import pytest

from harness.evaluate import (
    condition_matches,
    field_matches,
    load_rule,
    rule_matches,
    score_rule,
)

RECORD = {
    "UserPrincipalName": "Alice@Contoso.example",
    "IPAddress": "203.0.113.7",
    "AutonomousSystemNumber": 64500,
    "AppDisplayName": "Office 365 Exchange Online",
    "Empty": "",
}


# --- Single field lines ---

@pytest.mark.parametrize(
    "spec, expected, should_match",
    [
        ("UserPrincipalName", "alice@contoso.example", True),   # exact, case-insensitive
        ("UserPrincipalName", "bob@contoso.example", False),
        ("UserPrincipalName", ["bob@x", "alice@contoso.example"], True),  # list = OR
        ("AppDisplayName|contains", "exchange", True),
        ("AppDisplayName|startswith", "office", True),
        ("AppDisplayName|endswith", "online", True),
        ("AppDisplayName|endswith", "teams", False),
        ("AppDisplayName|contains|all", ["office", "exchange"], True),
        ("AppDisplayName|contains|all", ["office", "teams"], False),
        ("IPAddress|re", r"^203\.0\.113\.\d+$", True),
        ("AutonomousSystemNumber|gt", 64000, True),
        ("AutonomousSystemNumber|lt", 64000, False),
        ("AutonomousSystemNumber|gte", 64500, True),
        ("AutonomousSystemNumber|lte", 64499, False),
        ("AutonomousSystemNumber", 64500, True),                # int compared as text
        ("Missing", None, True),                                # null = absent
        ("Empty", None, True),                                  # null = empty
        ("IPAddress", None, False),
        ("Missing", "anything", False),
    ],
)
def test_field_matches(spec, expected, should_match):
    assert field_matches(RECORD, spec, expected) is should_match


def test_dotted_field_reads_nested_value():
    cloudtrail_like = {"userIdentity": {"type": "IAMUser", "userName": "dev-ci"}}
    assert field_matches(cloudtrail_like, "userIdentity.type", "iamuser")
    assert not field_matches(cloudtrail_like, "userIdentity.arn", "x")


def test_unknown_modifier_is_an_error():
    with pytest.raises(ValueError):
        field_matches(RECORD, "IPAddress|base64", "x")


# --- Condition strings ---

RESULTS = {"selection_a": True, "selection_b": False, "filter": True}


@pytest.mark.parametrize(
    "condition, expected",
    [
        ("selection_a", True),
        ("selection_b", False),
        ("selection_a and selection_b", False),
        ("selection_a or selection_b", True),
        ("selection_a and not filter", False),
        ("not selection_b", True),
        ("selection_b or selection_a and filter", True),        # and binds tighter than or
        ("(selection_b or selection_a) and not filter", False),
        ("1 of selection*", True),
        ("all of selection*", False),
        ("not not selection_a", True),
    ],
)
def test_condition_matches(condition, expected):
    assert condition_matches(condition, RESULTS) is expected


@pytest.mark.parametrize("bad", ["nosuchname", "selection_a and", "(selection_a", "1 of zzz*"])
def test_bad_conditions_raise(bad):
    with pytest.raises((ValueError, IndexError)):
        condition_matches(bad, RESULTS)


# --- Whole rules, loaded from YAML, and scoring ---

TOY_RULE_YAML = """
title: Toy rule - sign-in from documentation IP range
detection:
  selection:
    IPAddress|startswith: '203.0.113.'
  filter_known_vpn:
    - UserPrincipalName: 'vpn-svc@contoso.example'
  condition: selection and not filter_known_vpn
"""


@pytest.fixture
def toy_rule(tmp_path):
    path = tmp_path / "toy.yml"
    path.write_text(TOY_RULE_YAML, encoding="utf-8")
    return load_rule(path)


def test_rule_fires_and_filters(toy_rule):
    assert rule_matches(toy_rule, {"IPAddress": "203.0.113.9", "UserPrincipalName": "a@x"})
    assert not rule_matches(toy_rule, {"IPAddress": "198.51.100.1", "UserPrincipalName": "a@x"})
    assert not rule_matches(
        toy_rule, {"IPAddress": "203.0.113.9", "UserPrincipalName": "vpn-svc@contoso.example"}
    )


def test_score_rule(toy_rule):
    records = [
        {"IPAddress": "203.0.113.1", "UserPrincipalName": "a@x", "lab_label": "malicious"},
        {"IPAddress": "203.0.113.2", "UserPrincipalName": "b@x", "lab_label": "benign"},
        {"IPAddress": "198.51.100.1", "UserPrincipalName": "c@x", "lab_label": "benign"},
        {"IPAddress": "198.51.100.2", "UserPrincipalName": "d@x", "lab_label": "benign"},
        {"IPAddress": "198.51.100.3", "UserPrincipalName": "e@x", "lab_label": "benign"},
    ]
    score = score_rule(toy_rule, records)
    assert score["hits"] == 2
    assert score["true_positives"] == 1
    assert score["false_positives"] == 1
    assert score["fp_rate"] == 0.25
