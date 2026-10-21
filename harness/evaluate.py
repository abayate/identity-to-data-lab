"""Checks which detection rules fired on which log events and scores true / false positives per rule.

This is a deliberately small Sigma matcher. Real Sigma tooling (pySigma) converts
rules into a SIEM's query language. Here we skip that and evaluate the rule's
`detection` block directly against each log record, which is enough to prove a
rule fires on attack traffic and stays quiet on benign traffic.

Supported Sigma features:
  - Named selections. A selection is a map of field -> value. All fields must
    match (AND). A list of values for one field means any of them (OR).
    A selection written as a list of maps matches if any map matches (OR).
  - Field modifiers: |contains, |startswith, |endswith, |re, |gt, |gte, |lt, |lte,
    and |all (every listed value must match instead of any).
  - Conditions using: and, or, not, parentheses, "1 of name*", "all of name*".

String comparisons ignore case, as the Sigma spec says they should.
"""

import re
from pathlib import Path

import yaml


# ---------------------------------------------------------------------------
# Loading rules
# ---------------------------------------------------------------------------

def load_rule(path):
    """Read one Sigma rule YAML file and return it as a dict."""
    with open(path, encoding="utf-8") as handle:
        rule = yaml.safe_load(handle)
    rule["_path"] = str(path)
    return rule


def load_rules(directory):
    """Load every .yml rule under a directory (searching sub-folders too), sorted by path."""
    return [load_rule(path) for path in sorted(Path(directory).rglob("*.yml"))]


# ---------------------------------------------------------------------------
# Matching one field
# ---------------------------------------------------------------------------

def value_matches(actual, expected, modifier):
    """Does one actual log value satisfy one expected rule value under a modifier?"""
    # In Sigma, `null` means "the field is missing or empty".
    if expected is None:
        return actual is None or actual == ""
    if actual is None:
        return False

    # Numeric comparisons.
    if modifier in ("gt", "gte", "lt", "lte"):
        try:
            actual_number = float(actual)
        except (TypeError, ValueError):
            return False
        expected_number = float(expected)
        if modifier == "gt":
            return actual_number > expected_number
        if modifier == "gte":
            return actual_number >= expected_number
        if modifier == "lt":
            return actual_number < expected_number
        return actual_number <= expected_number

    # Everything else is compared as text, ignoring case.
    actual_text = str(actual).lower()
    expected_text = str(expected).lower()
    if modifier == "contains":
        return expected_text in actual_text
    if modifier == "startswith":
        return actual_text.startswith(expected_text)
    if modifier == "endswith":
        return actual_text.endswith(expected_text)
    if modifier == "re":
        # Regexes keep their original case; add (?i) in the rule if you want case-insensitive.
        return re.search(str(expected), str(actual)) is not None
    if modifier is None:
        return actual_text == expected_text
    raise ValueError(f"unsupported Sigma modifier: {modifier}")


def get_field(record, field):
    """Look up a field, following dots into nested objects.

    CloudTrail nests data, so Sigma rules write `userIdentity.type` to mean
    record["userIdentity"]["type"]. A flat key with a literal dot wins if present.
    """
    if field in record:
        return record[field]
    value = record
    for part in field.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def field_matches(record, field_spec, expected):
    """Check one `field|modifier: value(s)` line of a selection against a record."""
    # "IPAddress|startswith|all" -> field "IPAddress", modifiers ["startswith", "all"]
    field, *modifiers = field_spec.split("|")
    require_all = "all" in modifiers
    value_modifiers = [m for m in modifiers if m != "all"]
    if len(value_modifiers) > 1:
        raise ValueError(f"only one value modifier is supported, got {field_spec}")
    modifier = value_modifiers[0] if value_modifiers else None

    actual = get_field(record, field)
    expected_values = expected if isinstance(expected, list) else [expected]
    results = [value_matches(actual, value, modifier) for value in expected_values]
    return all(results) if require_all else any(results)


def selection_matches(record, selection):
    """Check a whole named selection against a record."""
    # A list of maps: any one map matching is enough (OR).
    if isinstance(selection, list):
        return any(selection_matches(record, item) for item in selection)
    # A single map: every field line must match (AND).
    return all(field_matches(record, spec, expected) for spec, expected in selection.items())


# ---------------------------------------------------------------------------
# Evaluating the condition line
# ---------------------------------------------------------------------------

def tokenize(condition):
    """Split a condition string into words and parentheses."""
    return condition.replace("(", " ( ").replace(")", " ) ").split()


def condition_matches(condition, selection_results):
    """Evaluate a Sigma condition string, given True/False for each named selection.

    Grammar, lowest to highest precedence:
        or_expr  := and_expr ("or" and_expr)*
        and_expr := not_expr ("and" not_expr)*
        not_expr := "not" not_expr | atom
        atom     := "(" or_expr ")" | ("1"|"all") "of" pattern | selection_name
    """
    tokens = tokenize(condition)
    position = 0

    def peek():
        return tokens[position] if position < len(tokens) else None

    def take():
        nonlocal position
        token = tokens[position]
        position += 1
        return token

    def names_for(pattern):
        # "selection*" means every selection whose name starts with "selection".
        if pattern.endswith("*"):
            prefix = pattern[:-1]
            names = [name for name in selection_results if name.startswith(prefix)]
        else:
            names = [pattern]
        if not names:
            raise ValueError(f"condition pattern {pattern!r} matches no selection")
        return names

    def parse_or():
        result = parse_and()
        while peek() == "or":
            take()
            right = parse_and()  # always parse both sides so the position stays correct
            result = result or right
        return result

    def parse_and():
        result = parse_not()
        while peek() == "and":
            take()
            right = parse_not()
            result = result and right
        return result

    def parse_not():
        if peek() == "not":
            take()
            return not parse_not()
        return parse_atom()

    def parse_atom():
        token = take()
        if token == "(":
            result = parse_or()
            if take() != ")":
                raise ValueError(f"missing ')' in condition: {condition}")
            return result
        if token in ("1", "all") and peek() == "of":
            take()  # the word "of"
            values = [selection_results[name] for name in names_for(take())]
            return any(values) if token == "1" else all(values)
        if token not in selection_results:
            raise ValueError(f"condition uses unknown selection {token!r}")
        return selection_results[token]

    result = parse_or()
    if position != len(tokens):
        raise ValueError(f"unexpected text in condition: {condition}")
    return result


# ---------------------------------------------------------------------------
# Whole rules and scoring
# ---------------------------------------------------------------------------

def rule_matches(rule, record):
    """Return True if the rule fires on this single log record."""
    detection = rule["detection"]
    selection_results = {
        name: selection_matches(record, selection)
        for name, selection in detection.items()
        if name != "condition"
    }
    return condition_matches(detection["condition"], selection_results)


def find_hits(rule, records):
    """Return the records the rule fires on."""
    return [record for record in records if rule_matches(rule, record)]


def score_rule(rule, records):
    """Count how the rule's hits line up with the answer key (`lab_label`) in the records.

    true_positives:  rule fired on a malicious record
    false_positives: rule fired on a benign record
    fp_rate:         false positives / all benign records (0.0 if there are none)

    False negatives are not counted per rule, because one rule is not expected to
    catch every malicious event. Each rule covers one step of the attack. Whole-
    chain coverage is measured across all rules together in harness/replay.py.
    """
    hits = find_hits(rule, records)
    true_positives = sum(1 for record in hits if record.get("lab_label") == "malicious")
    false_positives = sum(1 for record in hits if record.get("lab_label") == "benign")
    benign_total = sum(1 for record in records if record.get("lab_label") == "benign")
    return {
        "rule": rule.get("title", rule.get("_path", "unnamed rule")),
        "hits": len(hits),
        "true_positives": true_positives,
        "false_positives": false_positives,
        "fp_rate": false_positives / benign_total if benign_total else 0.0,
    }
