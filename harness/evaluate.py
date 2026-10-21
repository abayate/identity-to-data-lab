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
  - Correlation rules (Sigma v2): a file with two YAML documents, a base rule
    and a `correlation:` rule that refers to it by `name`. Supported types:
      event_count  - more than N matching events per group within a timespan
      value_count  - more than N distinct values of a field per group within a timespan
    Only one base rule per correlation is supported.

String comparisons ignore case, as the Sigma spec says they should.

An ALERT is what an analyst would receive. A normal rule raises one alert per
matching event. A correlation rule raises one alert per group (e.g. per user)
whose events meet the condition, and that alert contains all of those events.
"""

import re
from datetime import datetime
from pathlib import Path

import yaml


# ---------------------------------------------------------------------------
# Loading rules
# ---------------------------------------------------------------------------

def load_rule(path):
    """Read one Sigma rule file and return it as a dict.

    For a correlation file (base rule + correlation rule as two YAML documents),
    the returned dict is the correlation rule with the base rule's `logsource`
    and `detection` copied in, so the rest of the code can treat it like any rule.
    """
    with open(path, encoding="utf-8") as handle:
        documents = [doc for doc in yaml.safe_load_all(handle) if doc]
    if len(documents) == 1:
        rule = documents[0]
    else:
        correlations = [doc for doc in documents if "correlation" in doc]
        if len(correlations) != 1:
            raise ValueError(f"{path}: a multi-document rule needs exactly one correlation rule")
        rule = correlations[0]
        base_names = rule["correlation"]["rules"]
        if len(base_names) != 1:
            raise ValueError(f"{path}: only one base rule per correlation is supported")
        bases = [doc for doc in documents if doc.get("name") == base_names[0]]
        if not bases:
            raise ValueError(f"{path}: correlation refers to unknown rule {base_names[0]!r}")
        rule["logsource"] = bases[0]["logsource"]
        rule["detection"] = bases[0]["detection"]
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


def parse_timespan(text):
    """Turn a Sigma timespan like '30s', '15m', '1h' or '1d' into seconds."""
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    match = re.fullmatch(r"(\d+)([smhd])", str(text).strip())
    if not match:
        raise ValueError(f"bad timespan {text!r}; use e.g. 30s, 15m, 1h, 1d")
    return int(match.group(1)) * units[match.group(2)]


def event_time(record):
    """Seconds since the epoch for a record's TimeGenerated (ISO 8601, 'Z' allowed)."""
    return datetime.fromisoformat(record["TimeGenerated"].replace("Z", "+00:00")).timestamp()


def window_meets_condition(events, correlation):
    """Does one group of events, inside one time window, satisfy the correlation condition?"""
    condition = correlation["condition"]
    if correlation["type"] == "event_count":
        amount = len(events)
    elif correlation["type"] == "value_count":
        amount = len({str(get_field(e, condition["field"])).lower() for e in events
                      if get_field(e, condition["field"]) is not None})
    else:
        raise ValueError(f"unsupported correlation type {correlation['type']!r}")
    # Reuse the numeric comparison code: e.g. {"gt": 1} means amount > 1.
    comparisons = {key: value for key, value in condition.items() if key != "field"}
    return all(value_matches(amount, threshold, operator) for operator, threshold in comparisons.items())


def correlation_alerts(rule, matching):
    """Group matching events and return one alert (a list of events) per qualifying group.

    For each group (e.g. each user), every event is tried as the start of a window
    of length `timespan`. If any window meets the condition, the group raises one
    alert containing every event from every qualifying window.
    """
    correlation = rule["correlation"]
    group_fields = correlation.get("group-by", [])
    timespan = parse_timespan(correlation["timespan"])

    groups = {}
    for record in matching:
        key = tuple(str(get_field(record, field)).lower() for field in group_fields)
        groups.setdefault(key, []).append(record)

    alerts = []
    for key in sorted(groups):
        events = sorted(groups[key], key=event_time)
        flagged = []
        for start_index, start in enumerate(events):
            window = [e for e in events[start_index:] if event_time(e) - event_time(start) <= timespan]
            if window_meets_condition(window, correlation):
                flagged.extend(e for e in window if not any(e is f for f in flagged))
        if flagged:
            alerts.append(sorted(flagged, key=event_time))
    return alerts


def find_alerts(rule, records):
    """Return the alerts the rule raises: a list of alerts, each a list of events."""
    matching = [record for record in records if rule_matches(rule, record)]
    if "correlation" in rule:
        return correlation_alerts(rule, matching)
    return [[record] for record in matching]


def find_hits(rule, records):
    """Return every event that is part of any alert the rule raises."""
    return [event for alert in find_alerts(rule, records) for event in alert]


def alert_is_true_positive(alert):
    """An alert is a true positive if any event in it is malicious.

    A correlation alert about a phished user usually also contains that user's own
    normal sign-ins. The alert is still correct, so it counts once, as a true positive.
    """
    return any(event.get("lab_label") == "malicious" for event in alert)


def score_rule(rule, records):
    """Count how the rule's alerts line up with the answer key (`lab_label`).

    hits:            number of alerts raised
    true_positives:  alerts containing at least one malicious event
    false_positives: alerts containing only benign events
    fp_rate:         false-positive alerts / all benign events (0.0 if there are none)

    False negatives are not counted per rule, because one rule is not expected to
    catch every malicious event. Each rule covers one step of the attack. Whole-
    chain coverage is measured across all rules together in harness/replay.py.
    """
    alerts = find_alerts(rule, records)
    true_positives = sum(1 for alert in alerts if alert_is_true_positive(alert))
    false_positives = len(alerts) - true_positives
    benign_total = sum(1 for record in records if record.get("lab_label") == "benign")
    return {
        "rule": rule.get("title", rule.get("_path", "unnamed rule")),
        "hits": len(alerts),
        "true_positives": true_positives,
        "false_positives": false_positives,
        "fp_rate": false_positives / benign_total if benign_total else 0.0,
    }
