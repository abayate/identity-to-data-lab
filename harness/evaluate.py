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
    |fieldref (compare with another field of the same event),
    and |all (every listed value must match instead of any).
  - Conditions using: and, or, not, parentheses, "1 of name*", "all of name*".
  - Correlation rules (Sigma v2). A correlation is a YAML document with a
    `correlation:` block that refers to other rules by their `name`, usually
    kept in the same file as extra YAML documents. Supported types:
      event_count  - more than N matching events per group within a timespan
      value_count  - more than N distinct values of a field per group within a timespan
      temporal     - every referenced rule fired for the same group within a timespan
    event_count / value_count take exactly one plain base rule. temporal can refer
    to several rules, including other correlations and rules in other files, and
    to rules over different log types. `aliases` map one group-by name to a
    different field per rule (e.g. user = UserPrincipalName in sign-ins but
    UserId in M365 audit).

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

def read_documents(path):
    """Read every YAML document in a rule file, tagging each with the file it came from."""
    with open(path, encoding="utf-8") as handle:
        documents = [doc for doc in yaml.safe_load_all(handle) if doc]
    for doc in documents:
        doc["_path"] = str(path)
    return documents


def build_registry(documents):
    """Map rule `name` -> document, so correlations can find the rules they refer to."""
    registry = {}
    for doc in documents:
        if "name" in doc:
            if doc["name"] in registry:
                raise ValueError(f"two rules are both named {doc['name']!r}")
            registry[doc["name"]] = doc
    return registry


def resolve(rule, registry, stack=()):
    """Attach the rules a correlation refers to as rule['_bases'] (recursively).

    For a simple correlation over one plain base rule, the base's `logsource` and
    `detection` are also copied onto the correlation, so it can be matched like any rule.
    """
    if "correlation" not in rule:
        return rule
    if rule.get("name") in stack:
        raise ValueError(f"correlation loop through {rule['name']!r}")
    bases = []
    for name in rule["correlation"]["rules"]:
        if name not in registry:
            raise ValueError(f"{rule['_path']}: correlation refers to unknown rule {name!r}")
        bases.append(resolve(registry[name], registry, stack + (rule.get("name"),)))
    rule["_bases"] = bases
    if rule["correlation"]["type"] in ("event_count", "value_count"):
        if len(bases) != 1 or "correlation" in bases[0]:
            raise ValueError(f"{rule['_path']}: {rule['correlation']['type']} needs exactly one plain base rule")
        rule["logsource"] = bases[0]["logsource"]
        rule["detection"] = bases[0]["detection"]
    return rule


def top_level_rules(documents):
    """The documents that raise alerts of their own.

    A plain rule that exists only to feed a correlation (a "base rule") is not
    reported separately: on its own it is too broad (e.g. "any successful sign-in").
    Correlations are always top level, even when another correlation uses them.
    """
    referenced = {name for doc in documents if "correlation" in doc
                  for name in doc["correlation"]["rules"]}
    return [doc for doc in documents
            if "correlation" in doc or doc.get("name") not in referenced]


def load_rule(path, registry=None):
    """Read the one top-level rule in a file and return it as a dict.

    `registry` lets the file refer to rules defined in other files (load_rules
    passes the registry of the whole detections directory).
    """
    documents = read_documents(path)
    full_registry = dict(registry or {})
    full_registry.update(build_registry(documents))
    rules = top_level_rules(documents)
    if len(rules) != 1:
        raise ValueError(f"{path}: expected exactly one top-level rule, found {len(rules)}")
    return resolve(rules[0], full_registry)


def load_rules(directory):
    """Load every top-level rule from every .yml file under a directory, sorted by path."""
    documents = [doc for path in sorted(Path(directory).rglob("*.yml")) for doc in read_documents(path)]
    registry = build_registry(documents)
    return [resolve(rule, registry) for rule in top_level_rules(documents)]


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
    If the path runs into a list, the rest of the path is looked up in every list
    item and a list of the values found is returned, e.g.
    `createVolumePermission.add.items.userId` -> ["111122223333", ...].
    """
    if field in record:
        return record[field]
    value = record
    parts = field.split(".")
    for index, part in enumerate(parts):
        if isinstance(value, list):
            rest = ".".join(parts[index:])
            found = [get_field(item, rest) for item in value if isinstance(item, dict)]
            found = [item for item in found if item is not None]
            return found or None
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
    # A list value (from a list inside the event) matches if any of its items matches.
    candidates = actual if isinstance(actual, list) else [actual]

    def matches(value):
        if modifier == "fieldref":
            # |fieldref compares against ANOTHER field of the same record (Sigma v2),
            # e.g. "the user a key was created for is the caller themself".
            other = get_field(record, value)
            return other is not None and any(value_matches(c, other, None) for c in candidates)
        return any(value_matches(c, value, modifier) for c in candidates)

    results = [matches(value) for value in expected_values]
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

def explain_match(rule, record):
    """Explain WHY a rule's detection did or didn't match one record.

    Returns each selection's result, every field check inside it (field, expected value,
    the record's actual value, matched or not), and the overall condition result. The
    dashboard uses this to show the rule logic working on a real log line.
    """
    detection = rule["detection"]
    selections = {}
    for name, selection in detection.items():
        if name == "condition":
            continue
        items = selection if isinstance(selection, list) else [selection]
        checks = []
        for item in items:
            for spec, expected in item.items():
                checks.append({
                    "field": spec,
                    "expected": expected,
                    "actual": get_field(record, spec.split("|")[0]),
                    "matched": field_matches(record, spec, expected),
                })
        selections[name] = {"matched": selection_matches(record, selection), "checks": checks}
    matched = condition_matches(detection["condition"],
                                {name: s["matched"] for name, s in selections.items()})
    return {"condition": detection["condition"], "selections": selections, "matched": matched}


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


def group_key(record, rule_name, correlation):
    """The group a record belongs to, e.g. ('alice@contoso.example',). None if a field is missing.

    `aliases` let one group-by name point at a different field for each rule:
        aliases: {user: {signin_rule: UserPrincipalName, m365_rule: UserId}}
    """
    aliases = correlation.get("aliases", {})
    key = []
    for name in correlation.get("group-by", []):
        field = aliases.get(name, {}).get(rule_name, name)
        value = get_field(record, field)
        if value is None:
            return None
        key.append(str(value).lower())
    return tuple(key)


def flag_windows(tagged_events, timespan, window_qualifies):
    """Slide a window over (tag, event) pairs and collect every event in any qualifying window.

    Every event is tried as the start of a window lasting `timespan` seconds.
    `window_qualifies(window)` decides if that window meets the rule's condition.
    """
    tagged_events = sorted(tagged_events, key=lambda pair: event_time(pair[1]))
    times = [event_time(event) for _, event in tagged_events]
    flagged, flagged_ids = [], set()
    end = 0
    # Two pointers: `end` only moves forward, so each window is found without rescanning.
    for start in range(len(tagged_events)):
        while end < len(tagged_events) and times[end] - times[start] <= timespan:
            end += 1
        window = tagged_events[start:end]
        if window_qualifies(window):
            for _, event in window:
                if id(event) not in flagged_ids:  # id() = this exact event object
                    flagged_ids.add(id(event))
                    flagged.append(event)
    return sorted(flagged, key=event_time)


def correlation_alerts(rule, matching):
    """event_count / value_count: one alert per group whose events meet the condition in some window."""
    correlation = rule["correlation"]
    base_name = correlation["rules"][0]
    groups = {}
    for record in matching:
        key = group_key(record, base_name, correlation)
        if key is not None:
            groups.setdefault(key, []).append((base_name, record))
    alerts = []
    for key in sorted(groups):
        flagged = flag_windows(groups[key], parse_timespan(correlation["timespan"]),
                               lambda window: window_meets_condition([e for _, e in window], correlation))
        if flagged:
            alerts.append(flagged)
    return alerts


def temporal_alerts(rule, records):
    """temporal: one alert per group in which EVERY referenced rule fired within the timespan."""
    correlation = rule["correlation"]
    needed = set(correlation["rules"])
    groups = {}
    for base in rule["_bases"]:
        for alert in find_alerts(base, records):
            for event in alert:
                key = group_key(event, base["name"], correlation)
                if key is not None:
                    groups.setdefault(key, []).append((base["name"], event))
    alerts = []
    for key in sorted(groups):
        flagged = flag_windows(groups[key], parse_timespan(correlation["timespan"]),
                               lambda window: {tag for tag, _ in window} == needed)
        if flagged:
            alerts.append(flagged)
    return alerts


def find_alerts(rule, records):
    """Return the alerts the rule raises: a list of alerts, each a list of events."""
    if "correlation" not in rule:
        return [[record] for record in records if rule_matches(rule, record)]
    if rule["correlation"]["type"] == "temporal":
        return temporal_alerts(rule, records)
    matching = [record for record in records if rule_matches(rule, record)]
    return correlation_alerts(rule, matching)


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
