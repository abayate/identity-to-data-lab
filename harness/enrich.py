"""Auto-closes known-benign false positives and attaches investigation context to real alerts.

When a rule fires, an analyst would normally ask two questions:
  1. "Is this something we already know is fine?"  (a known-benign pattern)
  2. "If not, what else do I need to know to investigate it?"

This module answers both automatically:
  - `harness/known_benign.yml` lists patterns that are expected and harmless,
    each with a written reason. A hit matching one is marked `auto_closed`.
  - Every other hit is marked `open` and gets context pulled from the rest of
    the logs: has this user been seen from this IP / network / country before,
    and how many events does the user have in total?

Known-benign entries use the same selection syntax as Sigma rules, so they are
matched with the same code (`selection_matches` from evaluate.py).
"""

from pathlib import Path

import yaml

from harness.evaluate import get_field, selection_matches

KNOWN_BENIGN_PATH = Path(__file__).resolve().parent / "known_benign.yml"

# Which field identifies the "who" in each log type. The first one present is used.
USER_FIELDS = ["UserPrincipalName", "UserId", "userIdentity.arn"]

# Fields we compare against the user's history to spot something new.
HISTORY_FIELDS = ["IPAddress", "AutonomousSystemNumber", "Location", "ClientIP", "sourceIPAddress"]


def load_known_benign(path=KNOWN_BENIGN_PATH):
    """Read the known-benign list. Each entry needs a name, a reason, and a match selection."""
    with open(path, encoding="utf-8") as handle:
        entries = yaml.safe_load(handle) or []
    for entry in entries:
        for key in ("name", "reason", "match"):
            if key not in entry:
                raise ValueError(f"known-benign entry is missing {key!r}: {entry}")
    return entries


def find_known_benign(record, rule, entries):
    """Return the first known-benign entry that covers this hit, or None.

    An entry can optionally list `rules:` (rule titles) to limit which rules it closes.
    Without that list it applies to every rule.
    """
    for entry in entries:
        limited_to = entry.get("rules")
        if limited_to and rule.get("title") not in limited_to:
            continue
        if selection_matches(record, entry["match"]):
            return entry
    return None


def user_of(record):
    """Return the user (or identity) a record belongs to, or None."""
    for field in USER_FIELDS:
        value = get_field(record, field)
        if value:
            return str(value).lower()
    return None


def build_context(record, all_records):
    """Describe how this event compares to everything else the same user did."""
    user = user_of(record)
    if user is None:
        return {"user": None}
    history = [other for other in all_records if other is not record and user_of(other) == user]
    context = {"user": user, "other_events_for_user": len(history)}
    for field in HISTORY_FIELDS:
        value = get_field(record, field)
        if value is None:
            continue
        seen_before = any(get_field(other, field) == value for other in history)
        context[f"new_{field}_for_user"] = not seen_before
    return context


def triage(rule, hits, all_records, entries):
    """Turn a rule's raw hits into triaged alerts (auto_closed or open, with context)."""
    alerts = []
    for record in hits:
        benign_entry = find_known_benign(record, rule, entries)
        if benign_entry:
            alerts.append({
                "status": "auto_closed",
                "reason": f"{benign_entry['name']}: {benign_entry['reason']}",
                "record": record,
            })
        else:
            alerts.append({
                "status": "open",
                "context": build_context(record, all_records),
                "record": record,
            })
    return alerts
