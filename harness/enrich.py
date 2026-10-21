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


def build_context(alert_events, all_records):
    """Describe how the events in one alert compare to everything else the same user did.

    For each history field (IP, ASN, country...), list the values seen in the alert and
    whether any of them is new for this user, i.e. never seen in the user's other events.
    """
    user = user_of(alert_events[0])
    if user is None:
        return {"user": None, "events_in_alert": len(alert_events)}
    history = [other for other in all_records
               if user_of(other) == user and not any(other is e for e in alert_events)]
    context = {"user": user, "events_in_alert": len(alert_events),
               "other_events_for_user": len(history)}
    for field in HISTORY_FIELDS:
        values = sorted({str(v) for v in (get_field(e, field) for e in alert_events) if v is not None})
        if not values:
            continue
        seen_before = {str(get_field(other, field)) for other in history}
        context[f"{field}_values"] = values
        context[f"new_{field}_for_user"] = any(value not in seen_before for value in values)
    return context


def triage(rule, alerts, all_records, entries):
    """Triage a rule's alerts: auto-close known-benign ones, add context to the rest.

    An alert is auto-closed only if EVERY event in it matches the same known-benign
    entry. One unexplained event is enough to keep it open for a human.
    """
    triaged = []
    for alert_events in alerts:
        matches = [find_known_benign(event, rule, entries) for event in alert_events]
        first = matches[0]
        if first is not None and all(match is first for match in matches):
            triaged.append({
                "status": "auto_closed",
                "reason": f"{first['name']}: {first['reason']}",
                "events": alert_events,
            })
        else:
            triaged.append({
                "status": "open",
                "context": build_context(alert_events, all_records),
                "events": alert_events,
            })
    return triaged
