"""Checks that every committed sample log is valid and follows its schema.

Sample logs are JSON Lines files (one JSON object per line) in data/sample-logs/.
The file name prefix says which schema applies: entra_signins*, entra_audit*,
m365_audit* (see simulations/schemas.py).
"""

import json
from datetime import datetime
from pathlib import Path

import pytest

from simulations.schemas import ALLOWED_LABELS, SCHEMAS

SAMPLE_LOG_DIR = Path(__file__).resolve().parent.parent / "data" / "sample-logs"
ALL_FILES = sorted(SAMPLE_LOG_DIR.glob("*.jsonl"))


def schema_for(path):
    """Return (required, optional) for a sample-log file, based on its name prefix."""
    for prefix, schema in SCHEMAS.items():
        if path.name.startswith(prefix):
            return schema
    raise AssertionError(f"{path.name} has no schema; name it with one of {sorted(SCHEMAS)}")


def load_records(path):
    """Read a JSON Lines file and return a list of (line_number, record) pairs."""
    records = []
    with open(path, encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if line.strip():  # tolerate a trailing blank line
                records.append((line_number, json.loads(line)))
    return records


def check_record(record, required, optional):
    """Return a list of problems with one record (empty list = valid)."""
    problems = []
    for field, expected_type in required.items():
        if record.get(field) is None:
            problems.append(f"missing field {field}")
        elif not isinstance(record[field], expected_type):
            problems.append(f"{field} should be {expected_type.__name__}")
    for field, expected_type in optional.items():
        if record.get(field) is not None and not isinstance(record[field], expected_type):
            problems.append(f"{field} should be {expected_type.__name__} or null")
    if record.get("lab_label") not in ALLOWED_LABELS:
        problems.append(f"lab_label must be one of {sorted(ALLOWED_LABELS)}")
    try:
        # fromisoformat does not accept a trailing "Z" before Python 3.11, so swap it for +00:00.
        datetime.fromisoformat(str(record.get("TimeGenerated")).replace("Z", "+00:00"))
    except ValueError:
        problems.append("TimeGenerated is not an ISO 8601 timestamp")
    return problems


# --- Tests for the checker itself, so we know it catches bad records. ---

TOY_REQUIRED = {"TimeGenerated": str, "IPAddress": str, "lab_label": str}
TOY_OPTIONAL = {"AutonomousSystemNumber": int}


def make_valid_record():
    return {"TimeGenerated": "2026-10-01T14:03:22Z", "IPAddress": "203.0.113.7", "lab_label": "benign"}


def test_checker_accepts_valid_record():
    assert check_record(make_valid_record(), TOY_REQUIRED, TOY_OPTIONAL) == []


def test_checker_rejects_missing_field():
    record = make_valid_record()
    del record["IPAddress"]
    assert "missing field IPAddress" in check_record(record, TOY_REQUIRED, TOY_OPTIONAL)


def test_checker_allows_null_optional_but_not_wrong_type():
    record = make_valid_record()
    record["AutonomousSystemNumber"] = None
    assert check_record(record, TOY_REQUIRED, TOY_OPTIONAL) == []
    record["AutonomousSystemNumber"] = "64500"
    assert check_record(record, TOY_REQUIRED, TOY_OPTIONAL)


def test_checker_rejects_bad_label():
    record = make_valid_record()
    record["lab_label"] = "suspicious"
    assert check_record(record, TOY_REQUIRED, TOY_OPTIONAL)


def test_checker_rejects_bad_timestamp():
    record = make_valid_record()
    record["TimeGenerated"] = "yesterday"
    assert check_record(record, TOY_REQUIRED, TOY_OPTIONAL)


# --- Tests over the real committed sample logs. ---

def test_sample_logs_exist():
    assert ALL_FILES, "no sample logs; run python -m simulations.public_datasets.generate"


@pytest.mark.parametrize("path", ALL_FILES, ids=lambda p: p.name)
def test_sample_log_file_is_valid(path):
    required, optional = schema_for(path)
    records = load_records(path)
    assert records, f"{path.name} is empty"
    for line_number, record in records:
        problems = check_record(record, required, optional)
        assert not problems, f"{path.name} line {line_number}: {problems}"


@pytest.mark.parametrize("prefix", ["entra_signins", "m365_audit"])
def test_log_type_has_both_labels(prefix):
    # Without both kinds we could not measure a true-positive or a false-positive rate.
    labels = {record["lab_label"]
              for path in ALL_FILES if path.name.startswith(prefix)
              for _, record in load_records(path)}
    assert labels == ALLOWED_LABELS
