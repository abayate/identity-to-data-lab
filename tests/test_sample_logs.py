"""Checks that committed Entra sign-in sample logs are valid and follow the schema.

Sample logs are JSON Lines files: one JSON object (one sign-in event) per line.
Entra sign-in files are named `entra_signins*.jsonl` inside data/sample-logs/.
Other log types (M365 file access, CloudTrail) get their own checks in later phases.
"""

import json
from datetime import datetime
from pathlib import Path

import pytest

from simulations.entra_aitm.schema import ALLOWED_LABELS, REQUIRED_FIELDS

SAMPLE_LOG_DIR = Path(__file__).resolve().parent.parent / "data" / "sample-logs"
SIGNIN_FILES = sorted(SAMPLE_LOG_DIR.glob("entra_signins*.jsonl"))


def load_records(path):
    """Read a JSON Lines file and return a list of (line_number, record) pairs."""
    records = []
    with open(path, encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if line.strip():  # tolerate a trailing blank line
                records.append((line_number, json.loads(line)))
    return records


def check_record(record):
    """Return a list of problems with one sign-in record (empty list = valid)."""
    problems = []
    for field, expected_type in REQUIRED_FIELDS.items():
        if field not in record:
            problems.append(f"missing field {field}")
        elif not isinstance(record[field], expected_type):
            problems.append(f"{field} should be {expected_type.__name__}")
    if record.get("lab_label") not in ALLOWED_LABELS:
        problems.append(f"lab_label must be one of {sorted(ALLOWED_LABELS)}")
    try:
        # fromisoformat does not accept a trailing "Z" before Python 3.11, so swap it for +00:00.
        datetime.fromisoformat(str(record.get("TimeGenerated")).replace("Z", "+00:00"))
    except ValueError:
        problems.append("TimeGenerated is not an ISO 8601 timestamp")
    return problems


# --- Tests for the checker itself, so we know it catches bad records. ---

def make_valid_record():
    """A hand-written record that satisfies the schema, used as a known-good baseline."""
    sample_values = {str: "x", int: 1}
    record = {field: sample_values[kind] for field, kind in REQUIRED_FIELDS.items()}
    record["TimeGenerated"] = "2026-10-01T14:03:22Z"
    record["lab_label"] = "benign"
    return record


def test_checker_accepts_valid_record():
    assert check_record(make_valid_record()) == []


def test_checker_rejects_missing_field():
    record = make_valid_record()
    del record["IPAddress"]
    assert "missing field IPAddress" in check_record(record)


def test_checker_rejects_bad_label():
    record = make_valid_record()
    record["lab_label"] = "suspicious"
    assert check_record(record)


def test_checker_rejects_bad_timestamp():
    record = make_valid_record()
    record["TimeGenerated"] = "yesterday"
    assert check_record(record)


# --- Tests over the real committed sample logs. ---

@pytest.mark.skipif(not SIGNIN_FILES, reason="no entra_signins*.jsonl committed yet")
@pytest.mark.parametrize("path", SIGNIN_FILES, ids=lambda p: p.name)
def test_signin_file_is_valid(path):
    records = load_records(path)
    assert records, f"{path.name} is empty"
    for line_number, record in records:
        problems = check_record(record)
        assert not problems, f"{path.name} line {line_number}: {problems}"


@pytest.mark.skipif(not SIGNIN_FILES, reason="no entra_signins*.jsonl committed yet")
def test_signin_logs_contain_both_labels():
    # Without both kinds we could not measure a true-positive or a false-positive rate.
    labels = {record["lab_label"] for path in SIGNIN_FILES for _, record in load_records(path)}
    assert labels == ALLOWED_LABELS
