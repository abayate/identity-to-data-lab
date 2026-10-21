"""Tests for the public-dataset converter (simulations/public_datasets/generate.py)."""

import pytest

from simulations.public_datasets import generate
from simulations.public_datasets.fetch import RAW_DIR, load_sources, raw_log_path

SOURCES = load_sources()


def test_every_dataset_has_evidence_and_a_raw_file():
    for dataset in SOURCES["datasets"]:
        assert dataset.get("evidence", "").strip(), f"{dataset['name']} needs written evidence"
        assert raw_log_path(dataset).is_file(), f"run fetch: missing {raw_log_path(dataset)}"
    assert (RAW_DIR / "LICENSE").is_file(), "the upstream Apache-2.0 LICENSE must be kept"


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("2023-08-03T22:00:48.7263711Z", "2023-08-03T22:00:48.726371Z"),  # 7 digits trimmed
        ("2023-01-12T19:22:14.5285742+00:00", "2023-01-12T19:22:14.528574Z"),
        ("2024-12-10T16:13:47", "2024-12-10T16:13:47.000000Z"),           # no zone = UTC
        ("2023-12-04T20:42:05Z", "2023-12-04T20:42:05.000000Z"),
    ],
)
def test_to_utc_iso(raw, expected):
    assert generate.to_utc_iso(raw) == expected


def test_label_precedence():
    dataset = {
        "default_label": "benign",
        "exclude_when": [{"category": "ServicePrincipalSignInLogs"}],
        "malicious_when": [{"properties.ipAddress": "4.4.4.4"}],
    }
    assert generate.label_event({"category": "ServicePrincipalSignInLogs",
                                 "properties": {"ipAddress": "4.4.4.4"}}, dataset) is None
    assert generate.label_event({"properties": {"ipAddress": "4.4.4.4"}}, dataset) == "malicious"
    assert generate.label_event({"properties": {"ipAddress": "10.0.0.1"}}, dataset) == "benign"


def test_signin_is_flattened_to_sentinel_columns():
    raw = {
        "time": "2023-08-03T21:59:28.1Z", "category": "SignInLogs", "correlationId": "c-1",
        "properties": {
            "userPrincipalName": "a@x", "appId": "app-1", "ipAddress": "4.4.4.4",
            "autonomousSystemNumber": 12252, "authenticationProtocol": "deviceCode",
            "status": {"errorCode": 0}, "location": {"countryOrRegion": "US", "city": "X"},
        },
    }
    record = generate.convert_signin(raw)
    assert record["UserPrincipalName"] == "a@x"
    assert record["IPAddress"] == "4.4.4.4"
    assert record["AuthenticationProtocol"] == "deviceCode"
    assert record["ResultType"] == "0"          # Sentinel stores ResultType as text
    assert record["Location"] == "US"
    assert record["CorrelationId"] == "c-1"


def test_graph_style_signin_without_properties_wrapper():
    raw = {"createdDateTime": "2023-12-04T20:42:05Z", "userPrincipalName": "a@x", "appId": "app",
           "ipAddress": "1.2.3.4", "isInteractive": True, "correlationId": "c", "status": {"errorCode": 0}}
    assert generate.event_kind(raw) == "signin"
    record = generate.convert_signin(raw)
    assert record["Category"] == "SignInLogs"
    assert record["IPAddress"] == "1.2.3.4"


def test_event_kind_recognizes_each_shape():
    assert generate.event_kind({"Operation": "FileDownloaded", "CreationTime": "x"}) == "m365"
    assert generate.event_kind({"category": "AuditLogs", "properties": {}}) == "audit"
    with pytest.raises(ValueError):
        generate.event_kind({"something": "else"})


def test_generate_is_deterministic(tmp_path):
    first, second = tmp_path / "one", tmp_path / "two"
    generate.main(out_dir=first)
    generate.main(out_dir=second)
    first_files = sorted(p.name for p in first.iterdir())
    assert first_files == sorted(p.name for p in second.iterdir())
    for name in first_files:
        assert (first / name).read_bytes() == (second / name).read_bytes(), name


def test_committed_sample_logs_are_up_to_date(tmp_path):
    # If someone edits sources.yml or the converter but forgets to regenerate, this fails.
    generate.main(out_dir=tmp_path)
    committed = generate.OUT_DIR
    for produced in tmp_path.iterdir():
        assert (committed / produced.name).read_bytes() == produced.read_bytes(), (
            f"{produced.name} is stale: run python -m simulations.public_datasets.generate")
