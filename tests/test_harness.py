"""Tests for the harness. For now, a smoke test that the Phase 0 scaffold is in place."""

import importlib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

EXPECTED_DIRS = [
    "docs",
    "detections/entra",
    "detections/data",
    "detections/aws",
    "simulations/entra_aitm",
    "simulations/data_exfil",
    "simulations/aws_keyleak",
    "data/sample-logs",
    "harness",
    "tests",
]


@pytest.mark.parametrize("relative_path", EXPECTED_DIRS)
def test_scaffold_directory_exists(relative_path):
    assert (REPO_ROOT / relative_path).is_dir()


@pytest.mark.parametrize("module", ["replay", "evaluate", "enrich", "coverage"])
def test_harness_module_imports(module):
    imported = importlib.import_module(f"harness.{module}")
    assert imported.__doc__, f"harness/{module}.py needs a docstring"
