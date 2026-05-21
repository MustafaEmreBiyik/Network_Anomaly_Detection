"""S1-08: Assert any existing live CSV conforms to the v2 16-column schema."""
import os
import sys
import pytest
import pandas as pd

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from kafka_consumer import CSV_HEADER_COLUMNS

CSV_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "live_captured_traffic.csv")
EXPECTED_COLUMNS = CSV_HEADER_COLUMNS


def test_v2_column_count():
    assert len(EXPECTED_COLUMNS) == 16, f"v2 schema must have 16 columns, got {len(EXPECTED_COLUMNS)}"


def test_csv_columns_if_exists():
    if not os.path.exists(CSV_PATH):
        pytest.skip("live_captured_traffic.csv does not exist yet")
    df = pd.read_csv(CSV_PATH, nrows=0)
    missing = [c for c in EXPECTED_COLUMNS if c not in df.columns]
    assert not missing, f"CSV missing v2 columns: {missing}"


def test_action_values_if_exists():
    if not os.path.exists(CSV_PATH):
        pytest.skip("live_captured_traffic.csv does not exist yet")
    df = pd.read_csv(CSV_PATH)
    if df.empty or "Action" not in df.columns:
        pytest.skip("No data rows or Action column absent")
    valid_actions = {"NONE", "ALLOWED", "BLOCKED"}
    bad = df[~df["Action"].isin(valid_actions)]
    assert bad.empty, f"Unexpected Action values: {bad['Action'].unique()}"
