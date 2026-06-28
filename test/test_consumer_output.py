"""S1-08: Feed a synthetic v2 Kafka message and assert process_message output."""
import os
import sys
import json
import tempfile
import warnings
from datetime import datetime

import joblib
import numpy as np
import pandas as pd
import pytest

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
SRC_DIR = os.path.join(os.path.dirname(__file__), "..", "src")
UTILS_DIR = os.path.join(SRC_DIR, "utils")
sys.path.insert(0, SRC_DIR)
sys.path.insert(0, UTILS_DIR)

PROJECT_ROOT = os.path.join(os.path.dirname(__file__), "..")
from model_registry import MODEL_REGISTRY, DEFAULT_MODEL

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_consumer_globals(tmp_csv):
    """Import kafka_consumer and point its CSV output to a temp file."""
    import importlib
    import kafka_consumer as kc
    importlib.reload(kc)  # fresh state

    entry = MODEL_REGISTRY[DEFAULT_MODEL]
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        kc.MODEL = joblib.load(entry["artifact_path"])
        kc.SCALER = joblib.load(entry["scaler_path"])
    kc.CURRENT_MODEL_TYPE = "sklearn"
    kc.CURRENT_MODEL_NAME = DEFAULT_MODEL
    kc.CSV_OUTPUT_PATH = tmp_csv

    # Write the CSV header
    pd.DataFrame(columns=kc.CSV_HEADER_COLUMNS).to_csv(tmp_csv, index=False)
    return kc


def _make_v2_message(scaler):
    """Build a minimal valid v2 Kafka message payload."""
    feature_names = list(scaler.feature_names_in_)
    features = {name: float(np.random.uniform(0, 100)) for name in feature_names}
    msg = {
        "timestamp": datetime.now().isoformat(),
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "features": features,
        "feature_count": len(features),
        "producer_id": "test_producer",
        "schema_version": "v2",
        "extraction_method": "cli",
    }
    return json.dumps(msg).encode("utf-8")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_process_message_returns_true():
    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
        tmp = f.name
    try:
        kc = _load_consumer_globals(tmp)
        msg_bytes = _make_v2_message(kc.SCALER)
        result = kc.process_message(msg_bytes)
        assert result is True, "process_message should return True on success"
    finally:
        os.unlink(tmp)


def test_csv_has_all_schema_columns():
    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
        tmp = f.name
    try:
        kc = _load_consumer_globals(tmp)
        msg_bytes = _make_v2_message(kc.SCALER)
        kc.process_message(msg_bytes)
        df = pd.read_csv(tmp)
        # Sabit sayi yerine consumer'in kendi semasiyla birebir karsilastir
        assert list(df.columns) == list(kc.CSV_HEADER_COLUMNS), (
            f"CSV sutunlari CSV_HEADER_COLUMNS ile birebir eslesmeli; alinan: {list(df.columns)}"
        )
    finally:
        os.unlink(tmp)


def test_confidence_matches_predicted_class():
    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
        tmp = f.name
    try:
        kc = _load_consumer_globals(tmp)
        msg_bytes = _make_v2_message(kc.SCALER)
        kc.process_message(msg_bytes)
        df = pd.read_csv(tmp)
        row = df.iloc[-1]
        label = int(row["Predicted_Label"])
        probs = [row["Prob_Benign"], row["Prob_Volumetric"], row["Prob_Semantic"]]
        expected_confidence = round(probs[label], 4)
        assert abs(row["Confidence_Score"] - expected_confidence) < 1e-3, (
            f"Confidence {row['Confidence_Score']} != probs[{label}] = {expected_confidence}"
        )
    finally:
        os.unlink(tmp)


def test_rejected_on_empty_features():
    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
        tmp = f.name
    try:
        kc = _load_consumer_globals(tmp)
        msg = {
            "timestamp": datetime.now().isoformat(),
            "src_ip": "1.2.3.4",
            "dst_ip": "5.6.7.8",
            "features": {},
            "producer_id": "test",
            "schema_version": "v2",
            "extraction_method": "cli",
        }
        result = kc.process_message(json.dumps(msg).encode())
        assert result is False, "Should reject empty feature dict"
        assert kc.STATS["rejected_messages"] >= 1
    finally:
        os.unlink(tmp)
