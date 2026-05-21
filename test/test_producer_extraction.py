"""S1-08: Assert that a successful extraction sends a v2 Kafka payload."""
import os
import sys
import json
import pytest
import pandas as pd
from unittest.mock import patch, MagicMock, call

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


def _make_fake_feature_df(num_rows=2, num_features=20):
    cols = [f"feat_{i}" for i in range(num_features)]
    return pd.DataFrame([[float(i)] * num_features for i in range(num_rows)], columns=cols)


def test_kafka_payload_contains_schema_version():
    import live_bridge

    mock_producer = MagicMock()
    live_bridge.KAFKA_PRODUCER = mock_producer
    live_bridge.KAFKA_TOPIC = "test-topic"

    fake_df = _make_fake_feature_df()

    with (
        patch("live_bridge.run_cicflowmeter_cli", return_value=(True, "")),
        patch("live_bridge.os.path.exists", return_value=True),
        patch("live_bridge.pd.read_csv", return_value=fake_df),
        patch("live_bridge.prepare_feature_frame", return_value=fake_df),
        patch("live_bridge.extract_source_ips", return_value=pd.Series(["1.2.3.4"] * len(fake_df))),
        patch("live_bridge.MODEL_FEATURE_COLUMNS", list(fake_df.columns)),
    ):
        result = live_bridge.feature_extraction_and_predict()

    assert result["success"] is True
    assert mock_producer.produce.called

    # Inspect the first call's message payload
    first_call_kwargs = mock_producer.produce.call_args_list[0]
    payload_bytes = first_call_kwargs[1]["value"] if "value" in first_call_kwargs[1] else first_call_kwargs[0][1]
    payload = json.loads(payload_bytes.decode())

    assert payload.get("schema_version") == "v2", f"schema_version missing or wrong: {payload.keys()}"
    assert "extraction_method" in payload
    assert "features" in payload
    assert "feature_count" in payload
