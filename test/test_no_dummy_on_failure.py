"""S1-08: Verify that extraction failure produces NO Kafka publish (no dummy data)."""
import os
import sys
import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


def test_no_kafka_publish_on_extraction_failure():
    """When run_cicflowmeter_cli fails, feature_extraction_and_predict must return
    success=False and must NOT call KAFKA_PRODUCER.produce()."""
    import live_bridge

    mock_producer = MagicMock()
    live_bridge.KAFKA_PRODUCER = mock_producer

    with patch("live_bridge.run_cicflowmeter_cli", return_value=(False, "simulated CLI error")):
        result = live_bridge.feature_extraction_and_predict()

    assert result["success"] is False, "Expected success=False on extraction failure"
    mock_producer.produce.assert_not_called(), "Producer must not publish dummy data on failure"


def test_no_kafka_publish_on_empty_csv(tmp_path):
    """When CSV is empty, feature_extraction_and_predict must not publish."""
    import live_bridge
    import pandas as pd

    mock_producer = MagicMock()
    live_bridge.KAFKA_PRODUCER = mock_producer

    empty_csv = tmp_path / "empty.csv"
    empty_csv.write_text("")  # exists but empty

    with (
        patch("live_bridge.run_cicflowmeter_cli", return_value=(True, "")),
        patch("live_bridge.TEMP_CSV", str(empty_csv)),
        patch("live_bridge.pd.read_csv", return_value=pd.DataFrame()),
    ):
        result = live_bridge.feature_extraction_and_predict()

    assert result["success"] is False
    mock_producer.produce.assert_not_called()
