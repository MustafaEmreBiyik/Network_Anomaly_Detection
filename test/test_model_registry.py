"""S1-08: Assert all registered artifact paths resolve to real files."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from model_registry import MODEL_REGISTRY


def test_all_live_model_artifacts_exist():
    missing = []
    for key, entry in MODEL_REGISTRY.items():
        if not entry["live_supported"]:
            continue
        for field in ("artifact_path", "scaler_path"):
            path = entry[field]
            if path and not os.path.exists(path):
                missing.append(f"{key}.{field}: {path}")
    assert not missing, f"Missing model files:\n" + "\n".join(missing)


def test_class_names_length():
    for key, entry in MODEL_REGISTRY.items():
        assert len(entry["class_names"]) >= 2, f"{key} must have at least 2 class names"


def test_live_models_subset():
    from model_registry import LIVE_MODELS, MODEL_REGISTRY
    for k in LIVE_MODELS:
        assert k in MODEL_REGISTRY
        assert MODEL_REGISTRY[k]["live_supported"]
