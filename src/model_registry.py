"""
Single source of truth for all model artifacts.
Import MODEL_REGISTRY, LIVE_MODELS, or DEFAULT_MODEL instead of
hardcoding paths in individual components.
"""

import os

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _model_path(filename):
    return os.path.join(_PROJECT_ROOT, "models", filename)


MODEL_REGISTRY = {
    "Random Forest": {
        "display_name": "Random Forest (3-class)",
        "artifact_path": _model_path("rf_3class_model.pkl"),
        "config_path": _model_path("rf_3class_config.json"),
        "scaler_path": _model_path("scaler.pkl"),
        "class_names": ["Benign", "Volumetric", "Semantic"],
        "input_kind": "tabular",
        "input_shape": (20,),
        "live_supported": True,
    },
    "Decision Tree": {
        "display_name": "Decision Tree (3-class)",
        "artifact_path": _model_path("dt_3class_model.pkl"),
        "config_path": None,
        "scaler_path": _model_path("scaler.pkl"),
        "class_names": ["Benign", "Volumetric", "Semantic"],
        "input_kind": "tabular",
        "input_shape": (20,),
        "live_supported": True,
    },
    "XGBoost": {
        "display_name": "XGBoost (3-class)",
        "artifact_path": _model_path("xgb_3class_model.pkl"),
        "config_path": _model_path("xgb_3class_config.json"),
        "scaler_path": _model_path("scaler.pkl"),
        "class_names": ["Benign", "Volumetric", "Semantic"],
        "input_kind": "tabular",
        "input_shape": (20,),
        "live_supported": True,
    },
    "LSTM": {
        "display_name": "LSTM (sequence, 10×20)",
        "artifact_path": _model_path("lstm_model.keras"),
        "config_path": _model_path("lstm_config.json"),
        "scaler_path": _model_path("scaler_lstm.pkl"),
        "class_names": ["Benign", "Volumetric", "Semantic"],
        "input_kind": "sequence",
        "input_shape": (10, 20),
        "live_supported": False,  # enabled in Sprint 2
    },
    "BiLSTM": {
        "display_name": "BiLSTM (sequence, 10×20)",
        "artifact_path": _model_path("bilstm_model.keras"),
        "config_path": _model_path("bilstm_config.json"),
        "scaler_path": _model_path("scaler_lstm.pkl"),
        "class_names": ["Benign", "Volumetric", "Semantic"],
        "input_kind": "sequence",
        "input_shape": (10, 20),
        "live_supported": False,  # enabled in Sprint 2
    },
}

LIVE_MODELS = {k: v for k, v in MODEL_REGISTRY.items() if v["live_supported"]}
DEFAULT_MODEL = "Random Forest"
