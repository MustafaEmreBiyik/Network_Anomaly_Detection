"""Utilities for compressing the feature space and producing SHAP assets."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import shap
# matplotlib yalnızca opsiyonel öznitelik grafiği için; main() içinde tembel içe aktarılır.

# parents[2] = repo kökü (model_registry/dashboard ile tutarlı; parents[1]=src yanlıştı).
PROJECT_ROOT = Path(__file__).resolve().parents[2]
# Aktif 3-sınıf model ve ölçeklenmiş eğitim verisi (canlı tüketici de bu uzayı kullanır).
DEFAULT_MODEL_PATH = PROJECT_ROOT / "models" / "rf_3class_model.pkl"
DEFAULT_DATA_PATH = PROJECT_ROOT / "data" / "processed_ml" / "train.csv"
DEFAULT_TOP_FEATURES_PATH = PROJECT_ROOT / "models" / "top_20_features.json"
DEFAULT_SHAP_PATH = PROJECT_ROOT / "models" / "shap_explainer.pkl"
DEFAULT_FIG_PATH = PROJECT_ROOT / "reports" / "figures" / "top20_features.png"


def parse_args():
    parser = argparse.ArgumentParser(description="Optimize RF model feature space and create SHAP assets")
    parser.add_argument("--model-path", default=DEFAULT_MODEL_PATH, type=Path, help="Path to trained RF model")
    parser.add_argument("--data-path", default=DEFAULT_DATA_PATH, type=Path, help="CSV used for feature names/background data")
    parser.add_argument("--label-column", default="Label", help="Name of the label column to drop from the dataset")
    parser.add_argument("--top-k", default=20, type=int, help="How many features to keep")
    parser.add_argument("--top-features-path", default=DEFAULT_TOP_FEATURES_PATH, type=Path,
                        help="Where to save the JSON list of top features")
    parser.add_argument("--shap-path", default=DEFAULT_SHAP_PATH, type=Path,
                        help="Where to persist the SHAP explainer")
    parser.add_argument("--figure-path", default=DEFAULT_FIG_PATH, type=Path,
                        help="Where to save the feature-importance chart")
    parser.add_argument("--background-samples", default=500, type=int,
                        help="Number of rows sampled for SHAP background data")
    return parser.parse_args()


def ensure_parent_dir(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)


def main():
    args = parse_args()

    if not args.model_path.exists():
        raise FileNotFoundError(f"Model not found: {args.model_path}")
    if not args.data_path.exists():
        raise FileNotFoundError(f"Data not found: {args.data_path}")

    model = joblib.load(args.model_path)
    if not hasattr(model, "feature_importances_"):
        raise AttributeError("Model does not expose feature_importances_.")

    df = pd.read_csv(args.data_path)
    if args.label_column in df.columns:
        df = df.drop(columns=[args.label_column])

    # Modelin eğitildiği öznitelik kümesi/sırasıyla hizala (fazladan sütunlara dayanıklı).
    importances_arr = model.feature_importances_
    if hasattr(model, "feature_names_in_"):
        model_features = [str(f) for f in model.feature_names_in_]
    elif len(df.columns) == len(importances_arr):
        model_features = df.columns.tolist()
    else:
        # numpy ile eğitilmiş + fazladan sütun: config.TOP_FEATURES ile hizalamayı dene
        import sys
        sys.path.insert(0, str(PROJECT_ROOT / "src"))
        try:
            from config import TOP_FEATURES as _CFG_TF
        except ImportError:
            _CFG_TF = []
        if _CFG_TF and len(_CFG_TF) == len(importances_arr) and all(f in df.columns for f in _CFG_TF):
            model_features = list(_CFG_TF)
        else:
            raise ValueError(
                f"Öznitelik sayısı uyuşmuyor (veri={len(df.columns)}, model={len(importances_arr)}). "
                "Doğru eğitim verisini --data-path ile verin."
            )

    missing = [f for f in model_features if f not in df.columns]
    if missing:
        raise ValueError(f"Veri kümesinde model öznitelikleri eksik: {missing}")
    df = df[model_features]

    importances = pd.Series(importances_arr, index=model_features)
    top_features = importances.sort_values(ascending=False).head(args.top_k)

    ensure_parent_dir(args.top_features_path)
    with open(args.top_features_path, "w", encoding="utf-8") as fp:
        json.dump({"top_features": top_features.index.tolist()}, fp, indent=2)

    # Öznitelik önem grafiği opsiyoneldir; matplotlib yoksa explainer üretimini engellemesin.
    try:
        import matplotlib
        matplotlib.use("Agg")  # başsız/GUI'siz ortam için
        import matplotlib.pyplot as plt

        ensure_parent_dir(args.figure_path)
        plt.figure(figsize=(8, 6))
        top_features.sort_values().plot(kind="barh", color="#ff7f50")
        plt.title("Top Feature Importances")
        plt.xlabel("Importance Score")
        plt.tight_layout()
        plt.savefig(args.figure_path, dpi=200)
        plt.close()
    except Exception as exc:
        print(f"[UYARI] Öznitelik grafiği atlandı (matplotlib eksik olabilir): {exc}")

    background = shap.utils.sample(df[top_features.index], args.background_samples, random_state=42)
    explainer = shap.TreeExplainer(model, background)

    ensure_parent_dir(args.shap_path)
    joblib.dump(explainer, args.shap_path)

    print(f"Top {args.top_k} features saved to {args.top_features_path}")
    print(f"SHAP explainer saved to {args.shap_path}")
    print(f"Feature importance figure saved to {args.figure_path}")


if __name__ == "__main__":
    main()
