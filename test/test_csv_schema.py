"""Mevcut canlı CSV'nin güncel CSV_HEADER_COLUMNS şemasına uyduğunu doğrular.

Şema = CSV_BASE_COLUMNS (17) + TOP_FEATURES (20) = 37 sütun. Sabit sihirli sayı
yerine bileşimden doğrulanır; öznitelik listesi değişirse test kendiliğinden uyum sağlar.
"""
import os
import sys

import pandas as pd
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from kafka_consumer import CSV_HEADER_COLUMNS, CSV_BASE_COLUMNS  # noqa: E402
from config import TOP_FEATURES  # noqa: E402

CSV_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "live_captured_traffic.csv")
EXPECTED_COLUMNS = CSV_HEADER_COLUMNS


def _is_lfs_pointer(path: str) -> bool:
    """Git LFS içeriği çekilmemişse dosya gerçek CSV değil, bir pointer'dır."""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.readline().startswith("version https://git-lfs")
    except OSError:
        return False


def test_schema_column_count():
    # Sihirli sabit yerine bileşimden doğrula (öznitelik sayısı değişirse kırılmaz)
    assert len(CSV_HEADER_COLUMNS) == len(CSV_BASE_COLUMNS) + len(TOP_FEATURES)


def test_schema_contains_base_and_feature_columns():
    for col in CSV_BASE_COLUMNS:
        assert col in CSV_HEADER_COLUMNS, f"Taban sütunu şemada yok: {col}"
    for feat in TOP_FEATURES:
        assert feat in CSV_HEADER_COLUMNS, f"Öznitelik şemada yok: {feat}"


def test_csv_columns_if_exists():
    if not os.path.exists(CSV_PATH):
        pytest.skip("live_captured_traffic.csv henüz yok")
    if _is_lfs_pointer(CSV_PATH):
        pytest.skip("live_captured_traffic.csv bir LFS pointer (içerik çekilmemiş)")
    df = pd.read_csv(CSV_PATH, nrows=0)
    missing = [c for c in EXPECTED_COLUMNS if c not in df.columns]
    assert not missing, f"CSV şu şema sütunlarını içermiyor: {missing}"


def test_action_values_if_exists():
    if not os.path.exists(CSV_PATH):
        pytest.skip("live_captured_traffic.csv henüz yok")
    if _is_lfs_pointer(CSV_PATH):
        pytest.skip("live_captured_traffic.csv bir LFS pointer (içerik çekilmemiş)")
    df = pd.read_csv(CSV_PATH)
    if df.empty or "Action" not in df.columns:
        pytest.skip("Veri satırı yok veya Action sütunu yok")
    valid_actions = {"NONE", "ALLOWED", "BLOCKED"}
    bad = df[~df["Action"].isin(valid_actions)]
    assert bad.empty, f"Beklenmeyen Action değerleri: {bad['Action'].unique()}"
