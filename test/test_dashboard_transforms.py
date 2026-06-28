"""Pano saf veri-dönüşüm yardımcıları için birim testler (src/dashboard/transforms.py).

Streamlit'e bağlı olmadıkları için app.py'yi çalıştırmadan hızlıca test edilir.
"""
import os
import sys

import pandas as pd
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src", "dashboard"))
from transforms import (  # noqa: E402
    calculate_avg_confidence,
    filter_dataframe,
    find_first_present_column,
    parse_classification_report_text,
)


# --------------------------------------------------------------------------
# calculate_avg_confidence
# --------------------------------------------------------------------------
def test_avg_confidence_empty_df_returns_zero():
    assert calculate_avg_confidence(pd.DataFrame()) == 0.0


def test_avg_confidence_uses_max_prob_per_row_then_mean():
    df = pd.DataFrame({
        "Prob_Benign": [0.7, 0.1],
        "Prob_Volumetric": [0.2, 0.8],
        "Prob_Semantic": [0.1, 0.1],
    })
    # satır1 max=0.7, satır2 max=0.8 -> ortalama 0.75
    assert calculate_avg_confidence(df) == pytest.approx(0.75)


def test_avg_confidence_prob_match_is_case_insensitive():
    df = pd.DataFrame({"prob_x": [0.4], "PROB_Y": [0.9]})
    assert calculate_avg_confidence(df) == pytest.approx(0.9)


def test_avg_confidence_falls_back_to_confidence_score():
    df = pd.DataFrame({"confidence_score": [0.6, 0.8], "other": [1, 2]})
    assert calculate_avg_confidence(df) == pytest.approx(0.7)


def test_avg_confidence_coerces_non_numeric():
    df = pd.DataFrame({"Prob_A": ["0.5", "abc"], "Prob_B": ["0.9", "0.4"]})
    # satır1 max(0.5,0.9)=0.9 ; satır2 max(NaN,0.4)=0.4 -> ortalama 0.65
    assert calculate_avg_confidence(df) == pytest.approx(0.65)


def test_avg_confidence_no_relevant_columns_returns_zero():
    df = pd.DataFrame({"foo": [1, 2], "bar": [3, 4]})
    assert calculate_avg_confidence(df) == 0.0


# --------------------------------------------------------------------------
# find_first_present_column
# --------------------------------------------------------------------------
def test_find_first_present_returns_first_in_candidate_order():
    df = pd.DataFrame(columns=["b", "c"])
    assert find_first_present_column(df, ["a", "b", "c"]) == "b"


def test_find_first_present_respects_candidate_priority():
    df = pd.DataFrame(columns=["b", "a"])
    # 'a' df'te olsa da aday sırasında 'b' önce gelir
    assert find_first_present_column(df, ["b", "a"]) == "b"


def test_find_first_present_none_when_absent():
    df = pd.DataFrame(columns=["x", "y"])
    assert find_first_present_column(df, ["a", "b"]) is None


# --------------------------------------------------------------------------
# filter_dataframe
# --------------------------------------------------------------------------
def _ts_df():
    now = pd.Timestamp("2026-01-01 12:00:00")
    return pd.DataFrame({
        "timestamp": [
            now - pd.Timedelta(minutes=10),
            now - pd.Timedelta(minutes=2),
            now,
        ],
        "v": [1, 2, 3],
    })


def test_filter_empty_df_unchanged():
    out = filter_dataframe(pd.DataFrame(), "Son 5 dk")
    assert out.empty


def test_filter_all_time_returns_same():
    df = _ts_df()
    out = filter_dataframe(df, "Tüm Zamanlar")
    assert out.equals(df)


def test_filter_no_timestamp_column_returns_input():
    df = pd.DataFrame({"v": [1, 2, 3]})
    out = filter_dataframe(df, "Son 5 dk")
    assert out.equals(df)


def test_filter_last_5_min():
    out = filter_dataframe(_ts_df(), "Son 5 dk")
    assert list(out["v"]) == [2, 3]


def test_filter_last_1_hour_keeps_all_recent():
    out = filter_dataframe(_ts_df(), "Son 1 saat")
    assert list(out["v"]) == [1, 2, 3]


def test_filter_last_24_hours_keeps_all_recent():
    out = filter_dataframe(_ts_df(), "Son 24 saat")
    assert list(out["v"]) == [1, 2, 3]


def test_filter_unknown_window_returns_input():
    df = _ts_df()
    out = filter_dataframe(df, "Geçersiz Pencere")
    assert len(out) == 3


def test_filter_supports_capital_timestamp_column():
    now = pd.Timestamp("2026-01-01 12:00:00")
    df = pd.DataFrame({
        "Timestamp": [now - pd.Timedelta(hours=2), now],
        "v": [1, 2],
    })
    out = filter_dataframe(df, "Son 5 dk")
    assert list(out["v"]) == [2]


def test_filter_does_not_mutate_input():
    # Plan'da işaretlenen hata: girdi df'in datetime'a dönüştürülmesi engellenmeli
    df = pd.DataFrame({
        "timestamp": ["2026-01-01 00:00:00", "2026-01-01 11:59:00"],
        "v": [1, 2],
    })
    before_dtype = df["timestamp"].dtype  # object (string)
    filter_dataframe(df, "Son 5 dk")
    assert df["timestamp"].dtype == before_dtype
    assert df["timestamp"].tolist() == ["2026-01-01 00:00:00", "2026-01-01 11:59:00"]


def test_filter_all_invalid_timestamps_returns_rows():
    df = pd.DataFrame({"timestamp": ["yok", "gecersiz"], "v": [1, 2]})
    out = filter_dataframe(df, "Son 5 dk")
    assert len(out) == 2


# --------------------------------------------------------------------------
# parse_classification_report_text
# --------------------------------------------------------------------------
SAMPLE_REPORT = """\
Accuracy: 0.9815

Benign (Class 0):
  Precision: 0.99
  Recall: 0.98
  F1-Score: 0.985

Volumetric (Class 1):
  Precision: 0.96
  Recall: 0.97
  F1-Score: 0.965

Semantic (Class 2):
  Precision: 0.94
  Recall: 0.93
  F1-Score: 0.935

Macro Average:
  Precision: 0.9633
  Recall: 0.96
  F1-Score: 0.9617

Weighted Average:
  Precision: 0.982
  Recall: 0.981
  F1-Score: 0.9815
"""


def test_parse_report_accuracy_and_macro():
    res = parse_classification_report_text(SAMPLE_REPORT)
    assert res["accuracy"] == pytest.approx(0.9815)
    assert res["macro_precision"] == pytest.approx(0.9633)
    assert res["macro_recall"] == pytest.approx(0.96)
    assert res["macro_f1"] == pytest.approx(0.9617)


def test_parse_report_per_class():
    res = parse_classification_report_text(SAMPLE_REPORT)
    assert set(res["per_class"]) == {"Benign", "Volumetric", "Semantic"}
    benign = res["per_class"]["Benign"]
    assert benign["precision"] == pytest.approx(0.99)
    assert benign["recall"] == pytest.approx(0.98)
    assert benign["f1"] == pytest.approx(0.985)
    assert benign["roc_auc"] is None


def test_parse_report_always_has_source_and_per_class():
    res = parse_classification_report_text("alakasiz metin")
    assert res["source"] == "rapor"
    assert res["per_class"] == {}
    assert "accuracy" not in res


def test_parse_report_accuracy_only():
    res = parse_classification_report_text("Accuracy: 0.7")
    assert res["accuracy"] == pytest.approx(0.7)
    assert res["per_class"] == {}
