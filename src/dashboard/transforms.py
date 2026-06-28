"""Pano için saf veri-dönüşüm yardımcıları.

Bu fonksiyonlar Streamlit'e bağlı değildir ve yan etkisizdir; böylece
``app.py``'yi (tüm SOC panosunu) çalıştırmadan birim testi yazılabilir.
``app.py`` bunları içe aktarır.
"""
from __future__ import annotations

import re

import pandas as pd


def calculate_avg_confidence(df: pd.DataFrame) -> float:
    """Olasılık sütunlarından (yoksa confidence_score'dan) ortalama güveni hesaplar."""
    if df.empty:
        return 0.0
    prob_cols = [c for c in df.columns if "prob" in c.lower()]
    if prob_cols:
        return df[prob_cols].apply(pd.to_numeric, errors="coerce").max(axis=1).mean()
    if "confidence_score" in df.columns:
        return pd.to_numeric(df["confidence_score"], errors="coerce").mean()
    return 0.0


def find_first_present_column(df: pd.DataFrame, candidates: list[str]) -> str | None:
    """Aday isimler arasından df'te bulunan ilk sütunu döndürür, yoksa None."""
    for candidate in candidates:
        if candidate in df.columns:
            return candidate
    return None


def filter_dataframe(df: pd.DataFrame, window: str) -> pd.DataFrame:
    """Zaman penceresine göre df'i süzer. Girdiyi yerinde DEĞİŞTİRMEZ (kopya döner)."""
    if df.empty or window == "Tüm Zamanlar":
        return df
    c = "timestamp" if "timestamp" in df.columns else "Timestamp"
    if c not in df.columns:
        return df
    df = df.copy()  # girdiyi yerinde değiştirme (mutasyon hatası önlenir)
    df[c] = pd.to_datetime(df[c], errors="coerce")
    m_ts = df[c].max()
    if pd.isna(m_ts):
        return df
    if window == "Son 5 dk":
        cutoff = m_ts - pd.Timedelta(minutes=5)
    elif window == "Son 1 saat":
        cutoff = m_ts - pd.Timedelta(hours=1)
    elif window == "Son 24 saat":
        cutoff = m_ts - pd.Timedelta(hours=24)
    else:
        return df
    return df[df[c] >= cutoff].copy()


def parse_classification_report_text(text: str) -> dict:
    """Özel formatlı classification_report.txt metnini normalize metriklere ayrıştırır.

    Dosya okuma ``app.py`` içindeki ince sarmalayıcıda kalır; burada yalnızca
    (saf, test edilebilir) metin ayrıştırma mantığı bulunur.
    """
    res: dict = {"source": "rapor", "per_class": {}}
    m = re.search(r"Accuracy:\s*([\d.]+)", text)
    if m:
        res["accuracy"] = float(m.group(1))
    mblock = re.search(r"Macro Average:(.*?)(?:Weighted Average:|Confusion Matrix:|=====|$)", text, re.S)
    if mblock:
        b = mblock.group(1)
        for key, pat in [("macro_precision", r"Precision:\s*([\d.]+)"),
                         ("macro_recall", r"Recall:\s*([\d.]+)"),
                         ("macro_f1", r"F1-Score:\s*([\d.]+)")]:
            mm = re.search(pat, b)
            if mm:
                res[key] = float(mm.group(1))
    for cm in re.finditer(
        r"([A-Za-z][\w ]*?) \(Class \d+\):\s*Precision:\s*([\d.]+).*?Recall:\s*([\d.]+).*?F1-Score:\s*([\d.]+)",
        text, re.S,
    ):
        res["per_class"][cm.group(1).strip()] = {
            "precision": float(cm.group(2)), "recall": float(cm.group(3)),
            "f1": float(cm.group(4)), "roc_auc": None,
        }
    return res
