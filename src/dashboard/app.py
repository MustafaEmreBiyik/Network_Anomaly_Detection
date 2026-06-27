#!/usr/bin/env python3
"""
Ağ Saldırı Önleme Panosu — SOC Sürümü
=====================================
3 sınıflı NIDS için çok sekmeli Güvenlik Operasyon Merkezi (SOC) panosu.
"""

import os
import sys
import time
import threading
import ipaddress
from io import BytesIO
from datetime import datetime

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from streamlit_autorefresh import st_autorefresh

try:
    import requests
except ImportError:
    requests = None

try:
    import folium
    from folium.plugins import MarkerCluster
except ImportError:
    folium = None
    MarkerCluster = None

try:
    from streamlit_folium import st_folium
except ImportError:
    st_folium = None

try:
    from st_aggrid import AgGrid, GridOptionsBuilder, GridUpdateMode, DataReturnMode
except ImportError:
    AgGrid = None
    GridOptionsBuilder = None
    GridUpdateMode = None
    DataReturnMode = None

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
except ImportError:
    colors = None
    A4 = None
    getSampleStyleSheet = None
    SimpleDocTemplate = None
    Paragraph = None
    Spacer = None
    Table = None
    TableStyle = None

# ---------------------------------------------------------------------------
# PATH SETUP
# ---------------------------------------------------------------------------
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(CURRENT_DIR)
PROJECT_ROOT = os.path.dirname(PARENT_DIR)
if PARENT_DIR not in sys.path:
    sys.path.append(PARENT_DIR)

try:
    from utils.db_manager import fetch_logs, log_heartbeat, fetch_recent_events, get_service_health
    from utils.firewall_manager import (
        block_ip, list_blocked_ips, unblock_ip, check_expired_blocks,
        get_block_records, WHITELIST, BLOCK_TTL_SECONDS,
    )
except ImportError:
    def fetch_logs():
        return pd.DataFrame()
    def log_heartbeat(*args, **kwargs):
        pass
    def fetch_recent_events(limit=50):
        return pd.DataFrame()
    def get_service_health():
        return pd.DataFrame()
    def block_ip(ip):
        return False
    def list_blocked_ips():
        return []
    def unblock_ip(ip):
        return False
    def check_expired_blocks(ttl_seconds=None):
        return []
    def get_block_records():
        return []
    WHITELIST = []
    BLOCK_TTL_SECONDS = 3600


def _ttl_expiry_loop():
    while True:
        try:
            check_expired_blocks()
        except Exception as exc:
            print(f"⚠️ TTL expiry loop error: {exc}")
        time.sleep(60)


_TTL_THREAD_STARTED = "_ttl_thread_started"
if _TTL_THREAD_STARTED not in st.session_state:
    t = threading.Thread(target=_ttl_expiry_loop, daemon=True)
    t.start()
    st.session_state[_TTL_THREAD_STARTED] = True

# ---------------------------------------------------------------------------
# CONSTANTS
# ---------------------------------------------------------------------------
LIVE_CSV_PATH = os.path.join(PROJECT_ROOT, "data", "live_captured_traffic_bilstm.csv")
LIVE_CSV_PATH_OLD = os.path.join(PROJECT_ROOT, "data", "live_captured_traffic.csv")
BILSTM_MODEL_PATH = os.path.join(PROJECT_ROOT, "models", "bilstm_best.keras")
LSTM_MODEL_PATH = os.path.join(PROJECT_ROOT, "models", "lstm_best.keras")
SCALER_PATH = os.path.join(PROJECT_ROOT, "models", "scaler_lstm.pkl")
SCALER_PATH_FALLBACK = os.path.join(PROJECT_ROOT, "models", "scaler.pkl")
ACTIVE_MODEL_PATH = os.path.join(PROJECT_ROOT, "data", "active_model.txt")
THRESHOLD_PATH = os.path.join(PROJECT_ROOT, "models", "threshold.txt")
BUCKET_FREQUENCY = "10s"

CLASS_NAMES = {0: "Benign", 1: "Volumetric", 2: "Semantic"}
CLASS_COLORS = {"Benign": "#00CC66", "Volumetric": "#FF4B4B", "Semantic": "#FFA500"}

# ---------------------------------------------------------------------------
# İKİ DİLLİ DESTEK (i18n) — TR / EN
# İç anahtarlar (Benign/Volumetric/Semantic, ALLOWED/BLOCKED...) sabit kalır;
# yalnızca kullanıcıya gösterilen metin aktif dile göre değişir. Varsayılan TR.
# t() Türkçe metni anahtar alır; EN sözlükte yoksa zarifçe TR'ye düşer.
# ---------------------------------------------------------------------------
CLASS_DISPLAY = {
    "TR": {"Benign": "Zararsız", "Volumetric": "Hacimsel", "Semantic": "Anlamsal"},
    "EN": {"Benign": "Benign", "Volumetric": "Volumetric", "Semantic": "Semantic"},
}
RISK_DISPLAY = {
    "TR": {"SAFE": "GÜVENLİ", "LOW": "DÜŞÜK", "MEDIUM": "ORTA", "HIGH": "YÜKSEK", "CRITICAL": "KRİTİK"},
    "EN": {"SAFE": "SAFE", "LOW": "LOW", "MEDIUM": "MEDIUM", "HIGH": "HIGH", "CRITICAL": "CRITICAL"},
}
ACTION_DISPLAY = {
    "TR": {"ALLOWED": "İZİN VERİLDİ", "BLOCKED": "ENGELLENDİ", "ALERT": "UYARI",
           "SUSPICIOUS": "ŞÜPHELİ", "NORMAL": "NORMAL", "NONE": "YOK", "UNKNOWN": "BİLİNMİYOR"},
    "EN": {"ALLOWED": "ALLOWED", "BLOCKED": "BLOCKED", "ALERT": "ALERT",
           "SUSPICIOUS": "SUSPICIOUS", "NORMAL": "NORMAL", "NONE": "NONE", "UNKNOWN": "UNKNOWN"},
}

# Türkçe görüntü metni -> İngilizce. (TR modunda metin olduğu gibi döner.)
_EN = {
    # Sistem durumu / metrikler
    "Sistem Durumu": "System Status",
    "Ölçekleyici": "Scaler",
    "Köprü": "Bridge",
    "📊 CSV: {rows:,} satır | Son güncelleme: {age:.0f}sn önce": "📊 CSV: {rows:,} rows | Last update: {age:.0f}s ago",
    "📊 Toplam Akış": "📊 Total Flows",
    "🟢 Zararsız": "🟢 Benign",
    "🔴 Hacimsel": "🔴 Volumetric",
    "🟠 Anlamsal": "🟠 Semantic",
    "🎯 Ort. Güven": "🎯 Avg Confidence",
    "#### 🎯 Güncel Risk Seviyesi": "#### 🎯 Current Risk Level",
    "Veri bekleniyor…": "Waiting for data…",
    "Veri bekleniyor...": "Waiting for data...",
    "Risk: {name}": "Risk: {name}",
    # Sınıf dağılımı
    "#### 📊 Sınıf Dağılımı (3 Sınıf)": "#### 📊 Class Distribution (3-Class)",
    "Sınıf sütunu bulunamadı.": "Class column not found.",
    "Trafik Sınıfı Dağılımı": "Traffic Class Distribution",
    "Toplam": "Total",
    # Saldırı dağılımı
    "#### Saldırı Dağılımı": "#### Attack Distribution",
    "Henüz sunburst dağılımı için saldırı tespiti yok.": "No attack detections available for the sunburst yet.",
    "Saldırılar": "Attacks",
    # Önem derecesi zaman çizelgesi
    "#### Önem Derecesi Zaman Çizelgesi": "#### Severity Timeline",
    "Zaman çizelgesi için henüz önem derecesi olayı yok.": "No severity events available for the timeline yet.",
    "Olay / dk": "Events / min",
    # Zaman serisi
    "#### 📈 Tespit Zaman Serisi": "#### 📈 Detection Time Series",
    "Zaman damgası sütunu bulunamadı.": "Timestamp column not found.",
    "Zaman serisi için yeterli veri yok.": "Not enough data for time series.",
    "Dakikadaki Tespitler": "Detections per Minute",
    "#### Tespit Zaman Serisi": "#### Detection Time Series",
    "Ort. Güven": "Avg Confidence",
    "Ort. güven: {y}": "Avg confidence: {y}",
    "Eşik": "Threshold",
    "Engel": "Block",
    "Engellenen": "Blocked",
    "Engellenen olay": "Blocked events",
    "Akış / 10sn": "Flows / 10s",
    "Güven (%)": "Confidence (%)",
    "10 saniyelik dilimlerde yığılmış sınıf hacmi, canlı güven eşiği ve engelleme işaretleri.":
        "10-second buckets: stacked class volume, live confidence threshold and block markers.",
    # Güven histogramı
    "#### 📊 Güven Skoru Dağılımı": "#### 📊 Confidence Score Distribution",
    "Olasılık sütunları bulunamadı.": "Probability columns not found.",
    "Yeterli veri yok.": "Not enough data.",
    "Frekans": "Frequency",
    "Tahmin Güven Dağılımı": "Prediction Confidence Distribution",
    "Ortalama: {v:.1f}%": "Mean: {v:.1f}%",
    # Isı haritası
    "#### Protokol / Port Isı Haritası": "#### Protocol / Port Heatmap",
    "Diğer": "Other",
    "Yok": "N/A",
    "Bilinmiyor": "Unknown",
    "Isı haritası için yeterli veri yok.": "Not enough data for heatmap.",
    "Akış": "Flows",
    "Protokol": "Protocol",
    "Yoğunluk ölçeği, protokol ve porta göre akış yoğunluğunu gösterir. Eksik veya düşük frekanslı portlar `Diğer` altında toplanır.":
        "Density scale shows flow concentration by protocol and port. Missing or low-frequency ports are grouped into `Other`.",
    "Mevcut canlı akışta port bilgisi yok; bu nedenle ısı haritası `Yok` port grubuyla protokol yoğunluğuna geri döner.":
        "Port metadata is unavailable in the current live feed, so the heatmap falls back to protocol density with an `N/A` bucket.",
    # Son tespitler tablosu
    "#### 📋 Son Tespitler (son 20)": "#### 📋 Recent Detections (last 20)",
    "Henüz tespit yok.": "No detections yet.",
    "Zaman": "Time", "Sınıf": "Class", "Risk": "Risk", "Durum": "Status", "Eylem": "Action",
    # Canlı saldırı akışı
    "#### Canlı Saldırı Akışı": "#### Live Attack Feed",
    "Yakın zamanda uyarı yok": "No recent alerts",
    "Saldırı kararları veritabanına yazıldıkça uyarı akışı otomatik olarak dolacaktır.":
        "The alert feed populates automatically as attack decisions are written to the database.",
    "Bilinmeyen zaman": "Unknown time", "Bilinmeyen IP": "Unknown IP", "Ayrıntı verilmedi.": "No details provided.",
    # Loglar grid / export
    "AgGrid bağımlılığı eksik. Gelişmiş filtreleme ve sayfalama için `streamlit-aggrid` paketini kurun.":
        "AgGrid dependency is missing. Install `streamlit-aggrid` for advanced filtering and pagination.",
    "Ayrıntılar": "Details", "Kaynak IP": "Source IP", "Zaman Damgası": "Timestamp",
    "Seçili satır: {n}": "Selected rows: {n}",
    "Yapay Zeka Ağ IPS Olay Raporu": "AI Network IPS Incident Report",
    "Oluşturulma: {ts}": "Generated: {ts}",
    "Metrik": "Metric", "Değer": "Value", "Toplam Kayıt": "Total Records",
    "İzin Verilen": "Allowed", "Son Olay": "Last Event", "Özet": "Summary",
    "Olay Kayıtları": "Incident Logs",
    # Toplu eylemler
    "##### Toplu Eylemler": "##### Batch Actions",
    "Seçili IP: {n}": "Selected IPs: {n}",
    "Hedefler: {preview}": "Targets: {preview}",
    "Toplu eylemleri etkinleştirmek için bir veya daha fazla kayıt satırı seçin.":
        "Select one or more log rows to enable batch actions.",
    "Seçili IP'lerin güvenlik duvarında güncellenmesini onaylıyorum.":
        "I confirm the selected IPs should be updated in the firewall.",
    "Seçilileri Engelle": "Block Selected", "Seçililerin Engelini Kaldır": "Unblock Selected",
    "{n} IP engellendi.": "Blocked {n} IP(s).", "{n} IP engellenemedi.": "{n} IP(s) could not be blocked.",
    "{n} IP'nin engeli kaldırıldı.": "Unblocked {n} IP(s).", "{n} IP'nin engeli kaldırılamadı.": "{n} IP(s) could not be unblocked.",
    # Güvenlik duvarı görüntüleyici
    "##### Güvenlik Duvarı Görüntüleyici": "##### Firewall Viewer",
    "Güvenlik duvarı kuralları okunamadı: {exc}": "Could not read firewall rules: {exc}",
    "Güvenlik duvarı yardımcısı tarafından yönetilen engelli IP yok.": "No blocked IPs managed by the firewall helper.",
    "Engelli IP: {n}": "Blocked IPs: {n}", "Güvenlik duvarı kuralı": "Firewall rule",
    "Yön: {d}": "Direction: {d}", "Engeli Kaldır": "Unblock",
    "{ip} engeli kaldırıldı.": "{ip} unblocked.", "{ip} engeli kaldırılamadı.": "Failed to unblock {ip}.",
    # Tehdit haritası
    "#### Tehdit Haritası": "#### Threat Map",
    "Coğrafi-IP haritalaması için olay kaydı yok.": "No incident records available for Geo-IP mapping.",
    "Tehdit Haritası bağımlılıkları eksik. Coğrafi-IP haritasını etkinleştirmek için `folium` ve `streamlit-folium` paketlerini kurun.":
        "Threat Map dependencies are missing. Install `folium` and `streamlit-folium` to enable the Geo-IP map.",
    "Uyarı kaydında kaynak IP verisi yok.": "Source IP data is not available in the alert log.",
    "Haritalanan Genel IP": "Mapped Public IPs", "Özel IP Uyarıları": "Private IP Alerts", "Sorgu Hataları": "Lookup Failures",
    "Tehdit Kaynakları": "Threat Sources",
    "Henüz haritalanabilecek genel IP yok. Özel IP'ler aşağıda ayrıca listelenmiştir.":
        "No public IPs could be mapped yet. Private IPs are listed separately below.",
    "##### Özel IP Uyarıları": "##### Private IP Alerts",
    "IP": "IP", "Son Görülme": "Last Seen",
    "Coğrafi-IP Sorgu Sorunları": "Geo-IP Lookup Issues",
    # XAI
    "##### 🌐 Global Öznitelik Önceliği": "##### 🌐 Global Feature Priority",
    "Öznitelik listesi bulunamadı (`reports/data/top_20_features.json`).":
        "Feature list not found (`reports/data/top_20_features.json`).",
    "Öznitelik": "Feature", "Öncelik": "Priority",
    "Model Öznitelik Önceliği (üstteki = en önemli)": "Model Feature Priority (top = most important)",
    "Öncelik puanı (sıra tabanlı)": "Priority score (rank-based)",
    "Sıralama, eğitimde Random Forest önem puanları ve SHAP analizine göre seçilen 20 önceliklendirilmiş özniteliği yansıtır. Sayısal SHAP önemleri için SHAP açıklayıcı gerekir.":
        "Ranking reflects the 20 prioritized features selected via Random Forest importance and SHAP analysis. Numeric SHAP importances require the SHAP explainer.",
    "##### 🎯 Seçili Tespit — Sınıf Olasılık Kırılımı": "##### 🎯 Selected Detection — Class Probability Breakdown",
    "Canlı akışta sınıf olasılığı (`Prob_*`) bulunamadı.": "Class probabilities (`Prob_*`) not found in the live feed.",
    "Tespit seç": "Select detection", "Olasılık": "Probability", "Olasılık (%)": "Probability (%)",
    "Tahmin: **{cls}**": "Prediction: **{cls}**", " · Güven: {conf:.1f}%": " · Confidence: {conf:.1f}%",
    "##### 🧩 SHAP Öznitelik Katkıları": "##### 🧩 SHAP Feature Contributions",
    "Tekil akış için SHAP açıklaması, 20 özniteliğin canlı kayıtta bulunmasını gerektirir. Tüketici güncellendiğinde öznitelik vektörü CSV'ye yazılır ve bu panel otomatik etkinleşir.":
        "Per-flow SHAP requires the 20 features in the live record. Once the consumer is updated, the feature vector is written to the CSV and this panel activates automatically.",
    "SHAP açıklayıcı henüz hazır değil. Etkinleştirmek için `models/shap_explainer.pkl` ve `models/top_20_features.json` dosyalarını `src/utils/model_optimizer.py` ile üretin (gerekirse `git lfs pull`).\n\nAyrıntı: `{exc}`":
        "SHAP explainer is not ready yet. Generate `models/shap_explainer.pkl` and `models/top_20_features.json` via `src/utils/model_optimizer.py` (run `git lfs pull` if needed).\n\nDetail: `{exc}`",
    "Seçili kayıtta bazı öznitelik değerleri eksik.": "Some feature values are missing in the selected record.",
    "SHAP açıklaması üretilemedi: {exc}": "Could not produce SHAP explanation: {exc}",
    "Bu tahmin için baskın öznitelik katkısı bulunamadı.": "No dominant feature contribution found for this prediction.",
    "Bu tahmine en çok katkı yapan öznitelikler (yön ve büyüklük):": "Top contributing features for this prediction (direction and magnitude):",
    # Model performansı
    "##### 📋 Model Karşılaştırma Tablosu": "##### 📋 Model Comparison Table",
    "Model": "Model", "Doğruluk": "Accuracy", "Makro F1": "Macro F1", "Makro ROC-AUC": "Macro ROC-AUC",
    "Gecikme (ms)": "Latency (ms)", "Verim (örnek/sn)": "Throughput (samples/s)", "Kaynak": "Source",
    "Kaynak: RF/XGBoost = model config; LSTM/BiLSTM = sınıflandırma raporu; hız = latency_benchmark.json; 'referans' = proje değerlendirme özeti.":
        "Source: RF/XGBoost = model config; LSTM/BiLSTM = classification report; speed = latency_benchmark.json; 'referans' = project evaluation summary.",
    "Makro F1 (yüksek = iyi)": "Macro F1 (higher = better)", "Karşılaştırılacak F1 verisi yok.": "No F1 data to compare.",
    "Hız ↔ Doğruluk dengesi": "Speed ↔ Accuracy trade-off", "Verim (örnek/sn, log)": "Throughput (samples/s, log)",
    "Hız/doğruluk dengesi için yeterli veri yok.": "Not enough data for the speed/accuracy trade-off.",
    "Doğruluk": "Accuracy", "Verim": "Throughput",
    "Kesinlik": "Precision", "Duyarlılık": "Recall",
    "Sınıf Bazlı Metrikler": "Per-Class Metrics", "Bu model için sınıf bazlı metrik dosyada bulunmuyor.": "No per-class metric file available for this model.",
    "Hiperparametreler": "Hyperparameters", " · Eğitim: {date}": " · Trained: {date}", "Metrik kaynağı: {src}{extra}{gpu}": "Metric source: {src}{extra}{gpu}",
    # Yönetim & Yanıt
    "##### 🎚️ Güven Referans Eşiği": "##### 🎚️ Confidence Reference Threshold",
    "Eşik (Canlı İzleme referans çizgisi)": "Threshold (Live Monitor reference line)",
    "Eşiği Kaydet": "Save Threshold", "Eşik kaydedildi: {v:.2f}": "Threshold saved: {v:.2f}", "Eşik kaydedilemedi.": "Could not save threshold.",
    "Geçerli: **{cur:.2f}** · `models/threshold.txt`'e yazılır, Canlı İzleme zaman serisindeki referans çizgisini günceller. Not: 3 sınıflı tüketici argmax kullandığından bu eşik analiz/görselleştirme amaçlıdır.":
        "Current: **{cur:.2f}** · written to `models/threshold.txt`, updates the reference line on the Live Monitor time series. Note: the 3-class consumer uses argmax, so this threshold is for analysis/visualization.",
    "##### 💓 Servis Sağlığı": "##### 💓 Service Health",
    "Henüz servis heartbeat kaydı yok.": "No service heartbeat records yet.",
    "🟢 Canlı": "🟢 Live", "🟡 Gecikmiş": "🟡 Stale", "🔴 Yanıtsız": "🔴 Down", "{age:.0f} sn önce": "{age:.0f}s ago",
    "##### 🧾 Sistem Olay Zaman Tüneli": "##### 🧾 System Event Timeline",
    "Kayıtlı sistem olayı yok (pipeline_events).": "No recorded system events (pipeline_events).",
    "##### 🛡️ Yanıt Politikası & Engel TTL": "##### 🛡️ Response Policy & Block TTL",
    "Engel TTL": "Block TTL", "Eskalasyon Penceresi": "Escalation Window", "Beyaz Liste": "Whitelist",
    "{m} dk": "{m} min", "{s} sn": "{s} s", "{n} IP": "{n} IP",
    "Eskalasyon: 1 tespit → UYARI · 2-3 → ŞÜPHELİ · 4+ → ENGELLENDİ. Bu değerler `.env` (WHITELIST_IPS, BLOCK_TTL_SECONDS, ESCALATION_WINDOW_SECONDS) ile ayarlanır; değişiklik için servisleri yeniden başlatın.":
        "Escalation: 1 detection → ALERT · 2-3 → SUSPICIOUS · 4+ → BLOCKED. These are set via `.env` (WHITELIST_IPS, BLOCK_TTL_SECONDS, ESCALATION_WINDOW_SECONDS); restart services to change.",
    "Beyaz liste: {ips}": "Whitelist: {ips}",
    "Aktif engel kaydı yok.": "No active block records.",
    "Engellenme (UTC)": "Blocked at (UTC)", "Kalan TTL": "Remaining TTL", "{m:.0f} dk": "{m:.0f} min", "süresi doldu": "expired",
    # Sidebar
    "**Veri Akışı:** {data} &nbsp;|&nbsp; **Motor:** {tf}": "**Data Flow:** {data} &nbsp;|&nbsp; **Engine:** {tf}",
    "TEHDİT SEVİYESİ (SON 60 SN)": "THREAT LEVEL (LAST 60S)",
    "📅 Zaman Penceresi": "📅 Time Window",
    "Son 5 dk": "Last 5 min", "Son 1 saat": "Last 1 hour", "Son 24 saat": "Last 24h", "Tüm Zamanlar": "All Time",
    "🔄 Canlı Yenileme": "🔄 Live Refresh", "⚡ Canlı Mod": "⚡ Live Mode", "Aralık (saniye)": "Interval (seconds)",
    "🧠 Aktif Yapay Zeka Modeli": "🧠 Active AI Model", "Model Seç": "Select Model",
    "● Aktif": "● Active", "● Canlı değil": "● Not live",
    "⚠️ Bu model henüz canlı pipeline'da desteklenmiyor (Sprint 2). Tüketici varsayılan modele dönebilir.":
        "⚠️ This model is not yet supported in the live pipeline (Sprint 2). The consumer may fall back to the default model.",
    "🔓 IP Engelini Kaldır": "🔓 Unblock IP", "IP Adresi": "IP Address",
    "✅ {ip} engeli kaldırıldı.": "✅ {ip} unblocked.", "⚠️ İşlem başarısız.": "⚠️ Operation failed.",
    "Geçerli bir IP adresi girin.": "Enter a valid IP address.",
    "🕐 Son yenileme: {time}": "🕐 Last refresh: {time}", "🔁 Yenileme #{n}": "🔁 Refresh #{n}",
    # Başlık + sekmeler
    "🛡️ Ağ Saldırı Önleme Sistemi — Güvenlik Operasyon Merkezi": "🛡️ Network Intrusion Prevention System — Security Operations Center",
    "3 Sınıflı NIDS &nbsp;|&nbsp; Zararsız · Hacimsel · Anlamsal &nbsp;|&nbsp; Gerçek Zamanlı Tespit":
        "3-Class NIDS &nbsp;|&nbsp; Benign · Volumetric · Semantic &nbsp;|&nbsp; Real-time Detection",
    "🖥️ Canlı İzleme": "🖥️ Live Monitor", "🗺️ Tehdit Haritası": "🗺️ Threat Map",
    "📋 Olay Kayıtları": "📋 Incident Logs", "🧠 XAI Açıklayıcı": "🧠 XAI Explainer",
    "📊 Model Performansı": "📊 Model Performance", "⚙️ Yönetim & Yanıt": "⚙️ Admin & Response",
    "Coğrafi-IP konumlandırma, saldırı dağılımı ve önem derecesi zaman çizelgesi.":
        "Geo-IP location, attack distribution and severity timeline.",
    "#### 📋 Olay Kayıtları": "#### 📋 Incident Logs", "Veritabanında olay kaydı bulunamadı.": "No incident records found in the database.",
    "##### Rapor Dışa Aktarımı": "##### Export Reports", "CSV Dışa Aktar": "Export CSV", "PDF Dışa Aktar": "Export PDF",
    "PDF dışa aktarımı için `reportlab` paketini kurun.": "Install `reportlab` to enable PDF export.",
    "#### 🧠 XAI Açıklayıcı": "#### 🧠 XAI Explainer",
    "Modelin kararlarını açıklar: global öznitelik önceliği, seçili tespit için sınıf olasılık kırılımı ve SHAP tabanlı öznitelik katkıları.":
        "Explains model decisions: global feature priority, per-detection class probability breakdown and SHAP-based feature contributions.",
    "#### 📊 Model Performansı & Karşılaştırma": "#### 📊 Model Performance & Comparison",
    "Eğitim/değerlendirme sonuçları: 5 modelin doğruluk, F1, ROC-AUC ve hız karşılaştırması ile seçili model için sınıf bazlı ayrıntılar.":
        "Training/evaluation results: accuracy, F1, ROC-AUC and speed across 5 models, plus per-class detail for the selected model.",
    "Model detayı seç": "Select model detail",
    "#### ⚙️ Yönetim & Yanıt": "#### ⚙️ Admin & Response",
    "Karar eşiği, servis sağlığı, sistem olay tüneli ve yanıt politikası.": "Decision threshold, service health, system event timeline and response policy.",
    # Ek anahtarlar
    "SOC Kontrol Paneli": "SOC Control Panel",
    "Ayrıntı": "Detail",
    "#### 🗗️ Tehdit Haritası": "#### 🗺️ Threat Map",
    "#### 🗺️ Tehdit Haritası": "#### 🗺️ Threat Map",
    "Pay": "Share",
    "Ort. güven": "Avg confidence",
    "Konum": "Location",
    "Bölge": "Region",
    "Bilinmeyen şehir": "Unknown city",
    "Bilinmeyen ülke": "Unknown country",
    "Port": "Port",
}


def _lang() -> str:
    try:
        return st.session_state.get("lang", "TR")
    except Exception:
        return "TR"


def t(text: str) -> str:
    """Görüntü metnini aktif dile çevirir (TR varsayılan; EN sözlükten, yoksa TR)."""
    return _EN.get(text, text) if _lang() == "EN" else text


def tr_class(name: str) -> str:
    """İç sınıf adını aktif dildeki görüntü etiketine çevirir."""
    return CLASS_DISPLAY[_lang()].get(str(name), str(name))


def tr_risk(name: str) -> str:
    """İç risk adını aktif dildeki görüntü etiketine çevirir."""
    return RISK_DISPLAY[_lang()].get(str(name).upper(), str(name))


def tr_action(name: str) -> str:
    """İç eylem adını aktif dildeki görüntü etiketine çevirir."""
    return ACTION_DISPLAY[_lang()].get(str(name).upper(), str(name))


def class_colors() -> dict:
    """Aktif dildeki sınıf etiketlerine göre renk eşlemesi (grafikler için)."""
    disp = CLASS_DISPLAY[_lang()]
    return {disp[k]: v for k, v in CLASS_COLORS.items()}
SIMPLE_LIVE_COLUMNS = [
    "Timestamp", "Src_IP", "Dst_IP", "Predicted_Label",
    "Confidence_Score", "Model_Used", "Processing_Time_Ms",
]
PROTOCOL_LABELS = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    47: "GRE",
    50: "ESP",
}
RISK_LEVELS = {
    1: {"name": "SAFE",     "color": "#00CC66", "emoji": "🟢"},
    2: {"name": "LOW",      "color": "#3498db", "emoji": "🔵"},
    3: {"name": "MEDIUM",   "color": "#FFD700", "emoji": "🟡"},
    4: {"name": "HIGH",     "color": "#FFA500", "emoji": "🟠"},
    5: {"name": "CRITICAL", "color": "#FF4B4B", "emoji": "🔴"},
}
try:
    from model_registry import MODEL_REGISTRY as _MODEL_REG
    MODEL_MAPPING = {k: os.path.basename(v["artifact_path"]) for k, v in _MODEL_REG.items()}
    # Hangi modeller canlı pipeline'da destekleniyor (LSTM/BiLSTM Sprint 2'de)
    MODEL_LIVE = {k: bool(v.get("live_supported", True)) for k, v in _MODEL_REG.items()}
except ImportError:
    MODEL_MAPPING = {
        "Random Forest": "rf_3class_model.pkl",
        "Decision Tree": "dt_3class_model.pkl",
        "XGBoost":       "xgb_3class_model.pkl",
        "LSTM":          "lstm_model.keras",
        "BiLSTM":        "bilstm_model.keras",
    }
    MODEL_LIVE = {
        "Random Forest": True, "Decision Tree": True, "XGBoost": True,
        "LSTM": False, "BiLSTM": False,
    }

# ---------------------------------------------------------------------------
# PAGE CONFIG
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="Ağ Saldırı Tespit Sistemi — SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Auto-refresh logic driven by session state
if "live_mode" not in st.session_state:
    st.session_state.live_mode = True
if "refresh_interval" not in st.session_state:
    st.session_state.refresh_interval = 15

if st.session_state.live_mode:
    count = st_autorefresh(interval=st.session_state.refresh_interval * 1000, limit=None, key="soc_autorefresh")
else:
    count = 0

log_heartbeat("dashboard", "alive")

# ---------------------------------------------------------------------------
# DARK-MODE CSS
# ---------------------------------------------------------------------------
st.markdown("""
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap');

  html, body, [class*="css"] { font-family: 'Inter', sans-serif; }

  [data-testid="stAppViewContainer"] { background: #0a0e17; color: #c9d1d9; }
  [data-testid="stSidebar"] { background: #0d1220; border-right: 1px solid #1e2d45; }

  /* Metric cards */
  div[data-testid="metric-container"], .kpi-card { 
    background: rgba(255,255,255,0.04); 
    border: 1px solid rgba(255,255,255,0.08); 
    border-radius: 12px; 
    backdrop-filter: blur(12px); 
    padding: 20px; 
    transition: transform .2s, box-shadow .2s; 
  }
  div[data-testid="metric-container"]:hover, .kpi-card:hover { 
    transform: translateY(-3px); 
    box-shadow: 0 8px 32px rgba(0,200,255,0.1); 
  }

  /* Critical Alerts */
  @keyframes criticalPulse { 
    0%,100% { box-shadow: 0 0 0 0 rgba(255,75,75,0.4);} 
    50% { box-shadow: 0 0 0 12px rgba(255,75,75,0);} 
  }
  .alert-critical { 
    animation: criticalPulse 1.5s infinite; 
    border: 1px solid #ff4b4b !important; 
    border-radius: 12px;
  }

  /* Tab bar */
  div[data-testid="stTabs"] button[data-baseweb="tab"] {
    background: transparent;
    color: #8b949e;
    border-bottom: 2px solid transparent;
    font-weight: 600;
    font-size: 0.85rem;
    padding: 8px 16px;
    transition: all 0.2s ease;
  }
  div[data-testid="stTabs"] button[data-baseweb="tab"]:hover {
    color: #58a6ff;
  }
  div[data-testid="stTabs"] button[aria-selected="true"] {
    color: #58a6ff !important;
    border-bottom: 2px solid #58a6ff !important;
  }

  /* Plotly charts */
  .js-plotly-plot { border-radius: 10px; }

  /* Dataframe */
  div[data-testid="stDataFrame"] { border-radius: 10px; overflow: hidden; }

  /* Divider */
  hr { border-color: #21262d; }

  /* Status badges */
  .badge-ok   { background:#0f5132; color:#75b798; padding:3px 10px; border-radius:20px; font-size:.75rem; font-weight:600; }
  .badge-warn { background:#5c3f00; color:#e3b341; padding:3px 10px; border-radius:20px; font-size:.75rem; font-weight:600; }
  .badge-err  { background:#3d0000; color:#ff7b72; padding:3px 10px; border-radius:20px; font-size:.75rem; font-weight:600; }

  /* Header accent */
  .soc-header { font-size:1.6rem; font-weight:700; color:#58a6ff; letter-spacing:-0.5px; }
  .soc-sub    { color:#8b949e; font-size:.85rem; }
</style>
""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# DATA LOADING
# ---------------------------------------------------------------------------

def derive_risk_level(predicted_class: int) -> int:
    if predicted_class == 0:
        return 1
    if predicted_class == 1:
        return 4
    return 5


def load_model_threshold() -> float:
    try:
        with open(THRESHOLD_PATH, "r", encoding="utf-8") as f:
            value = float(f.read().strip())
        return min(max(value, 0.0), 1.0)
    except Exception:
        return 0.5


def load_live_traffic() -> pd.DataFrame:
    csv_path = LIVE_CSV_PATH if os.path.exists(LIVE_CSV_PATH) else LIVE_CSV_PATH_OLD
    if not os.path.exists(csv_path):
        return pd.DataFrame()
    try:
        df = pd.read_csv(csv_path, on_bad_lines="skip", encoding="utf-8", engine="python")
        if "Timestamp" not in df.columns and "timestamp" not in df.columns:
            df = pd.read_csv(
                csv_path,
                names=SIMPLE_LIVE_COLUMNS,
                header=None,
                on_bad_lines="skip",
                encoding="utf-8",
                engine="python",
            )
        col_map = {
            "Predicted_Class": "predicted_class", "Class_Name": "class_name",
            "Risk_Level": "risk_level", "Risk_Name": "risk_name",
            "Prob_Benign": "prob_benign", "Prob_Volumetric": "prob_volumetric",
            "Prob_Semantic": "prob_semantic", "Action": "action", "Timestamp": "timestamp",
            "Predicted_Label": "predicted_class", "Confidence_Score": "confidence_score",
            "Src_IP": "src_ip", "Dst_IP": "dst_ip", "Model_Used": "model_used",
            "Processing_Time_Ms": "processing_time_ms",
        }
        df.rename(columns=col_map, inplace=True)
        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
            df = df.dropna(subset=["timestamp"])
        if "predicted_class" in df.columns:
            df["predicted_class"] = pd.to_numeric(df["predicted_class"], errors="coerce")
            df = df.dropna(subset=["predicted_class"])
            df["predicted_class"] = df["predicted_class"].astype(int)
        if "predicted_class" in df.columns and "class_name" not in df.columns:
            df["class_name"] = df["predicted_class"].map(CLASS_NAMES)
        if "risk_level" not in df.columns and "predicted_class" in df.columns:
            df["risk_level"] = df["predicted_class"].map(derive_risk_level)
        if "risk_name" not in df.columns and "risk_level" in df.columns:
            df["risk_name"] = df["risk_level"].map(lambda level: RISK_LEVELS.get(level, RISK_LEVELS[1])["name"])
        if "action" in df.columns:
            df["action"] = df["action"].astype(str).str.upper()
        return df
    except Exception as e:
        st.error(f"CSV load error: {e}")
        return pd.DataFrame()


def load_logs() -> pd.DataFrame:
    df = fetch_logs()
    if df.empty:
        return df
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    return df.sort_values("timestamp", ascending=False)


def get_system_status() -> dict:
    csv_path = LIVE_CSV_PATH if os.path.exists(LIVE_CSV_PATH) else LIVE_CSV_PATH_OLD
    csv_exists = os.path.exists(csv_path)
    csv_age, csv_rows, data_flowing = 999, 0, False
    if csv_exists:
        try:
            mtime = os.path.getmtime(csv_path)
            csv_age = time.time() - mtime
            data_flowing = csv_age < 30
            with open(csv_path, "r", encoding="utf-8", errors="ignore") as f:
                csv_rows = sum(1 for _ in f) - 1
        except Exception:
            pass
    sequence_model_exists = os.path.exists(BILSTM_MODEL_PATH) or os.path.exists(LSTM_MODEL_PATH)
    scaler_exists = os.path.exists(SCALER_PATH) or os.path.exists(SCALER_PATH_FALLBACK)
    return {
        "sequence_model": sequence_model_exists, "scaler": scaler_exists,
        "tensorflow": sequence_model_exists, "scapy": data_flowing,
        "scapy_status": "Capturing" if data_flowing else ("Waiting" if csv_exists else "Inactive"),
        "live_bridge_status": "active" if data_flowing else ("waiting" if csv_exists and csv_age < 120 else "stopped"),
        "csv_age": csv_age, "csv_exists": csv_exists, "csv_rows": csv_rows, "data_flowing": data_flowing,
    }


def calculate_avg_confidence(df: pd.DataFrame) -> float:
    if df.empty:
        return 0.0
    prob_cols = [c for c in df.columns if "prob" in c.lower()]
    if prob_cols:
        return df[prob_cols].apply(pd.to_numeric, errors="coerce").max(axis=1).mean()
    if "confidence_score" in df.columns:
        return pd.to_numeric(df["confidence_score"], errors="coerce").mean()
    return 0.0


def find_first_present_column(df: pd.DataFrame, candidates: list[str]) -> str | None:
    for candidate in candidates:
        if candidate in df.columns:
            return candidate
    return None


def format_protocol_label(value) -> str:
    numeric = pd.to_numeric(pd.Series([value]), errors="coerce").iloc[0]
    if pd.notna(numeric):
        numeric = int(numeric)
        return PROTOCOL_LABELS.get(numeric, f"Proto {numeric}")

    text = str(value).strip().upper()
    if not text or text == "NAN":
        return "Bilinmiyor"
    return text


def is_private_ip(ip_value: str) -> bool:
    try:
        return ipaddress.ip_address(str(ip_value)).is_private
    except ValueError:
        return False


@st.cache_data(ttl=60 * 60 * 24, show_spinner=False)
def lookup_geo_ip(ip_value: str) -> dict:
    if is_private_ip(ip_value):
        return {"status": "private", "ip": ip_value}
    if requests is None:
        return {"status": "error", "ip": ip_value, "reason": "requests dependency is unavailable"}

    try:
        response = requests.get(f"https://ipwho.is/{ip_value}", timeout=5)
        response.raise_for_status()
        payload = response.json()
    except Exception as exc:
        return {"status": "error", "ip": ip_value, "reason": str(exc)}

    if not payload.get("success", False):
        return {
            "status": "error",
            "ip": ip_value,
            "reason": payload.get("message", "Geo-IP lookup failed"),
        }

    return {
        "status": "ok",
        "ip": ip_value,
        "latitude": payload.get("latitude"),
        "longitude": payload.get("longitude"),
        "city": payload.get("city"),
        "country": payload.get("country"),
        "region": payload.get("region"),
        "continent": payload.get("continent"),
        "isp": payload.get("connection", {}).get("isp"),
    }

# ---------------------------------------------------------------------------
# RENDER HELPERS
# ---------------------------------------------------------------------------

def render_system_status(status: dict):
    st.markdown(f"#### ⚙️ {t('Sistem Durumu')}")
    c1, c2, c3, c4, c5 = st.columns(5)
    def badge(col, label, ok, warn=False):
        cls = "badge-ok" if ok else ("badge-warn" if warn else "badge-err")
        icon = "✅" if ok else ("⏳" if warn else "❌")
        col.markdown(f'<span class="{cls}">{icon} {label}</span>', unsafe_allow_html=True)
    badge(c1, "LSTM/BiLSTM", status["sequence_model"])
    badge(c2, t("Ölçekleyici"), status["scaler"])
    badge(c3, "TensorFlow", status["tensorflow"])
    badge(c4, "Scapy",      status["scapy"], warn=status["csv_exists"] and not status["scapy"])
    ok5 = status["data_flowing"]
    warn5 = status["csv_exists"] and not ok5
    badge(c5, f"{t('Köprü')} ({status['csv_age']:.0f}sn)", ok5, warn=warn5)
    if status["csv_exists"]:
        st.caption(t("📊 CSV: {rows:,} satır | Son güncelleme: {age:.0f}sn önce").format(rows=status['csv_rows'], age=status['csv_age']))


def render_metrics(df: pd.DataFrame):
    total = len(df)
    if df.empty:
        benign = volumetric = semantic = 0
        avg_conf = 0.0
    else:
        c = "class_name" if "class_name" in df.columns else "Class_Name"
        p = "predicted_class" if "predicted_class" in df.columns else "Predicted_Class"
        if c in df.columns:
            benign    = int((df[c] == "Benign").sum())
            volumetric = int((df[c] == "Volumetric").sum())
            semantic  = int((df[c] == "Semantic").sum())
        elif p in df.columns:
            benign, volumetric, semantic = int((df[p]==0).sum()), int((df[p]==1).sum()), int((df[p]==2).sum())
        else:
            benign, volumetric, semantic = total, 0, 0
        avg_conf = calculate_avg_confidence(df)
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric(t("📊 Toplam Akış"), f"{total:,}")
    c2.metric(t("🟢 Zararsız"),    f"{benign:,}",    delta=f"{benign/total*100:.1f}%" if total else "0%")
    c3.metric(t("🔴 Hacimsel"),    f"{volumetric:,}", delta=f"{volumetric/total*100:.1f}%" if total else "0%", delta_color="inverse")
    c4.metric(t("🟠 Anlamsal"),    f"{semantic:,}",   delta=f"{semantic/total*100:.1f}%" if total else "0%",  delta_color="inverse")
    c5.metric(t("🎯 Ort. Güven"), f"{avg_conf*100:.1f}%")


def render_risk_gauge(df: pd.DataFrame):
    st.markdown(t("#### 🎯 Güncel Risk Seviyesi"))
    if df.empty:
        st.info(t("Veri bekleniyor…"))
        return
    risk_col = "risk_level" if "risk_level" in df.columns else "Risk_Level"
    if risk_col in df.columns:
        current_risk = int(df[risk_col].iloc[-1]) if not pd.isna(df[risk_col].iloc[-1]) else 1
    else:
        pred = "predicted_class" if "predicted_class" in df.columns else "Predicted_Class"
        lc = df[pred].iloc[-1] if pred in df.columns else 0
        current_risk = 1 if lc == 0 else (4 if lc == 1 else 5)
    info = RISK_LEVELS.get(current_risk, RISK_LEVELS[1])
    
    div_class = "alert-critical" if current_risk == 5 else ""
    if div_class:
        st.markdown(f'<div class="{div_class}">', unsafe_allow_html=True)

    fig = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=current_risk,
        title={"text": t("Risk: {name}").format(name=tr_risk(info['name'])), "font": {"size": 20, "color": "#c9d1d9"}},
        delta={"reference": 2, "increasing": {"color": "#ff4b4b"}, "decreasing": {"color": "#00cc66"}},
        gauge={
            "axis": {"range": [1, 5], "tickcolor": "#8b949e"},
            "bar":  {"color": info["color"]},
            "bgcolor": "rgba(255,255,255,0.05)",
            "steps": [
                {"range": [1, 2], "color": "#0f3d22"},
                {"range": [2, 3], "color": "#0d2b4a"},
                {"range": [3, 4], "color": "#3d3000"},
                {"range": [4, 5], "color": "#3d1f00"},
            ],
            "threshold": {"line": {"color": "#ff4b4b", "width": 4}, "thickness": 0.75, "value": 4},
        }
    ))
    fig.update_layout(height=240, margin=dict(l=20, r=20, t=50, b=10),
                      paper_bgcolor="rgba(0,0,0,0)", font_color="#c9d1d9")
    st.plotly_chart(fig, width="stretch")
    
    if div_class:
        st.markdown('</div>', unsafe_allow_html=True)


def render_class_distribution(df: pd.DataFrame):
    st.markdown(t("#### 📊 Sınıf Dağılımı (3 Sınıf)"))
    if df.empty:
        st.info(t("Veri bekleniyor…"))
        return
    col = "class_name" if "class_name" in df.columns else "Class_Name"
    if col not in df.columns:
        st.warning(t("Sınıf sütunu bulunamadı."))
        return
    counts = df[col].value_counts().reset_index()
    counts.columns = ["Class", "Count"]
    counts["Class"] = counts["Class"].map(tr_class)
    fig = px.pie(counts, values="Count", names="Class", hole=0.6,
                 color="Class", color_discrete_map=class_colors(),
                 title=t("Trafik Sınıfı Dağılımı"))
    fig.update_traces(textposition="inside", textinfo="percent+label",
                      marker=dict(line=dict(color="#0d1117", width=2)))
    total = counts["Count"].sum()
    fig.add_annotation(text=f"<b>{total:,}</b><br>{t('Toplam')}", x=0.5, y=0.5,
                       font_size=14, showarrow=False, font_color="#c9d1d9")
    fig.update_layout(height=320, paper_bgcolor="rgba(0,0,0,0)", font_color="#c9d1d9",
                      legend=dict(orientation="h", y=-0.15, x=0.5, xanchor="center"))
    st.plotly_chart(fig, width="stretch")


def render_attack_distribution(df: pd.DataFrame):
    st.markdown(t("#### Saldırı Dağılımı"))
    if df.empty:
        st.info(t("Veri bekleniyor..."))
        return

    working = df.copy()
    if "class_name" not in working.columns and "predicted_class" in working.columns:
        working["class_name"] = working["predicted_class"].map(CLASS_NAMES)
    if "risk_name" not in working.columns and "risk_level" in working.columns:
        working["risk_name"] = working["risk_level"].map(lambda level: RISK_LEVELS.get(level, RISK_LEVELS[1])["name"])

    if "class_name" not in working.columns:
        st.warning(t("Sınıf sütunu bulunamadı."))
        return

    attack_df = working[working["class_name"].isin(["Volumetric", "Semantic"])].copy()
    if attack_df.empty:
        st.info(t("Henüz sunburst dağılımı için saldırı tespiti yok."))
        return

    if "risk_name" not in attack_df.columns:
        attack_df["risk_name"] = attack_df["class_name"].map({
            "Volumetric": "HIGH",
            "Semantic": "CRITICAL",
        })

    # Türkçe görüntü için sınıf/risk adlarını çevir
    attack_df["class_name"] = attack_df["class_name"].map(tr_class)
    attack_df["risk_name"] = attack_df["risk_name"].map(tr_risk)

    distribution = (
        attack_df.groupby(["class_name", "risk_name"])
        .size()
        .reset_index(name="count")
    )
    distribution["root"] = t("Saldırılar")

    fig = px.sunburst(
        distribution,
        path=["root", "class_name", "risk_name"],
        values="count",
        color="class_name",
        color_discrete_map=class_colors(),
    )
    fig.update_traces(
        branchvalues="total",
        insidetextorientation="radial",
        hovertemplate="<b>%{label}</b><br>" + t("Akış") + ": %{value}<br>" + t("Pay") + ": %{percentParent:.1%}<extra></extra>",
    )
    fig.update_layout(
        height=340,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(255,255,255,0.05)",
        font_color="#c9d1d9",
        margin=dict(l=20, r=20, t=20, b=10),
    )
    st.plotly_chart(fig, width="stretch")


def render_severity_timeline(live_df: pd.DataFrame, logs_df: pd.DataFrame):
    st.markdown(t("#### Önem Derecesi Zaman Çizelgesi"))

    timeline_df = pd.DataFrame()
    if not live_df.empty and "timestamp" in live_df.columns:
        timeline_df = live_df.copy()
        timeline_df["timestamp"] = pd.to_datetime(timeline_df["timestamp"], errors="coerce")
        if "risk_name" not in timeline_df.columns and "risk_level" in timeline_df.columns:
            timeline_df["risk_name"] = timeline_df["risk_level"].map(
                lambda level: RISK_LEVELS.get(level, RISK_LEVELS[1])["name"]
            )
    elif not logs_df.empty and "timestamp" in logs_df.columns:
        timeline_df = logs_df.copy()
        timeline_df["timestamp"] = pd.to_datetime(timeline_df["timestamp"], errors="coerce")
        if "risk_name" not in timeline_df.columns and "action" in timeline_df.columns:
            timeline_df["risk_name"] = timeline_df["action"].astype(str).str.upper().map({
                "BLOCKED": "CRITICAL",
                "ALLOWED": "HIGH",
            }).fillna("LOW")

    if timeline_df.empty or "timestamp" not in timeline_df.columns or "risk_name" not in timeline_df.columns:
        st.info(t("Zaman çizelgesi için henüz önem derecesi olayı yok."))
        return

    timeline_df = timeline_df.dropna(subset=["timestamp", "risk_name"]).copy()
    if timeline_df.empty:
        st.info(t("Zaman çizelgesi için henüz önem derecesi olayı yok."))
        return

    severity_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    severity_colors = {
        "LOW": RISK_LEVELS[2]["color"],
        "MEDIUM": RISK_LEVELS[3]["color"],
        "HIGH": RISK_LEVELS[4]["color"],
        "CRITICAL": RISK_LEVELS[5]["color"],
    }

    timeline_df = timeline_df[timeline_df["risk_name"].isin(severity_order)]
    if timeline_df.empty:
        st.info(t("Zaman çizelgesi için henüz önem derecesi olayı yok."))
        return

    timeline_series = (
        timeline_df.groupby([pd.Grouper(key="timestamp", freq="1min"), "risk_name"])
        .size()
        .unstack(fill_value=0)
        .reindex(columns=severity_order, fill_value=0)
        .sort_index()
    )
    if timeline_series.empty:
        st.info(t("Zaman çizelgesi için henüz önem derecesi olayı yok."))
        return

    fig = go.Figure()
    for severity in severity_order:
        fig.add_trace(go.Scatter(
            x=timeline_series.index,
            y=timeline_series[severity],
            mode="lines+markers",
            name=tr_risk(severity),
            line=dict(color=severity_colors[severity], width=2.2),
            marker=dict(size=6),
            hovertemplate=f"{tr_risk(severity)}: %{{y}}<br>%{{x|%Y-%m-%d %H:%M}}<extra></extra>",
        ))

    fig.update_layout(
        height=320,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(255,255,255,0.05)",
        font_color="#c9d1d9",
        margin=dict(l=20, r=20, t=20, b=10),
        legend=dict(orientation="h", y=-0.22, x=0.5, xanchor="center"),
        xaxis=dict(title=None, gridcolor="rgba(255,255,255,0.08)"),
        yaxis=dict(title=t("Olay / dk"), rangemode="tozero", gridcolor="rgba(255,255,255,0.08)"),
        hovermode="x unified",
    )
    st.plotly_chart(fig, width="stretch")


def render_time_series(df: pd.DataFrame):
    st.markdown(t("#### 📈 Tespit Zaman Serisi"))
    if df.empty:
        st.info(t("Veri bekleniyor…"))
        return
    ts = "timestamp" if "timestamp" in df.columns else "Timestamp"
    if ts not in df.columns:
        st.warning(t("Zaman damgası sütunu bulunamadı."))
        return
    tmp = df.copy()
    tmp[ts] = pd.to_datetime(tmp[ts], errors="coerce")
    tmp = tmp.dropna(subset=[ts]).set_index(ts)
    if len(tmp) < 2:
        st.info(t("Zaman serisi için yeterli veri yok."))
        return
    c = "class_name" if "class_name" in tmp.columns else "Class_Name"
    if c in tmp.columns:
        series = tmp.groupby([pd.Grouper(freq="1min"), c]).size().unstack(fill_value=0)
    else:
        series = tmp.resample("1min").size().to_frame("count")
    fig = px.line(series.reset_index(), x=ts,
                  y=series.columns.tolist(),
                  color_discrete_map=CLASS_COLORS,
                  title=t("Dakikadaki Tespitler"))
    fig.update_layout(height=280, paper_bgcolor="rgba(0,0,0,0)", font_color="#c9d1d9",
                      legend=dict(orientation="h", y=-0.25, x=0.5, xanchor="center"),
                      plot_bgcolor="rgba(255,255,255,0.05)")
    st.plotly_chart(fig, width="stretch")


def render_stacked_time_series(df: pd.DataFrame, logs_df: pd.DataFrame):
    st.markdown(t("#### Tespit Zaman Serisi"))
    if df.empty:
        st.info(t("Veri bekleniyor..."))
        return
    if "timestamp" not in df.columns:
        st.warning(t("Zaman damgası sütunu bulunamadı."))
        return

    tmp = df.copy()
    tmp["timestamp"] = pd.to_datetime(tmp["timestamp"], errors="coerce")
    tmp = tmp.dropna(subset=["timestamp"])
    if tmp.empty:
        st.info(t("Zaman serisi için yeterli veri yok."))
        return

    if "class_name" not in tmp.columns and "predicted_class" in tmp.columns:
        tmp["class_name"] = tmp["predicted_class"].map(CLASS_NAMES)

    tmp = tmp.set_index("timestamp")
    series = (
        tmp.groupby([pd.Grouper(freq=BUCKET_FREQUENCY), "class_name"])
        .size()
        .unstack(fill_value=0)
        .reindex(columns=list(CLASS_COLORS.keys()), fill_value=0)
        .sort_index()
    )
    if series.empty:
        st.info(t("Zaman serisi için yeterli veri yok."))
        return

    confidence_cols = [c for c in tmp.columns if "prob" in c.lower()]
    if confidence_cols:
        confidence = (
            tmp[confidence_cols]
            .apply(pd.to_numeric, errors="coerce")
            .max(axis=1)
            .resample(BUCKET_FREQUENCY)
            .mean()
            .fillna(0.0)
            * 100
        )
    elif "confidence_score" in tmp.columns:
        confidence = (
            pd.to_numeric(tmp["confidence_score"], errors="coerce")
            .resample(BUCKET_FREQUENCY)
            .mean()
            .fillna(0.0)
            * 100
        )
    else:
        confidence = pd.Series(0.0, index=series.index)

    fig = go.Figure()
    for class_name, color in CLASS_COLORS.items():
        fig.add_trace(go.Scatter(
            x=series.index,
            y=series[class_name],
            mode="lines",
            name=tr_class(class_name),
            stackgroup="traffic",
            line=dict(color=color, width=1.4),
            hovertemplate=f"{tr_class(class_name)}: %{{y}}<br>%{{x|%H:%M:%S}}<extra></extra>",
        ))

    fig.add_trace(go.Scatter(
        x=confidence.index,
        y=confidence.values,
        mode="lines",
        name=t("Ort. Güven"),
        yaxis="y2",
        line=dict(color="#58A6FF", width=2),
        hovertemplate=t("Ort. güven") + ": %{y:.1f}%<br>%{x|%H:%M:%S}<extra></extra>",
    ))

    threshold_value = load_model_threshold() * 100
    fig.add_trace(go.Scatter(
        x=[series.index.min(), series.index.max()],
        y=[threshold_value, threshold_value],
        mode="lines",
        name=f"{t('Eşik')} ({threshold_value:.1f}%)",
        yaxis="y2",
        line=dict(color="#FFD166", width=2, dash="dash"),
        hovertemplate=t("Eşik") + ": %{y:.1f}%<extra></extra>",
    ))

    blocked_events = pd.DataFrame()
    if not logs_df.empty and "timestamp" in logs_df.columns and "action" in logs_df.columns:
        blocked_events = logs_df.copy()
        blocked_events["timestamp"] = pd.to_datetime(blocked_events["timestamp"], errors="coerce")
        blocked_events = blocked_events[
            blocked_events["action"].astype(str).str.upper().eq("BLOCKED")
        ].dropna(subset=["timestamp"])
    elif "action" in tmp.columns:
        blocked_events = tmp.reset_index()
        blocked_events = blocked_events[
            blocked_events["action"].astype(str).str.upper().eq("BLOCKED")
        ][["timestamp"]]

    if not blocked_events.empty:
        blocked_counts = (
            blocked_events.set_index("timestamp")
            .resample(BUCKET_FREQUENCY)
            .size()
            .rename("blocked_count")
        )
        blocked_counts = blocked_counts[blocked_counts > 0]
        if not blocked_counts.empty:
            total_flows = series.sum(axis=1).reindex(blocked_counts.index, fill_value=0)
            marker_y = total_flows + blocked_counts.clip(lower=1)
            marker_text = [f"{t('Engel')} x{int(count)}" for count in blocked_counts]
            if len(blocked_counts) > 8:
                marker_text = None
            fig.add_trace(go.Scatter(
                x=blocked_counts.index,
                y=marker_y,
                mode="markers+text" if marker_text else "markers",
                name=t("Engellenen"),
                text=marker_text,
                textposition="top center",
                marker=dict(
                    color="#FF7B72",
                    size=12,
                    symbol="diamond",
                    line=dict(color="#0d1117", width=1.5),
                ),
                customdata=blocked_counts.astype(int),
                hovertemplate=t("Engellenen olay") + ": %{customdata}<br>%{x|%H:%M:%S}<extra></extra>",
            ))

    fig.update_layout(
        height=320,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(255,255,255,0.05)",
        font_color="#c9d1d9",
        hovermode="x unified",
        legend=dict(orientation="h", y=-0.25, x=0.5, xanchor="center"),
        margin=dict(l=20, r=20, t=40, b=10),
        xaxis=dict(title=None, gridcolor="rgba(255,255,255,0.08)"),
        yaxis=dict(title=t("Akış / 10sn"), rangemode="tozero", gridcolor="rgba(255,255,255,0.08)"),
        yaxis2=dict(
            title=t("Güven (%)"),
            overlaying="y",
            side="right",
            range=[0, 100],
            showgrid=False,
        ),
    )
    st.plotly_chart(fig, width="stretch")
    st.caption(t("10 saniyelik dilimlerde yığılmış sınıf hacmi, canlı güven eşiği ve engelleme işaretleri."))


def render_confidence_histogram(df: pd.DataFrame):
    st.markdown(t("#### 📊 Güven Skoru Dağılımı"))
    if df.empty:
        st.info(t("Veri bekleniyor…"))
        return
    prob_cols = [c for c in df.columns if "prob" in c.lower()]
    if prob_cols:
        max_probs = df[prob_cols].apply(pd.to_numeric, errors="coerce").max(axis=1).dropna()
    elif "confidence_score" in df.columns:
        max_probs = pd.to_numeric(df["confidence_score"], errors="coerce").dropna()
    else:
        st.warning(t("Olasılık sütunları bulunamadı."))
        return
    if len(max_probs) < 5:
        st.info(t("Yeterli veri yok."))
        return
    fig = px.histogram(max_probs * 100, nbins=20,
                       labels={"value": t("Güven (%)"), "count": t("Frekans")},
                       color_discrete_sequence=["#58a6ff"],
                       title=t("Tahmin Güven Dağılımı"))
    mean_c = max_probs.mean() * 100
    fig.add_vline(x=mean_c, line_dash="dash", line_color="#ff7b72",
                  annotation_text=t("Ortalama: {v:.1f}%").format(v=mean_c), annotation_font_color="#ff7b72")
    fig.update_layout(showlegend=False, height=280,
                      paper_bgcolor="rgba(0,0,0,0)", font_color="#c9d1d9",
                      plot_bgcolor="rgba(255,255,255,0.05)")
    st.plotly_chart(fig, width="stretch")


def render_protocol_port_heatmap(df: pd.DataFrame):
    st.markdown(t("#### Protokol / Port Isı Haritası"))
    if df.empty:
        st.info(t("Veri bekleniyor..."))
        return

    protocol_col = find_first_present_column(df, ["protocol", "Protocol"])
    dst_port_col = find_first_present_column(df, ["dst_port", "Dst Port", "Destination Port", "Dest Port"])
    src_port_col = find_first_present_column(df, ["src_port", "Src Port", "Source Port"])
    port_col = dst_port_col or src_port_col

    working = df.copy()
    if protocol_col is not None:
        working["protocol_label"] = working[protocol_col].apply(format_protocol_label)
    else:
        working["protocol_label"] = "Bilinmiyor"

    has_port_data = port_col is not None
    if has_port_data:
        ports = pd.to_numeric(working[port_col], errors="coerce")
        valid_ports = ports.where(ports.between(0, 65535))
        top_ports = valid_ports.dropna().astype(int).value_counts().head(12).index.tolist()
        if top_ports:
            working["port_label"] = valid_ports.apply(
                lambda value: str(int(value)) if pd.notna(value) and int(value) in top_ports else "Diğer"
            )
        else:
            working["port_label"] = "Yok"
            has_port_data = False
    else:
        working["port_label"] = "Yok"

    heatmap_df = (
        working.groupby(["protocol_label", "port_label"])
        .size()
        .reset_index(name="flow_count")
    )
    if heatmap_df.empty:
        st.info(t("Isı haritası için yeterli veri yok."))
        return

    protocol_order = (
        heatmap_df.groupby("protocol_label")["flow_count"]
        .sum()
        .sort_values(ascending=False)
        .index
        .tolist()
    )
    if has_port_data:
        port_order = [str(port) for port in top_ports]
        if "Diğer" in heatmap_df["port_label"].values:
            port_order.append("Diğer")
    else:
        port_order = ["Yok"]

    pivot = (
        heatmap_df.pivot(index="protocol_label", columns="port_label", values="flow_count")
        .reindex(index=protocol_order, columns=port_order, fill_value=0)
        .fillna(0)
    )

    fig = go.Figure(data=go.Heatmap(
        z=pivot.values,
        x=[t(c) for c in pivot.columns.tolist()],   # eksen etiketlerini yerelleştir
        y=[t(i) for i in pivot.index.tolist()],
        colorscale=[
            [0.0, "#0b1220"],
            [0.2, "#123b5a"],
            [0.45, "#1f8a70"],
            [0.7, "#f4b942"],
            [1.0, "#ff5d5d"],
        ],
        colorbar=dict(title=t("Akış")),
        hovertemplate=t("Protokol") + ": %{y}<br>Port: %{x}<br>" + t("Akış") + ": %{z}<extra></extra>",
    ))
    fig.update_layout(
        height=320,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(255,255,255,0.05)",
        font_color="#c9d1d9",
        margin=dict(l=20, r=20, t=20, b=10),
        xaxis=dict(title="Port", side="bottom"),
        yaxis=dict(title=t("Protokol")),
    )
    st.plotly_chart(fig, width="stretch")
    if has_port_data:
        st.caption(t("Yoğunluk ölçeği, protokol ve porta göre akış yoğunluğunu gösterir. Eksik veya düşük frekanslı portlar `Diğer` altında toplanır."))
    else:
        st.caption(t("Mevcut canlı akışta port bilgisi yok; bu nedenle ısı haritası `Yok` port grubuyla protokol yoğunluğuna geri döner."))


def render_recent_detections(df: pd.DataFrame):
    st.markdown(t("#### 📋 Son Tespitler (son 20)"))
    if df.empty:
        st.info(t("Henüz tespit yok."))
        return
    col_map = {
        "timestamp": "Zaman", "Timestamp": "Zaman",
        "class_name": "Sınıf", "Class_Name": "Sınıf",
        "risk_level": "Risk", "Risk_Level": "Risk",
        "risk_name": "Durum", "Risk_Name": "Durum",
        "action": "Eylem", "Action": "Eylem",
    }
    display_cols = [c for c in col_map if c in df.columns]
    if not display_cols:
        display_cols = df.columns[:6].tolist()
    recent = df[display_cols].tail(20).iloc[::-1].rename(columns=col_map)
    # Sınıf/Durum/Eylem değerlerini Türkçe görüntüye çevir
    if "Sınıf" in recent.columns:
        recent["Sınıf"] = recent["Sınıf"].map(tr_class)
    if "Durum" in recent.columns:
        recent["Durum"] = recent["Durum"].map(tr_risk)
    if "Eylem" in recent.columns:
        recent["Eylem"] = recent["Eylem"].map(tr_action)
    recent.columns = [t(c) for c in recent.columns]  # sütun başlıklarını yerelleştir
    st.dataframe(recent, width="stretch", hide_index=True)

# ---------------------------------------------------------------------------
# SIDEBAR — global controls (persistent across all tabs)
# ---------------------------------------------------------------------------
def render_live_attack_feed(logs_df: pd.DataFrame):
    st.markdown(t("#### Canlı Saldırı Akışı"))
    if logs_df.empty:
        st.markdown(
            f"""
            <div style="background: rgba(255,255,255,0.04); border: 1px dashed rgba(255,255,255,0.16); border-radius: 12px; padding: 18px;">
                <div style="font-size: 0.95rem; font-weight: 600; color: #c9d1d9; margin-bottom: 6px;">{t("Yakın zamanda uyarı yok")}</div>
                <div style="font-size: 0.85rem; color: #8b949e;">{t("Saldırı kararları veritabanına yazıldıkça uyarı akışı otomatik olarak dolacaktır.")}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        return

    recent_alerts = logs_df.copy()
    if "timestamp" in recent_alerts.columns:
        recent_alerts["timestamp"] = pd.to_datetime(recent_alerts["timestamp"], errors="coerce")
        recent_alerts = recent_alerts.sort_values("timestamp", ascending=False)
    recent_alerts = recent_alerts.head(10)

    action_styles = {
        "BLOCKED": {"bg": "rgba(255,75,75,0.18)", "fg": "#ff7b72", "border": "rgba(255,75,75,0.35)"},
        "ALLOWED": {"bg": "rgba(255,209,102,0.18)", "fg": "#ffd166", "border": "rgba(255,209,102,0.35)"},
        "NORMAL": {"bg": "rgba(0,204,102,0.18)", "fg": "#00cc66", "border": "rgba(0,204,102,0.35)"},
    }

    for _, row in recent_alerts.iterrows():
        action = str(row.get("action", "UNKNOWN")).upper()
        style = action_styles.get(
            action,
            {"bg": "rgba(88,166,255,0.18)", "fg": "#58a6ff", "border": "rgba(88,166,255,0.35)"},
        )
        timestamp = row.get("timestamp")
        timestamp_label = timestamp.strftime("%Y-%m-%d %H:%M:%S") if pd.notna(timestamp) else t("Bilinmeyen zaman")
        src_ip = row.get("src_ip", t("Bilinmeyen IP"))
        details = str(row.get("details", t("Ayrıntı verilmedi."))).strip() or t("Ayrıntı verilmedi.")

        st.markdown(
            f"""
            <div style="background: rgba(255,255,255,0.04); border: 1px solid rgba(255,255,255,0.08); border-radius: 14px; padding: 16px 18px; margin-bottom: 12px;">
                <div style="display: flex; justify-content: space-between; align-items: center; gap: 12px; margin-bottom: 10px;">
                    <div>
                        <div style="font-size: 0.96rem; font-weight: 700; color: #c9d1d9;">{src_ip}</div>
                        <div style="font-size: 0.78rem; color: #8b949e;">{timestamp_label}</div>
                    </div>
                    <span style="background: {style['bg']}; color: {style['fg']}; border: 1px solid {style['border']}; border-radius: 999px; padding: 4px 10px; font-size: 0.72rem; font-weight: 700; letter-spacing: 0.04em;">{tr_action(action)}</span>
                </div>
                <div style="font-size: 0.85rem; line-height: 1.55; color: #c9d1d9;">{details}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_logs_grid(logs_df: pd.DataFrame):
    if AgGrid is None or GridOptionsBuilder is None:
        st.warning(t("AgGrid bağımlılığı eksik. Gelişmiş filtreleme ve sayfalama için `streamlit-aggrid` paketini kurun."))
        st.dataframe(logs_df, width="stretch", hide_index=True)
        return {"selected_rows": [], "filtered_df": logs_df.copy()}

    grid_df = logs_df.copy()
    if "timestamp" in grid_df.columns:
        grid_df["timestamp"] = pd.to_datetime(grid_df["timestamp"], errors="coerce")
        grid_df["timestamp"] = grid_df["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")

    gb = GridOptionsBuilder.from_dataframe(grid_df)
    gb.configure_default_column(
        filter=True,
        sortable=True,
        resizable=True,
        floatingFilter=True,
        min_column_width=120,
    )
    gb.configure_selection(
        selection_mode="multiple",
        use_checkbox=True,
        groupSelectsChildren=False,
        groupSelectsFiltered=True,
    )
    gb.configure_pagination(
        enabled=True,
        paginationAutoPageSize=False,
        paginationPageSize=10,
    )
    if "details" in grid_df.columns:
        gb.configure_column("details", header_name=t("Ayrıntılar"), wrapText=True, autoHeight=True, flex=2, minWidth=260)
    if "src_ip" in grid_df.columns:
        gb.configure_column("src_ip", header_name=t("Kaynak IP"), minWidth=150)
    if "timestamp" in grid_df.columns:
        gb.configure_column("timestamp", header_name=t("Zaman Damgası"), sort="desc")
    if "action" in grid_df.columns:
        gb.configure_column("action", header_name=t("Eylem"), minWidth=120)

    grid_options = gb.build()
    grid_response = AgGrid(
        grid_df,
        gridOptions=grid_options,
        data_return_mode=DataReturnMode.FILTERED_AND_SORTED,
        update_mode=GridUpdateMode.SELECTION_CHANGED | GridUpdateMode.FILTERING_CHANGED,
        fit_columns_on_grid_load=False,
        allow_unsafe_jscode=False,
        enable_enterprise_modules=False,
        theme="balham-dark",
        height=420,
        width="100%",
        reload_data=False,
    )
    selected_rows = grid_response.get("selected_rows", [])
    filtered_rows = grid_response.get("data", grid_df.to_dict("records"))
    filtered_df = pd.DataFrame(filtered_rows)
    st.caption(t("Seçili satır: {n}").format(n=len(selected_rows)))
    return {"selected_rows": selected_rows, "filtered_df": filtered_df}


def get_selected_log_ips(selected_rows) -> list[str]:
    if not selected_rows:
        return []

    selected_df = pd.DataFrame(selected_rows)
    if selected_df.empty or "src_ip" not in selected_df.columns:
        return []

    ips = (
        selected_df["src_ip"]
        .astype(str)
        .str.strip()
        .replace("", pd.NA)
        .dropna()
        .drop_duplicates()
        .tolist()
    )
    return ips


def build_logs_csv_bytes(logs_df: pd.DataFrame) -> bytes:
    export_df = logs_df.copy()
    return export_df.to_csv(index=False).encode("utf-8")


def build_logs_pdf_bytes(logs_df: pd.DataFrame, total_records: int, blocked_count: int, allowed_count: int, last_event: str) -> bytes | None:
    if SimpleDocTemplate is None:
        return None

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, leftMargin=28, rightMargin=28, topMargin=28, bottomMargin=28)
    styles = getSampleStyleSheet()
    story = [
        Paragraph(t("Yapay Zeka Ağ IPS Olay Raporu"), styles["Title"]),
        Spacer(1, 12),
        Paragraph(t("Oluşturulma: {ts}").format(ts=datetime.now().strftime('%Y-%m-%d %H:%M:%S')), styles["BodyText"]),
        Spacer(1, 12),
    ]

    summary_data = [
        [t("Metrik"), t("Değer")],
        [t("Toplam Kayıt"), f"{total_records:,}"],
        [t("Engellenen"), f"{blocked_count:,}"],
        [t("İzin Verilen"), f"{allowed_count:,}"],
        [t("Son Olay"), last_event],
    ]
    summary_table = Table(summary_data, colWidths=[150, 300])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2a44")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#8b949e")),
        ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f4f6fa")),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))
    story.extend([Paragraph(t("Özet"), styles["Heading2"]), Spacer(1, 8), summary_table, Spacer(1, 16)])

    log_columns = [col for col in ["timestamp", "src_ip", "action", "details"] if col in logs_df.columns]
    export_df = logs_df.copy()
    if "timestamp" in export_df.columns:
        export_df["timestamp"] = pd.to_datetime(export_df["timestamp"], errors="coerce").dt.strftime("%Y-%m-%d %H:%M:%S")
    export_df = export_df.fillna("")

    table_rows = [[t("Zaman Damgası"), t("Kaynak IP"), t("Eylem"), t("Ayrıntılar")]]
    for _, row in export_df.head(50).iterrows():
        table_rows.append([
            str(row.get("timestamp", "")),
            str(row.get("src_ip", "")),
            str(row.get("action", "")),
            str(row.get("details", ""))[:140],
        ])

    log_table = Table(table_rows, colWidths=[110, 95, 70, 245], repeatRows=1)
    log_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#22304d")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#9aa4b2")),
        ("BACKGROUND", (0, 1), (-1, -1), colors.white),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("LEADING", (0, 1), (-1, -1), 10),
        ("PADDING", (0, 0), (-1, -1), 4),
    ]))
    story.extend([Paragraph(t("Olay Kayıtları"), styles["Heading2"]), Spacer(1, 8), log_table])

    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()


def render_batch_log_actions(selected_rows):
    selected_ips = get_selected_log_ips(selected_rows)
    has_selection = len(selected_ips) > 0

    st.markdown(t("##### Toplu Eylemler"))
    st.caption(t("Seçili IP: {n}").format(n=len(selected_ips)))

    if has_selection:
        preview = ", ".join(selected_ips[:5])
        if len(selected_ips) > 5:
            preview += ", ..."
        st.caption(t("Hedefler: {preview}").format(preview=preview))
    else:
        st.caption(t("Toplu eylemleri etkinleştirmek için bir veya daha fazla kayıt satırı seçin."))

    confirm_key = "confirm_batch_log_action"
    confirm = st.checkbox(
        t("Seçili IP'lerin güvenlik duvarında güncellenmesini onaylıyorum."),
        key=confirm_key,
        disabled=not has_selection,
    )

    col_block, col_unblock = st.columns(2)
    with col_block:
        block_clicked = st.button(
            t("Seçilileri Engelle"),
            key="batch_block_selected",
            disabled=not has_selection or not confirm,
            width="stretch",
        )
    with col_unblock:
        unblock_clicked = st.button(
            t("Seçililerin Engelini Kaldır"),
            key="batch_unblock_selected",
            disabled=not has_selection or not confirm,
            width="stretch",
        )

    if block_clicked:
        success_count = sum(1 for ip in selected_ips if block_ip(ip))
        failure_count = len(selected_ips) - success_count
        st.session_state[confirm_key] = False
        if success_count:
            st.toast(t("{n} IP engellendi.").format(n=success_count))
        if failure_count:
            st.toast(t("{n} IP engellenemedi.").format(n=failure_count), icon="⚠️")

    if unblock_clicked:
        success_count = sum(1 for ip in selected_ips if unblock_ip(ip))
        failure_count = len(selected_ips) - success_count
        st.session_state[confirm_key] = False
        if success_count:
            st.toast(t("{n} IP'nin engeli kaldırıldı.").format(n=success_count))
        if failure_count:
            st.toast(t("{n} IP'nin engeli kaldırılamadı.").format(n=failure_count), icon="⚠️")


def render_firewall_viewer():
    st.markdown(t("##### Güvenlik Duvarı Görüntüleyici"))

    pending_toast = st.session_state.pop("firewall_viewer_toast", None)
    if pending_toast:
        st.toast(pending_toast["message"], icon=pending_toast.get("icon"))

    # OS güvenlik duvarı yardımcısının hatası tüm panoyu çökertmesin
    try:
        blocked_rules = list_blocked_ips()
    except Exception as exc:
        st.warning(t("Güvenlik duvarı kuralları okunamadı: {exc}").format(exc=exc))
        return
    if not blocked_rules:
        st.info(t("Güvenlik duvarı yardımcısı tarafından yönetilen engelli IP yok."))
        return

    st.caption(t("Engelli IP: {n}").format(n=len(blocked_rules)))
    for rule in blocked_rules:
        ip_address = rule.get("ip", t("Bilinmiyor"))
        direction = rule.get("direction", "In")
        cols = st.columns([3, 2, 1])
        with cols[0]:
            st.markdown(f"**{ip_address}**")
            st.caption(rule.get("rule_name", t("Güvenlik duvarı kuralı")))
        with cols[1]:
            st.caption(t("Yön: {d}").format(d=direction))
        with cols[2]:
            if st.button(t("Engeli Kaldır"), key=f"firewall_unblock_{ip_address}", width="stretch"):
                ok = unblock_ip(ip_address)
                if ok:
                    st.session_state["firewall_viewer_toast"] = {
                        "message": t("{ip} engeli kaldırıldı.").format(ip=ip_address),
                        "icon": "✅",
                    }
                else:
                    st.session_state["firewall_viewer_toast"] = {
                        "message": t("{ip} engeli kaldırılamadı.").format(ip=ip_address),
                        "icon": "⚠️",
                    }
                st.rerun()


def render_threat_map(logs_df: pd.DataFrame):
    st.markdown(t("#### Tehdit Haritası"))
    if logs_df.empty:
        st.info(t("Coğrafi-IP haritalaması için olay kaydı yok."))
        return
    if folium is None or st_folium is None:
        st.warning(t("Tehdit Haritası bağımlılıkları eksik. Coğrafi-IP haritasını etkinleştirmek için `folium` ve `streamlit-folium` paketlerini kurun."))
        return

    alert_ips = logs_df.copy()
    if "src_ip" not in alert_ips.columns:
        st.warning(t("Uyarı kaydında kaynak IP verisi yok."))
        return

    if "timestamp" in alert_ips.columns:
        alert_ips["timestamp"] = pd.to_datetime(alert_ips["timestamp"], errors="coerce")
        alert_ips = alert_ips.sort_values("timestamp", ascending=False)

    alert_ips["src_ip"] = alert_ips["src_ip"].astype(str).str.strip()
    alert_ips = alert_ips[alert_ips["src_ip"].ne("")]
    unique_ips = alert_ips.drop_duplicates(subset=["src_ip"], keep="first").head(40)

    private_alerts = unique_ips[unique_ips["src_ip"].apply(is_private_ip)].copy()
    public_alerts = unique_ips[~unique_ips["src_ip"].apply(is_private_ip)].copy()

    geocoded_rows = []
    lookup_errors = []
    for _, row in public_alerts.iterrows():
        geo = lookup_geo_ip(row["src_ip"])
        if geo.get("status") == "ok" and geo.get("latitude") is not None and geo.get("longitude") is not None:
            geocoded_rows.append({**row.to_dict(), **geo})
        elif geo.get("status") != "private":
            lookup_errors.append({"src_ip": row["src_ip"], "reason": geo.get("reason", "Unknown error")})

    geo_df = pd.DataFrame(geocoded_rows)

    c1, c2, c3 = st.columns(3)
    c1.metric(t("Haritalanan Genel IP"), f"{len(geo_df):,}")
    c2.metric(t("Özel IP Uyarıları"), f"{len(private_alerts):,}")
    c3.metric(t("Sorgu Hataları"), f"{len(lookup_errors):,}")

    if not geo_df.empty:
        map_center = [geo_df["latitude"].mean(), geo_df["longitude"].mean()]
        threat_map = folium.Map(
            location=map_center,
            zoom_start=2,
            tiles="CartoDB dark_matter",
            control_scale=True,
        )
        marker_layer = MarkerCluster(name=t("Tehdit Kaynakları")).add_to(threat_map) if MarkerCluster else threat_map

        for _, row in geo_df.iterrows():
            timestamp = row.get("timestamp")
            last_seen = timestamp.strftime("%Y-%m-%d %H:%M:%S") if pd.notna(timestamp) else t("Bilinmiyor")
            popup_html = f"""
                <div style="min-width: 220px;">
                    <div style="font-weight: 700; margin-bottom: 6px;">{row['src_ip']}</div>
                    <div><strong>{t('Konum')}:</strong> {row.get('city') or t('Bilinmeyen şehir')}, {row.get('country') or t('Bilinmeyen ülke')}</div>
                    <div><strong>{t('Bölge')}:</strong> {row.get('region') or row.get('continent') or t('Bilinmiyor')}</div>
                    <div><strong>ISP:</strong> {row.get('isp') or t('Bilinmiyor')}</div>
                    <div><strong>{t('Eylem')}:</strong> {tr_action(row.get('action', 'Bilinmiyor'))}</div>
                    <div><strong>{t('Son Görülme')}:</strong> {last_seen}</div>
                </div>
            """
            folium.CircleMarker(
                location=[row["latitude"], row["longitude"]],
                radius=7,
                color="#ff7b72" if str(row.get("action", "")).upper() == "BLOCKED" else "#ffd166",
                fill=True,
                fill_opacity=0.85,
                weight=2,
                popup=folium.Popup(popup_html, max_width=320),
                tooltip=row["src_ip"],
            ).add_to(marker_layer)

        st_folium(threat_map, use_container_width=True, height=460, returned_objects=[])
    else:
        st.info(t("Henüz haritalanabilecek genel IP yok. Özel IP'ler aşağıda ayrıca listelenmiştir."))

    if not private_alerts.empty:
        st.markdown(t("##### Özel IP Uyarıları"))
        private_display = private_alerts.reindex(columns=["src_ip", "action", "timestamp", "details"]).copy()
        if "action" in private_display.columns:
            private_display["action"] = private_display["action"].map(tr_action)
        private_display.columns = [t("IP"), t("Eylem"), t("Son Görülme"), t("Ayrıntılar")]
        st.dataframe(private_display, width="stretch", hide_index=True)

    if lookup_errors:
        unresolved = pd.DataFrame(lookup_errors)
        with st.expander(t("Coğrafi-IP Sorgu Sorunları")):
            st.dataframe(unresolved, width="stretch", hide_index=True)


# ---------------------------------------------------------------------------
# XAI (Açıklanabilir Yapay Zeka) yardımcıları
# ---------------------------------------------------------------------------
# Kanonik liste: model_optimizer'ın ürettiği (explainer'ın öznitelik sırasını tanımlayan) dosya.
# SHAP vektör hizalaması için bu sıra önceliklidir; sonra reports kopyası, sonra config.
MODELS_TOP_FEATURES_PATH = os.path.join(PROJECT_ROOT, "models", "top_20_features.json")
REPORTS_TOP_FEATURES_PATH = os.path.join(PROJECT_ROOT, "reports", "data", "top_20_features.json")


@st.cache_data(ttl=300, show_spinner=False)
def load_top_feature_names() -> list[str]:
    """20 öznitelik adını döndürür (models JSON → reports JSON → config → boş)."""
    import json
    for path in (MODELS_TOP_FEATURES_PATH, REPORTS_TOP_FEATURES_PATH):
        try:
            with open(path, "r", encoding="utf-8") as fp:
                names = json.load(fp).get("top_features") or []
            if names:
                return list(names)
        except Exception:
            continue
    try:
        from config import TOP_FEATURES as _TF
        if _TF:
            return list(_TF)
    except Exception:
        pass
    return []


def render_xai_global_importance():
    """JSON'daki öncelik sırasına dayalı global öznitelik önem grafiği (her ortamda çalışır)."""
    st.markdown(t("##### 🌐 Global Öznitelik Önceliği"))
    names = load_top_feature_names()
    if not names:
        st.info(t("Öznitelik listesi bulunamadı (`reports/data/top_20_features.json`)."))
        return
    n = len(names)
    imp_df = pd.DataFrame({"Öznitelik": names, "Öncelik": [n - i for i in range(n)]})
    imp_df = imp_df.sort_values("Öncelik", ascending=True)
    fig = px.bar(
        imp_df, x="Öncelik", y="Öznitelik", orientation="h",
        color="Öncelik", color_continuous_scale="Blues",
        labels={"Öncelik": t("Öncelik"), "Öznitelik": t("Öznitelik")},
        title=t("Model Öznitelik Önceliği (üstteki = en önemli)"),
    )
    fig.update_layout(
        height=520, paper_bgcolor="rgba(0,0,0,0)", font_color="#c9d1d9",
        plot_bgcolor="rgba(255,255,255,0.05)", coloraxis_showscale=False,
        margin=dict(l=10, r=10, t=50, b=10),
        xaxis=dict(title=t("Öncelik puanı (sıra tabanlı)"), gridcolor="rgba(255,255,255,0.08)"),
        yaxis=dict(title=None),
    )
    st.plotly_chart(fig, width="stretch")
    st.caption(t(
        "Sıralama, eğitimde Random Forest önem puanları ve SHAP analizine göre seçilen 20 "
        "önceliklendirilmiş özniteliği yansıtır. Sayısal SHAP önemleri için SHAP açıklayıcı gerekir."
    ))


def render_xai_probability_breakdown(df: pd.DataFrame):
    """Seçili tespit için 3 sınıf olasılık kırılımı (canlı Prob_* alanlarından)."""
    st.markdown(t("##### 🎯 Seçili Tespit — Sınıf Olasılık Kırılımı"))
    if df.empty:
        st.info(t("Veri bekleniyor…"))
        return None
    # İç sınıf adı -> Prob sütunu (görüntü etiketi tr_class ile dile göre üretilir)
    prob_map = {"Benign": "prob_benign", "Volumetric": "prob_volumetric", "Semantic": "prob_semantic"}
    present = {cls: col for cls, col in prob_map.items() if col in df.columns}
    if not present:
        st.info(t("Canlı akışta sınıf olasılığı (`Prob_*`) bulunamadı."))
        return None

    recent = df.copy()
    if "timestamp" in recent.columns:
        recent = recent.sort_values("timestamp", ascending=False)
    recent = recent.head(50).reset_index(drop=True)

    def _row_label(i: int) -> str:
        row = recent.iloc[i]
        ts = row.get("timestamp")
        ts_label = ts.strftime("%H:%M:%S") if pd.notna(ts) else "—"
        cls_internal = row.get("class_name")
        if not isinstance(cls_internal, str):
            cls_internal = CLASS_NAMES.get(int(pd.to_numeric(row.get("predicted_class", 0), errors="coerce") or 0), "?")
        return f"#{i} · {ts_label} · {tr_class(cls_internal)} · {row.get('src_ip', '—')}"

    idx = st.selectbox(
        t("Tespit seç"), list(range(len(recent))),
        format_func=_row_label, key="xai_detection_select",
    )
    row = recent.iloc[idx]

    labels = [tr_class(cls) for cls in present.keys()]   # dile göre sınıf etiketi
    values = [float(pd.to_numeric(row.get(col), errors="coerce") or 0.0) * 100 for col in present.values()]
    bar_df = pd.DataFrame({"Sınıf": labels, "Olasılık": values})
    fig = px.bar(bar_df, x="Sınıf", y="Olasılık", color="Sınıf",
                 color_discrete_map=class_colors(), text="Olasılık",
                 labels={"Sınıf": t("Sınıf"), "Olasılık": t("Olasılık")})
    fig.update_traces(texttemplate="%{text:.1f}%", textposition="outside")
    fig.update_layout(
        height=320, paper_bgcolor="rgba(0,0,0,0)", font_color="#c9d1d9",
        plot_bgcolor="rgba(255,255,255,0.05)", showlegend=False,
        margin=dict(l=10, r=10, t=20, b=10),
        yaxis=dict(title=t("Olasılık (%)"), range=[0, 100], gridcolor="rgba(255,255,255,0.08)"),
        xaxis=dict(title=None),
    )
    st.plotly_chart(fig, width="stretch")

    pred_cls = tr_class(row.get("class_name", "?"))
    conf = pd.to_numeric(row.get("confidence_score"), errors="coerce")
    st.caption(t("Tahmin: **{cls}**").format(cls=pred_cls) + (t(" · Güven: {conf:.1f}%").format(conf=conf*100) if pd.notna(conf) else ""))
    return row


def render_xai_shap_explanation(df: pd.DataFrame, selected_row=None):
    """SHAP öznitelik katkıları — artefakt/öznitelik yoksa zarifçe rehberlik eder."""
    st.markdown(t("##### 🧩 SHAP Öznitelik Katkıları"))

    # 1) Önce veri: 20 öznitelik canlı kayıtta var mı? (Yoksa ağır SHAP motorunu yükleme.)
    feature_names = load_top_feature_names()
    available = [f for f in feature_names if f in df.columns]
    if not feature_names or len(available) < len(feature_names):
        st.info(t(
            "Tekil akış için SHAP açıklaması, 20 özniteliğin canlı kayıtta bulunmasını gerektirir. "
            "Tüketici güncellendiğinde öznitelik vektörü CSV'ye yazılır ve bu panel otomatik etkinleşir."
        ))
        return

    # 2) Sonra artefakt: SHAP açıklayıcıyı güvenli (lazy) içe aktar.
    try:
        from utils.xai_engine import explain_attack  # import anında SHAP yükler
    except Exception as exc:
        st.info(t(
            "SHAP açıklayıcı henüz hazır değil. Etkinleştirmek için `models/shap_explainer.pkl` "
            "ve `models/top_20_features.json` dosyalarını `src/utils/model_optimizer.py` ile üretin "
            "(gerekirse `git lfs pull`).\n\nAyrıntı: `{exc}`"
        ).format(exc=exc))
        return

    if selected_row is None:
        selected_row = df.iloc[-1]
    vector = [pd.to_numeric(selected_row.get(f), errors="coerce") for f in feature_names]
    if any(pd.isna(v) for v in vector):
        st.warning(t("Seçili kayıtta bazı öznitelik değerleri eksik."))
        return

    pred = int(pd.to_numeric(selected_row.get("predicted_class", 1), errors="coerce") or 1)
    attack_idx = pred if pred in (1, 2) else 1
    try:
        reasons = explain_attack(vector, feature_names, attack_class_index=attack_idx, top_n=10)
    except Exception as exc:
        st.warning(t("SHAP açıklaması üretilemedi: {exc}").format(exc=exc))
        return
    if not reasons:
        st.info(t("Bu tahmin için baskın öznitelik katkısı bulunamadı."))
        return
    st.caption(t("Bu tahmine en çok katkı yapan öznitelikler (yön ve büyüklük):"))
    for item in reasons:
        st.markdown(f"- **{item['feature']}** — {item['impact']}")


# ---------------------------------------------------------------------------
# Model Performansı yardımcıları (Sprint 3)
# ---------------------------------------------------------------------------
LATENCY_BENCHMARK_PATH = os.path.join(PROJECT_ROOT, "reports", "latency_benchmark.json")
PERF_MODELS = ["Random Forest", "XGBoost", "Decision Tree", "LSTM", "BiLSTM"]
PERF_CONFIG_FILES = {
    "Random Forest": "rf_3class_config.json",
    "XGBoost": "xgb_3class_config.json",
    "LSTM": "lstm_config.json",
    "BiLSTM": "bilstm_config.json",
}
PERF_REPORT_FILES = {
    "LSTM": os.path.join("reports", "lstm", "classification_report.txt"),
    "BiLSTM": os.path.join("reports", "bilstm", "classification_report.txt"),
}
PERF_LATENCY_ALIASES = {
    "XGBoost (GPU)": "XGBoost", "XGBoost": "XGBoost", "Random Forest": "Random Forest",
    "Decision Tree": "Decision Tree", "LSTM": "LSTM", "BiLSTM": "BiLSTM",
}
# Dosyada metrik bulunmayan modeller için referans (kaynak: proje değerlendirme özeti)
PERF_REFERENCE = {
    "Decision Tree": {"accuracy": 0.9727, "macro_f1": 0.94},
}


def _perf_cls_label(cls) -> str:
    """Sınıf anahtarını (isim ya da indeks) Türkçe görüntü etiketine çevirir."""
    s = str(cls)
    if s.isdigit():
        return tr_class(CLASS_NAMES.get(int(s), s))
    return tr_class(s)


@st.cache_data(ttl=300, show_spinner=False)
def load_latency_benchmark() -> dict:
    """{registry_key: {latency_ms, throughput, gpu}}"""
    import json
    out = {}
    try:
        with open(LATENCY_BENCHMARK_PATH, "r", encoding="utf-8") as fp:
            data = json.load(fp)
        for entry in data.get("results", []):
            key = PERF_LATENCY_ALIASES.get(entry.get("model"), entry.get("model"))
            out[key] = {
                "latency_ms": entry.get("latency_ms"),
                "throughput": entry.get("throughput"),
                "gpu": entry.get("gpu"),
            }
    except Exception:
        pass
    return out


def _config_metrics(model_key: str) -> dict:
    """Model config JSON'undan normalize metrikler (RF ve XGB yapılarını destekler)."""
    import json
    fname = PERF_CONFIG_FILES.get(model_key)
    if not fname:
        return {}
    try:
        with open(os.path.join(PROJECT_ROOT, "models", fname), "r", encoding="utf-8") as fp:
            cfg = json.load(fp)
    except Exception:
        return {}
    tm = cfg.get("test_metrics", {}) or {}
    result = {
        "accuracy": tm.get("accuracy"),
        "macro_precision": tm.get("macro_precision"),
        "macro_recall": tm.get("macro_recall"),
        "macro_f1": tm.get("macro_f1"),
        "macro_roc_auc": tm.get("macro_roc_auc"),
        "hyperparameters": cfg.get("hyperparameters"),
        "training_date": cfg.get("training_date"),
        "source": "config",
    }
    per_class = cfg.get("per_class_metrics") or tm.get("per_class") or {}
    roc_pc = cfg.get("per_class_roc_auc") or tm.get("roc_auc_per_class") or {}
    norm_pc = {}
    if isinstance(per_class, dict):
        for cls, m in per_class.items():
            if isinstance(m, dict):
                norm_pc[cls] = {
                    "precision": m.get("precision"), "recall": m.get("recall"),
                    "f1": m.get("f1") or m.get("f1-score") or m.get("f1_score"),
                    "roc_auc": roc_pc.get(cls) if isinstance(roc_pc, dict) else None,
                }
    result["per_class"] = norm_pc
    return result


def parse_classification_report(rel_path: str) -> dict:
    """Özel formatlı classification_report.txt -> normalize metrikler."""
    import re
    try:
        with open(os.path.join(PROJECT_ROOT, rel_path), "r", encoding="utf-8", errors="replace") as fp:
            text = fp.read()
    except Exception:
        return {}
    res = {"source": "rapor", "per_class": {}}
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


@st.cache_data(ttl=300, show_spinner=False)
def load_model_performance() -> dict:
    """Tüm modeller için birleşik performans: config/rapor metrikleri + latency."""
    latency = load_latency_benchmark()
    perf = {}
    for key in PERF_MODELS:
        metrics = _config_metrics(key)
        if not metrics.get("macro_f1") and key in PERF_REPORT_FILES:
            parsed = parse_classification_report(PERF_REPORT_FILES[key])
            if parsed.get("macro_f1") or parsed.get("accuracy"):
                metrics = parsed
        if not metrics.get("macro_f1") and not metrics.get("accuracy") and key in PERF_REFERENCE:
            metrics = {**PERF_REFERENCE[key], "source": "referans", "per_class": {}}
        lat = latency.get(key, {})
        metrics["latency_ms"] = lat.get("latency_ms")
        metrics["throughput"] = lat.get("throughput")
        metrics["gpu"] = lat.get("gpu")
        metrics.setdefault("per_class", {})
        perf[key] = metrics
    return perf


def render_perf_comparison_table(perf: dict) -> pd.DataFrame:
    st.markdown(t("##### 📋 Model Karşılaştırma Tablosu"))
    rows = []
    for key in PERF_MODELS:
        m = perf.get(key, {})
        rows.append({
            "Model": key,
            "Doğruluk": m.get("accuracy"),
            "Makro F1": m.get("macro_f1"),
            "Makro ROC-AUC": m.get("macro_roc_auc"),
            "Gecikme (ms)": m.get("latency_ms"),
            "Verim (örnek/sn)": m.get("throughput"),
            "Kaynak": m.get("source", "—"),
        })
    df = pd.DataFrame(rows)
    disp = df.copy()
    for c in ["Doğruluk", "Makro F1", "Makro ROC-AUC"]:
        disp[c] = df[c].apply(lambda v: f"{v*100:.2f}%" if pd.notna(v) else "—")
    disp["Gecikme (ms)"] = df["Gecikme (ms)"].apply(lambda v: f"{v:.4f}" if pd.notna(v) else "—")
    disp["Verim (örnek/sn)"] = df["Verim (örnek/sn)"].apply(lambda v: f"{v:,.0f}" if pd.notna(v) else "—")
    disp.columns = [t(c) for c in disp.columns]  # sütun başlıklarını yerelleştir
    st.dataframe(disp, width="stretch", hide_index=True)
    st.caption(t(
        "Kaynak: RF/XGBoost = model config; LSTM/BiLSTM = sınıflandırma raporu; "
        "hız = latency_benchmark.json; 'referans' = proje değerlendirme özeti."
    ))
    return df


def render_perf_comparison_charts(df: pd.DataFrame):
    c1, c2 = st.columns(2)
    with c1:
        f1df = df.dropna(subset=["Makro F1"]).sort_values("Makro F1")
        if not f1df.empty:
            fig = px.bar(f1df, x="Makro F1", y="Model", orientation="h",
                         color="Makro F1", color_continuous_scale="Tealgrn",
                         labels={"Makro F1": t("Makro F1"), "Model": t("Model")},
                         title=t("Makro F1 (yüksek = iyi)"))
            fig.update_layout(height=320, paper_bgcolor="rgba(0,0,0,0)", font_color="#c9d1d9",
                              plot_bgcolor="rgba(255,255,255,0.05)", coloraxis_showscale=False,
                              xaxis=dict(tickformat=".0%"), yaxis=dict(title=None),
                              margin=dict(l=10, r=10, t=40, b=10))
            st.plotly_chart(fig, width="stretch")
        else:
            st.info(t("Karşılaştırılacak F1 verisi yok."))
    with c2:
        tdf = df.dropna(subset=["Verim (örnek/sn)", "Makro F1"])
        if not tdf.empty:
            fig = px.scatter(tdf, x="Verim (örnek/sn)", y="Makro F1", text="Model",
                             log_x=True, title=t("Hız ↔ Doğruluk dengesi"),
                             labels={"Makro F1": t("Makro F1"), "Verim (örnek/sn)": t("Verim (örnek/sn, log)")})
            fig.update_traces(textposition="top center", marker=dict(size=13, color="#58a6ff"))
            fig.update_layout(height=320, paper_bgcolor="rgba(0,0,0,0)", font_color="#c9d1d9",
                              plot_bgcolor="rgba(255,255,255,0.05)", yaxis=dict(tickformat=".0%"),
                              margin=dict(l=10, r=10, t=40, b=10))
            st.plotly_chart(fig, width="stretch")
        else:
            st.info(t("Hız/doğruluk dengesi için yeterli veri yok."))


def render_perf_model_detail(perf: dict, model_key: str):
    m = perf.get(model_key, {})
    st.markdown(f"##### 🔬 {model_key} — {t('Ayrıntı')}")
    cols = st.columns(4)
    cols[0].metric(t("Doğruluk"), f"{m['accuracy']*100:.2f}%" if m.get("accuracy") else "—")
    cols[1].metric(t("Makro F1"), f"{m['macro_f1']*100:.2f}%" if m.get("macro_f1") else "—")
    cols[2].metric(t("Makro ROC-AUC"), f"{m['macro_roc_auc']*100:.2f}%" if m.get("macro_roc_auc") else "—")
    cols[3].metric(t("Verim"), f"{m['throughput']:,.0f}/sn" if m.get("throughput") else "—")

    pc = m.get("per_class") or {}
    rows = []
    for cls, vals in pc.items():
        for label, val in [("Kesinlik", vals.get("precision")), ("Duyarlılık", vals.get("recall")), ("F1", vals.get("f1"))]:
            if val is not None:
                rows.append({"Sınıf": _perf_cls_label(cls), "Metrik": t(label), "Değer": val})
    if rows:
        pcdf = pd.DataFrame(rows)
        fig = px.bar(pcdf, x="Sınıf", y="Değer", color="Metrik", barmode="group",
                     labels={"Sınıf": t("Sınıf"), "Değer": t("Değer"), "Metrik": t("Metrik")},
                     title=t("Sınıf Bazlı Metrikler"))
        fig.update_layout(height=320, paper_bgcolor="rgba(0,0,0,0)", font_color="#c9d1d9",
                          plot_bgcolor="rgba(255,255,255,0.05)",
                          yaxis=dict(tickformat=".0%", range=[0, 1]),
                          xaxis=dict(title=None), margin=dict(l=10, r=10, t=40, b=10),
                          legend=dict(orientation="h", y=-0.2, x=0.5, xanchor="center"))
        st.plotly_chart(fig, width="stretch")
    else:
        st.info(t("Bu model için sınıf bazlı metrik dosyada bulunmuyor."))

    hp = m.get("hyperparameters")
    if hp:
        with st.expander(t("Hiperparametreler")):
            st.json(hp)
    src = m.get("source")
    if src:
        extra = t(" · Eğitim: {date}").format(date=m["training_date"]) if m.get("training_date") else ""
        gpu = f" · {m['gpu']}" if m.get("gpu") else ""
        st.caption(t("Metrik kaynağı: {src}{extra}{gpu}").format(src=src, extra=extra, gpu=gpu))


# ---------------------------------------------------------------------------
# Yönetim & Yanıt yardımcıları (Sprint 4)
# ---------------------------------------------------------------------------
ESCALATION_WINDOW_VIEW = int(os.getenv("ESCALATION_WINDOW_SECONDS", "60"))


def save_model_threshold(value: float) -> bool:
    """Güven referans eşiğini models/threshold.txt'e yazar."""
    try:
        with open(THRESHOLD_PATH, "w", encoding="utf-8") as f:
            f.write(f"{min(max(value, 0.0), 1.0):.4f}")
        return True
    except Exception:
        return False


def render_admin_threshold():
    st.markdown(t("##### 🎚️ Güven Referans Eşiği"))
    current = load_model_threshold()
    new_val = st.slider(
        t("Eşik (Canlı İzleme referans çizgisi)"), 0.0, 1.0, float(current), 0.01,
        key="admin_threshold_slider",
    )
    if st.button(t("Eşiği Kaydet"), key="admin_save_threshold", width="stretch"):
        if save_model_threshold(new_val):
            st.toast(t("Eşik kaydedildi: {v:.2f}").format(v=new_val))
        else:
            st.toast(t("Eşik kaydedilemedi."), icon="⚠️")
    st.caption(t(
        "Geçerli: **{cur:.2f}** · `models/threshold.txt`'e yazılır, Canlı İzleme zaman "
        "serisindeki referans çizgisini günceller. Not: 3 sınıflı tüketici argmax kullandığından "
        "bu eşik analiz/görselleştirme amaçlıdır."
    ).format(cur=current))


def render_admin_service_health():
    st.markdown(t("##### 💓 Servis Sağlığı"))
    health = get_service_health()
    if health is None or health.empty:
        st.info(t("Henüz servis heartbeat kaydı yok."))
        return
    now = pd.Timestamp.now(tz="UTC")
    cols = st.columns(max(len(health), 1))
    for i, (_, row) in enumerate(health.iterrows()):
        last = pd.to_datetime(row.get("last_seen"), utc=True, errors="coerce")
        age = (now - last).total_seconds() if pd.notna(last) else 1e9
        if age < 30:
            badge, color = t("🟢 Canlı"), "#00cc66"
        elif age < 120:
            badge, color = t("🟡 Gecikmiş"), "#FFD700"
        else:
            badge, color = t("🔴 Yanıtsız"), "#ff4b4b"
        age_label = t("{age:.0f} sn önce").format(age=age)
        with cols[i % len(cols)]:
            st.markdown(
                f"<div style='background:rgba(255,255,255,0.04);border:1px solid {color}55;"
                f"border-radius:10px;padding:12px;text-align:center;'>"
                f"<div style='font-weight:700;color:#c9d1d9;'>{row.get('service','?')}</div>"
                f"<div style='color:{color};font-size:0.9rem;'>{badge}</div>"
                f"<div style='color:#8b949e;font-size:0.75rem;'>{age_label}</div></div>",
                unsafe_allow_html=True,
            )


def render_admin_events():
    st.markdown(t("##### 🧾 Sistem Olay Zaman Tüneli"))
    events = fetch_recent_events(limit=30)
    if events is None or events.empty:
        st.info(t("Kayıtlı sistem olayı yok (pipeline_events)."))
        return
    sev_style = {
        "ERROR": ("#ff4b4b", "🔴"), "CRITICAL": ("#ff4b4b", "🔴"),
        "WARNING": ("#FFD700", "🟡"), "INFO": ("#58a6ff", "🔵"),
    }
    for _, ev in events.iterrows():
        sev = str(ev.get("severity", "INFO")).upper()
        color, icon = sev_style.get(sev, ("#8b949e", "⚪"))
        ts = pd.to_datetime(ev.get("timestamp"), errors="coerce")
        ts_label = ts.strftime("%Y-%m-%d %H:%M:%S") if pd.notna(ts) else "—"
        st.markdown(
            f"<div style='border-left:3px solid {color};padding:6px 12px;margin-bottom:6px;"
            f"background:rgba(255,255,255,0.03);border-radius:0 8px 8px 0;'>"
            f"<span style='color:{color};font-weight:600;'>{icon} {sev}</span> "
            f"<span style='color:#8b949e;font-size:0.8rem;'>· {ev.get('service','?')} · {ts_label}</span><br>"
            f"<span style='color:#c9d1d9;'>{ev.get('summary','')}</span></div>",
            unsafe_allow_html=True,
        )


def render_admin_policy():
    st.markdown(t("##### 🛡️ Yanıt Politikası & Engel TTL"))
    wl = [w.strip() for w in (WHITELIST or []) if w.strip()]
    c1, c2, c3 = st.columns(3)
    c1.metric(t("Engel TTL"), t("{m} dk").format(m=BLOCK_TTL_SECONDS // 60))
    c2.metric(t("Eskalasyon Penceresi"), t("{s} sn").format(s=ESCALATION_WINDOW_VIEW))
    c3.metric(t("Beyaz Liste"), t("{n} IP").format(n=len(wl)))
    st.caption(t(
        "Eskalasyon: 1 tespit → UYARI · 2-3 → ŞÜPHELİ · 4+ → ENGELLENDİ. Bu değerler `.env` "
        "(WHITELIST_IPS, BLOCK_TTL_SECONDS, ESCALATION_WINDOW_SECONDS) ile ayarlanır; "
        "değişiklik için servisleri yeniden başlatın."
    ))
    if wl:
        st.caption(t("Beyaz liste: {ips}").format(ips=", ".join(wl)))

    records = get_block_records()
    if not records:
        st.info(t("Aktif engel kaydı yok."))
        return
    now = pd.Timestamp.now(tz="UTC")
    rows = []
    for r in records:
        blocked = pd.to_datetime(r.get("blocked_at"), utc=True, errors="coerce")
        if pd.notna(blocked):
            remaining = max(BLOCK_TTL_SECONDS - (now - blocked).total_seconds(), 0)
            rem_label = t("{m:.0f} dk").format(m=remaining / 60) if remaining > 0 else t("süresi doldu")
            blocked_label = blocked.tz_convert(None).strftime("%Y-%m-%d %H:%M:%S")
        else:
            rem_label, blocked_label = "—", "—"
        rows.append({t("IP"): r.get("ip"), t("Engellenme (UTC)"): blocked_label, t("Kalan TTL"): rem_label})
    st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)


# 0. Dil seçici (en üstte — tüm panonun dilini belirler)
st.sidebar.radio("🌐 Dil / Language", ["Türkçe", "English"], horizontal=True, key="lang_choice")
st.session_state["lang"] = "EN" if st.session_state.get("lang_choice") == "English" else "TR"

st.sidebar.markdown(f'<p class="soc-header">{t("SOC Kontrol Paneli")}</p>', unsafe_allow_html=True)

# 1. Durum LED'leri
status = get_system_status()
led_data = "🟢" if status["data_flowing"] else ("🟡" if status["csv_exists"] else "🔴")
led_tf = "🟢" if status["tensorflow"] else "🔴"
st.sidebar.markdown(t("**Veri Akışı:** {data} &nbsp;|&nbsp; **Motor:** {tf}").format(data=led_data, tf=led_tf))
st.sidebar.markdown("---")

# Pre-load data for global filtering & banner
df_live_full = load_live_traffic()
df_logs_full = load_logs()

# 2. Threat Level Banner (Last 60s)
threat_info = RISK_LEVELS[1]
if not df_live_full.empty:
    ts_col = "timestamp" if "timestamp" in df_live_full.columns else "Timestamp"
    if ts_col in df_live_full.columns:
        df_live_full[ts_col] = pd.to_datetime(df_live_full[ts_col], errors="coerce")
        max_ts = df_live_full[ts_col].max()
        if not pd.isna(max_ts):
            last_60s = df_live_full[df_live_full[ts_col] >= (max_ts - pd.Timedelta(seconds=60))]
            if not last_60s.empty:
                risk_col = "risk_level" if "risk_level" in last_60s.columns else "Risk_Level"
                if risk_col in last_60s.columns:
                    max_r = int(last_60s[risk_col].max())
                else:
                    pred = "predicted_class" if "predicted_class" in last_60s.columns else "Predicted_Class"
                    max_c = int(last_60s[pred].max()) if pred in last_60s.columns else 0
                    max_r = 1 if max_c == 0 else (4 if max_c == 1 else 5)
                threat_info = RISK_LEVELS.get(max_r, RISK_LEVELS[1])

st.sidebar.markdown(f"""
<div style="background: {threat_info['color']}15; border: 1px solid {threat_info['color']}50; padding: 12px; border-radius: 8px; text-align: center; margin-bottom: 15px;">
    <div style="font-size: 0.8rem; color: #8b949e; margin-bottom: 5px;">{t("TEHDİT SEVİYESİ (SON 60 SN)")}</div>
    <div style="font-size: 1.4rem; font-weight: bold; color: {threat_info['color']};">{threat_info['emoji']} {tr_risk(threat_info['name'])}</div>
</div>
""", unsafe_allow_html=True)

# 3. Zaman Penceresi (değerler TR sabit — mantık anahtarı; yalnız görüntü yerelleşir)
time_window = st.sidebar.selectbox(t("📅 Zaman Penceresi"), ["Son 5 dk", "Son 1 saat", "Son 24 saat", "Tüm Zamanlar"], format_func=t)
st.sidebar.markdown("---")

# 4. Canlı Mod
st.sidebar.subheader(t("🔄 Canlı Yenileme"))
live_mode = st.sidebar.toggle(t("⚡ Canlı Mod"), key="live_mode")
refresh_interval = st.sidebar.slider(t("Aralık (saniye)"), 5, 60, key="refresh_interval", disabled=not live_mode)
st.sidebar.markdown("---")

# Sekmeler için veri çerçevelerini filtrele
def filter_dataframe(df: pd.DataFrame, window: str) -> pd.DataFrame:
    if df.empty or window == "Tüm Zamanlar": return df
    c = "timestamp" if "timestamp" in df.columns else "Timestamp"
    if c not in df.columns: return df
    df = df.copy()  # girdiyi yerinde değiştirme (mutasyon hatası önlenir)
    df[c] = pd.to_datetime(df[c], errors="coerce")
    m_ts = df[c].max()
    if pd.isna(m_ts): return df
    if window == "Son 5 dk": cutoff = m_ts - pd.Timedelta(minutes=5)
    elif window == "Son 1 saat": cutoff = m_ts - pd.Timedelta(hours=1)
    elif window == "Son 24 saat": cutoff = m_ts - pd.Timedelta(hours=24)
    else: return df
    return df[df[c] >= cutoff].copy()

live_df = filter_dataframe(df_live_full, time_window)
logs_df = filter_dataframe(df_logs_full, time_window)

# 5. Model Durum Rozeti
st.sidebar.subheader(t("🧠 Aktif Yapay Zeka Modeli"))
os.makedirs(os.path.dirname(ACTIVE_MODEL_PATH), exist_ok=True)
_default_model_key = "Random Forest"
try:
    if os.path.exists(ACTIVE_MODEL_PATH):
        with open(ACTIVE_MODEL_PATH) as f:
            _stored = f.read().strip()
        # Support both registry key names and legacy filenames
        if _stored in MODEL_MAPPING:
            current_model = _stored
        else:
            current_model = next((k for k, v in MODEL_MAPPING.items() if v == _stored), _default_model_key)
    else:
        current_model = _default_model_key
        with open(ACTIVE_MODEL_PATH, "w") as f:
            f.write(_default_model_key)
except Exception:
    current_model = _default_model_key

_model_keys = list(MODEL_MAPPING.keys())
selected_model = st.sidebar.selectbox(
    t("Model Seç"),
    _model_keys,
    index=_model_keys.index(current_model) if current_model in _model_keys else 0,
    key="model_selector",
    label_visibility="collapsed",
)
if selected_model != current_model:
    try:
        with open(ACTIVE_MODEL_PATH, "w") as f:
            f.write(selected_model)  # dosya adı değil, registry anahtar adı yazılır
    except Exception:
        pass

_is_live = MODEL_LIVE.get(selected_model, True)
_badge_color = "#00CC66" if _is_live else "#FFA500"
_badge_text = t("● Aktif") if _is_live else t("● Canlı değil")
st.sidebar.markdown(f"""
<div style="display: flex; justify-content: space-between; align-items: center; background: rgba(255,255,255,0.05); padding: 8px 12px; border-radius: 6px; margin-top: -10px;">
    <span style="font-weight: 600; font-size: 0.9rem;">{selected_model}</span>
    <span style="color: {_badge_color}; font-size: 0.8rem;">{_badge_text}</span>
</div>
""", unsafe_allow_html=True)
if not _is_live:
    st.sidebar.warning(t("⚠️ Bu model henüz canlı pipeline'da desteklenmiyor (Sprint 2). Tüketici varsayılan modele dönebilir."))

st.sidebar.markdown("---")

# 6. IP Engel Kaldırma
st.sidebar.subheader(t("🔓 IP Engelini Kaldır"))
ip_input = st.sidebar.text_input(t("IP Adresi"), key="ip_unblock_input")
if st.sidebar.button(t("Engeli Kaldır"), key="unblock_btn"):
    if ip_input.strip():
        ok = unblock_ip(ip_input.strip())
        st.sidebar.success(t("✅ {ip} engeli kaldırıldı.").format(ip=ip_input)) if ok else st.sidebar.warning(t("⚠️ İşlem başarısız."))
    else:
        st.sidebar.warning(t("Geçerli bir IP adresi girin."))

st.sidebar.markdown("---")
st.sidebar.caption(t("🕐 Son yenileme: {time}").format(time=datetime.now().strftime('%H:%M:%S')))
st.sidebar.caption(t("🔁 Yenileme #{n}").format(n=count))

# ---------------------------------------------------------------------------
# PAGE HEADER
# ---------------------------------------------------------------------------
st.markdown(f'<p class="soc-header">{t("🛡️ Ağ Saldırı Önleme Sistemi — Güvenlik Operasyon Merkezi")}</p>', unsafe_allow_html=True)
st.markdown(f'<p class="soc-sub">{t("3 Sınıflı NIDS &nbsp;|&nbsp; Zararsız · Hacimsel · Anlamsal &nbsp;|&nbsp; Gerçek Zamanlı Tespit")}</p>', unsafe_allow_html=True)
st.markdown("---")

# ---------------------------------------------------------------------------
# BEŞ SEKMELİ DÜZEN
# ---------------------------------------------------------------------------
tab_monitor, tab_map, tab_logs, tab_xai, tab_perf, tab_admin = st.tabs([
    t("🖥️ Canlı İzleme"),
    t("🗺️ Tehdit Haritası"),
    t("📋 Olay Kayıtları"),
    t("🧠 XAI Açıklayıcı"),
    t("📊 Model Performansı"),
    t("⚙️ Yönetim & Yanıt"),
])

# ── Tab 1: Live Monitor ────────────────────────────────────────────────────
with tab_monitor:
    render_system_status(status)
    st.markdown("---")
    render_metrics(live_df)
    st.markdown("---")

    col_gauge, col_dist = st.columns([1, 2])
    with col_gauge:
        render_risk_gauge(live_df)
    with col_dist:
        render_class_distribution(live_df)

    st.markdown("---")
    col_conf, col_time = st.columns(2)
    with col_conf:
        render_confidence_histogram(live_df)
    with col_time:
        render_stacked_time_series(live_df, logs_df)

    st.markdown("---")
    render_protocol_port_heatmap(live_df)

    st.markdown("---")
    render_live_attack_feed(logs_df)

    st.markdown("---")
    render_recent_detections(live_df)

# ── Sekme 2: Tehdit Haritası ───────────────────────────────────────────────
with tab_map:
    st.markdown(t("#### 🗺️ Tehdit Haritası"))
    st.caption(t("Coğrafi-IP konumlandırma, saldırı dağılımı ve önem derecesi zaman çizelgesi."))
    render_threat_map(logs_df)
    st.markdown("---")
    render_attack_distribution(live_df)
    st.markdown("---")
    render_severity_timeline(live_df, logs_df)

# ── Sekme 3: Olay Kayıtları ────────────────────────────────────────────────
with tab_logs:
    st.markdown(t("#### 📋 Olay Kayıtları"))
    if logs_df.empty:
        st.info(t("Veritabanında olay kaydı bulunamadı."))
    else:
        # Hızlı özet metrikleri
        total_l   = len(logs_df)
        blocked_l = int((logs_df.get("action", pd.Series(dtype=str)) == "BLOCKED").sum())
        allowed_l = int((logs_df.get("action", pd.Series(dtype=str)) == "ALLOWED").sum())
        last_evt  = logs_df["timestamp"].max().strftime("%Y-%m-%d %H:%M:%S") if "timestamp" in logs_df.columns else "—"
        c1, c2, c3, c4 = st.columns(4)
        c1.metric(t("Toplam Kayıt"), f"{total_l:,}")
        c2.metric(t("Engellenen"), f"{blocked_l:,}")
        c3.metric(t("İzin Verilen"), f"{allowed_l:,}")
        c4.metric(t("Son Olay"), last_evt)
        st.markdown("---")
        grid_state = render_logs_grid(logs_df)
        selected_rows = grid_state["selected_rows"]
        export_df = grid_state["filtered_df"]
        export_total = len(export_df)
        export_blocked = int((export_df.get("action", pd.Series(dtype=str)) == "BLOCKED").sum()) if not export_df.empty else 0
        export_allowed = int((export_df.get("action", pd.Series(dtype=str)) == "ALLOWED").sum()) if not export_df.empty else 0
        export_last = "—"
        if not export_df.empty and "timestamp" in export_df.columns:
            export_ts = pd.to_datetime(export_df["timestamp"], errors="coerce")
            if not export_ts.dropna().empty:
                export_last = export_ts.max().strftime("%Y-%m-%d %H:%M:%S")

        st.markdown("---")
        st.markdown(t("##### Rapor Dışa Aktarımı"))
        csv_bytes = build_logs_csv_bytes(export_df)
        pdf_bytes = build_logs_pdf_bytes(export_df, export_total, export_blocked, export_allowed, export_last)
        export_col_csv, export_col_pdf = st.columns(2)
        with export_col_csv:
            st.download_button(
                t("CSV Dışa Aktar"),
                data=csv_bytes,
                file_name=f"olay_kayitlari_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                width="stretch",
            )
        with export_col_pdf:
            if pdf_bytes is None:
                st.button(
                    t("PDF Dışa Aktar"),
                    disabled=True,
                    help=t("PDF dışa aktarımı için `reportlab` paketini kurun."),
                    width="stretch",
                )
            else:
                st.download_button(
                    t("PDF Dışa Aktar"),
                    data=pdf_bytes,
                    file_name=f"olay_raporu_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                    mime="application/pdf",
                    width="stretch",
                )
        st.markdown("---")
        render_batch_log_actions(selected_rows)

# ── Sekme 4: XAI Açıklayıcı ─────────────────────────────────────────────────
with tab_xai:
    st.markdown(t("#### 🧠 XAI Açıklayıcı"))
    st.caption(t(
        "Modelin kararlarını açıklar: global öznitelik önceliği, seçili tespit için sınıf "
        "olasılık kırılımı ve SHAP tabanlı öznitelik katkıları."
    ))
    col_global, col_local = st.columns([1, 1])
    with col_global:
        render_xai_global_importance()
    with col_local:
        xai_selected_row = render_xai_probability_breakdown(live_df)
    st.markdown("---")
    render_xai_shap_explanation(live_df, xai_selected_row)

# ── Sekme 5: Model Performansı ──────────────────────────────────────────────
with tab_perf:
    st.markdown(t("#### 📊 Model Performansı & Karşılaştırma"))
    st.caption(t(
        "Eğitim/değerlendirme sonuçları: 5 modelin doğruluk, F1, ROC-AUC ve hız karşılaştırması "
        "ile seçili model için sınıf bazlı ayrıntılar."
    ))
    perf_data = load_model_performance()
    perf_df = render_perf_comparison_table(perf_data)
    st.markdown("---")
    render_perf_comparison_charts(perf_df)
    st.markdown("---")
    _perf_default = selected_model if selected_model in PERF_MODELS else PERF_MODELS[0]
    detail_model = st.selectbox(
        t("Model detayı seç"), PERF_MODELS,
        index=PERF_MODELS.index(_perf_default), key="perf_detail_model",
    )
    render_perf_model_detail(perf_data, detail_model)

# ── Sekme 6: Yönetim & Yanıt ────────────────────────────────────────────────
with tab_admin:
    st.markdown(t("#### ⚙️ Yönetim & Yanıt"))
    st.caption(t("Karar eşiği, servis sağlığı, sistem olay tüneli ve yanıt politikası."))

    col_thr, col_health = st.columns([1, 1])
    with col_thr:
        render_admin_threshold()
    with col_health:
        render_admin_service_health()

    st.markdown("---")
    render_admin_policy()

    st.markdown("---")
    render_admin_events()

    st.markdown("---")
    render_firewall_viewer()
