import os
import sys
import time

import pandas as pd
import plotly.express as px
import streamlit as st

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(CURRENT_DIR)
if PARENT_DIR not in sys.path:
    sys.path.append(PARENT_DIR)

from utils.db_manager import fetch_logs
from utils.firewall_manager import unblock_ip

st.set_page_config(page_title="Network IPS Dashboard", layout="wide")
st.title(" AI Network IPS Dashboard")


def load_logs() -> pd.DataFrame:
    logs_df = fetch_logs()
    if logs_df.empty:
        return logs_df
    logs_df["timestamp"] = pd.to_datetime(logs_df["timestamp"], errors="coerce")
    return logs_df.sort_values("timestamp", ascending=False)


def render_kpis(logs_df: pd.DataFrame):
    total = len(logs_df)
    blocked = int((logs_df["action"] == "BLOCKED").sum())
    allowed = int((logs_df["action"] == "ALLOWED").sum())
    last_event = "-" if logs_df.empty else logs_df["timestamp"].max().strftime("%Y-%m-%d %H:%M:%S")

    col1, col2, col3 = st.columns(3)
    col1.metric("Toplam Kayıt", total)
    col2.metric("Engellenen IP", blocked)
    col3.metric("Son Olay", last_event)


def render_charts(logs_df: pd.DataFrame):
    col_line, col_pie = st.columns(2)

    if logs_df.empty:
        col_line.info("Grafik göstermek için yeterli veri yok.")
        col_pie.info("Grafik göstermek için yeterli veri yok.")
        return

    line_df = (
        logs_df.set_index("timestamp")
        .resample("1min")
        .size()
        .reset_index(name="attacks")
    )
    if line_df.empty:
        col_line.info("Saldırı frekansı için veri yok.")
    else:
        line_fig = px.line(line_df, x="timestamp", y="attacks", title="Saldırı Frekansı (1 dk)")
        col_line.plotly_chart(line_fig, width="stretch")

    pie_df = logs_df["action"].value_counts().reset_index()
    pie_df.columns = ["action", "count"]
    if pie_df.empty:
        col_pie.info("Eylem dağılımı için veri yok.")
    else:
        pie_fig = px.pie(pie_df, values="count", names="action", title="Blocked vs Allowed", hole=0.3)
        col_pie.plotly_chart(pie_fig, width="stretch")


logs = load_logs()
render_kpis(logs)
render_charts(logs)

st.subheader("Detaylı Loglar")
if logs.empty:
    st.info("Henüz kayıt bulunamadı.")
else:
    st.dataframe(logs)

st.sidebar.header("Kontroller")

# ---------------------------------------------------------------------------
# MODEL SELECTION
# ---------------------------------------------------------------------------
st.sidebar.subheader("🧠 Aktif Yapay Zeka Modeli")

MODEL_MAPPING = {
    "Random Forest": "rf_3class_model.pkl",
    "Decision Tree": "dt_model.pkl",
    "XGBoost": "xgboost_model.pkl",
    "LSTM": "lstm_model.keras",
    "BiLSTM": "bilstm_model.keras"
}

# Read current active model
ACTIVE_MODEL_PATH = os.path.join(PARENT_DIR, "data", "active_model.txt")
os.makedirs(os.path.dirname(ACTIVE_MODEL_PATH), exist_ok=True)

try:
    if os.path.exists(ACTIVE_MODEL_PATH):
        with open(ACTIVE_MODEL_PATH, "r") as f:
            current_model_file = f.read().strip()
        # Find the friendly name
        current_model = next((k for k, v in MODEL_MAPPING.items() if v == current_model_file), "Random Forest")
    else:
        current_model = "Random Forest"
        # Create default config
        with open(ACTIVE_MODEL_PATH, "w") as f:
            f.write(MODEL_MAPPING["Random Forest"])
except Exception:
    current_model = "Random Forest"

selected_model = st.sidebar.selectbox(
    "Model Seçin",
    list(MODEL_MAPPING.keys()),
    index=list(MODEL_MAPPING.keys()).index(current_model),
    key="model_selector"
)

# Write to config file when selection changes
if selected_model != current_model:
    try:
        with open(ACTIVE_MODEL_PATH, "w") as f:
            f.write(MODEL_MAPPING[selected_model])
        st.sidebar.success(f"✅ Model değiştirildi: {selected_model}")
        st.sidebar.info("⏳ Consumer yeni modeli birkaç saniye içinde yükleyecek...")
    except Exception as e:
        st.sidebar.error(f"❌ Model yazma hatası: {e}")

st.sidebar.caption(f"📊 Şu an aktif: **{selected_model}**")
st.sidebar.markdown("---")

auto_refresh = st.sidebar.checkbox("Otomatik Yenile", value=True)
refresh_interval = st.sidebar.slider("Yenileme Aralığı (sn)", min_value=5, max_value=60, value=15, key="refresh_rate_slider")

ip_to_unblock = st.sidebar.text_input("Engeli Kaldırılacak IP")
if st.sidebar.button("Unblock IP"):
    if ip_to_unblock.strip():
        success = unblock_ip(ip_to_unblock.strip())
        if success:
            st.sidebar.success(f"{ip_to_unblock} engeli kaldırıldı.")
        else:
            st.sidebar.warning(f"{ip_to_unblock} için kural bulunamadı veya işlem başarısız.")
    else:
        st.sidebar.warning("Lütfen geçerli bir IP girin.")

if auto_refresh:
    st.sidebar.caption(f"Sayfa {refresh_interval} sn'de bir yenileniyor.")
    time.sleep(refresh_interval)
    st.rerun()
