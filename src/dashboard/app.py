#!/usr/bin/env python3
"""
Network IPS Dashboard - SOC Edition
=====================================
Multi-tab Security Operations Center dashboard for LSTM/BiLSTM-based 3-class NIDS.
"""

import os
import sys
import time
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
    from utils.firewall_manager import block_ip, list_blocked_ips, unblock_ip
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
except ImportError:
    MODEL_MAPPING = {
        "Random Forest": "rf_3class_model.pkl",
        "Decision Tree": "dt_3class_model.pkl",
        "XGBoost":       "xgb_3class_model.pkl",
        "LSTM":          "lstm_model.keras",
        "BiLSTM":        "bilstm_model.keras",
    }

# ---------------------------------------------------------------------------
# PAGE CONFIG
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title=" SOC Network IPS",
    page_icon="",
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
        return "Unknown"
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
    st.markdown("#### ⚙️ System Status")
    c1, c2, c3, c4, c5 = st.columns(5)
    def badge(col, label, ok, warn=False):
        cls = "badge-ok" if ok else ("badge-warn" if warn else "badge-err")
        icon = "✅" if ok else ("⏳" if warn else "❌")
        col.markdown(f'<span class="{cls}">{icon} {label}</span>', unsafe_allow_html=True)
    badge(c1, "LSTM/BiLSTM", status["sequence_model"])
    badge(c2, "Scaler",     status["scaler"])
    badge(c3, "TensorFlow", status["tensorflow"])
    badge(c4, "Scapy",      status["scapy"], warn=status["csv_exists"] and not status["scapy"])
    ok5 = status["data_flowing"]
    warn5 = status["csv_exists"] and not ok5
    badge(c5, f"Bridge ({status['csv_age']:.0f}s)", ok5, warn=warn5)
    if status["csv_exists"]:
        st.caption(f"📊 CSV: {status['csv_rows']:,} rows | Last update: {status['csv_age']:.0f}s ago")


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
    c1.metric("📊 Total Flows", f"{total:,}")
    c2.metric("🟢 Benign",      f"{benign:,}",    delta=f"{benign/total*100:.1f}%" if total else "0%")
    c3.metric("🔴 Volumetric",  f"{volumetric:,}", delta=f"{volumetric/total*100:.1f}%" if total else "0%", delta_color="inverse")
    c4.metric("🟠 Semantic",    f"{semantic:,}",   delta=f"{semantic/total*100:.1f}%" if total else "0%",  delta_color="inverse")
    c5.metric("🎯 Avg Confidence", f"{avg_conf*100:.1f}%")


def render_risk_gauge(df: pd.DataFrame):
    st.markdown("#### 🎯 Current Risk Level")
    if df.empty:
        st.info("Waiting for data…")
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
        title={"text": f"Risk: {info['name']}", "font": {"size": 20, "color": "#c9d1d9"}},
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
    st.markdown("#### 📊 Class Distribution (3-Class)")
    if df.empty:
        st.info("Waiting for data…")
        return
    col = "class_name" if "class_name" in df.columns else "Class_Name"
    if col not in df.columns:
        st.warning("Class column not found.")
        return
    counts = df[col].value_counts().reset_index()
    counts.columns = ["Class", "Count"]
    fig = px.pie(counts, values="Count", names="Class", hole=0.6,
                 color="Class", color_discrete_map=CLASS_COLORS,
                 title="Traffic Class Distribution")
    fig.update_traces(textposition="inside", textinfo="percent+label",
                      marker=dict(line=dict(color="#0d1117", width=2)))
    total = counts["Count"].sum()
    fig.add_annotation(text=f"<b>{total:,}</b><br>Total", x=0.5, y=0.5,
                       font_size=14, showarrow=False, font_color="#c9d1d9")
    fig.update_layout(height=320, paper_bgcolor="rgba(0,0,0,0)", font_color="#c9d1d9",
                      legend=dict(orientation="h", y=-0.15, x=0.5, xanchor="center"))
    st.plotly_chart(fig, width="stretch")


def render_attack_distribution(df: pd.DataFrame):
    st.markdown("#### Attack Distribution")
    if df.empty:
        st.info("Waiting for data...")
        return

    working = df.copy()
    if "class_name" not in working.columns and "predicted_class" in working.columns:
        working["class_name"] = working["predicted_class"].map(CLASS_NAMES)
    if "risk_name" not in working.columns and "risk_level" in working.columns:
        working["risk_name"] = working["risk_level"].map(lambda level: RISK_LEVELS.get(level, RISK_LEVELS[1])["name"])

    if "class_name" not in working.columns:
        st.warning("Class column not found.")
        return

    attack_df = working[working["class_name"].isin(["Volumetric", "Semantic"])].copy()
    if attack_df.empty:
        st.info("No attack detections available for sunburst distribution yet.")
        return

    if "risk_name" not in attack_df.columns:
        attack_df["risk_name"] = attack_df["class_name"].map({
            "Volumetric": "HIGH",
            "Semantic": "CRITICAL",
        })

    distribution = (
        attack_df.groupby(["class_name", "risk_name"])
        .size()
        .reset_index(name="count")
    )
    distribution["root"] = "Attacks"

    fig = px.sunburst(
        distribution,
        path=["root", "class_name", "risk_name"],
        values="count",
        color="class_name",
        color_discrete_map=CLASS_COLORS,
    )
    fig.update_traces(
        branchvalues="total",
        insidetextorientation="radial",
        hovertemplate="<b>%{label}</b><br>Flows: %{value}<br>Share: %{percentParent:.1%}<extra></extra>",
    )
    fig.update_layout(
        height=340,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(255,255,255,0.05)",
        font_color="#c9d1d9",
        margin=dict(l=20, r=20, t=20, b=10),
    )
    st.plotly_chart(fig, use_container_width=True)


def render_severity_timeline(live_df: pd.DataFrame, logs_df: pd.DataFrame):
    st.markdown("#### Severity Timeline")

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
        st.info("No severity events available for the timeline yet.")
        return

    timeline_df = timeline_df.dropna(subset=["timestamp", "risk_name"]).copy()
    if timeline_df.empty:
        st.info("No severity events available for the timeline yet.")
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
        st.info("No severity events available for the timeline yet.")
        return

    timeline_series = (
        timeline_df.groupby([pd.Grouper(key="timestamp", freq="1min"), "risk_name"])
        .size()
        .unstack(fill_value=0)
        .reindex(columns=severity_order, fill_value=0)
        .sort_index()
    )
    if timeline_series.empty:
        st.info("No severity events available for the timeline yet.")
        return

    fig = go.Figure()
    for severity in severity_order:
        fig.add_trace(go.Scatter(
            x=timeline_series.index,
            y=timeline_series[severity],
            mode="lines+markers",
            name=severity,
            line=dict(color=severity_colors[severity], width=2.2),
            marker=dict(size=6),
            hovertemplate=f"{severity}: %{{y}}<br>%{{x|%Y-%m-%d %H:%M}}<extra></extra>",
        ))

    fig.update_layout(
        height=320,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(255,255,255,0.05)",
        font_color="#c9d1d9",
        margin=dict(l=20, r=20, t=20, b=10),
        legend=dict(orientation="h", y=-0.22, x=0.5, xanchor="center"),
        xaxis=dict(title=None, gridcolor="rgba(255,255,255,0.08)"),
        yaxis=dict(title="Events / min", rangemode="tozero", gridcolor="rgba(255,255,255,0.08)"),
        hovermode="x unified",
    )
    st.plotly_chart(fig, use_container_width=True)


def render_time_series(df: pd.DataFrame):
    st.markdown("#### 📈 Detection Time Series")
    if df.empty:
        st.info("Waiting for data…")
        return
    ts = "timestamp" if "timestamp" in df.columns else "Timestamp"
    if ts not in df.columns:
        st.warning("Timestamp column not found.")
        return
    tmp = df.copy()
    tmp[ts] = pd.to_datetime(tmp[ts], errors="coerce")
    tmp = tmp.dropna(subset=[ts]).set_index(ts)
    if len(tmp) < 2:
        st.info("Not enough data for time series.")
        return
    c = "class_name" if "class_name" in tmp.columns else "Class_Name"
    if c in tmp.columns:
        series = tmp.groupby([pd.Grouper(freq="1min"), c]).size().unstack(fill_value=0)
    else:
        series = tmp.resample("1min").size().to_frame("count")
    fig = px.line(series.reset_index(), x=ts,
                  y=series.columns.tolist(),
                  color_discrete_map=CLASS_COLORS,
                  title="Detections per Minute")
    fig.update_layout(height=280, paper_bgcolor="rgba(0,0,0,0)", font_color="#c9d1d9",
                      legend=dict(orientation="h", y=-0.25, x=0.5, xanchor="center"),
                      plot_bgcolor="rgba(255,255,255,0.05)")
    st.plotly_chart(fig, width="stretch")


def render_stacked_time_series(df: pd.DataFrame, logs_df: pd.DataFrame):
    st.markdown("#### Detection Time Series")
    if df.empty:
        st.info("Waiting for data...")
        return
    if "timestamp" not in df.columns:
        st.warning("Timestamp column not found.")
        return

    tmp = df.copy()
    tmp["timestamp"] = pd.to_datetime(tmp["timestamp"], errors="coerce")
    tmp = tmp.dropna(subset=["timestamp"])
    if tmp.empty:
        st.info("Not enough data for time series.")
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
        st.info("Not enough data for time series.")
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
            name=class_name,
            stackgroup="traffic",
            line=dict(color=color, width=1.4),
            hovertemplate=f"{class_name}: %{{y}}<br>%{{x|%H:%M:%S}}<extra></extra>",
        ))

    fig.add_trace(go.Scatter(
        x=confidence.index,
        y=confidence.values,
        mode="lines",
        name="Avg Confidence",
        yaxis="y2",
        line=dict(color="#58A6FF", width=2),
        hovertemplate="Avg confidence: %{y:.1f}%<br>%{x|%H:%M:%S}<extra></extra>",
    ))

    threshold_value = load_model_threshold() * 100
    fig.add_trace(go.Scatter(
        x=[series.index.min(), series.index.max()],
        y=[threshold_value, threshold_value],
        mode="lines",
        name=f"Threshold ({threshold_value:.1f}%)",
        yaxis="y2",
        line=dict(color="#FFD166", width=2, dash="dash"),
        hovertemplate="Threshold: %{y:.1f}%<extra></extra>",
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
            marker_text = [f"Block x{int(count)}" for count in blocked_counts]
            if len(blocked_counts) > 8:
                marker_text = None
            fig.add_trace(go.Scatter(
                x=blocked_counts.index,
                y=marker_y,
                mode="markers+text" if marker_text else "markers",
                name="Blocked",
                text=marker_text,
                textposition="top center",
                marker=dict(
                    color="#FF7B72",
                    size=12,
                    symbol="diamond",
                    line=dict(color="#0d1117", width=1.5),
                ),
                customdata=blocked_counts.astype(int),
                hovertemplate="Blocked events: %{customdata}<br>%{x|%H:%M:%S}<extra></extra>",
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
        yaxis=dict(title="Flows / 10s", rangemode="tozero", gridcolor="rgba(255,255,255,0.08)"),
        yaxis2=dict(
            title="Confidence (%)",
            overlaying="y",
            side="right",
            range=[0, 100],
            showgrid=False,
        ),
    )
    st.plotly_chart(fig, width="stretch")
    st.caption("10-second buckets with stacked class volume, live confidence threshold, and block markers.")


def render_confidence_histogram(df: pd.DataFrame):
    st.markdown("#### 📊 Confidence Score Distribution")
    if df.empty:
        st.info("Waiting for data…")
        return
    prob_cols = [c for c in df.columns if "prob" in c.lower()]
    if prob_cols:
        max_probs = df[prob_cols].apply(pd.to_numeric, errors="coerce").max(axis=1).dropna()
    elif "confidence_score" in df.columns:
        max_probs = pd.to_numeric(df["confidence_score"], errors="coerce").dropna()
    else:
        st.warning("Probability columns not found.")
        return
    if len(max_probs) < 5:
        st.info("Not enough data.")
        return
    fig = px.histogram(max_probs * 100, nbins=20,
                       labels={"value": "Confidence (%)", "count": "Frequency"},
                       color_discrete_sequence=["#58a6ff"],
                       title="Prediction Confidence Distribution")
    mean_c = max_probs.mean() * 100
    fig.add_vline(x=mean_c, line_dash="dash", line_color="#ff7b72",
                  annotation_text=f"Mean: {mean_c:.1f}%", annotation_font_color="#ff7b72")
    fig.update_layout(showlegend=False, height=280,
                      paper_bgcolor="rgba(0,0,0,0)", font_color="#c9d1d9",
                      plot_bgcolor="rgba(255,255,255,0.05)")
    st.plotly_chart(fig, width="stretch")


def render_protocol_port_heatmap(df: pd.DataFrame):
    st.markdown("#### Protocol / Port Heatmap")
    if df.empty:
        st.info("Waiting for data...")
        return

    protocol_col = find_first_present_column(df, ["protocol", "Protocol"])
    dst_port_col = find_first_present_column(df, ["dst_port", "Dst Port", "Destination Port", "Dest Port"])
    src_port_col = find_first_present_column(df, ["src_port", "Src Port", "Source Port"])
    port_col = dst_port_col or src_port_col

    working = df.copy()
    if protocol_col is not None:
        working["protocol_label"] = working[protocol_col].apply(format_protocol_label)
    else:
        working["protocol_label"] = "Unknown"

    has_port_data = port_col is not None
    if has_port_data:
        ports = pd.to_numeric(working[port_col], errors="coerce")
        valid_ports = ports.where(ports.between(0, 65535))
        top_ports = valid_ports.dropna().astype(int).value_counts().head(12).index.tolist()
        if top_ports:
            working["port_label"] = valid_ports.apply(
                lambda value: str(int(value)) if pd.notna(value) and int(value) in top_ports else "Other"
            )
        else:
            working["port_label"] = "N/A"
            has_port_data = False
    else:
        working["port_label"] = "N/A"

    heatmap_df = (
        working.groupby(["protocol_label", "port_label"])
        .size()
        .reset_index(name="flow_count")
    )
    if heatmap_df.empty:
        st.info("Not enough data for heatmap.")
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
        if "Other" in heatmap_df["port_label"].values:
            port_order.append("Other")
    else:
        port_order = ["N/A"]

    pivot = (
        heatmap_df.pivot(index="protocol_label", columns="port_label", values="flow_count")
        .reindex(index=protocol_order, columns=port_order, fill_value=0)
        .fillna(0)
    )

    fig = go.Figure(data=go.Heatmap(
        z=pivot.values,
        x=pivot.columns.tolist(),
        y=pivot.index.tolist(),
        colorscale=[
            [0.0, "#0b1220"],
            [0.2, "#123b5a"],
            [0.45, "#1f8a70"],
            [0.7, "#f4b942"],
            [1.0, "#ff5d5d"],
        ],
        colorbar=dict(title="Flows"),
        hovertemplate="Protocol: %{y}<br>Port: %{x}<br>Flows: %{z}<extra></extra>",
    ))
    fig.update_layout(
        height=320,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(255,255,255,0.05)",
        font_color="#c9d1d9",
        margin=dict(l=20, r=20, t=20, b=10),
        xaxis=dict(title="Port", side="bottom"),
        yaxis=dict(title="Protocol"),
    )
    st.plotly_chart(fig, width="stretch")
    if has_port_data:
        st.caption("Density scale shows flow concentration by protocol and port. Missing or low-frequency ports are grouped into `Other`.")
    else:
        st.caption("Port metadata is not available in the current live feed, so the heatmap falls back to protocol density with an `N/A` port bucket.")


def render_recent_detections(df: pd.DataFrame):
    st.markdown("#### 📋 Recent Detections (last 20)")
    if df.empty:
        st.info("No detections yet.")
        return
    col_map = {
        "timestamp": "Time", "Timestamp": "Time",
        "class_name": "Class", "Class_Name": "Class",
        "risk_level": "Risk", "Risk_Level": "Risk",
        "risk_name": "Status", "Risk_Name": "Status",
        "action": "Action", "Action": "Action",
    }
    display_cols = [c for c in col_map if c in df.columns]
    if not display_cols:
        display_cols = df.columns[:6].tolist()
    recent = df[display_cols].tail(20).iloc[::-1].rename(columns=col_map)
    st.dataframe(recent, width="stretch", hide_index=True)

# ---------------------------------------------------------------------------
# SIDEBAR — global controls (persistent across all tabs)
# ---------------------------------------------------------------------------
def render_live_attack_feed(logs_df: pd.DataFrame):
    st.markdown("#### Live Attack Feed")
    if logs_df.empty:
        st.markdown(
            """
            <div style="background: rgba(255,255,255,0.04); border: 1px dashed rgba(255,255,255,0.16); border-radius: 12px; padding: 18px;">
                <div style="font-size: 0.95rem; font-weight: 600; color: #c9d1d9; margin-bottom: 6px;">No recent alerts</div>
                <div style="font-size: 0.85rem; color: #8b949e;">The alert feed will populate automatically as attack decisions are written to the database.</div>
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
        timestamp_label = timestamp.strftime("%Y-%m-%d %H:%M:%S") if pd.notna(timestamp) else "Unknown time"
        src_ip = row.get("src_ip", "Unknown IP")
        details = str(row.get("details", "No details provided.")).strip() or "No details provided."

        st.markdown(
            f"""
            <div style="background: rgba(255,255,255,0.04); border: 1px solid rgba(255,255,255,0.08); border-radius: 14px; padding: 16px 18px; margin-bottom: 12px;">
                <div style="display: flex; justify-content: space-between; align-items: center; gap: 12px; margin-bottom: 10px;">
                    <div>
                        <div style="font-size: 0.96rem; font-weight: 700; color: #c9d1d9;">{src_ip}</div>
                        <div style="font-size: 0.78rem; color: #8b949e;">{timestamp_label}</div>
                    </div>
                    <span style="background: {style['bg']}; color: {style['fg']}; border: 1px solid {style['border']}; border-radius: 999px; padding: 4px 10px; font-size: 0.72rem; font-weight: 700; letter-spacing: 0.04em;">{action}</span>
                </div>
                <div style="font-size: 0.85rem; line-height: 1.55; color: #c9d1d9;">{details}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_logs_grid(logs_df: pd.DataFrame):
    if AgGrid is None or GridOptionsBuilder is None:
        st.warning("AgGrid dependency is missing. Install `streamlit-aggrid` to enable advanced filtering and pagination.")
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
        gb.configure_column("details", wrapText=True, autoHeight=True, flex=2, minWidth=260)
    if "src_ip" in grid_df.columns:
        gb.configure_column("src_ip", header_name="Source IP", minWidth=150)
    if "timestamp" in grid_df.columns:
        gb.configure_column("timestamp", header_name="Timestamp", sort="desc")
    if "action" in grid_df.columns:
        gb.configure_column("action", header_name="Action", minWidth=120)

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
    st.caption(f"Selected rows: {len(selected_rows)}")
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
        Paragraph("AI Network IPS Incident Report", styles["Title"]),
        Spacer(1, 12),
        Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles["BodyText"]),
        Spacer(1, 12),
    ]

    summary_data = [
        ["Metric", "Value"],
        ["Total Records", f"{total_records:,}"],
        ["Blocked", f"{blocked_count:,}"],
        ["Allowed", f"{allowed_count:,}"],
        ["Last Event", last_event],
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
    story.extend([Paragraph("Summary", styles["Heading2"]), Spacer(1, 8), summary_table, Spacer(1, 16)])

    log_columns = [col for col in ["timestamp", "src_ip", "action", "details"] if col in logs_df.columns]
    export_df = logs_df.copy()
    if "timestamp" in export_df.columns:
        export_df["timestamp"] = pd.to_datetime(export_df["timestamp"], errors="coerce").dt.strftime("%Y-%m-%d %H:%M:%S")
    export_df = export_df.fillna("")

    table_rows = [["Timestamp", "Source IP", "Action", "Details"]]
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
    story.extend([Paragraph("Incident Logs", styles["Heading2"]), Spacer(1, 8), log_table])

    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()


def render_batch_log_actions(selected_rows):
    selected_ips = get_selected_log_ips(selected_rows)
    has_selection = len(selected_ips) > 0

    st.markdown("##### Batch Actions")
    st.caption(f"Selected IPs: {len(selected_ips)}")

    if has_selection:
        preview = ", ".join(selected_ips[:5])
        if len(selected_ips) > 5:
            preview += ", ..."
        st.caption(f"Targets: {preview}")
    else:
        st.caption("Select one or more log rows to enable batch actions.")

    confirm_key = "confirm_batch_log_action"
    confirm = st.checkbox(
        "I confirm the selected IPs should be updated in the firewall.",
        key=confirm_key,
        disabled=not has_selection,
    )

    col_block, col_unblock = st.columns(2)
    with col_block:
        block_clicked = st.button(
            "Block Selected",
            key="batch_block_selected",
            disabled=not has_selection or not confirm,
            use_container_width=True,
        )
    with col_unblock:
        unblock_clicked = st.button(
            "Unblock Selected",
            key="batch_unblock_selected",
            disabled=not has_selection or not confirm,
            use_container_width=True,
        )

    if block_clicked:
        success_count = sum(1 for ip in selected_ips if block_ip(ip))
        failure_count = len(selected_ips) - success_count
        st.session_state[confirm_key] = False
        if success_count:
            st.toast(f"Blocked {success_count} IP(s).")
        if failure_count:
            st.toast(f"{failure_count} IP(s) could not be blocked.", icon="⚠️")

    if unblock_clicked:
        success_count = sum(1 for ip in selected_ips if unblock_ip(ip))
        failure_count = len(selected_ips) - success_count
        st.session_state[confirm_key] = False
        if success_count:
            st.toast(f"Unblocked {success_count} IP(s).")
        if failure_count:
            st.toast(f"{failure_count} IP(s) could not be unblocked.", icon="⚠️")


def render_firewall_viewer():
    st.markdown("##### Firewall Viewer")

    pending_toast = st.session_state.pop("firewall_viewer_toast", None)
    if pending_toast:
        st.toast(pending_toast["message"], icon=pending_toast.get("icon"))

    blocked_rules = list_blocked_ips()
    if not blocked_rules:
        st.info("No blocked IPs currently managed by the firewall helper.")
        return

    st.caption(f"Blocked IPs: {len(blocked_rules)}")
    for rule in blocked_rules:
        ip_address = rule.get("ip", "Unknown")
        direction = rule.get("direction", "In")
        cols = st.columns([3, 2, 1])
        with cols[0]:
            st.markdown(f"**{ip_address}**")
            st.caption(rule.get("rule_name", "Firewall rule"))
        with cols[1]:
            st.caption(f"Direction: {direction}")
        with cols[2]:
            if st.button("Unblock", key=f"firewall_unblock_{ip_address}", use_container_width=True):
                ok = unblock_ip(ip_address)
                if ok:
                    st.session_state["firewall_viewer_toast"] = {
                        "message": f"Unblocked {ip_address}.",
                        "icon": "✅",
                    }
                else:
                    st.session_state["firewall_viewer_toast"] = {
                        "message": f"Failed to unblock {ip_address}.",
                        "icon": "⚠️",
                    }
                st.rerun()


def render_threat_map(logs_df: pd.DataFrame):
    st.markdown("#### Threat Map")
    if logs_df.empty:
        st.info("No incident records available for Geo-IP mapping.")
        return
    if folium is None or st_folium is None:
        st.warning("Threat Map dependencies are missing. Install `folium` and `streamlit-folium` to enable the Geo-IP map.")
        return

    alert_ips = logs_df.copy()
    if "src_ip" not in alert_ips.columns:
        st.warning("Source IP data is not available in the alert log.")
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
    c1.metric("Mapped Public IPs", f"{len(geo_df):,}")
    c2.metric("Private IP Alerts", f"{len(private_alerts):,}")
    c3.metric("Lookup Failures", f"{len(lookup_errors):,}")

    if not geo_df.empty:
        map_center = [geo_df["latitude"].mean(), geo_df["longitude"].mean()]
        threat_map = folium.Map(
            location=map_center,
            zoom_start=2,
            tiles="CartoDB dark_matter",
            control_scale=True,
        )
        marker_layer = MarkerCluster(name="Threat Sources").add_to(threat_map) if MarkerCluster else threat_map

        for _, row in geo_df.iterrows():
            timestamp = row.get("timestamp")
            last_seen = timestamp.strftime("%Y-%m-%d %H:%M:%S") if pd.notna(timestamp) else "Unknown"
            popup_html = f"""
                <div style="min-width: 220px;">
                    <div style="font-weight: 700; margin-bottom: 6px;">{row['src_ip']}</div>
                    <div><strong>Location:</strong> {row.get('city') or 'Unknown city'}, {row.get('country') or 'Unknown country'}</div>
                    <div><strong>Region:</strong> {row.get('region') or row.get('continent') or 'Unknown'}</div>
                    <div><strong>ISP:</strong> {row.get('isp') or 'Unknown'}</div>
                    <div><strong>Action:</strong> {row.get('action', 'Unknown')}</div>
                    <div><strong>Last Seen:</strong> {last_seen}</div>
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
        st.info("No public IPs could be mapped yet. Private IPs are listed separately below.")

    if not private_alerts.empty:
        st.markdown("##### Private IP Alerts")
        private_display = private_alerts.reindex(columns=["src_ip", "action", "timestamp", "details"]).copy()
        private_display.columns = ["IP", "Action", "Last Seen", "Details"]
        st.dataframe(private_display, width="stretch", hide_index=True)

    if lookup_errors:
        unresolved = pd.DataFrame(lookup_errors)
        with st.expander("Geo-IP Lookup Issues"):
            st.dataframe(unresolved, width="stretch", hide_index=True)


st.sidebar.markdown('<p class="soc-header">SOC Control Panel</p>', unsafe_allow_html=True)

# 1. Status LEDs
status = get_system_status()
led_data = "🟢" if status["data_flowing"] else ("🟡" if status["csv_exists"] else "🔴")
led_tf = "🟢" if status["tensorflow"] else "🔴"
st.sidebar.markdown(f"**Data Flow:** {led_data} &nbsp;|&nbsp; **Engine:** {led_tf}")
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
    <div style="font-size: 0.8rem; color: #8b949e; margin-bottom: 5px;">THREAT LEVEL (LAST 60S)</div>
    <div style="font-size: 1.4rem; font-weight: bold; color: {threat_info['color']};">{threat_info['emoji']} {threat_info['name']}</div>
</div>
""", unsafe_allow_html=True)

# 3. Time Window
time_window = st.sidebar.selectbox("📅 Time Window", ["Last 5 min", "Last 1 hour", "Last 24h", "All Time"])
st.sidebar.markdown("---")

# 4. Live Mode
st.sidebar.subheader("🔄 Live Refresh")
live_mode = st.sidebar.toggle("⚡ Live Mode", key="live_mode")
refresh_interval = st.sidebar.slider("Interval (seconds)", 5, 60, key="refresh_interval", disabled=not live_mode)
st.sidebar.markdown("---")

# Filter dataframes for the tabs
def filter_dataframe(df: pd.DataFrame, window: str) -> pd.DataFrame:
    if df.empty or window == "All Time": return df
    c = "timestamp" if "timestamp" in df.columns else "Timestamp"
    if c not in df.columns: return df
    df[c] = pd.to_datetime(df[c], errors="coerce")
    m_ts = df[c].max()
    if pd.isna(m_ts): return df
    if window == "Last 5 min": cutoff = m_ts - pd.Timedelta(minutes=5)
    elif window == "Last 1 hour": cutoff = m_ts - pd.Timedelta(hours=1)
    elif window == "Last 24h": cutoff = m_ts - pd.Timedelta(hours=24)
    else: return df
    return df[df[c] >= cutoff].copy()

live_df = filter_dataframe(df_live_full, time_window)
logs_df = filter_dataframe(df_logs_full, time_window)

# 5. Model Status Badge
st.sidebar.subheader("🧠 Active AI Model")
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
    "Select Model",
    _model_keys,
    index=_model_keys.index(current_model) if current_model in _model_keys else 0,
    key="model_selector",
    label_visibility="collapsed",
)
if selected_model != current_model:
    try:
        with open(ACTIVE_MODEL_PATH, "w") as f:
            f.write(selected_model)  # write registry key name, not filename
    except Exception:
        pass

st.sidebar.markdown(f"""
<div style="display: flex; justify-content: space-between; align-items: center; background: rgba(255,255,255,0.05); padding: 8px 12px; border-radius: 6px; margin-top: -10px;">
    <span style="font-weight: 600; font-size: 0.9rem;">{selected_model}</span>
    <span style="color: #00CC66; font-size: 0.8rem;">● Active</span>
</div>
""", unsafe_allow_html=True)

st.sidebar.markdown("---")

# 6. IP Unblock
st.sidebar.subheader("🔓 IP Unblock")
ip_input = st.sidebar.text_input("IP Address", key="ip_unblock_input")
if st.sidebar.button("Unblock IP", key="unblock_btn"):
    if ip_input.strip():
        ok = unblock_ip(ip_input.strip())
        st.sidebar.success(f"✅ {ip_input} unblocked.") if ok else st.sidebar.warning("⚠️ Operation failed.")
    else:
        st.sidebar.warning("Enter a valid IP address.")

st.sidebar.markdown("---")
st.sidebar.caption(f"🕐 Last refresh: {datetime.now().strftime('%H:%M:%S')}")
st.sidebar.caption(f"🔁 Refresh #{count}")

# ---------------------------------------------------------------------------
# PAGE HEADER
# ---------------------------------------------------------------------------
st.markdown('<p class="soc-header"> AI Network IPS — Security Operations Center</p>', unsafe_allow_html=True)
st.markdown('<p class="soc-sub">3-Class LSTM/BiLSTM NIDS &nbsp;|&nbsp; Benign · Volumetric · Semantic &nbsp;|&nbsp; Real-time Detection</p>', unsafe_allow_html=True)
st.markdown("---")

# ---------------------------------------------------------------------------
# FIVE-TAB LAYOUT
# ---------------------------------------------------------------------------
tab_monitor, tab_map, tab_logs, tab_xai, tab_admin = st.tabs([
    "🖥️ Live Monitor",
    "🗺️ Threat Map",
    "📋 Incident Logs",
    "🧠 XAI Explainer",
    "⚙️ Admin & Response",
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

# ── Tab 2: Threat Map ──────────────────────────────────────────────────────
with tab_map:
    st.markdown("#### 🗺️ Threat Map")
    st.info("🚧 **Coming in Sprint 2** — Geographic threat heatmap with IP geolocation and attack-origin clustering.")
    col1, col2, col3 = st.columns(3)
    col1.metric("Active Threat Sources", "—")
    col2.metric("Top Attack Country", "—")
    col3.metric("Blocked IPs (24h)", "—")
    st.markdown("---")
    render_threat_map(logs_df)
    st.markdown("---")
    render_attack_distribution(live_df)
    st.markdown("---")
    render_severity_timeline(live_df, logs_df)

# ── Tab 3: Incident Logs ──────────────────────────────────────────────────
with tab_logs:
    st.markdown("#### 📋 Incident Logs")
    if logs_df.empty:
        st.info("No incident records found in the database.")
    else:
        # Quick summary metrics
        total_l   = len(logs_df)
        blocked_l = int((logs_df.get("action", pd.Series(dtype=str)) == "BLOCKED").sum())
        allowed_l = int((logs_df.get("action", pd.Series(dtype=str)) == "ALLOWED").sum())
        last_evt  = logs_df["timestamp"].max().strftime("%Y-%m-%d %H:%M:%S") if "timestamp" in logs_df.columns else "—"
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total Records", f"{total_l:,}")
        c2.metric("Blocked", f"{blocked_l:,}")
        c3.metric("Allowed", f"{allowed_l:,}")
        c4.metric("Last Event", last_evt)
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
        st.markdown("##### Export Reports")
        csv_bytes = build_logs_csv_bytes(export_df)
        pdf_bytes = build_logs_pdf_bytes(export_df, export_total, export_blocked, export_allowed, export_last)
        export_col_csv, export_col_pdf = st.columns(2)
        with export_col_csv:
            st.download_button(
                "Export CSV",
                data=csv_bytes,
                file_name=f"incident_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                use_container_width=True,
            )
        with export_col_pdf:
            if pdf_bytes is None:
                st.button(
                    "Export PDF",
                    disabled=True,
                    help="Install `reportlab` to enable PDF export.",
                    use_container_width=True,
                )
            else:
                st.download_button(
                    "Export PDF",
                    data=pdf_bytes,
                    file_name=f"incident_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                    mime="application/pdf",
                    use_container_width=True,
                )
        st.markdown("---")
        render_batch_log_actions(selected_rows)

# ── Tab 4: XAI Explainer ──────────────────────────────────────────────────
with tab_xai:
    st.markdown("#### 🧠 XAI Explainer")
    st.info("🚧 **Coming in Sprint 3** — SHAP / LIME feature-importance explanations for individual predictions, with attention heatmaps from the BiLSTM layer.")
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("**Planned visualizations:**")
        st.markdown("- SHAP waterfall charts per prediction\n- Top-N feature importance bar chart\n- Attention weight heatmap (BiLSTM)\n- Counterfactual 'what-if' sliders")
    with col2:
        st.markdown("**Supported models:**")
        for m in MODEL_MAPPING:
            st.markdown(f"- {m}")

# ── Tab 5: Admin & Response ───────────────────────────────────────────────
with tab_admin:
    st.markdown("#### ⚙️ Admin & Response")
    st.info("🚧 **Coming in Sprint 4** — Automated response rules, block/allow policy management, alert thresholds, and audit trail.")

    st.markdown("##### 🔧 Quick Actions")
    a1, a2, a3 = st.columns(3)
    with a1:
        st.markdown("**Model Management**")
        st.caption(f"Active model: `{selected_model}`")
        st.caption(f"File: `{MODEL_MAPPING[selected_model]}`")
    with a2:
        st.markdown("**System Health**")
        status_q = get_system_status()
        st.caption(f"Data flowing: {'✅ Yes' if status_q['data_flowing'] else '❌ No'}")
        st.caption(f"CSV rows: {status_q['csv_rows']:,}")
    with a3:
        st.markdown("**Response Actions**")
        st.caption("IP blocking managed via firewall_manager")
        st.caption("Use sidebar → IP Unblock for immediate relief")

    st.markdown("---")
    render_firewall_viewer()
