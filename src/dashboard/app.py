#!/usr/bin/env python3
"""
Network IPS Dashboard - SOC Edition
=====================================
Multi-tab Security Operations Center dashboard for LSTM/BiLSTM-based 3-class NIDS.
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
    from utils.firewall_manager import block_ip, list_blocked_ips, unblock_ip, check_expired_blocks
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


def _ttl_expiry_loop():
    while True:
        try:
            check_expired_blocks()
        except Exception as exc:
            print(f"TTL expiry loop error: {exc}")
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
    page_title="SOC Network IPS",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

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
# DESIGN SYSTEM CSS  (Sprint 1-5)
# ---------------------------------------------------------------------------
st.markdown("""
<style>
  /* ── Tokens ──────────────────────────────────────────────────────────── */
  :root {
    --color-bg-base:       #0a0e17;
    --color-bg-surface:    #0d1220;
    --color-bg-card:       rgba(255,255,255,0.04);
    --color-border:        rgba(255,255,255,0.08);
    --color-border-accent: rgba(88,166,255,0.25);
    --color-text-primary:  #c9d1d9;
    --color-text-muted:    #9ca5b0;
    --color-text-link:     #58a6ff;
    --color-safe:          #00CC66;
    --color-low:           #3498db;
    --color-medium:        #FFD700;
    --color-high:          #FFA500;
    --color-critical:      #FF4B4B;
    --radius-sm: 6px;  --radius-md: 12px;  --radius-lg: 16px;
    --shadow-card:  0 2px 8px rgba(0,0,0,0.4);
    --shadow-hover: 0 8px 32px rgba(88,166,255,0.12);
    --space-1:4px; --space-2:8px; --space-3:12px;
    --space-4:16px; --space-5:20px; --space-6:24px;
    --font-xs:0.72rem; --font-sm:0.82rem; --font-base:0.92rem;
    --font-lg:1.05rem; --font-xl:1.4rem; --font-2xl:1.8rem;
  }

  /* ── Base ────────────────────────────────────────────────────────────── */
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap');
  html, body, [class*="css"] { font-family: 'Inter', sans-serif; }
  [data-testid="stAppViewContainer"] { background: var(--color-bg-base); color: var(--color-text-primary); }
  [data-testid="stSidebar"]          { background: var(--color-bg-surface); border-right: 1px solid var(--color-border); }

  /* ── Typography scale ────────────────────────────────────────────────── */
  .text-xs    { font-size: var(--font-xs); }
  .text-sm    { font-size: var(--font-sm); }
  .text-base  { font-size: var(--font-base); }
  .text-lg    { font-size: var(--font-lg); }
  .text-xl    { font-size: var(--font-xl); }
  .text-2xl   { font-size: var(--font-2xl); }
  .text-muted { color: var(--color-text-muted); }
  .text-accent{ color: var(--color-text-link); }
  .text-danger{ color: var(--color-critical); }
  .text-safe  { color: var(--color-safe); }
  .fw-600     { font-weight: 600; }
  .fw-700     { font-weight: 700; }

  /* ── Chart cards ─────────────────────────────────────────────────────── */
  .chart-card {
    background: var(--color-bg-card);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-md);
    padding: var(--space-5);
    margin-bottom: var(--space-4);
    box-shadow: var(--shadow-card);
    animation: fadeIn 0.3s ease both;
  }
  .chart-card__header {
    display: flex; align-items: center; justify-content: space-between;
    margin-bottom: var(--space-3);
  }
  .chart-card__title { font-size: var(--font-base); font-weight: 600; color: var(--color-text-primary); }
  .chart-card__badge {
    background: rgba(88,166,255,0.12); color: var(--color-text-link);
    border: 1px solid var(--color-border-accent);
    border-radius: 999px; padding: 2px 10px;
    font-size: var(--font-xs); font-weight: 700; letter-spacing: 0.05em;
  }
  .chart-card__badge--live  { background: rgba(0,204,102,0.12); color: var(--color-safe); border-color: rgba(0,204,102,0.3); }
  .chart-card__badge--alert { background: rgba(255,75,75,0.14); color: var(--color-critical); border-color: rgba(255,75,75,0.3); }

  /* ── Section headers ─────────────────────────────────────────────────── */
  .section-header {
    display: flex; align-items: center; gap: var(--space-3);
    border-left: 3px solid var(--color-text-link);
    padding-left: var(--space-4);
    margin: var(--space-5) 0 var(--space-4) 0;
  }
  .section-icon  { font-size: 1.15rem; }
  .section-title { font-size: var(--font-lg); font-weight: 700; color: var(--color-text-primary); line-height: 1.2; }
  .section-sub   { font-size: var(--font-xs); color: var(--color-text-muted); margin-top: 2px; }

  /* ── KPI cards ───────────────────────────────────────────────────────── */
  .kpi-card {
    background: var(--color-bg-card);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-md);
    padding: var(--space-5) var(--space-4);
    transition: transform 0.2s, box-shadow 0.2s;
    box-shadow: var(--shadow-card);
    animation: fadeIn 0.3s ease both;
    min-height: 110px;
  }
  .kpi-card:hover { transform: translateY(-3px); box-shadow: var(--shadow-hover); }
  .kpi-card__label {
    font-size: var(--font-xs); font-weight: 700; color: var(--color-text-muted);
    letter-spacing: 0.08em; text-transform: uppercase;
    margin-bottom: var(--space-2);
    display: flex; align-items: center; gap: var(--space-2);
  }
  .kpi-card__value  { font-size: var(--font-2xl); font-weight: 700; color: var(--color-text-primary); line-height: 1.1; margin-bottom: var(--space-1); }
  .kpi-card__delta  { font-size: var(--font-sm); font-weight: 600; display: inline-flex; align-items: center; gap: 3px; }
  .kpi-card__delta--up      { color: var(--color-safe); }
  .kpi-card__delta--down    { color: var(--color-critical); }
  .kpi-card__delta--neutral { color: var(--color-text-muted); }

  /* ── Page header ─────────────────────────────────────────────────────── */
  .page-header {
    background: linear-gradient(90deg, rgba(88,166,255,0.07) 0%, transparent 70%);
    border-bottom: 1px solid var(--color-border-accent);
    border-radius: var(--radius-md) var(--radius-md) 0 0;
    padding: var(--space-5) var(--space-6);
    display: flex; justify-content: space-between; align-items: center;
    margin-bottom: var(--space-4);
    animation: fadeIn 0.4s ease both;
  }
  .page-header__brand { font-size: var(--font-2xl); font-weight: 700; color: var(--color-text-link); letter-spacing: -0.5px; }
  .page-header__sub   { font-size: var(--font-sm); color: var(--color-text-muted); margin-top: 4px; }
  .page-header__right { display: flex; align-items: center; gap: var(--space-3); text-align: right; }
  .page-header__clock { font-size: var(--font-sm); color: var(--color-text-muted); font-variant-numeric: tabular-nums; }
  .live-dot {
    display: inline-block; width: 8px; height: 8px; border-radius: 50%;
    background: var(--color-safe); box-shadow: 0 0 0 0 rgba(0,204,102,0.4);
    animation: livePulse 2s infinite;
  }

  /* ── Status bar ──────────────────────────────────────────────────────── */
  .status-bar {
    display: flex; align-items: center; flex-wrap: wrap; gap: var(--space-4);
    background: var(--color-bg-card); border: 1px solid var(--color-border);
    border-radius: var(--radius-md); padding: var(--space-3) var(--space-5);
    margin-bottom: var(--space-4);
  }
  .status-item { display: flex; align-items: center; gap: var(--space-2); font-size: var(--font-sm); color: var(--color-text-primary); white-space: nowrap; }
  .status-dot  { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
  .status-dot--ok   { background: var(--color-safe); }
  .status-dot--warn { background: var(--color-medium); }
  .status-dot--err  { background: var(--color-critical); }
  .status-divider   { width: 1px; height: 18px; background: var(--color-border); margin: 0 var(--space-2); }
  .status-stats     { margin-left: auto; font-size: var(--font-xs); color: var(--color-text-muted); display: flex; gap: var(--space-4); }

  /* ── Badges ──────────────────────────────────────────────────────────── */
  .badge     { display: inline-block; padding: 3px 10px; border-radius: 999px; font-size: var(--font-xs); font-weight: 700; letter-spacing: 0.04em; }
  .badge-ok  { background: rgba(0,204,102,0.15);  color: var(--color-safe);     border: 1px solid rgba(0,204,102,0.3); }
  .badge-warn{ background: rgba(255,215,0,0.12);  color: var(--color-medium);   border: 1px solid rgba(255,215,0,0.3); }
  .badge-err { background: rgba(255,75,75,0.14);  color: var(--color-critical); border: 1px solid rgba(255,75,75,0.3); }
  .badge-info{ background: rgba(88,166,255,0.12); color: var(--color-text-link);border: 1px solid var(--color-border-accent); }

  /* ── Alert feed cards ────────────────────────────────────────────────── */
  .alert-card {
    display: flex; background: var(--color-bg-card);
    border: 1px solid var(--color-border); border-radius: var(--radius-md);
    overflow: hidden; margin-bottom: var(--space-3);
    animation: slideIn 0.2s ease both;
    transition: box-shadow 0.2s;
  }
  .alert-card:hover { box-shadow: var(--shadow-hover); }
  .alert-card__accent { width: 4px; flex-shrink: 0; }
  .alert-card__body   { padding: var(--space-4); flex: 1; }
  .alert-card__header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: var(--space-2); }
  .alert-card__ip     { font-size: var(--font-base); font-weight: 700; color: var(--color-text-primary); }
  .alert-card__time   { font-size: var(--font-xs); color: var(--color-text-muted); margin-top: 2px; }
  .alert-card__detail { font-size: var(--font-sm); color: var(--color-text-primary); line-height: 1.55; border-top: 1px solid var(--color-border); padding-top: var(--space-2); margin-top: var(--space-2); }

  /* ── Empty states ────────────────────────────────────────────────────── */
  .empty-state {
    display: flex; flex-direction: column; align-items: center; justify-content: center;
    min-height: 160px; border: 1px dashed var(--color-border);
    border-radius: var(--radius-md); padding: var(--space-6); text-align: center;
    animation: fadeIn 0.3s ease both;
  }
  .empty-state__icon  { font-size: 2rem; margin-bottom: var(--space-3); opacity: 0.45; }
  .empty-state__title { font-size: var(--font-base); font-weight: 600; color: var(--color-text-primary); margin-bottom: var(--space-2); }
  .empty-state__desc  { font-size: var(--font-sm); color: var(--color-text-muted); max-width: 340px; line-height: 1.55; }

  /* ── Skeleton screens ────────────────────────────────────────────────── */
  .skeleton-card { background: var(--color-bg-card); border: 1px solid var(--color-border); border-radius: var(--radius-md); padding: var(--space-5); animation: fadeIn 0.3s ease both; }
  .skeleton-line {
    background: linear-gradient(90deg, rgba(255,255,255,0.04) 0%, rgba(255,255,255,0.09) 50%, rgba(255,255,255,0.04) 100%);
    background-size: 200% 100%;
    animation: shimmer 1.6s infinite;
    border-radius: var(--radius-sm); height: 14px; margin-bottom: var(--space-3);
  }

  /* ── Detection table ─────────────────────────────────────────────────── */
  .det-table { width: 100%; border-collapse: collapse; font-size: var(--font-sm); }
  .det-table th {
    text-align: left; padding: 8px 12px;
    background: rgba(255,255,255,0.05);
    color: var(--color-text-muted); font-size: var(--font-xs); font-weight: 700;
    letter-spacing: 0.05em; text-transform: uppercase;
    border-bottom: 1px solid var(--color-border);
  }
  .det-table td { padding: 7px 12px; border-bottom: 1px solid rgba(255,255,255,0.04); color: var(--color-text-primary); vertical-align: middle; }
  .det-table tr:last-child td { border-bottom: none; }
  .det-table tr:hover td { background: rgba(255,255,255,0.03); }

  /* ── Gauge card ──────────────────────────────────────────────────────── */
  .gauge-card {
    background: var(--color-bg-card); border: 1px solid var(--color-border);
    border-radius: var(--radius-md); padding: var(--space-5);
    box-shadow: var(--shadow-card); animation: fadeIn 0.3s ease both;
  }
  .gauge-card--critical { border-color: rgba(255,75,75,0.4) !important; animation: fadeIn 0.3s ease both, criticalPulse 1.5s infinite; }

  /* ── Sidebar ─────────────────────────────────────────────────────────── */
  .sidebar-section-label {
    font-size: var(--font-xs); font-weight: 700; color: var(--color-text-muted);
    letter-spacing: 0.1em; text-transform: uppercase;
    padding: var(--space-3) 0 var(--space-2) 0;
    border-bottom: 1px solid var(--color-border); margin-bottom: var(--space-3);
  }
  .threat-banner { border-radius: var(--radius-md); padding: var(--space-4); text-align: center; margin-bottom: var(--space-3); }
  .threat-banner__label  { font-size: var(--font-xs); font-weight: 700; letter-spacing: 0.1em; text-transform: uppercase; color: var(--color-text-muted); margin-bottom: var(--space-2); }
  .threat-banner__level  { font-size: var(--font-xl); font-weight: 700; line-height: 1.2; margin-bottom: var(--space-3); }
  .threat-progress-track { background: rgba(255,255,255,0.08); border-radius: 999px; height: 6px; overflow: hidden; margin-bottom: var(--space-2); }
  .threat-progress-fill  { height: 100%; border-radius: 999px; transition: width 0.6s ease; }
  .threat-banner__ts     { font-size: var(--font-xs); color: var(--color-text-muted); }
  .model-card { background: var(--color-bg-card); border: 1px solid var(--color-border); border-radius: var(--radius-md); padding: var(--space-3) var(--space-4); margin-bottom: var(--space-3); }
  .model-card__row  { display: flex; justify-content: space-between; align-items: center; margin-bottom: var(--space-1); }
  .model-card__name { font-size: var(--font-base); font-weight: 700; color: var(--color-text-primary); }
  .model-card__file { font-size: var(--font-xs); color: var(--color-text-muted); font-family: monospace; }
  .active-dot { display: inline-flex; align-items: center; gap: 5px; font-size: var(--font-xs); color: var(--color-safe); font-weight: 600; }
  .active-dot::before { content:''; display:inline-block; width:7px; height:7px; border-radius:50%; background:var(--color-safe); animation: livePulse 2s infinite; }
  .mini-stats { background: var(--color-bg-card); border: 1px solid var(--color-border); border-radius: var(--radius-md); padding: var(--space-3) var(--space-4); display: flex; justify-content: space-around; text-align: center; margin-bottom: var(--space-3); }
  .mini-stat__value { font-size: var(--font-xl); font-weight: 700; color: var(--color-text-primary); line-height: 1.1; }
  .mini-stat__label { font-size: var(--font-xs); color: var(--color-text-muted); margin-top: 2px; }

  /* ── Feature preview cards (XAI / Admin) ─────────────────────────────── */
  .feature-preview { background: rgba(255,255,255,0.02); border: 1px dashed var(--color-border); border-radius: var(--radius-md); padding: var(--space-5); opacity: 0.7; transition: opacity 0.2s; }
  .feature-preview:hover { opacity: 0.9; }
  .feature-preview__icon  { font-size: 1.6rem; margin-bottom: var(--space-3); }
  .feature-preview__title { font-size: var(--font-base); font-weight: 700; color: var(--color-text-primary); margin-bottom: var(--space-2); }
  .feature-preview__desc  { font-size: var(--font-sm); color: var(--color-text-muted); line-height: 1.55; margin-bottom: var(--space-3); }
  .feature-preview__pill  { display: inline-block; background: rgba(88,166,255,0.1); color: var(--color-text-link); border: 1px solid var(--color-border-accent); border-radius: 999px; padding: 2px 10px; font-size: var(--font-xs); font-weight: 700; }

  /* ── Tab bar ─────────────────────────────────────────────────────────── */
  div[data-testid="stTabs"] button[data-baseweb="tab"] {
    background: transparent; color: var(--color-text-muted);
    border-bottom: none !important; border-radius: var(--radius-sm);
    font-weight: 600; font-size: var(--font-sm); padding: 8px 16px;
    transition: background 0.15s, color 0.15s; opacity: 0.7;
  }
  div[data-testid="stTabs"] button[data-baseweb="tab"]:hover { background: rgba(255,255,255,0.05); color: var(--color-text-primary); opacity: 1; }
  div[data-testid="stTabs"] button[aria-selected="true"]      { background: rgba(88,166,255,0.12) !important; color: var(--color-text-link) !important; opacity: 1; }

  /* ── Plotly / DataFrame polish ───────────────────────────────────────── */
  .js-plotly-plot { border-radius: var(--radius-sm); }
  div[data-testid="stDataFrame"] { border-radius: var(--radius-sm); overflow: hidden; }
  hr { border-color: var(--color-border); }

  /* ── Animations ──────────────────────────────────────────────────────── */
  @keyframes fadeIn    { from { opacity:0; transform:translateY(6px); } to { opacity:1; transform:none; } }
  @keyframes slideIn   { from { opacity:0; transform:translateX(-8px); } to { opacity:1; transform:none; } }
  @keyframes shimmer   { 0% { background-position:-200% 0; } 100% { background-position:200% 0; } }
  @keyframes livePulse { 0% { box-shadow:0 0 0 0 rgba(0,204,102,0.5); } 70% { box-shadow:0 0 0 6px rgba(0,204,102,0); } 100% { box-shadow:0 0 0 0 rgba(0,204,102,0); } }
  @keyframes criticalPulse { 0%,100% { box-shadow:0 0 0 0 rgba(255,75,75,0.4); } 50% { box-shadow:0 0 0 12px rgba(255,75,75,0); } }

  /* ── Responsive guards ───────────────────────────────────────────────── */
  @media (max-width: 1100px) { [data-testid="column"] { min-width: 160px !important; } }
</style>
""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# UI HELPERS  (Sprint 1 & 2)
# ---------------------------------------------------------------------------

def _apply_chart_defaults(fig):
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(255,255,255,0.03)",
        font=dict(family="Inter", color="#c9d1d9", size=11),
        hoverlabel=dict(bgcolor="#1a2235", bordercolor="rgba(255,255,255,0.15)", font_color="#c9d1d9"),
        legend=dict(bgcolor="rgba(0,0,0,0)", bordercolor="rgba(0,0,0,0)"),
    )
    fig.update_xaxes(gridcolor="rgba(255,255,255,0.06)", zerolinecolor="rgba(255,255,255,0.1)")
    fig.update_yaxes(gridcolor="rgba(255,255,255,0.06)", zerolinecolor="rgba(255,255,255,0.1)")
    return fig


def section_header(title: str, subtitle: str = None, icon: str = None):
    sub_html  = f'<div class="section-sub">{subtitle}</div>' if subtitle else ""
    icon_html = f'<span class="section-icon">{icon}</span>' if icon else ""
    st.markdown(
        f'<div class="section-header">{icon_html}'
        f'<div><div class="section-title">{title}</div>{sub_html}</div></div>',
        unsafe_allow_html=True,
    )


def render_empty_state(title: str, description: str = "", icon: str = "📡"):
    st.markdown(
        f"""<div class="empty-state">
          <div class="empty-state__icon">{icon}</div>
          <div class="empty-state__title">{title}</div>
          <div class="empty-state__desc">{description}</div>
        </div>""",
        unsafe_allow_html=True,
    )


def render_skeleton(lines: int = 3):
    widths = ["40%", "70%", "55%", "80%", "45%"]
    html = "".join(
        f'<div class="skeleton-line" style="width:{widths[i % len(widths)]}"></div>'
        for i in range(lines)
    )
    st.markdown(f'<div class="skeleton-card">{html}</div>', unsafe_allow_html=True)


def kpi_card(label: str, value: str, delta: str = None, delta_dir: str = "neutral",
             accent_color: str = None, icon: str = None):
    border = f"border-left: 3px solid {accent_color};" if accent_color else ""
    icon_html = f'<span>{icon}&nbsp;</span>' if icon else ""
    arrow = "▲" if delta_dir == "up" else ("▼" if delta_dir == "down" else "")
    delta_html = (
        f'<div class="kpi-card__delta kpi-card__delta--{delta_dir}">{arrow} {delta}</div>'
        if delta else ""
    )
    st.markdown(
        f"""<div class="kpi-card" style="{border}">
          <div class="kpi-card__label">{icon_html}{label}</div>
          <div class="kpi-card__value">{value}</div>
          {delta_html}
        </div>""",
        unsafe_allow_html=True,
    )


def sidebar_section(title: str):
    st.sidebar.markdown(
        f'<div class="sidebar-section-label">{title}</div>',
        unsafe_allow_html=True,
    )


def feature_preview_card(icon: str, title: str, description: str, pill: str = "Planned"):
    st.markdown(
        f"""<div class="feature-preview">
          <div class="feature-preview__icon">{icon}</div>
          <div class="feature-preview__title">{title}</div>
          <div class="feature-preview__desc">{description}</div>
          <span class="feature-preview__pill">● {pill}</span>
        </div>""",
        unsafe_allow_html=True,
    )


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
        return {"status": "error", "ip": ip_value, "reason": payload.get("message", "Geo-IP lookup failed")}
    return {
        "status": "ok", "ip": ip_value,
        "latitude": payload.get("latitude"), "longitude": payload.get("longitude"),
        "city": payload.get("city"), "country": payload.get("country"),
        "region": payload.get("region"), "continent": payload.get("continent"),
        "isp": payload.get("connection", {}).get("isp"),
    }


# ---------------------------------------------------------------------------
# RENDER HELPERS
# ---------------------------------------------------------------------------

def render_system_status(status: dict):
    def dot(ok, warn=False):
        if ok:   return '<span class="status-dot status-dot--ok"></span>'
        if warn: return '<span class="status-dot status-dot--warn"></span>'
        return '<span class="status-dot status-dot--err"></span>'

    services = [
        (dot(status["sequence_model"]),  "LSTM/BiLSTM"),
        (dot(status["scaler"]),          "Scaler"),
        (dot(status["tensorflow"]),      "TensorFlow"),
        (dot(status["scapy"], warn=status["csv_exists"] and not status["scapy"]), "Scapy"),
        (dot(status["data_flowing"], warn=status["csv_exists"] and not status["data_flowing"]),
         f"Bridge ({status['csv_age']:.0f}s)"),
    ]
    items_html = "".join(
        f'<div class="status-item">{d}<span>{name}</span></div>'
        for d, name in services
    )
    stats_html = ""
    if status["csv_exists"]:
        stats_html = (
            f'<div class="status-stats">'
            f'<span>{status["csv_rows"]:,} rows</span>'
            f'<span>Updated {status["csv_age"]:.0f}s ago</span>'
            f'</div>'
        )
    st.markdown(
        f'<div class="status-bar">{items_html}'
        f'<div class="status-divider"></div>{stats_html}</div>',
        unsafe_allow_html=True,
    )


def render_metrics(df: pd.DataFrame):
    total = len(df)
    if df.empty:
        benign = volumetric = semantic = 0
        avg_conf = 0.0
    else:
        c = "class_name" if "class_name" in df.columns else "Class_Name"
        p = "predicted_class" if "predicted_class" in df.columns else "Predicted_Class"
        if c in df.columns:
            benign     = int((df[c] == "Benign").sum())
            volumetric = int((df[c] == "Volumetric").sum())
            semantic   = int((df[c] == "Semantic").sum())
        elif p in df.columns:
            benign, volumetric, semantic = int((df[p]==0).sum()), int((df[p]==1).sum()), int((df[p]==2).sum())
        else:
            benign, volumetric, semantic = total, 0, 0
        avg_conf = calculate_avg_confidence(df)

    def pct(n): return f"{n/total*100:.1f}%" if total else "0%"

    if df.empty:
        c1, c2, c3, c4, c5 = st.columns(5)
        for col in (c1, c2, c3, c4, c5):
            with col:
                render_skeleton(2)
        return

    c1, c2, c3, c4, c5 = st.columns(5)
    with c1:
        kpi_card("Total Flows", f"{total:,}", icon="📊", accent_color="#58a6ff")
    with c2:
        kpi_card("Benign", f"{benign:,}", delta=pct(benign), delta_dir="up", icon="🟢", accent_color="#00CC66")
    with c3:
        kpi_card("Volumetric", f"{volumetric:,}", delta=pct(volumetric),
                 delta_dir="down" if volumetric else "neutral", icon="🔴", accent_color="#FF4B4B")
    with c4:
        kpi_card("Semantic", f"{semantic:,}", delta=pct(semantic),
                 delta_dir="down" if semantic else "neutral", icon="🟠", accent_color="#FFA500")
    with c5:
        kpi_card("Avg Confidence", f"{avg_conf*100:.1f}%", icon="🎯", accent_color="#58a6ff")


def render_risk_gauge(df: pd.DataFrame):
    section_header("Current Risk Level", icon="🎯")
    if df.empty:
        render_empty_state("No risk data", "Risk level will display once traffic is detected.", "🎯")
        return

    risk_col = "risk_level" if "risk_level" in df.columns else "Risk_Level"
    if risk_col in df.columns:
        current_risk = int(df[risk_col].iloc[-1]) if not pd.isna(df[risk_col].iloc[-1]) else 1
    else:
        pred = "predicted_class" if "predicted_class" in df.columns else "Predicted_Class"
        lc = df[pred].iloc[-1] if pred in df.columns else 0
        current_risk = 1 if lc == 0 else (4 if lc == 1 else 5)
    info = RISK_LEVELS.get(current_risk, RISK_LEVELS[1])

    card_cls   = "gauge-card--critical" if current_risk == 5 else "gauge-card"
    top_border = "" if current_risk == 5 else f"border-top: 3px solid {info['color']};"
    st.markdown(f'<div class="{card_cls}" style="{top_border}">', unsafe_allow_html=True)

    fig = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=current_risk,
        title={"text": f"Risk: {info['name']}", "font": {"size": 18, "color": "#c9d1d9"}},
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
    fig.update_layout(height=220, margin=dict(l=20, r=20, t=50, b=10),
                      paper_bgcolor="rgba(0,0,0,0)", font_color="#c9d1d9")
    st.plotly_chart(fig, use_container_width=True)

    ts_col = "timestamp" if "timestamp" in df.columns else None
    last_ts = df[ts_col].max().strftime("%H:%M:%S") if (ts_col and not df.empty and not pd.isna(df[ts_col].max())) else "—"
    st.markdown(
        f'<div style="text-align:center;font-size:var(--font-xs);color:var(--color-text-muted);margin-top:-8px;">'
        f'Last updated: {last_ts}</div>',
        unsafe_allow_html=True,
    )
    st.markdown('</div>', unsafe_allow_html=True)


def render_class_distribution(df: pd.DataFrame):
    section_header("Class Distribution", subtitle="3-class NIDS breakdown", icon="📊")
    if df.empty:
        render_empty_state("Waiting for traffic data", "Class distribution will populate once flows are classified.", "📡")
        return
    col = "class_name" if "class_name" in df.columns else "Class_Name"
    if col not in df.columns:
        st.warning("Class column not found.")
        return
    counts = df[col].value_counts().reset_index()
    counts.columns = ["Class", "Count"]
    fig = px.pie(counts, values="Count", names="Class", hole=0.6,
                 color="Class", color_discrete_map=CLASS_COLORS)
    fig.update_traces(
        textposition="inside", textinfo="percent+label",
        marker=dict(line=dict(color="#0d1117", width=2)),
    )
    total = counts["Count"].sum()
    fig.add_annotation(text=f"<b>{total:,}</b><br>Total", x=0.5, y=0.5,
                       font_size=14, showarrow=False, font_color="#c9d1d9")
    _apply_chart_defaults(fig)
    fig.update_layout(
        height=300, margin=dict(l=10, r=10, t=20, b=0),
        legend=dict(orientation="h", y=-0.15, x=0.5, xanchor="center"),
    )
    st.plotly_chart(fig, use_container_width=True)


def render_attack_distribution(df: pd.DataFrame):
    section_header("Attack Distribution", subtitle="Sunburst by class and severity", icon="🎯")
    if df.empty:
        render_empty_state("No attack data", "Attack distribution will appear once threats are detected.", "🚨")
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
        render_empty_state("No attack detections yet", "Sunburst will appear once volumetric or semantic threats are classified.", "🔎")
        return

    if "risk_name" not in attack_df.columns:
        attack_df["risk_name"] = attack_df["class_name"].map({"Volumetric": "HIGH", "Semantic": "CRITICAL"})

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
    _apply_chart_defaults(fig)
    fig.update_layout(height=300, margin=dict(l=10, r=10, t=20, b=10))
    st.plotly_chart(fig, use_container_width=True)


def render_severity_timeline(live_df: pd.DataFrame, logs_df: pd.DataFrame):
    section_header("Severity Timeline", subtitle="Events per minute by severity level", icon="📈")

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
            timeline_df["risk_name"] = timeline_df["action"].astype(str).str.upper().map(
                {"BLOCKED": "CRITICAL", "ALLOWED": "HIGH"}
            ).fillna("LOW")

    if timeline_df.empty or "timestamp" not in timeline_df.columns or "risk_name" not in timeline_df.columns:
        render_empty_state("No severity events yet", "The timeline populates as events are classified.", "⏱️")
        return

    timeline_df = timeline_df.dropna(subset=["timestamp", "risk_name"]).copy()
    severity_order  = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    severity_colors = {
        "LOW": RISK_LEVELS[2]["color"], "MEDIUM": RISK_LEVELS[3]["color"],
        "HIGH": RISK_LEVELS[4]["color"], "CRITICAL": RISK_LEVELS[5]["color"],
    }
    timeline_df = timeline_df[timeline_df["risk_name"].isin(severity_order)]
    if timeline_df.empty:
        render_empty_state("No severity events yet", "The timeline populates as events are classified.", "⏱️")
        return

    timeline_series = (
        timeline_df.groupby([pd.Grouper(key="timestamp", freq="1min"), "risk_name"])
        .size().unstack(fill_value=0)
        .reindex(columns=severity_order, fill_value=0).sort_index()
    )
    if timeline_series.empty:
        render_empty_state("Not enough data for timeline", "", "⏱️")
        return

    fig = go.Figure()
    for severity in severity_order:
        fig.add_trace(go.Scatter(
            x=timeline_series.index, y=timeline_series[severity],
            mode="lines+markers", name=severity,
            line=dict(color=severity_colors[severity], width=2.2),
            marker=dict(size=6),
            hovertemplate=f"{severity}: %{{y}}<br>%{{x|%Y-%m-%d %H:%M}}<extra></extra>",
        ))
    _apply_chart_defaults(fig)
    fig.update_layout(
        height=300, margin=dict(l=10, r=10, t=20, b=10),
        legend=dict(orientation="h", y=-0.22, x=0.5, xanchor="center"),
        xaxis=dict(title=None), yaxis=dict(title="Events / min", rangemode="tozero"),
        hovermode="x unified",
    )
    st.plotly_chart(fig, use_container_width=True)


def render_stacked_time_series(df: pd.DataFrame, logs_df: pd.DataFrame):
    section_header("Detection Time Series", subtitle="Stacked class volume with confidence overlay", icon="📈")
    if df.empty:
        render_skeleton(4)
        return
    if "timestamp" not in df.columns:
        st.warning("Timestamp column not found.")
        return

    tmp = df.copy()
    tmp["timestamp"] = pd.to_datetime(tmp["timestamp"], errors="coerce")
    tmp = tmp.dropna(subset=["timestamp"])
    if tmp.empty:
        render_empty_state("Not enough data", "Time series needs at least 2 timestamped rows.", "📈")
        return

    if "class_name" not in tmp.columns and "predicted_class" in tmp.columns:
        tmp["class_name"] = tmp["predicted_class"].map(CLASS_NAMES)

    tmp = tmp.set_index("timestamp")
    series = (
        tmp.groupby([pd.Grouper(freq=BUCKET_FREQUENCY), "class_name"])
        .size().unstack(fill_value=0)
        .reindex(columns=list(CLASS_COLORS.keys()), fill_value=0).sort_index()
    )
    if series.empty:
        render_empty_state("Not enough data", "", "📈")
        return

    confidence_cols = [c for c in tmp.columns if "prob" in c.lower()]
    if confidence_cols:
        confidence = (
            tmp[confidence_cols].apply(pd.to_numeric, errors="coerce")
            .max(axis=1).resample(BUCKET_FREQUENCY).mean().fillna(0.0) * 100
        )
    elif "confidence_score" in tmp.columns:
        confidence = (
            pd.to_numeric(tmp["confidence_score"], errors="coerce")
            .resample(BUCKET_FREQUENCY).mean().fillna(0.0) * 100
        )
    else:
        confidence = pd.Series(0.0, index=series.index)

    fig = go.Figure()
    for class_name, color in CLASS_COLORS.items():
        fig.add_trace(go.Scatter(
            x=series.index, y=series[class_name],
            mode="lines", name=class_name, stackgroup="traffic",
            line=dict(color=color, width=1.4),
            hovertemplate=f"{class_name}: %{{y}}<br>%{{x|%H:%M:%S}}<extra></extra>",
        ))

    fig.add_trace(go.Scatter(
        x=confidence.index, y=confidence.values,
        mode="lines", name="Avg Confidence", yaxis="y2",
        line=dict(color="#58A6FF", width=2),
        hovertemplate="Avg confidence: %{y:.1f}%<br>%{x|%H:%M:%S}<extra></extra>",
    ))

    threshold_value = load_model_threshold() * 100
    fig.add_trace(go.Scatter(
        x=[series.index.min(), series.index.max()],
        y=[threshold_value, threshold_value],
        mode="lines", name=f"Threshold ({threshold_value:.1f}%)", yaxis="y2",
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
            blocked_events.set_index("timestamp").resample(BUCKET_FREQUENCY)
            .size().rename("blocked_count")
        )
        blocked_counts = blocked_counts[blocked_counts > 0]
        if not blocked_counts.empty:
            total_flows = series.sum(axis=1).reindex(blocked_counts.index, fill_value=0)
            marker_y    = total_flows + blocked_counts.clip(lower=1)
            marker_text = [f"Block x{int(c)}" for c in blocked_counts] if len(blocked_counts) <= 8 else None
            fig.add_trace(go.Scatter(
                x=blocked_counts.index, y=marker_y,
                mode="markers+text" if marker_text else "markers",
                name="Blocked", text=marker_text, textposition="top center",
                marker=dict(color="#FF7B72", size=12, symbol="diamond",
                            line=dict(color="#0d1117", width=1.5)),
                customdata=blocked_counts.astype(int),
                hovertemplate="Blocked events: %{customdata}<br>%{x|%H:%M:%S}<extra></extra>",
            ))

    _apply_chart_defaults(fig)
    fig.update_layout(
        height=300, hovermode="x unified",
        legend=dict(orientation="h", y=-0.25, x=0.5, xanchor="center"),
        margin=dict(l=10, r=10, t=20, b=10),
        xaxis=dict(title=None),
        yaxis=dict(title="Flows / 10s", rangemode="tozero"),
        yaxis2=dict(
            title="Confidence (%)", overlaying="y", side="right",
            range=[0, 100], showgrid=False,
        ),
    )
    st.plotly_chart(fig, use_container_width=True)
    st.caption("10-second buckets · stacked class volume · live confidence threshold · block markers")


def render_confidence_histogram(df: pd.DataFrame):
    section_header("Confidence Distribution", subtitle="Prediction score spread", icon="📊")
    if df.empty:
        render_skeleton(3)
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
        render_empty_state("Not enough data", "Need at least 5 classified flows.", "📊")
        return
    fig = px.histogram(max_probs * 100, nbins=20,
                       labels={"value": "Confidence (%)", "count": "Frequency"},
                       color_discrete_sequence=["#58a6ff"])
    mean_c = max_probs.mean() * 100
    fig.add_vline(x=mean_c, line_dash="dash", line_color="#ff7b72",
                  annotation_text=f"Mean: {mean_c:.1f}%", annotation_font_color="#ff7b72")
    _apply_chart_defaults(fig)
    fig.update_layout(
        height=260, showlegend=False,
        margin=dict(l=10, r=10, t=20, b=0),
        xaxis=dict(title="Confidence (%)"),
        yaxis=dict(title="Frequency"),
    )
    st.plotly_chart(fig, use_container_width=True)


def render_protocol_port_heatmap(df: pd.DataFrame):
    section_header("Protocol / Port Heatmap", subtitle="Flow density by protocol and destination port", icon="🔥")
    if df.empty:
        render_empty_state("No traffic data", "Heatmap will populate once flows are captured.", "🔥")
        return

    protocol_col = find_first_present_column(df, ["protocol", "Protocol"])
    dst_port_col = find_first_present_column(df, ["dst_port", "Dst Port", "Destination Port", "Dest Port"])
    src_port_col = find_first_present_column(df, ["src_port", "Src Port", "Source Port"])
    port_col = dst_port_col or src_port_col

    working = df.copy()
    working["protocol_label"] = working[protocol_col].apply(format_protocol_label) if protocol_col else "Unknown"

    has_port_data = port_col is not None
    if has_port_data:
        ports = pd.to_numeric(working[port_col], errors="coerce")
        valid_ports = ports.where(ports.between(0, 65535))
        top_ports = valid_ports.dropna().astype(int).value_counts().head(12).index.tolist()
        if top_ports:
            working["port_label"] = valid_ports.apply(
                lambda v: str(int(v)) if pd.notna(v) and int(v) in top_ports else "Other"
            )
        else:
            working["port_label"] = "N/A"
            has_port_data = False
    else:
        working["port_label"] = "N/A"

    heatmap_df = working.groupby(["protocol_label", "port_label"]).size().reset_index(name="flow_count")
    if heatmap_df.empty:
        render_empty_state("Not enough data for heatmap", "", "🔥")
        return

    protocol_order = (
        heatmap_df.groupby("protocol_label")["flow_count"].sum()
        .sort_values(ascending=False).index.tolist()
    )
    port_order = ([str(p) for p in top_ports] + (["Other"] if "Other" in heatmap_df["port_label"].values else [])
                  if has_port_data else ["N/A"])

    pivot = (
        heatmap_df.pivot(index="protocol_label", columns="port_label", values="flow_count")
        .reindex(index=protocol_order, columns=port_order, fill_value=0).fillna(0)
    )

    fig = go.Figure(data=go.Heatmap(
        z=pivot.values, x=pivot.columns.tolist(), y=pivot.index.tolist(),
        colorscale=[
            [0.0, "#0b1220"], [0.2, "#123b5a"],
            [0.45, "#1f8a70"], [0.7, "#f4b942"], [1.0, "#ff5d5d"],
        ],
        colorbar=dict(title="Flows"),
        hovertemplate="Protocol: %{y}<br>Port: %{x}<br>Flows: %{z}<extra></extra>",
    ))
    _apply_chart_defaults(fig)
    fig.update_layout(
        height=300, margin=dict(l=10, r=10, t=20, b=10),
        xaxis=dict(title="Port", side="bottom"),
        yaxis=dict(title="Protocol"),
    )
    st.plotly_chart(fig, use_container_width=True)
    if has_port_data:
        st.caption("Density scale shows flow concentration by protocol and port. Low-frequency ports are grouped into `Other`.")
    else:
        st.caption("Port metadata unavailable — heatmap falls back to protocol density with an `N/A` port bucket.")


def render_recent_detections(df: pd.DataFrame):
    section_header("Recent Detections", subtitle="Last 20 classified flows", icon="📋")
    if df.empty:
        render_empty_state("No detections yet", "Flows will appear here once the live bridge starts sending data.", "📋")
        return

    col_map = {
        "timestamp": "Time", "Timestamp": "Time",
        "class_name": "Class", "Class_Name": "Class",
        "risk_level": "Risk", "Risk_Level": "Risk",
        "risk_name": "Status", "Risk_Name": "Status",
        "action": "Action", "Action": "Action",
    }
    display_cols = [c for c in col_map if c in df.columns] or df.columns[:6].tolist()
    recent = df[display_cols].tail(20).iloc[::-1].rename(columns=col_map)

    row_bg_map = {"Volumetric": "rgba(255,75,75,0.06)", "Semantic": "rgba(255,165,0,0.08)"}
    badge_map  = {
        "BLOCKED": "badge-err", "ALLOWED": "badge-warn", "NORMAL": "badge-ok",
        "Benign": "badge-ok", "Volumetric": "badge-err", "Semantic": "badge-warn",
        "SAFE": "badge-ok", "HIGH": "badge-warn", "CRITICAL": "badge-err",
    }

    headers_html = "".join(f"<th>{col}</th>" for col in recent.columns)
    rows_html = ""
    for _, row in recent.iterrows():
        bg = ""
        if "Class" in row.index:
            bg = f'style="background:{row_bg_map.get(str(row.get("Class", "")), "")}"'
        cells = ""
        for col_name, val in row.items():
            if pd.isna(val):
                cell = "—"
            elif col_name in ("Action", "Class", "Status"):
                cls = badge_map.get(str(val), "")
                cell = f'<span class="badge {cls}">{val}</span>' if cls else str(val)
            elif col_name == "Time" and hasattr(val, "strftime"):
                cell = val.strftime("%H:%M:%S")
            else:
                cell = str(val)
            cells += f"<td>{cell}</td>"
        rows_html += f"<tr {bg}>{cells}</tr>"

    st.markdown(
        f'<div class="chart-card" style="padding:0;overflow:hidden;">'
        f'<table class="det-table"><thead><tr>{headers_html}</tr></thead>'
        f'<tbody>{rows_html}</tbody></table></div>',
        unsafe_allow_html=True,
    )


def render_live_attack_feed(logs_df: pd.DataFrame):
    section_header("Live Attack Feed", subtitle="Most recent 10 security events", icon="⚡")
    if logs_df.empty:
        render_empty_state(
            "No recent alerts",
            "The alert feed will populate automatically as attack decisions are written to the database.",
            "🛡️",
        )
        return

    recent_alerts = logs_df.copy()
    if "timestamp" in recent_alerts.columns:
        recent_alerts["timestamp"] = pd.to_datetime(recent_alerts["timestamp"], errors="coerce")
        recent_alerts = recent_alerts.sort_values("timestamp", ascending=False)
    recent_alerts = recent_alerts.head(10)

    accent_map = {"BLOCKED": "#FF4B4B", "ALLOWED": "#FFD700", "NORMAL": "#00CC66"}
    badge_map  = {"BLOCKED": "badge-err", "ALLOWED": "badge-warn", "NORMAL": "badge-ok"}

    for _, row in recent_alerts.iterrows():
        action    = str(row.get("action", "UNKNOWN")).upper()
        accent    = accent_map.get(action, "#58a6ff")
        badge_cls = badge_map.get(action, "badge-info")
        timestamp = row.get("timestamp")
        ts_label  = timestamp.strftime("%Y-%m-%d %H:%M:%S") if pd.notna(timestamp) else "Unknown time"
        src_ip    = row.get("src_ip", "Unknown IP")
        details   = str(row.get("details", "No details provided.")).strip() or "No details provided."

        st.markdown(
            f"""<div class="alert-card">
              <div class="alert-card__accent" style="background:{accent};"></div>
              <div class="alert-card__body">
                <div class="alert-card__header">
                  <div>
                    <div class="alert-card__ip">{src_ip}</div>
                    <div class="alert-card__time">{ts_label}</div>
                  </div>
                  <span class="badge {badge_cls}">{action}</span>
                </div>
                <div class="alert-card__detail">{details}</div>
              </div>
            </div>""",
            unsafe_allow_html=True,
        )


def render_logs_grid(logs_df: pd.DataFrame):
    if AgGrid is None or GridOptionsBuilder is None:
        st.warning("AgGrid dependency is missing. Install `streamlit-aggrid` to enable advanced filtering and pagination.")
        st.dataframe(logs_df, use_container_width=True, hide_index=True)
        return {"selected_rows": [], "filtered_df": logs_df.copy()}

    grid_df = logs_df.copy()
    if "timestamp" in grid_df.columns:
        grid_df["timestamp"] = pd.to_datetime(grid_df["timestamp"], errors="coerce")
        grid_df["timestamp"] = grid_df["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")

    gb = GridOptionsBuilder.from_dataframe(grid_df)
    gb.configure_default_column(filter=True, sortable=True, resizable=True, floatingFilter=True, min_column_width=120)
    gb.configure_selection(selection_mode="multiple", use_checkbox=True,
                           groupSelectsChildren=False, groupSelectsFiltered=True)
    gb.configure_pagination(enabled=True, paginationAutoPageSize=False, paginationPageSize=10)
    if "details" in grid_df.columns:
        gb.configure_column("details", wrapText=True, autoHeight=True, flex=2, minWidth=260)
    if "src_ip" in grid_df.columns:
        gb.configure_column("src_ip", header_name="Source IP", minWidth=150)
    if "timestamp" in grid_df.columns:
        gb.configure_column("timestamp", header_name="Timestamp", sort="desc")
    if "action" in grid_df.columns:
        gb.configure_column("action", header_name="Action", minWidth=120)

    grid_options  = gb.build()
    grid_response = AgGrid(
        grid_df, gridOptions=grid_options,
        data_return_mode=DataReturnMode.FILTERED_AND_SORTED,
        update_mode=GridUpdateMode.SELECTION_CHANGED | GridUpdateMode.FILTERING_CHANGED,
        fit_columns_on_grid_load=False, allow_unsafe_jscode=False,
        enable_enterprise_modules=False, theme="balham-dark",
        height=420, width="100%", reload_data=False,
    )
    selected_rows = grid_response.get("selected_rows", [])
    filtered_df   = pd.DataFrame(grid_response.get("data", grid_df.to_dict("records")))
    st.caption(f"Selected rows: {len(selected_rows)}")
    return {"selected_rows": selected_rows, "filtered_df": filtered_df}


def get_selected_log_ips(selected_rows) -> list[str]:
    if not selected_rows:
        return []
    selected_df = pd.DataFrame(selected_rows)
    if selected_df.empty or "src_ip" not in selected_df.columns:
        return []
    return (
        selected_df["src_ip"].astype(str).str.strip()
        .replace("", pd.NA).dropna().drop_duplicates().tolist()
    )


def build_logs_csv_bytes(logs_df: pd.DataFrame) -> bytes:
    return logs_df.copy().to_csv(index=False).encode("utf-8")


def build_logs_pdf_bytes(logs_df: pd.DataFrame, total_records: int, blocked_count: int,
                         allowed_count: int, last_event: str) -> bytes | None:
    if SimpleDocTemplate is None:
        return None
    buffer = BytesIO()
    doc    = SimpleDocTemplate(buffer, pagesize=A4, leftMargin=28, rightMargin=28, topMargin=28, bottomMargin=28)
    styles = getSampleStyleSheet()
    story  = [
        Paragraph("AI Network IPS Incident Report", styles["Title"]),
        Spacer(1, 12),
        Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles["BodyText"]),
        Spacer(1, 12),
    ]
    summary_data  = [["Metric", "Value"], ["Total Records", f"{total_records:,}"],
                     ["Blocked", f"{blocked_count:,}"], ["Allowed", f"{allowed_count:,}"], ["Last Event", last_event]]
    summary_table = Table(summary_data, colWidths=[150, 300])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2a44")),
        ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
        ("GRID",       (0, 0), (-1, -1), 0.5, colors.HexColor("#8b949e")),
        ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f4f6fa")),
        ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
        ("PADDING",    (0, 0), (-1, -1), 6),
    ]))
    story.extend([Paragraph("Summary", styles["Heading2"]), Spacer(1, 8), summary_table, Spacer(1, 16)])

    export_df = logs_df.copy()
    if "timestamp" in export_df.columns:
        export_df["timestamp"] = pd.to_datetime(export_df["timestamp"], errors="coerce").dt.strftime("%Y-%m-%d %H:%M:%S")
    export_df = export_df.fillna("")

    table_rows = [["Timestamp", "Source IP", "Action", "Details"]]
    for _, row in export_df.head(50).iterrows():
        table_rows.append([
            str(row.get("timestamp", "")), str(row.get("src_ip", "")),
            str(row.get("action", "")),    str(row.get("details", ""))[:140],
        ])
    log_table = Table(table_rows, colWidths=[110, 95, 70, 245], repeatRows=1)
    log_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#22304d")),
        ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
        ("GRID",       (0, 0), (-1, -1), 0.5, colors.HexColor("#9aa4b2")),
        ("BACKGROUND", (0, 1), (-1, -1), colors.white),
        ("VALIGN",     (0, 0), (-1, -1), "TOP"),
        ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",   (0, 0), (-1, -1), 8),
        ("LEADING",    (0, 1), (-1, -1), 10),
        ("PADDING",    (0, 0), (-1, -1), 4),
    ]))
    story.extend([Paragraph("Incident Logs", styles["Heading2"]), Spacer(1, 8), log_table])
    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()


def render_batch_log_actions(selected_rows):
    selected_ips = get_selected_log_ips(selected_rows)
    has_selection = len(selected_ips) > 0

    section_header("Batch Actions", icon="⚡")
    st.caption(f"Selected IPs: {len(selected_ips)}")
    if has_selection:
        preview = ", ".join(selected_ips[:5]) + (", …" if len(selected_ips) > 5 else "")
        st.caption(f"Targets: {preview}")
    else:
        st.caption("Select one or more log rows to enable batch actions.")

    confirm_key = "confirm_batch_log_action"
    confirm = st.checkbox(
        "I confirm the selected IPs should be updated in the firewall.",
        key=confirm_key, disabled=not has_selection,
    )
    col_block, col_unblock = st.columns(2)
    with col_block:
        block_clicked = st.button("Block Selected", key="batch_block_selected",
                                  disabled=not has_selection or not confirm, use_container_width=True)
    with col_unblock:
        unblock_clicked = st.button("Unblock Selected", key="batch_unblock_selected",
                                    disabled=not has_selection or not confirm, use_container_width=True)

    if block_clicked:
        success_count = sum(1 for ip in selected_ips if block_ip(ip))
        failure_count = len(selected_ips) - success_count
        st.session_state[confirm_key] = False
        if success_count: st.toast(f"Blocked {success_count} IP(s).")
        if failure_count: st.toast(f"{failure_count} IP(s) could not be blocked.", icon="⚠️")

    if unblock_clicked:
        success_count = sum(1 for ip in selected_ips if unblock_ip(ip))
        failure_count = len(selected_ips) - success_count
        st.session_state[confirm_key] = False
        if success_count: st.toast(f"Unblocked {success_count} IP(s).")
        if failure_count: st.toast(f"{failure_count} IP(s) could not be unblocked.", icon="⚠️")


def render_firewall_viewer():
    section_header("Firewall Viewer", subtitle="Currently blocked IPs", icon="🔒")
    pending_toast = st.session_state.pop("firewall_viewer_toast", None)
    if pending_toast:
        st.toast(pending_toast["message"], icon=pending_toast.get("icon"))

    blocked_rules = list_blocked_ips()
    if not blocked_rules:
        render_empty_state("No blocked IPs", "Blocked IPs will appear here once firewall rules are applied.", "🔓")
        return

    st.caption(f"Blocked IPs: {len(blocked_rules)}")
    for rule in blocked_rules:
        ip_address = rule.get("ip", "Unknown")
        direction  = rule.get("direction", "In")
        cols = st.columns([3, 2, 1])
        with cols[0]:
            st.markdown(f"**{ip_address}**")
            st.caption(rule.get("rule_name", "Firewall rule"))
        with cols[1]:
            st.caption(f"Direction: {direction}")
        with cols[2]:
            if st.button("Unblock", key=f"firewall_unblock_{ip_address}", use_container_width=True):
                ok = unblock_ip(ip_address)
                st.session_state["firewall_viewer_toast"] = {
                    "message": f"Unblocked {ip_address}." if ok else f"Failed to unblock {ip_address}.",
                    "icon": "✅" if ok else "⚠️",
                }
                st.rerun()


def render_threat_map(logs_df: pd.DataFrame):
    section_header("Threat Map", subtitle="Geo-IP origin of attack sources", icon="🗺️")
    if logs_df.empty:
        render_empty_state("No incident records", "Geo-IP mapping will appear once alerts are logged.", "🌍")
        return
    if folium is None or st_folium is None:
        st.warning("Threat Map dependencies missing. Install `folium` and `streamlit-folium`.")
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
    public_alerts  = unique_ips[~unique_ips["src_ip"].apply(is_private_ip)].copy()

    geocoded_rows, lookup_errors = [], []
    for _, row in public_alerts.iterrows():
        geo = lookup_geo_ip(row["src_ip"])
        if geo.get("status") == "ok" and geo.get("latitude") is not None:
            geocoded_rows.append({**row.to_dict(), **geo})
        elif geo.get("status") != "private":
            lookup_errors.append({"src_ip": row["src_ip"], "reason": geo.get("reason", "Unknown error")})

    geo_df = pd.DataFrame(geocoded_rows)

    c1, c2, c3 = st.columns(3)
    c1.metric("Mapped Public IPs",  f"{len(geo_df):,}")
    c2.metric("Private IP Alerts",  f"{len(private_alerts):,}")
    c3.metric("Lookup Failures",    f"{len(lookup_errors):,}")

    if not geo_df.empty:
        threat_map    = folium.Map(location=[geo_df["latitude"].mean(), geo_df["longitude"].mean()],
                                   zoom_start=2, tiles="CartoDB dark_matter", control_scale=True)
        marker_layer  = MarkerCluster(name="Threat Sources").add_to(threat_map) if MarkerCluster else threat_map
        for _, row in geo_df.iterrows():
            timestamp = row.get("timestamp")
            last_seen = timestamp.strftime("%Y-%m-%d %H:%M:%S") if pd.notna(timestamp) else "Unknown"
            popup_html = f"""
                <div style="min-width:220px;">
                  <div style="font-weight:700;margin-bottom:6px;">{row['src_ip']}</div>
                  <div><strong>Location:</strong> {row.get('city') or 'Unknown'}, {row.get('country') or 'Unknown'}</div>
                  <div><strong>Region:</strong> {row.get('region') or row.get('continent') or 'Unknown'}</div>
                  <div><strong>ISP:</strong> {row.get('isp') or 'Unknown'}</div>
                  <div><strong>Action:</strong> {row.get('action', 'Unknown')}</div>
                  <div><strong>Last Seen:</strong> {last_seen}</div>
                </div>"""
            folium.CircleMarker(
                location=[row["latitude"], row["longitude"]],
                radius=7,
                color="#ff7b72" if str(row.get("action", "")).upper() == "BLOCKED" else "#ffd166",
                fill=True, fill_opacity=0.85, weight=2,
                popup=folium.Popup(popup_html, max_width=320),
                tooltip=row["src_ip"],
            ).add_to(marker_layer)
        st_folium(threat_map, use_container_width=True, height=460, returned_objects=[])
    else:
        render_empty_state("No public IPs mapped yet", "Private IPs are listed separately below.", "🌍")

    if not private_alerts.empty:
        section_header("Private IP Alerts", icon="🔒")
        private_display = private_alerts.reindex(columns=["src_ip", "action", "timestamp", "details"]).copy()
        private_display.columns = ["IP", "Action", "Last Seen", "Details"]
        st.dataframe(private_display, use_container_width=True, hide_index=True)

    if lookup_errors:
        with st.expander("Geo-IP Lookup Issues"):
            st.dataframe(pd.DataFrame(lookup_errors), use_container_width=True, hide_index=True)


# ---------------------------------------------------------------------------
# SIDEBAR
# ---------------------------------------------------------------------------
st.sidebar.markdown(
    '<div style="font-size:1.15rem;font-weight:700;color:#58a6ff;margin-bottom:var(--space-3);">🛡️ SOC Control Panel</div>',
    unsafe_allow_html=True,
)

status = get_system_status()
led_data = "🟢" if status["data_flowing"] else ("🟡" if status["csv_exists"] else "🔴")
led_tf   = "🟢" if status["tensorflow"] else "🔴"
st.sidebar.markdown(
    f'<div style="font-size:var(--font-sm);color:var(--color-text-muted);margin-bottom:var(--space-3);">'
    f'Data {led_data} &nbsp;·&nbsp; Engine {led_tf}</div>',
    unsafe_allow_html=True,
)

# Pre-load data
df_live_full = load_live_traffic()
df_logs_full = load_logs()

# Threat Level Banner
threat_info      = RISK_LEVELS[1]
current_risk_val = 1
if not df_live_full.empty:
    _ts_col = "timestamp" if "timestamp" in df_live_full.columns else None
    if _ts_col:
        df_live_full[_ts_col] = pd.to_datetime(df_live_full[_ts_col], errors="coerce")
        _max_ts = df_live_full[_ts_col].max()
        if not pd.isna(_max_ts):
            _last_60s = df_live_full[df_live_full[_ts_col] >= (_max_ts - pd.Timedelta(seconds=60))]
            if not _last_60s.empty:
                _risk_col = "risk_level" if "risk_level" in _last_60s.columns else "Risk_Level"
                if _risk_col in _last_60s.columns:
                    current_risk_val = int(_last_60s[_risk_col].max())
                else:
                    _pred = "predicted_class" if "predicted_class" in _last_60s.columns else "Predicted_Class"
                    _max_c = int(_last_60s[_pred].max()) if _pred in _last_60s.columns else 0
                    current_risk_val = 1 if _max_c == 0 else (4 if _max_c == 1 else 5)
                threat_info = RISK_LEVELS.get(current_risk_val, RISK_LEVELS[1])

_progress_pct  = int((current_risk_val - 1) / 4 * 100)
_now_str       = datetime.now().strftime("%H:%M:%S")
_pulse_style   = "animation: criticalPulse 1.5s infinite;" if current_risk_val == 5 else ""
st.sidebar.markdown(f"""
<div class="threat-banner" style="background:{threat_info['color']}12; border:1px solid {threat_info['color']}40; {_pulse_style}">
  <div class="threat-banner__label">Threat Level — Last 60s</div>
  <div class="threat-banner__level" style="color:{threat_info['color']};">{threat_info['emoji']} {threat_info['name']}</div>
  <div class="threat-progress-track">
    <div class="threat-progress-fill" style="width:{_progress_pct}%; background:{threat_info['color']};"></div>
  </div>
  <div class="threat-banner__ts">checked {_now_str}</div>
</div>
""", unsafe_allow_html=True)

# Mini stats — last 60s
sidebar_section("LAST 60 SECONDS")
_total_60 = _attacks_60 = _blocks_60 = 0
if not df_live_full.empty and _ts_col and not pd.isna(_max_ts):
    _l60 = df_live_full[df_live_full[_ts_col] >= (_max_ts - pd.Timedelta(seconds=60))]
    _total_60 = len(_l60)
    _cn = "class_name" if "class_name" in _l60.columns else None
    if _cn:
        _attacks_60 = int((_l60[_cn] != "Benign").sum())
    if "action" in _l60.columns:
        _blocks_60 = int((_l60["action"].astype(str).str.upper() == "BLOCKED").sum())
    elif not df_logs_full.empty and "action" in df_logs_full.columns and "timestamp" in df_logs_full.columns:
        _lts = pd.to_datetime(df_logs_full["timestamp"], errors="coerce")
        _blocks_60 = int(
            df_logs_full[_lts >= (_max_ts - pd.Timedelta(seconds=60))]["action"]
            .astype(str).str.upper().eq("BLOCKED").sum()
        )

_atk_color = "var(--color-critical)" if _attacks_60 > 0 else "inherit"
_blk_color = "var(--color-critical)" if _blocks_60  > 0 else "inherit"
st.sidebar.markdown(f"""
<div class="mini-stats">
  <div><div class="mini-stat__value">{_total_60:,}</div><div class="mini-stat__label">Flows</div></div>
  <div><div class="mini-stat__value" style="color:{_atk_color};">{_attacks_60:,}</div><div class="mini-stat__label">Attacks</div></div>
  <div><div class="mini-stat__value" style="color:{_blk_color};">{_blocks_60:,}</div><div class="mini-stat__label">Blocks</div></div>
</div>
""", unsafe_allow_html=True)

# Data source
sidebar_section("DATA SOURCE")
time_window = st.sidebar.selectbox(
    "Time Window", ["Last 5 min", "Last 1 hour", "Last 24h", "All Time"],
    label_visibility="collapsed",
)

# Live mode
sidebar_section("LIVE MODE")
live_mode        = st.sidebar.toggle("⚡ Live Mode", key="live_mode")
refresh_interval = st.sidebar.slider("Interval (seconds)", 5, 60, key="refresh_interval", disabled=not live_mode)


def filter_dataframe(df: pd.DataFrame, window: str) -> pd.DataFrame:
    if df.empty or window == "All Time":
        return df
    c = "timestamp" if "timestamp" in df.columns else "Timestamp"
    if c not in df.columns:
        return df
    df[c] = pd.to_datetime(df[c], errors="coerce")
    m_ts = df[c].max()
    if pd.isna(m_ts):
        return df
    cutoffs = {"Last 5 min": pd.Timedelta(minutes=5), "Last 1 hour": pd.Timedelta(hours=1), "Last 24h": pd.Timedelta(hours=24)}
    if window not in cutoffs:
        return df
    return df[df[c] >= (m_ts - cutoffs[window])].copy()


live_df = filter_dataframe(df_live_full, time_window)
logs_df = filter_dataframe(df_logs_full, time_window)

# AI engine
sidebar_section("AI ENGINE")
os.makedirs(os.path.dirname(ACTIVE_MODEL_PATH), exist_ok=True)
_default_model_key = "Random Forest"
try:
    if os.path.exists(ACTIVE_MODEL_PATH):
        with open(ACTIVE_MODEL_PATH) as f:
            _stored = f.read().strip()
        current_model = _stored if _stored in MODEL_MAPPING else next(
            (k for k, v in MODEL_MAPPING.items() if v == _stored), _default_model_key
        )
    else:
        current_model = _default_model_key
        with open(ACTIVE_MODEL_PATH, "w") as f:
            f.write(_default_model_key)
except Exception:
    current_model = _default_model_key

_model_keys    = list(MODEL_MAPPING.keys())
selected_model = st.sidebar.selectbox(
    "Select Model", _model_keys,
    index=_model_keys.index(current_model) if current_model in _model_keys else 0,
    key="model_selector", label_visibility="collapsed",
)
if selected_model != current_model:
    try:
        with open(ACTIVE_MODEL_PATH, "w") as f:
            f.write(selected_model)
    except Exception:
        pass

st.sidebar.markdown(f"""
<div class="model-card">
  <div class="model-card__row">
    <span class="model-card__name">{selected_model}</span>
    <span class="active-dot">Active</span>
  </div>
  <div class="model-card__file">{MODEL_MAPPING[selected_model]}</div>
</div>
""", unsafe_allow_html=True)

# Firewall
sidebar_section("FIREWALL")
ip_input = st.sidebar.text_input("IP Address", placeholder="e.g. 192.168.1.1", key="ip_unblock_input")
_col_blk, _col_ublk = st.sidebar.columns(2)
with _col_blk:
    if st.button("Block", key="block_btn", use_container_width=True):
        if ip_input.strip():
            ok = block_ip(ip_input.strip())
            st.sidebar.success(f"✅ {ip_input} blocked.") if ok else st.sidebar.warning("⚠️ Operation failed.")
        else:
            st.sidebar.warning("Enter a valid IP.")
with _col_ublk:
    if st.button("Unblock", key="unblock_btn", use_container_width=True):
        if ip_input.strip():
            ok = unblock_ip(ip_input.strip())
            st.sidebar.success(f"✅ {ip_input} unblocked.") if ok else st.sidebar.warning("⚠️ Operation failed.")
        else:
            st.sidebar.warning("Enter a valid IP.")

st.sidebar.markdown("---")
st.sidebar.caption(f"🕐 {datetime.now().strftime('%H:%M:%S')}  ·  Refresh #{count}")

# ---------------------------------------------------------------------------
# PAGE HEADER
# ---------------------------------------------------------------------------
_clock_str  = datetime.now().strftime("%H:%M:%S UTC")
_live_label = "LIVE" if st.session_state.live_mode else "PAUSED"
st.markdown(f"""
<div class="page-header">
  <div>
    <div class="page-header__brand">🛡️ AI Network IPS</div>
    <div class="page-header__sub">SOC &nbsp;·&nbsp; 3-Class LSTM/BiLSTM NIDS &nbsp;·&nbsp; Benign · Volumetric · Semantic</div>
  </div>
  <div class="page-header__right">
    <span class="live-dot"></span>
    <div>
      <div class="page-header__clock">{_clock_str}</div>
      <div style="font-size:var(--font-xs);font-weight:700;color:var(--color-safe);text-align:right;">{_live_label}</div>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)

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
    render_metrics(live_df)

    col_gauge, col_dist = st.columns([1, 2])
    with col_gauge:
        render_risk_gauge(live_df)
    with col_dist:
        render_class_distribution(live_df)

    col_conf, col_time = st.columns(2)
    with col_conf:
        render_confidence_histogram(live_df)
    with col_time:
        render_stacked_time_series(live_df, logs_df)

    render_protocol_port_heatmap(live_df)
    render_live_attack_feed(logs_df)
    render_recent_detections(live_df)

# ── Tab 2: Threat Map ──────────────────────────────────────────────────────
with tab_map:
    col1, col2, col3 = st.columns(3)
    col1.metric("Active Threat Sources", f"{len(logs_df['src_ip'].dropna().unique()):,}" if not logs_df.empty and 'src_ip' in logs_df.columns else "—")
    col2.metric("Blocked IPs (window)", f"{int((logs_df.get('action', pd.Series(dtype=str)) == 'BLOCKED').sum()):,}" if not logs_df.empty else "—")
    col3.metric("Total Alerts (window)", f"{len(logs_df):,}" if not logs_df.empty else "—")

    render_threat_map(logs_df)
    render_attack_distribution(live_df)
    render_severity_timeline(live_df, logs_df)

# ── Tab 3: Incident Logs ───────────────────────────────────────────────────
with tab_logs:
    section_header("Incident Logs", subtitle="Full filterable event history", icon="📋")
    if logs_df.empty:
        render_empty_state("No incident records", "Incident logs will appear once attack events are written to the database.", "📋")
    else:
        total_l   = len(logs_df)
        blocked_l = int((logs_df.get("action", pd.Series(dtype=str)) == "BLOCKED").sum())
        allowed_l = int((logs_df.get("action", pd.Series(dtype=str)) == "ALLOWED").sum())
        last_evt  = logs_df["timestamp"].max().strftime("%Y-%m-%d %H:%M:%S") if "timestamp" in logs_df.columns else "—"
        c1, c2, c3, c4 = st.columns(4)
        with c1: kpi_card("Total Records", f"{total_l:,}",   icon="📊", accent_color="#58a6ff")
        with c2: kpi_card("Blocked",       f"{blocked_l:,}", icon="🔴", accent_color="#FF4B4B")
        with c3: kpi_card("Allowed",       f"{allowed_l:,}", icon="🟢", accent_color="#00CC66")
        with c4: kpi_card("Last Event",    last_evt,         icon="🕐", accent_color="#9ca5b0")

        grid_state    = render_logs_grid(logs_df)
        selected_rows = grid_state["selected_rows"]
        export_df     = grid_state["filtered_df"]
        export_total  = len(export_df)
        export_blocked = int((export_df.get("action", pd.Series(dtype=str)) == "BLOCKED").sum()) if not export_df.empty else 0
        export_allowed = int((export_df.get("action", pd.Series(dtype=str)) == "ALLOWED").sum()) if not export_df.empty else 0
        export_last    = "—"
        if not export_df.empty and "timestamp" in export_df.columns:
            _exp_ts = pd.to_datetime(export_df["timestamp"], errors="coerce")
            if not _exp_ts.dropna().empty:
                export_last = _exp_ts.max().strftime("%Y-%m-%d %H:%M:%S")

        section_header("Export Reports", icon="📤")
        csv_bytes = build_logs_csv_bytes(export_df)
        pdf_bytes = build_logs_pdf_bytes(export_df, export_total, export_blocked, export_allowed, export_last)
        export_col_csv, export_col_pdf = st.columns(2)
        with export_col_csv:
            st.download_button("Export CSV", data=csv_bytes,
                               file_name=f"incident_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                               mime="text/csv", use_container_width=True)
        with export_col_pdf:
            if pdf_bytes is None:
                st.button("Export PDF", disabled=True, help="Install `reportlab` to enable PDF export.", use_container_width=True)
            else:
                st.download_button("Export PDF", data=pdf_bytes,
                                   file_name=f"incident_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                                   mime="application/pdf", use_container_width=True)

        render_batch_log_actions(selected_rows)

# ── Tab 4: XAI Explainer ──────────────────────────────────────────────────
with tab_xai:
    section_header("XAI Explainer", subtitle="Explainable AI — model decision transparency", icon="🧠")
    st.markdown(
        '<div style="font-size:var(--font-sm);color:var(--color-text-muted);margin-bottom:var(--space-5);">'
        'Feature-importance visualizations and attention analysis for individual predictions. '
        'Implementation in progress.</div>',
        unsafe_allow_html=True,
    )
    xai_r1c1, xai_r1c2 = st.columns(2)
    with xai_r1c1:
        feature_preview_card(
            icon="🌊",
            title="SHAP Waterfall Chart",
            description="Per-prediction breakdown showing which features pushed the model toward or away from each class. One chart per selected flow.",
            pill="Sprint 3",
        )
    with xai_r1c2:
        feature_preview_card(
            icon="📊",
            title="Feature Importance Bar",
            description="Global top-N feature contribution ranking across the entire session window, with color coding by feature group.",
            pill="Sprint 3",
        )
    xai_r2c1, xai_r2c2 = st.columns(2)
    with xai_r2c1:
        feature_preview_card(
            icon="🔥",
            title="BiLSTM Attention Heatmap",
            description="Temporal attention weight visualization showing which timesteps the BiLSTM attended to when classifying a flow sequence.",
            pill="Sprint 3",
        )
    with xai_r2c2:
        feature_preview_card(
            icon="🎛️",
            title="Counterfactual Sliders",
            description="Interactive 'what-if' panel — adjust individual feature values and see how the model's prediction changes in real time.",
            pill="Sprint 4",
        )

    section_header("Supported Models", subtitle="XAI will be available for all registered models", icon="🤖")
    model_cols = st.columns(len(MODEL_MAPPING))
    for col, (name, filename) in zip(model_cols, MODEL_MAPPING.items()):
        with col:
            st.markdown(
                f'<div class="chart-card" style="text-align:center;padding:var(--space-4);">'
                f'<div style="font-size:var(--font-base);font-weight:700;">{name}</div>'
                f'<div style="font-size:var(--font-xs);color:var(--color-text-muted);font-family:monospace;margin-top:4px;">{filename}</div>'
                f'</div>',
                unsafe_allow_html=True,
            )

# ── Tab 5: Admin & Response ────────────────────────────────────────────────
with tab_admin:
    section_header("Admin & Response", subtitle="System management and automated response controls", icon="⚙️")

    adm_c1, adm_c2, adm_c3 = st.columns(3)
    with adm_c1:
        status_q = get_system_status()
        st.markdown(
            f'<div class="chart-card">'
            f'<div class="chart-card__header"><span class="chart-card__title">Model Management</span></div>'
            f'<div style="font-size:var(--font-sm);color:var(--color-text-muted);">Active model</div>'
            f'<div style="font-size:var(--font-base);font-weight:700;margin:var(--space-2) 0;">{selected_model}</div>'
            f'<div style="font-size:var(--font-xs);font-family:monospace;color:var(--color-text-muted);">{MODEL_MAPPING[selected_model]}</div>'
            f'</div>',
            unsafe_allow_html=True,
        )
    with adm_c2:
        df_color = "var(--color-safe)" if status_q["data_flowing"] else "var(--color-critical)"
        st.markdown(
            f'<div class="chart-card">'
            f'<div class="chart-card__header"><span class="chart-card__title">System Health</span></div>'
            f'<div style="font-size:var(--font-sm);color:var(--color-text-muted);">Data flowing</div>'
            f'<div style="font-size:var(--font-base);font-weight:700;color:{df_color};margin:var(--space-2) 0;">{"✅ Yes" if status_q["data_flowing"] else "❌ No"}</div>'
            f'<div style="font-size:var(--font-xs);color:var(--color-text-muted);">{status_q["csv_rows"]:,} CSV rows</div>'
            f'</div>',
            unsafe_allow_html=True,
        )
    with adm_c3:
        st.markdown(
            f'<div class="chart-card">'
            f'<div class="chart-card__header"><span class="chart-card__title">Response Actions</span></div>'
            f'<div style="font-size:var(--font-sm);color:var(--color-text-muted);line-height:1.6;">'
            f'IP blocking is managed via <code>firewall_manager</code>.<br>'
            f'Use the sidebar Firewall panel for immediate block/unblock.</div>'
            f'</div>',
            unsafe_allow_html=True,
        )

    adm_f1, adm_f2 = st.columns(2)
    with adm_f1:
        feature_preview_card(
            icon="🤖",
            title="Automated Response Rules",
            description="Define policy rules that automatically block, rate-limit, or alert based on traffic class, confidence threshold, and flow volume.",
            pill="Sprint 4",
        )
    with adm_f2:
        feature_preview_card(
            icon="📜",
            title="Audit Trail",
            description="Immutable log of all manual and automated firewall actions with operator ID, timestamp, and justification fields.",
            pill="Sprint 4",
        )

    render_firewall_viewer()
