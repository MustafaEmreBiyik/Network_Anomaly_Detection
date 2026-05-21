import json
import os
import sqlite3
from datetime import datetime

import pandas as pd

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "alerts.db")

_ALERTS_DDL = """
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    action TEXT NOT NULL,
    details TEXT
);
"""

_PIPELINE_EVENTS_DDL = """
CREATE TABLE IF NOT EXISTS pipeline_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    service TEXT NOT NULL,
    severity TEXT NOT NULL,
    summary TEXT NOT NULL,
    details TEXT
);
"""

_SERVICE_HEARTBEATS_DDL = """
CREATE TABLE IF NOT EXISTS service_heartbeats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    service TEXT NOT NULL,
    status TEXT NOT NULL,
    metadata TEXT
);
"""


def _get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(_ALERTS_DDL)
    conn.execute(_PIPELINE_EVENTS_DDL)
    conn.execute(_SERVICE_HEARTBEATS_DDL)
    return conn


def log_attack(src_ip: str, action: str, details: str):
    """Persist detection results for later dashboard use."""
    timestamp = datetime.utcnow().isoformat()
    try:
        with _get_connection() as conn:
            conn.execute(
                "INSERT INTO alerts (timestamp, src_ip, action, details) VALUES (?, ?, ?, ?)",
                (timestamp, src_ip, action, details),
            )
            conn.commit()
    except sqlite3.Error as exc:
        print(f"⚠️ DB yazma hatası: {exc}")


def fetch_logs():
    """Return alert history as a DataFrame ordered by latest timestamp."""
    columns = ["id", "timestamp", "src_ip", "action", "details"]

    try:
        with _get_connection() as conn:
            df = pd.read_sql_query(
                "SELECT id, timestamp, src_ip, action, details FROM alerts "
                "ORDER BY datetime(timestamp) DESC",
                conn,
            )
            return df
    except sqlite3.Error as exc:
        print(f"⚠️ DB okuma hatası: {exc}")
        return pd.DataFrame(columns=columns)


def log_pipeline_event(service: str, severity: str, summary: str, details=None):
    """Record a pipeline event (error, schema adjustment, model reload, etc.)."""
    timestamp = datetime.utcnow().isoformat()
    details_str = json.dumps(details) if details is not None else None
    try:
        with _get_connection() as conn:
            conn.execute(
                "INSERT INTO pipeline_events (timestamp, service, severity, summary, details) "
                "VALUES (?, ?, ?, ?, ?)",
                (timestamp, service, severity, summary, details_str),
            )
            conn.commit()
    except sqlite3.Error as exc:
        print(f"⚠️ DB pipeline_event write error: {exc}")


def log_heartbeat(service: str, status: str = "alive", metadata=None):
    """Stamp a service alive in service_heartbeats."""
    timestamp = datetime.utcnow().isoformat()
    metadata_str = json.dumps(metadata) if metadata is not None else None
    try:
        with _get_connection() as conn:
            conn.execute(
                "INSERT INTO service_heartbeats (timestamp, service, status, metadata) "
                "VALUES (?, ?, ?, ?)",
                (timestamp, service, status, metadata_str),
            )
            conn.commit()
    except sqlite3.Error as exc:
        print(f"⚠️ DB heartbeat write error: {exc}")


def fetch_recent_events(limit: int = 50) -> pd.DataFrame:
    """Return the most recent pipeline events."""
    columns = ["id", "timestamp", "service", "severity", "summary", "details"]
    try:
        with _get_connection() as conn:
            return pd.read_sql_query(
                "SELECT id, timestamp, service, severity, summary, details "
                "FROM pipeline_events ORDER BY datetime(timestamp) DESC LIMIT ?",
                conn,
                params=(limit,),
            )
    except sqlite3.Error as exc:
        print(f"⚠️ DB fetch_recent_events error: {exc}")
        return pd.DataFrame(columns=columns)


def get_service_health() -> pd.DataFrame:
    """Return the latest heartbeat per service."""
    columns = ["service", "last_seen", "status"]
    try:
        with _get_connection() as conn:
            return pd.read_sql_query(
                "SELECT service, MAX(timestamp) AS last_seen, status "
                "FROM service_heartbeats GROUP BY service",
                conn,
            )
    except sqlite3.Error as exc:
        print(f"⚠️ DB get_service_health error: {exc}")
        return pd.DataFrame(columns=columns)
