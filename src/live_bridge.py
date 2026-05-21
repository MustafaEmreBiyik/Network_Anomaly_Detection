import pandas as pd
import joblib
import os
import sys
import time
import shutil
import subprocess
import threading
import queue
import atexit
import json
import io
import contextlib
import gc
import warnings
from datetime import datetime
from scapy.all import sniff, wrpcap, conf

import joblib
import numpy as np
import pandas as pd
from scapy.all import sniff, wrpcap, rdpcap
from dotenv import load_dotenv
from confluent_kafka import Producer

try:
    from scapy.arch.windows import get_windows_if_list
except Exception:
    get_windows_if_list = None

# Load environment variables
load_dotenv()

# ---------------------------------------------------------------------------
# PATH SETUP
# ---------------------------------------------------------------------------
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, CURRENT_DIR)
sys.path.append(os.path.join(CURRENT_DIR, "utils"))

from model_registry import MODEL_REGISTRY, DEFAULT_MODEL

_default_entry = MODEL_REGISTRY[DEFAULT_MODEL]
SCALER_PATH = _default_entry["scaler_path"]

# Utils Import
try:
    from firewall_manager import block_ip
    from db_manager import log_attack, log_heartbeat, log_pipeline_event
except ImportError:
    def log_attack(*_args, **_kwargs):
        pass
    def log_heartbeat(*_args, **_kwargs):
        pass
    def log_pipeline_event(*_args, **_kwargs):
        pass

# ---------------------------------------------------------------------------
# RUNTIME CONFIG
# ---------------------------------------------------------------------------
# Scapy interface name must match show_interfaces() output exactly.
def resolve_capture_interface(interface_value: str) -> str:
    """Resolve Windows adapter names/descriptions to the Scapy capture name."""
    raw_value = (interface_value or "").strip()
    if not raw_value:
        return "Wi-Fi"

    if os.name != "nt" or get_windows_if_list is None:
        return raw_value

    target = raw_value.casefold()
    for iface in get_windows_if_list():
        name = str(iface.get("name") or "").strip()
        description = str(iface.get("description") or "").strip()
        guid = str(iface.get("guid") or "").strip()
        device_name = f"\\Device\\NPF_{guid.strip('{}')}" if guid else ""

        candidates = {
            name.casefold(),
            description.casefold(),
            guid.casefold(),
            guid.strip("{}").casefold(),
            device_name.casefold(),
        }
        if target in candidates:
            if raw_value != name:
                print(
                    f"ℹ️ NETWORK_INTERFACE resolved: '{raw_value}' -> '{name}' "
                    f"({description or device_name})"
                )
            return name

    print(f"⚠️ NETWORK_INTERFACE '{raw_value}' did not match a known Scapy interface; using as-is.")
    return raw_value


INTERFACE = resolve_capture_interface(os.getenv("NETWORK_INTERFACE", "Wi-Fi"))
TEMP_PCAP = "temp_live.pcap"
TEMP_CSV = "temp_live.csv"
WHITELIST_IPS = os.getenv("WHITELIST_IPS", "192.168.1.1,127.0.0.1,0.0.0.0,localhost").split(",")


def _get_env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


CAPTURE_TIMEOUT_SECONDS = _get_env_int("LIVE_CAPTURE_TIMEOUT_SECONDS", 4)
MIN_BUFFER_PACKETS = _get_env_int("LIVE_MIN_BUFFER_PACKETS", 30)
MIN_BUFFER_FLOW_PACKETS = _get_env_int("LIVE_MIN_BUFFER_FLOW_PACKETS", 20)
MAX_BUFFER_PACKETS = _get_env_int("LIVE_MAX_BUFFER_PACKETS", 600)
MAX_BUFFER_WINDOWS = _get_env_int("LIVE_MAX_BUFFER_WINDOWS", 4)
DROP_COLS = [
    "Flow ID",
    "Source IP",
    "Src IP",
    "src_ip",
    "dst_ip",
    "Source Port",
    "Src Port",
    "src_port",
    "dst_port",
    "Destination IP",
    "Dest IP",
    "Destination Port",
    "Dest Port",
    "Timestamp",
    "timestamp",
    "Date",
    "protocol",
    "Flow_ID",
    "SimillarHTTP",
    "Label",
]

# ---------------------------------------------------------------------------
# DATA HARVEST - TRAFFIC LOGGER
# ---------------------------------------------------------------------------
HARVEST_CSV_PATH = os.path.join(PROJECT_ROOT, "data", "live_captured_traffic.csv")
HARVEST_BUFFER_SIZE = 25  # Number of rows to buffer before writing to disk
HARVEST_FLUSH_INTERVAL = 30.0  # Force flush every N seconds even if buffer not full

PRODUCER_STATS = {
    "capture_windows": 0,
    "extract_attempts": 0,
    "extract_successes": 0,
    "extract_failures": 0,
    "skipped_windows": 0,
    "flows_sent": 0,
}

#for only 20 features add this function written by betul to convert 20 features to 78 features with 0 filling for missing columns
def load_model_feature_columns():
    """Load the exact feature order expected by the deployed scaler/model."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            scaler = joblib.load(SCALER_PATH)
        feature_names = list(getattr(scaler, "feature_names_in_", []))
        return feature_names
    except Exception:
        return []


MODEL_FEATURE_COLUMNS = load_model_feature_columns()

# Training data schema (78 features) - must match exactly with model training columns
TRAINING_FEATURE_COLUMNS = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "CWE Flag Count",
    "ECE Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",
    "Fwd Header Length.1",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Bwd Bytes",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "act_data_pkt_fwd",
    "min_seg_size_forward",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
]


class TrafficLogger:
    """
    Thread-safe traffic logger with buffered writes for minimal latency impact.
    
    Features:
    - Buffers rows in memory to reduce disk I/O frequency
    - Uses a separate writer thread to avoid blocking the main sniffing loop
    - Auto-flushes on buffer full or time interval
    - Graceful shutdown with atexit hook
    """
    
    def __init__(
        self,
        csv_path: str = HARVEST_CSV_PATH,
        buffer_size: int = HARVEST_BUFFER_SIZE,
        flush_interval: float = HARVEST_FLUSH_INTERVAL,
    ):
        self.csv_path = csv_path
        self.buffer_size = buffer_size
        self.flush_interval = flush_interval
        
        # Thread-safe queue for passing data to writer thread
        self._queue: queue.Queue = queue.Queue()
        self._buffer: list = []
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._last_flush_time = time.time()
        
        # CSV header columns: Timestamp + 78 features + Predicted_Label + Confidence_Score
        self._csv_columns = ["Timestamp"] + TRAINING_FEATURE_COLUMNS + ["Predicted_Label", "Confidence_Score"]
        
        # Ensure data directory exists
        os.makedirs(os.path.dirname(self.csv_path), exist_ok=True)
        
        # Initialize CSV file with header if it doesn't exist
        self._initialize_csv()
        
        # Start the background writer thread
        self._writer_thread = threading.Thread(target=self._writer_loop, daemon=True, name="TrafficLoggerWriter")
        self._writer_thread.start()
        
        # Register shutdown hook to flush remaining data
        atexit.register(self.shutdown)
        
        print(f"📊 [TrafficLogger] Data harvesting aktif -> {self.csv_path}")
    
    def _initialize_csv(self):
        """Create CSV file with header if it doesn't exist."""
        if not os.path.exists(self.csv_path):
            try:
                header_df = pd.DataFrame(columns=self._csv_columns)
                header_df.to_csv(self.csv_path, index=False)
                print(f"   ↳ Yeni CSV dosyası oluşturuldu ({len(self._csv_columns)} sütun)")
            except Exception as e:
                print(f"⚠️ [TrafficLogger] CSV başlatma hatası: {e}")
        else:
            # Validate existing file has correct columns
            try:
                existing_df = pd.read_csv(self.csv_path, nrows=0)
                if list(existing_df.columns) != self._csv_columns:
                    print(f"⚠️ [TrafficLogger] Mevcut CSV şeması uyumsuz, yedekleniyor...")
                    backup_path = self.csv_path.replace(".csv", f"_backup_{int(time.time())}.csv")
                    shutil.move(self.csv_path, backup_path)
                    self._initialize_csv()
            except Exception:
                pass  # File might be empty or corrupted, will be overwritten
    
    def log(
        self,
        features_df: pd.DataFrame,
        predictions: np.ndarray,
        probabilities: np.ndarray = None,
        debug: bool = False,
    ):
        """
        Queue feature data with predictions for async logging.
        
        Args:
            features_df: DataFrame with 78 feature columns (already scaled or raw)
            predictions: Array of 0/1 predictions
            probabilities: Optional array of confidence scores (attack probability)
            debug: If True, print column alignment diagnostics
        """
        if features_df.empty:
            return
        
        try:
            timestamp = datetime.now().isoformat()
            
            # === COLUMN ALIGNMENT DEBUGGING ===
            if debug or not hasattr(self, '_alignment_checked'):
                input_cols = set(features_df.columns)
                expected_cols = set(TRAINING_FEATURE_COLUMNS)
                
                missing_cols = expected_cols - input_cols
                extra_cols = input_cols - expected_cols
                
                print(f"\n🔍 [TrafficLogger] Column Alignment Check:")
                print(f"   Input columns:    {len(features_df.columns)}")
                print(f"   Expected columns: {len(TRAINING_FEATURE_COLUMNS)}")
                
                if missing_cols:
                    print(f"   ⚠️ MISSING ({len(missing_cols)}): {list(missing_cols)[:5]}{'...' if len(missing_cols) > 5 else ''}")
                if extra_cols:
                    print(f"   ⚠️ EXTRA ({len(extra_cols)}): {list(extra_cols)[:5]}{'...' if len(extra_cols) > 5 else ''}")
                
                if not missing_cols and not extra_cols:
                    print(f"   ✅ Perfect match! All 78 columns aligned.")
                else:
                    print(f"   ℹ️ Missing columns will be filled with 0, extra columns ignored.")
                
                self._alignment_checked = True
            
            # Ensure features are in correct column order
            aligned_features = features_df.reindex(columns=TRAINING_FEATURE_COLUMNS, fill_value=0)
            
            for idx in range(len(aligned_features)):
                row_data = {
                    "Timestamp": timestamp,
                    "Predicted_Label": int(predictions[idx]),
                    "Confidence_Score": float(probabilities[idx, 1]) if probabilities is not None else float(predictions[idx]),
                }
                # Add all 78 features
                for col in TRAINING_FEATURE_COLUMNS:
                    row_data[col] = aligned_features.iloc[idx][col]
                
                # Put row in queue (non-blocking)
                self._queue.put(row_data, block=False)
        except Exception as e:
            print(f"⚠️ [TrafficLogger] Log hatası: {e}")
            import traceback
            traceback.print_exc()
    
    def _writer_loop(self):
        """Background thread that processes queue and writes to CSV."""
        while not self._stop_event.is_set():
            try:
                # Try to get item from queue with timeout
                try:
                    row = self._queue.get(timeout=1.0)
                    with self._lock:
                        self._buffer.append(row)
                    self._queue.task_done()
                except queue.Empty:
                    pass
                
                # Check if we should flush
                should_flush = False
                with self._lock:
                    buffer_full = len(self._buffer) >= self.buffer_size  # buffer size is 25
                    time_elapsed = (time.time() - self._last_flush_time) >= self.flush_interval
                    should_flush = (buffer_full or time_elapsed) and len(self._buffer) > 0
                
                if should_flush:
                    self._flush_buffer()
                    
            except Exception as e:
                print(f"⚠️ [TrafficLogger] Writer thread hatası: {e}")
                time.sleep(1)
    
    def _flush_buffer(self):
        """Write buffered data to CSV file."""
        with self._lock:
            if not self._buffer:
                return
            
            rows_to_write = self._buffer.copy()
            self._buffer.clear()
            self._last_flush_time = time.time()
        
        try:
            df = pd.DataFrame(rows_to_write, columns=self._csv_columns)
            df.to_csv(self.csv_path, mode='a', header=False, index=False)
            print(f"💾 [TrafficLogger] {len(rows_to_write)} satır kaydedildi (Toplam: {self._get_total_rows()})")
        except Exception as e:
            print(f"⚠️ [TrafficLogger] Flush hatası: {e}")
            # Put rows back in queue for retry
            with self._lock:
                self._buffer.extend(rows_to_write)
    
    def _get_total_rows(self) -> int:
        """Get approximate total row count in CSV."""
        try:
            if os.path.exists(self.csv_path):
                with open(self.csv_path, 'r', encoding='utf-8') as f:
                    return sum(1 for _ in f) - 1  # Subtract header
        except Exception:
            pass
        return 0
    
    def shutdown(self):
        """Gracefully shutdown the logger, flushing remaining data."""
        print("\n🔄 [TrafficLogger] Kapanıyor, buffer temizleniyor...")
        self._stop_event.set()
        
        # Drain the queue
        while not self._queue.empty():
            try:
                row = self._queue.get_nowait()
                with self._lock:
                    self._buffer.append(row)
            except queue.Empty:
                break
        
        # Final flush
        self._flush_buffer()
        
        if self._writer_thread.is_alive():
            self._writer_thread.join(timeout=5.0)
        
        print(f"✅ [TrafficLogger] Tüm veriler kaydedildi -> {self.csv_path}")
    
    def get_stats(self) -> dict:
        """Return current logger statistics."""
        with self._lock:
            return {
                "buffer_size": len(self._buffer),
                "queue_size": self._queue.qsize(),
                "total_rows": self._get_total_rows(),
                "csv_path": self.csv_path,
            }


# Global Kafka Producer instance
KAFKA_PRODUCER = None
KAFKA_TOPIC = "network-traffic"

COLUMN_RENAME_MAP = {
    "flow_duration": "Flow Duration",
    "tot_fwd_pkts": "Total Fwd Packets",
    "tot_bwd_pkts": "Total Backward Packets",
    "totlen_fwd_pkts": "Total Length of Fwd Packets",
    "totlen_bwd_pkts": "Total Length of Bwd Packets",
    "fwd_pkt_len_max": "Fwd Packet Length Max",
    "fwd_pkt_len_min": "Fwd Packet Length Min",
    "fwd_pkt_len_mean": "Fwd Packet Length Mean",
    "fwd_pkt_len_std": "Fwd Packet Length Std",
    "bwd_pkt_len_max": "Bwd Packet Length Max",
    "bwd_pkt_len_min": "Bwd Packet Length Min",
    "bwd_pkt_len_mean": "Bwd Packet Length Mean",
    "bwd_pkt_len_std": "Bwd Packet Length Std",
    "flow_byts_s": "Flow Bytes/s",
    "flow_pkts_s": "Flow Packets/s",
    "flow_iat_mean": "Flow IAT Mean",
    "flow_iat_std": "Flow IAT Std",
    "flow_iat_max": "Flow IAT Max",
    "flow_iat_min": "Flow IAT Min",
    "fwd_iat_tot": "Fwd IAT Total",
    "fwd_iat_mean": "Fwd IAT Mean",
    "fwd_iat_std": "Fwd IAT Std",
    "fwd_iat_max": "Fwd IAT Max",
    "fwd_iat_min": "Fwd IAT Min",
    "bwd_iat_tot": "Bwd IAT Total",
    "bwd_iat_mean": "Bwd IAT Mean",
    "bwd_iat_std": "Bwd IAT Std",
    "bwd_iat_max": "Bwd IAT Max",
    "bwd_iat_min": "Bwd IAT Min",
    "fwd_psh_flags": "Fwd PSH Flags",
    "bwd_psh_flags": "Bwd PSH Flags",
    "fwd_urg_flags": "Fwd URG Flags",
    "bwd_urg_flags": "Bwd URG Flags",
    "fwd_header_len": "Fwd Header Length",
    "bwd_header_len": "Bwd Header Length",
    "fwd_pkts_s": "Fwd Packets/s",
    "bwd_pkts_s": "Bwd Packets/s",
    "pkt_len_min": "Min Packet Length",
    "pkt_len_max": "Max Packet Length",
    "pkt_len_mean": "Packet Length Mean",
    "pkt_len_std": "Packet Length Std",
    "pkt_len_var": "Packet Length Variance",
    "fin_flag_cnt": "FIN Flag Count",
    "syn_flag_cnt": "SYN Flag Count",
    "rst_flag_cnt": "RST Flag Count",
    "psh_flag_cnt": "PSH Flag Count",
    "ack_flag_cnt": "ACK Flag Count",
    "urg_flag_cnt": "URG Flag Count",
    "cwr_flag_count": "CWE Flag Count",
    "ece_flag_cnt": "ECE Flag Count",
    "down_up_ratio": "Down/Up Ratio",
    "pkt_size_avg": "Average Packet Size",
    "fwd_seg_size_avg": "Avg Fwd Segment Size",
    "bwd_seg_size_avg": "Avg Bwd Segment Size",
    "fwd_byts_b_avg": "Fwd Avg Bytes/Bulk",
    "fwd_pkts_b_avg": "Fwd Avg Packets/Bulk",
    "fwd_blk_rate_avg": "Fwd Avg Bulk Rate",
    "bwd_byts_b_avg": "Bwd Avg Bytes/Bulk",
    "bwd_pkts_b_avg": "Bwd Avg Packets/Bulk",
    "bwd_blk_rate_avg": "Bwd Avg Bulk Rate",
    "subflow_fwd_pkts": "Subflow Fwd Packets",
    "subflow_fwd_byts": "Subflow Fwd Bytes",
    "subflow_bwd_pkts": "Subflow Bwd Packets",
    "subflow_bwd_byts": "Subflow Bwd Bytes",
    "init_fwd_win_byts": "Init_Win_bytes_forward",
    "init_bwd_win_byts": "Init_Win_bytes_backward",
    "fwd_act_data_pkts": "act_data_pkt_fwd",
    "fwd_seg_size_min": "min_seg_size_forward",
    "active_mean": "Active Mean",
    "active_std": "Active Std",
    "active_max": "Active Max",
    "active_min": "Active Min",
    "idle_mean": "Idle Mean",
    "idle_std": "Idle Std",
    "idle_max": "Idle Max",
    "idle_min": "Idle Min",
}

def feature_extraction_and_predict_dummy_fallback():
    """
    Extract features from PCAP and send to Kafka.
    Uses cicflowmeter CLI with fallback to dummy features if extraction fails.
    """
    GOLD_STANDARD_FEATURES = [
        "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "timestamp",
        "flow_duration", "flow_byts_s", "flow_pkts_s", "fwd_pkts_s", "bwd_pkts_s",
        "tot_fwd_pkts", "tot_bwd_pkts", "totlen_fwd_pkts", "totlen_bwd_pkts",
        "fwd_pkt_len_max", "fwd_pkt_len_min", "fwd_pkt_len_mean", "fwd_pkt_len_std",
        "bwd_pkt_len_max", "bwd_pkt_len_min", "bwd_pkt_len_mean", "bwd_pkt_len_std",
        "pkt_len_max", "pkt_len_min", "pkt_len_mean", "pkt_len_std", "pkt_len_var",
        "fwd_header_len", "bwd_header_len", "fwd_seg_size_min", "fwd_act_data_pkts",
        "flow_iat_mean", "flow_iat_max", "flow_iat_min", "flow_iat_std",
        "fwd_iat_tot", "fwd_iat_max", "fwd_iat_min", "fwd_iat_mean", "fwd_iat_std",
        "bwd_iat_tot", "bwd_iat_max", "bwd_iat_min", "bwd_iat_mean", "bwd_iat_std",
        "fwd_psh_flags", "bwd_psh_flags", "fwd_urg_flags", "bwd_urg_flags",
        "fin_flag_cnt", "syn_flag_cnt", "rst_flag_cnt", "psh_flag_cnt",
        "ack_flag_cnt", "urg_flag_cnt", "ece_flag_cnt", "down_up_ratio",
        "pkt_size_avg", "init_fwd_win_byts", "init_bwd_win_byts",
        "active_max", "active_min", "active_mean", "active_std",
        "idle_max", "idle_min", "idle_mean", "idle_std",
        "fwd_byts_b_avg", "fwd_pkts_b_avg", "bwd_byts_b_avg", "bwd_pkts_b_avg",
        "fwd_blk_rate_avg", "bwd_blk_rate_avg", "fwd_seg_size_avg", "bwd_seg_size_avg",
        "cwr_flag_count", "subflow_fwd_pkts", "subflow_bwd_pkts",
        "subflow_fwd_byts", "subflow_bwd_byts",
    ]
    LOG_ONLY_COLUMNS = [
        "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "timestamp",
    ]

    print("   ↳ ⚙️ Analiz ediliyor...", end="\r")

    # Try cicflowmeter CLI
    cli_ok, cli_err = run_cicflowmeter_cli(TEMP_PCAP, TEMP_CSV)
    
    if not cli_ok:
        print(f"   ⚠️ CICFlowMeter CLI failed: {cli_err[:100]}")
        print(f"   🔄 Falling back to DUMMY FEATURES to keep pipeline alive...")
        
        # Generate dummy features to test pipeline
        df = generate_dummy_features(packet_count=1)
        print(f"   💡 Generated {len(df)} dummy flow(s) with 0-filled features")
    else:
        # CLI succeeded, try to read CSV
        if not os.path.exists(TEMP_CSV):
            print("   ⚠️ CSV file missing despite CLI success")
            print("   🔄 Falling back to DUMMY FEATURES...")
            df = generate_dummy_features(packet_count=1)
        else:
            try:
                df = pd.read_csv(TEMP_CSV)
                if df.empty:
                    print("   ⚠️ CSV is empty")
                    print("   🔄 Falling back to DUMMY FEATURES...")
                    df = generate_dummy_features(packet_count=1)
                else:
                    print(f"   ✅ Parsed {len(df)} flow(s) from CSV", end="\r")
            except Exception as exc:
                print(f"   ⚠️ CSV read error: {exc}")
                print("   🔄 Falling back to DUMMY FEATURES...")
                df = generate_dummy_features(packet_count=1)

    # Clean and normalize column names
    df.columns = df.columns.str.strip()
    src_ips = extract_source_ips(df)

    # Prepare features
    features = prepare_feature_frame(df)
    features.replace([float("inf"), float("-inf")], 0, inplace=True)
    features.fillna(0, inplace=True)

    # Ensure correct column alignment
    features = features.reindex(columns=GOLD_STANDARD_FEATURES, fill_value=0)

    # Remove metadata columns for model input
    model_features = features.drop(columns=LOG_ONLY_COLUMNS, errors="ignore")

    # Send to Kafka: One message per flow
    try:
        for idx in range(len(model_features)):
            # Convert feature vector to dictionary
            feature_dict = model_features.iloc[idx].to_dict()
            
            # Add metadata (IP, timestamp, etc.)
            kafka_message = {
                "timestamp": datetime.now().isoformat(),
                "src_ip": src_ips.iloc[idx] if (src_ips is not None and idx < len(src_ips)) else "0.0.0.0",
                "dst_ip": features.iloc[idx].get("dst_ip", "0.0.0.0") if "dst_ip" in features.columns else "0.0.0.0",
                "features": feature_dict,
                "feature_count": len(feature_dict),
                "producer_id": "live_bridge_v1"
            }
            
            # JSON serialize and send to Kafka
            message_json = json.dumps(kafka_message, default=str)
            KAFKA_PRODUCER.produce(
                KAFKA_TOPIC,
                value=message_json.encode('utf-8'),
                callback=delivery_report
            )
        
        # Flush all messages
        KAFKA_PRODUCER.flush(timeout=10)
        
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"✅ [{timestamp}] {len(model_features)} flow(s) sent to Kafka (Topic: {KAFKA_TOPIC})           ")
        
    except Exception as exc:
        print(f"⚠️ Kafka send error: {exc}")
        import traceback
        traceback.print_exc()
        return
def count_extractable_packets(packets) -> int:
    """Count packets that can participate in flow extraction."""
    count = 0
    for pkt in packets:
        if (("IP" in pkt) or ("IPv6" in pkt)) and (("TCP" in pkt) or ("UDP" in pkt)):
            count += 1
    return count


def trim_packet_buffer(packet_buffer):
    """Keep the packet buffer bounded while preserving the most recent traffic."""
    if len(packet_buffer) <= MAX_BUFFER_PACKETS:
        return list(packet_buffer)

    return list(packet_buffer[-MAX_BUFFER_PACKETS:])


def print_producer_stats():
    attempts = PRODUCER_STATS["extract_attempts"]
    success_rate = (
        (PRODUCER_STATS["extract_successes"] / attempts) * 100.0
        if attempts
        else 0.0
    )
    print(
        "📊 [Producer Stats] "
        f"windows={PRODUCER_STATS['capture_windows']} "
        f"attempts={attempts} "
        f"success={PRODUCER_STATS['extract_successes']} "
        f"skipped={PRODUCER_STATS['skipped_windows']} "
        f"failed={PRODUCER_STATS['extract_failures']} "
        f"flows={PRODUCER_STATS['flows_sent']} "
        f"success_rate={success_rate:.1f}%"
    )


def feature_extraction_and_predict_legacy_76():
    """
    Extract features from PCAP and send only real flows to Kafka.
    Returns a status dict so the caller can decide whether to keep buffering.
    """
    gold_standard_features = [
        "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "timestamp",
        "flow_duration", "flow_byts_s", "flow_pkts_s", "fwd_pkts_s", "bwd_pkts_s",
        "tot_fwd_pkts", "tot_bwd_pkts", "totlen_fwd_pkts", "totlen_bwd_pkts",
        "fwd_pkt_len_max", "fwd_pkt_len_min", "fwd_pkt_len_mean", "fwd_pkt_len_std",
        "bwd_pkt_len_max", "bwd_pkt_len_min", "bwd_pkt_len_mean", "bwd_pkt_len_std",
        "pkt_len_max", "pkt_len_min", "pkt_len_mean", "pkt_len_std", "pkt_len_var",
        "fwd_header_len", "bwd_header_len", "fwd_seg_size_min", "fwd_act_data_pkts",
        "flow_iat_mean", "flow_iat_max", "flow_iat_min", "flow_iat_std",
        "fwd_iat_tot", "fwd_iat_max", "fwd_iat_min", "fwd_iat_mean", "fwd_iat_std",
        "bwd_iat_tot", "bwd_iat_max", "bwd_iat_min", "bwd_iat_mean", "bwd_iat_std",
        "fwd_psh_flags", "bwd_psh_flags", "fwd_urg_flags", "bwd_urg_flags",
        "fin_flag_cnt", "syn_flag_cnt", "rst_flag_cnt", "psh_flag_cnt",
        "ack_flag_cnt", "urg_flag_cnt", "ece_flag_cnt", "down_up_ratio",
        "pkt_size_avg", "init_fwd_win_byts", "init_bwd_win_byts",
        "active_max", "active_min", "active_mean", "active_std",
        "idle_max", "idle_min", "idle_mean", "idle_std",
        "fwd_byts_b_avg", "fwd_pkts_b_avg", "bwd_byts_b_avg", "bwd_pkts_b_avg",
        "fwd_blk_rate_avg", "bwd_blk_rate_avg", "fwd_seg_size_avg", "bwd_seg_size_avg",
        "cwr_flag_count", "subflow_fwd_pkts", "subflow_bwd_pkts",
        "subflow_fwd_byts", "subflow_bwd_byts",
    ]
    log_only_columns = [
        "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "timestamp",
    ]

    print("   ↳ Analiz ediliyor...", end="\r")
    PRODUCER_STATS["extract_attempts"] += 1

    cli_ok, cli_err = run_cicflowmeter_cli(TEMP_PCAP, TEMP_CSV)
    if not cli_ok:
        PRODUCER_STATS["extract_failures"] += 1
        error_preview = cli_err[:180] if cli_err else "unknown error"
        print(f"   ⚠️ Feature extraction failed: {error_preview}")
        return {
            "success": False,
            "flows_sent": 0,
            "reason": cli_err or "feature extraction failed",
        }

    if not os.path.exists(TEMP_CSV):
        PRODUCER_STATS["extract_failures"] += 1
        print("   ⚠️ Feature extraction produced no CSV output")
        return {"success": False, "flows_sent": 0, "reason": "csv missing"}

    try:
        df = pd.read_csv(TEMP_CSV)
    except Exception as exc:
        PRODUCER_STATS["extract_failures"] += 1
        print(f"   ⚠️ CSV read error: {exc}")
        return {"success": False, "flows_sent": 0, "reason": f"csv read error: {exc}"}

    if df.empty:
        PRODUCER_STATS["extract_failures"] += 1
        print("   ⚠️ Feature extraction returned an empty CSV")
        return {"success": False, "flows_sent": 0, "reason": "csv empty"}

    print(f"   ✅ Parsed {len(df)} flow(s) from CSV", end="\r")
    df.columns = df.columns.str.strip()
    src_ips = extract_source_ips(df)

    features = prepare_feature_frame(df)
    features.replace([float("inf"), float("-inf")], 0, inplace=True)
    features.fillna(0, inplace=True)
    features = features.reindex(columns=gold_standard_features, fill_value=0)

    model_features = features.drop(columns=log_only_columns, errors="ignore")
    if model_features.empty:
        PRODUCER_STATS["extract_failures"] += 1
        print("   ⚠️ No model-ready features were produced from the extracted flows")
        return {"success": False, "flows_sent": 0, "reason": "no model features"}

    try:
        for idx in range(len(model_features)):
            feature_dict = model_features.iloc[idx].to_dict()
            kafka_message = {
                "timestamp": datetime.now().isoformat(),
                "src_ip": src_ips.iloc[idx] if (src_ips is not None and idx < len(src_ips)) else "0.0.0.0",
                "dst_ip": features.iloc[idx].get("dst_ip", "0.0.0.0") if "dst_ip" in features.columns else "0.0.0.0",
                "features": feature_dict,
                "feature_count": len(feature_dict),
                "producer_id": "live_bridge_v1_76f",
            }
            message_json = json.dumps(kafka_message, default=str)
            KAFKA_PRODUCER.produce(
                KAFKA_TOPIC,
                value=message_json.encode("utf-8"),
                callback=delivery_report,
            )

        KAFKA_PRODUCER.flush(timeout=10)
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"✅ [{timestamp}] {len(model_features)} flow(s) sent to Kafka (Topic: {KAFKA_TOPIC})           ")
        PRODUCER_STATS["extract_successes"] += 1
        PRODUCER_STATS["flows_sent"] += len(model_features)
        return {"success": True, "flows_sent": len(model_features), "reason": None}

    except Exception as exc:
        PRODUCER_STATS["extract_failures"] += 1
        print(f"⚠️ Kafka send error: {exc}")
        import traceback
        traceback.print_exc()
        return {"success": False, "flows_sent": 0, "reason": f"kafka send error: {exc}"}


def feature_extraction_and_predict(): 
    """
    Extract features from PCAP and send only real flows to Kafka.
    This override publishes the training-schema feature names expected by the scaler/model.
    """
    print("   ↳ Analiz ediliyor...", end="\r")
    PRODUCER_STATS["extract_attempts"] += 1

    cli_ok, cli_err = run_cicflowmeter_cli(TEMP_PCAP, TEMP_CSV)
    if not cli_ok:
        PRODUCER_STATS["extract_failures"] += 1
        error_preview = cli_err[:180] if cli_err else "unknown error"
        print(f"   ⚠️ Feature extraction failed: {error_preview}")
        return {
            "success": False,
            "flows_sent": 0,
            "reason": cli_err or "feature extraction failed",
        }

    if not os.path.exists(TEMP_CSV):
        PRODUCER_STATS["extract_failures"] += 1
        print("   ⚠️ Feature extraction produced no CSV output")
        return {"success": False, "flows_sent": 0, "reason": "csv missing"}

    try:
        df = pd.read_csv(TEMP_CSV)
    except Exception as exc:
        PRODUCER_STATS["extract_failures"] += 1
        print(f"   ⚠️ CSV read error: {exc}")
        return {"success": False, "flows_sent": 0, "reason": f"csv read error: {exc}"}

    if df.empty:
        PRODUCER_STATS["extract_failures"] += 1
        print("   ⚠️ Feature extraction returned an empty CSV")
        return {"success": False, "flows_sent": 0, "reason": "csv empty"}

    print(f"   ✅ Parsed {len(df)} flow(s) from CSV", end="\r")
    df.columns = df.columns.str.strip()
    src_ips = extract_source_ips(df)

    dst_ips = None
    for candidate in ("Dst IP", "Destination IP", "dst_ip"):
        if candidate in df.columns:
            dst_ips = df[candidate]
            break

    features = prepare_feature_frame(df)
    features.replace([float("inf"), float("-inf")], 0, inplace=True)
    features.fillna(0, inplace=True)
    outgoing_feature_columns = MODEL_FEATURE_COLUMNS or EXPECTED_FEATURES
    features = features.reindex(columns=outgoing_feature_columns, fill_value=0.0)

    if features.empty:
        PRODUCER_STATS["extract_failures"] += 1
        print("   ⚠️ No model-ready features were produced from the extracted flows")
        return {"success": False, "flows_sent": 0, "reason": "no model features"}

    try:
        for idx in range(len(features)):
            feature_dict = features.iloc[idx].to_dict()
            kafka_message = {
                "timestamp": datetime.now().isoformat(),
                "src_ip": src_ips.iloc[idx] if (src_ips is not None and idx < len(src_ips)) else "0.0.0.0",
                "dst_ip": dst_ips.iloc[idx] if (dst_ips is not None and idx < len(dst_ips)) else "0.0.0.0",
                "features": feature_dict,
                "feature_count": len(feature_dict),
                "producer_id": "live_bridge_v2",
                "schema_version": "v2",
                "extraction_method": "cli",
            }
            message_json = json.dumps(kafka_message, default=str)
            KAFKA_PRODUCER.produce(
                KAFKA_TOPIC,
                value=message_json.encode("utf-8"),
                callback=delivery_report,
            )

        KAFKA_PRODUCER.flush(timeout=10)
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"✅ [{timestamp}] {len(features)} flow(s) sent to Kafka (Topic: {KAFKA_TOPIC})           ")
        PRODUCER_STATS["extract_successes"] += 1
        PRODUCER_STATS["flows_sent"] += len(features)
        return {"success": True, "flows_sent": len(features), "reason": None}

    except Exception as exc:
        PRODUCER_STATS["extract_failures"] += 1
        print(f"⚠️ Kafka send error: {exc}")
        import traceback
        traceback.print_exc()
        return {"success": False, "flows_sent": 0, "reason": f"kafka send error: {exc}"}


EXPECTED_FEATURES = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "CWE Flag Count",
    "ECE Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",
    "Fwd Header Length.1",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Bwd Bytes",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "act_data_pkt_fwd",
    "min_seg_size_forward",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
]

print("\n" + "=" * 60)

def extract_source_ips(df: pd.DataFrame):
    """Return whichever source IP column exists."""
    for candidate in ("Src IP", "Source IP", "src_ip"):
        if candidate in df.columns:
            return df[candidate]
    return None


def prepare_feature_frame(df: pd.DataFrame) -> pd.DataFrame:
    """Rename CICFlowMeter columns and align them with training schema."""
    working = df.copy()
    working.columns = working.columns.str.strip()
    working.drop(columns=DROP_COLS, errors="ignore", inplace=True)
    working.rename(columns=COLUMN_RENAME_MAP, inplace=True)

    if "Fwd Header Length" in working.columns and "Fwd Header Length.1" not in working.columns:
        working["Fwd Header Length.1"] = working["Fwd Header Length"]

    missing_cols = [col for col in EXPECTED_FEATURES if col not in working.columns]
    for col in missing_cols:
        working[col] = 0

    return working.reindex(columns=EXPECTED_FEATURES, fill_value=0)


def delivery_report(err, msg):
    """Kafka delivery callback - mesajın başarıyla gönderildiğini doğrular."""
    if err is not None:
        print(f"⚠️ Mesaj gönderimi başarısız: {err}")
    # Başarılı gönderimler için sessiz mod (spam önleme)


print("  AI NETWORK IPS - KAFKA PRODUCER MODE")
print("=" * 60)

try:
    print("⏳ Kafka Producer başlatılıyor...", end="\r")
    KAFKA_PRODUCER = Producer({
        'bootstrap.servers': '127.0.0.1:9092',
        'client.id': 'network-ips-producer',
        'acks': 'all',
        'retries': 3,
        'max.in.flight.requests.per.connection': 1
    })
    print("✅ Kafka Producer Aktif (127.0.0.1:9092).        ")
except Exception as exc:
    print(f"❌ Kafka bağlantı hatası: {exc}")
    print("⚠️  Docker Compose ile Kafka'yı başlattığınızdan emin olun: docker-compose up -d")
    sys.exit(1)

if shutil.which("cicflowmeter") is None:
    print("\n⚠️  WARNING: 'cicflowmeter' CLI not found (pip install cicflowmeter)")
    print("   System will use DUMMY FEATURES if feature extraction fails.")
    print("   For production use, install cicflowmeter properly.\n")


# ---------------------------------------------------------------------------
# CICFLOWMETER HELPERS
# ---------------------------------------------------------------------------

def run_cicflowmeter_cli(pcap_file: str, csv_file: str):
    """
    Extract flow features from a PCAP into CSV and return (success, error_message).
    Prefer the in-process Python API when available because the installed
    cicflowmeter CLI is version-dependent and has proven brittle on Windows.
    """
    for candidate in (csv_file, f"{os.path.splitext(pcap_file)[0]}_Flow.csv"):
        try:
            if os.path.exists(candidate):
                os.remove(candidate)
        except OSError:
            pass

    api_ok, api_err = run_cicflowmeter_api(pcap_file, csv_file)
    if api_ok:
        return True, None

    cli_attempts = []
    executable_dir = os.path.dirname(sys.executable)
    bundled_cic = os.path.join(
        executable_dir,
        "cicflowmeter.exe" if os.name == "nt" else "cicflowmeter",
    )
    cli_candidates = []

    if os.path.exists(bundled_cic):
        cli_candidates.append([bundled_cic, "-f", pcap_file, "-c", csv_file])
        cli_candidates.append([bundled_cic, "-f", pcap_file, "-c", csv_file, csv_file])

    cli_candidates.append([sys.executable, "-m", "cicflowmeter", "-f", pcap_file, "-c", csv_file])
    cli_candidates.append([sys.executable, "-m", "cicflowmeter", "-f", pcap_file, "-c", csv_file, csv_file])

    direct_cic = shutil.which("cicflowmeter")
    if direct_cic:
        cli_candidates.append([direct_cic, "-f", pcap_file, "-c", csv_file])
        cli_candidates.append([direct_cic, "-f", pcap_file, "-c", csv_file, csv_file])

    for cmd in cli_candidates:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
        except subprocess.TimeoutExpired:
            cli_attempts.append(f"{os.path.basename(cmd[0])}: timeout")
            continue
        except Exception as exc:
            cli_attempts.append(f"{os.path.basename(cmd[0])}: {exc}")
            continue

        if result.returncode != 0:
            err = result.stderr.strip() or result.stdout.strip() or f"CLI exit code {result.returncode}"
            cli_attempts.append(f"{os.path.basename(cmd[0])}: {err}")
            continue

        resolved_csv = resolve_cicflowmeter_output(pcap_file, csv_file)
        if resolved_csv and os.path.getsize(resolved_csv) > 0:
            return True, None

        cli_attempts.append(f"{os.path.basename(cmd[0])}: empty CSV output")

    details = [f"API failed: {api_err}"] if api_err else []
    details.extend(cli_attempts)
    return False, " | ".join(details) if details else "Feature extraction failed"


def run_cicflowmeter_api(pcap_file: str, csv_file: str):
    """Use cicflowmeter's Python internals directly to avoid CLI issues."""
    try:
        from scapy.all import PcapReader
        from cicflowmeter.flow_session import FlowSession
    except Exception as exc:
        return False, f"Python API unavailable: {exc}"

    total_packets = 0
    accepted_packets = 0

    try:
        session = None
        with contextlib.redirect_stdout(io.StringIO()):
            if hasattr(FlowSession, "on_packet_received"):
                setattr(FlowSession, "output_mode", "csv")
                setattr(FlowSession, "output", csv_file)
                setattr(FlowSession, "fields", None)
                setattr(FlowSession, "verbose", False)
                session = FlowSession()
                packet_handler = session.on_packet_received
                finalizer = lambda: session.garbage_collect(None)
            else:
                session = FlowSession(
                    output_mode="csv",
                    output=csv_file,
                    fields=None,
                    verbose=False,
                )
                if hasattr(session, "process"):
                    packet_handler = session.process
                elif hasattr(session, "on_packet_received"):
                    packet_handler = session.on_packet_received
                else:
                    return False, "Python API error: FlowSession has no packet handler"

                def finalizer():
                    session.flush_flows()
                    if hasattr(session, "_gc_stop"):
                        session._gc_stop.set()
                    if hasattr(session, "_gc_thread"):
                        session._gc_thread.join(timeout=2.0)

            with PcapReader(pcap_file) as reader:
                for pkt in reader:
                    total_packets += 1
                    if (("IP" in pkt) or ("IPv6" in pkt)) and (("TCP" in pkt) or ("UDP" in pkt)):
                        packet_handler(pkt)
                        accepted_packets += 1

            finalizer()
            del session
            gc.collect()
    except Exception as exc:
        return False, f"Python API error: {exc}"

    resolved_csv = resolve_cicflowmeter_output(pcap_file, csv_file)
    if resolved_csv and os.path.getsize(resolved_csv) > 0:
        return True, None

    if accepted_packets == 0:
        return False, f"No extractable IP/TCP/UDP packets found ({total_packets} packets scanned)"

    return False, f"Processed {accepted_packets} packets but produced an empty CSV"


def resolve_cicflowmeter_output(pcap_file: str, csv_file: str):
    """Normalize cicflowmeter's output naming to the requested CSV path."""
    if os.path.exists(csv_file):
        return csv_file

    alt_name = f"{os.path.splitext(pcap_file)[0]}_Flow.csv"
    if os.path.exists(alt_name):
        try:
            shutil.move(alt_name, csv_file)
            return csv_file
        except OSError:
            return alt_name

    return None


def generate_dummy_features(packet_count: int = 1) -> pd.DataFrame:
    """
    Generate dummy feature data when cicflowmeter fails.
    Returns a DataFrame with 78 features filled with zeros.
    This keeps the Kafka pipeline alive for testing.
    """
    dummy_data = {}
    
    # Create gold standard feature set with all zeros
    GOLD_STANDARD_FEATURES = [
        "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "timestamp",
        "flow_duration", "flow_byts_s", "flow_pkts_s", "fwd_pkts_s", "bwd_pkts_s",
        "tot_fwd_pkts", "tot_bwd_pkts", "totlen_fwd_pkts", "totlen_bwd_pkts",
        "fwd_pkt_len_max", "fwd_pkt_len_min", "fwd_pkt_len_mean", "fwd_pkt_len_std",
        "bwd_pkt_len_max", "bwd_pkt_len_min", "bwd_pkt_len_mean", "bwd_pkt_len_std",
        "pkt_len_max", "pkt_len_min", "pkt_len_mean", "pkt_len_std", "pkt_len_var",
        "fwd_header_len", "bwd_header_len", "fwd_seg_size_min", "fwd_act_data_pkts",
        "flow_iat_mean", "flow_iat_max", "flow_iat_min", "flow_iat_std",
        "fwd_iat_tot", "fwd_iat_max", "fwd_iat_min", "fwd_iat_mean", "fwd_iat_std",
        "bwd_iat_tot", "bwd_iat_max", "bwd_iat_min", "bwd_iat_mean", "bwd_iat_std",
        "fwd_psh_flags", "bwd_psh_flags", "fwd_urg_flags", "bwd_urg_flags",
        "fin_flag_cnt", "syn_flag_cnt", "rst_flag_cnt", "psh_flag_cnt",
        "ack_flag_cnt", "urg_flag_cnt", "ece_flag_cnt", "down_up_ratio",
        "pkt_size_avg", "init_fwd_win_byts", "init_bwd_win_byts",
        "active_max", "active_min", "active_mean", "active_std",
        "idle_max", "idle_min", "idle_mean", "idle_std",
        "fwd_byts_b_avg", "fwd_pkts_b_avg", "bwd_byts_b_avg", "bwd_pkts_b_avg",
        "fwd_blk_rate_avg", "bwd_blk_rate_avg", "fwd_seg_size_avg", "bwd_seg_size_avg",
        "cwr_flag_count", "subflow_fwd_pkts", "subflow_bwd_pkts",
        "subflow_fwd_byts", "subflow_bwd_byts",
    ]
    
    for feature in GOLD_STANDARD_FEATURES:
        if feature in ["src_ip", "dst_ip"]:
            dummy_data[feature] = ["0.0.0.0"] * packet_count
        elif feature in ["src_port", "dst_port"]:
            dummy_data[feature] = [0] * packet_count
        elif feature == "protocol":
            dummy_data[feature] = [6] * packet_count  # TCP
        elif feature == "timestamp":
            dummy_data[feature] = [datetime.now().isoformat()] * packet_count
        else:
            dummy_data[feature] = [0.0] * packet_count
    
    return pd.DataFrame(dummy_data)


def _producer_heartbeat_worker(stop_event: threading.Event, interval: int = 10):
    while not stop_event.wait(interval):
        log_heartbeat("producer", "alive")


def main_loop():
    global KAFKA_PRODUCER

    print(f"\n📡 Ağ Dinleniyor: {INTERFACE}")
    print(f"📤 Kafka Topic: {KAFKA_TOPIC}")
    print("⏹️  Durdurmak için CTRL+C yapın...\n")

    _hb_stop = threading.Event()
    _hb_thread = threading.Thread(target=_producer_heartbeat_worker, args=(_hb_stop,), daemon=True)
    _hb_thread.start()

    packet_buffer = []
    buffered_windows = 0
    last_stats_window = 0

    while True:
        try:
            print("⏳ Paket toplanıyor...", end="\r")
            packets = sniff(iface=INTERFACE, timeout=CAPTURE_TIMEOUT_SECONDS)

            if len(packets) > 0:
                PRODUCER_STATS["capture_windows"] += 1
                packet_buffer.extend(list(packets))
                packet_buffer = trim_packet_buffer(packet_buffer)
                buffered_windows = min(buffered_windows + 1, MAX_BUFFER_WINDOWS)

                total_packets = len(packet_buffer)
                extractable_packets = count_extractable_packets(packet_buffer)

                if total_packets < MIN_BUFFER_PACKETS or extractable_packets < MIN_BUFFER_FLOW_PACKETS:
                    print(
                        f"   ⏳ Buffering packets: total={total_packets} "
                        f"extractable={extractable_packets} "
                        f"windows={buffered_windows}/{MAX_BUFFER_WINDOWS}",
                        end="\r",
                    )
                    continue

                wrpcap(TEMP_PCAP, packet_buffer)
                result = feature_extraction_and_predict()

                if result["success"]:
                    packet_buffer = []
                    buffered_windows = 0
                else:
                    PRODUCER_STATS["skipped_windows"] += 1
                    if buffered_windows >= MAX_BUFFER_WINDOWS:
                        retained_packets = max(MIN_BUFFER_PACKETS, MAX_BUFFER_PACKETS // 2)
                        packet_buffer = packet_buffer[-retained_packets:]
                        buffered_windows = max(1, MAX_BUFFER_WINDOWS // 2)
                        print(
                            "   ⚠️ Keeping the most recent buffered traffic after extraction failure "
                            f"({result['reason']})"
                        )
            else:
                print(f"⚠️ 0 Paket! '{INTERFACE}' ismini kontrol et.        ", end="\r")

            if (
                PRODUCER_STATS["capture_windows"] > 0
                and PRODUCER_STATS["capture_windows"] % 10 == 0
                and PRODUCER_STATS["capture_windows"] != last_stats_window
            ):
                print_producer_stats()
                last_stats_window = PRODUCER_STATS["capture_windows"]

        except KeyboardInterrupt:
            _hb_stop.set()
            print("\n🛑 Sistem kullanıcı tarafından durduruldu.")
            if KAFKA_PRODUCER is not None:
                print("⏳ Kafka Producer kapatılıyor...")
                KAFKA_PRODUCER.flush(timeout=5)
                print("✅ Kafka Producer kapatıldı.")
            print_producer_stats()
            break
        except Exception as e:
            print(f"⚠️ Ana döngü hatası: {e}")
            time.sleep(1)


if __name__ == "__main__":
    main_loop()
