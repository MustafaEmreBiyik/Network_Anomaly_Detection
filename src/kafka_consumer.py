#!/usr/bin/env python3
"""
Kafka Consumer for Network Anomaly Detection System
Consumes network flow features from Kafka, runs ML prediction, and logs results.
"""

import os
import sys
import json
import time
import shutil
import threading
import joblib
import pandas as pd
import numpy as np
from datetime import datetime
from confluent_kafka import Consumer, KafkaError

# ---------------------------------------------------------------------------
# PATH SETUP
# ---------------------------------------------------------------------------
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
CSV_OUTPUT_PATH = os.path.join(PROJECT_ROOT, "data", "live_captured_traffic.csv")
ACTIVE_MODEL_CONFIG = os.path.join(PROJECT_ROOT, "data", "active_model.txt")

# Add src and utils to path
sys.path.insert(0, CURRENT_DIR)
sys.path.append(os.path.join(CURRENT_DIR, "utils"))

from model_registry import MODEL_REGISTRY, LIVE_MODELS, DEFAULT_MODEL

try:
    from db_manager import log_attack, log_heartbeat, log_pipeline_event
    from firewall_manager import block_ip
    DB_AVAILABLE = True
except ImportError:
    print("⚠️  WARNING: db_manager or firewall_manager not found. Logging disabled.")
    DB_AVAILABLE = False
    def log_attack(*args, **kwargs):
        pass
    def log_heartbeat(*args, **kwargs):
        pass
    def log_pipeline_event(*args, **kwargs):
        pass
    def block_ip(*args, **kwargs):
        pass

# ---------------------------------------------------------------------------
# ANSI COLOR CODES
# ---------------------------------------------------------------------------
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
RESET = '\033[0m'
BOLD = '\033[1m'

# ---------------------------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------------------------
KAFKA_BOOTSTRAP_SERVERS = '127.0.0.1:9092'
KAFKA_TOPIC = 'network-traffic'
KAFKA_GROUP_ID = os.getenv("KAFKA_GROUP_ID", "nids-consumer-group-v2")
KAFKA_AUTO_OFFSET_RESET = os.getenv("KAFKA_AUTO_OFFSET_RESET", "latest")
WHITELIST_IPS = os.getenv("WHITELIST_IPS", "192.168.1.1,127.0.0.1,0.0.0.0,localhost").split(",")
CSV_HEADER_COLUMNS = [
    "Timestamp",
    "Src_IP",
    "Dst_IP",
    "Predicted_Label",
    "Class_Name",
    "Confidence_Score",
    "Prob_Benign",
    "Prob_Volumetric",
    "Prob_Semantic",
    "Model_Used",
    "Model_Type",
    "Producer_ID",
    "Feature_Count",
    "Schema_Adjusted",
    "Processing_Time_Ms",
    "Action",
]
# ---------------------------------------------------------------------------
# GLOBAL MODEL & SCALER
# ---------------------------------------------------------------------------
MODEL = None
SCALER = None
CURRENT_MODEL_NAME = DEFAULT_MODEL
CURRENT_MODEL_TYPE = "sklearn"  # 'sklearn' or 'keras'
LAST_CONFIG_CHECK = 0  # Timestamp of last config file check
CONFIG_CHECK_INTERVAL = 5  # Check config file every 5 seconds

# Statistics tracking
STATS = {
    "total_processed": 0,
    "attacks_detected": 0,
    "clean_traffic": 0,
    "rejected_messages": 0,
    "schema_adjustments": 0,
    "errors": 0,
    "start_time": datetime.now()
}


def get_expected_feature_names():
    if SCALER is not None and hasattr(SCALER, "feature_names_in_"):
        return list(SCALER.feature_names_in_)
    return []





def initialize_csv_file():
    """Initialize CSV output file with headers if it doesn't exist."""
    os.makedirs(os.path.dirname(CSV_OUTPUT_PATH), exist_ok=True)

    if os.path.exists(CSV_OUTPUT_PATH):
        try:
            existing_header = list(pd.read_csv(CSV_OUTPUT_PATH, nrows=0).columns)
        except Exception as exc:
            existing_header = None
            print(f"{YELLOW}⚠️  Existing CSV could not be parsed: {exc}{RESET}")

        if existing_header == CSV_HEADER_COLUMNS:
            print(f"{CYAN}ℹ️  Using existing CSV: {CSV_OUTPUT_PATH}{RESET}")
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = CSV_OUTPUT_PATH.replace(".csv", f".invalid_{timestamp}.csv")
        shutil.move(CSV_OUTPUT_PATH, backup_path)
        print(f"{YELLOW}⚠️  Existing CSV schema mismatch; moved to: {backup_path}{RESET}")
        if existing_header is not None:
            print(f"{YELLOW}   Found columns: {existing_header}{RESET}")

    header_df = pd.DataFrame(columns=CSV_HEADER_COLUMNS)
    header_df.to_csv(CSV_OUTPUT_PATH, index=False)
    print(f"{GREEN}✅ CSV output file initialized: {CSV_OUTPUT_PATH}{RESET}")


_FILENAME_TO_REGISTRY_KEY = {
    os.path.basename(v["artifact_path"]): k
    for k, v in MODEL_REGISTRY.items()
}


def _resolve_registry_key(model_key_or_filename):
    """Return a MODEL_REGISTRY key given either a registry key or a bare filename."""
    if model_key_or_filename in MODEL_REGISTRY:
        return model_key_or_filename
    mapped = _FILENAME_TO_REGISTRY_KEY.get(model_key_or_filename)
    if mapped:
        print(f"{YELLOW}⚠️  Mapping filename '{model_key_or_filename}' → registry key '{mapped}'{RESET}")
        return mapped
    return None


def load_model_and_scaler(model_key=None):
    """Load the ML model and scaler from MODEL_REGISTRY.

    Args:
        model_key: Registry key (e.g. 'Random Forest') or bare filename for
                   backward compatibility. If None, reads from active_model.txt.
    """
    global MODEL, SCALER, CURRENT_MODEL_NAME, CURRENT_MODEL_TYPE

    if model_key is None:
        if os.path.exists(ACTIVE_MODEL_CONFIG):
            try:
                with open(ACTIVE_MODEL_CONFIG, "r") as f:
                    model_key = f.read().strip()
            except Exception:
                model_key = DEFAULT_MODEL
        else:
            model_key = DEFAULT_MODEL
            os.makedirs(os.path.dirname(ACTIVE_MODEL_CONFIG), exist_ok=True)
            try:
                with open(ACTIVE_MODEL_CONFIG, "w") as f:
                    f.write(model_key)
            except Exception:
                pass

    registry_key = _resolve_registry_key(model_key)
    if registry_key is None:
        print(f"{RED}❌ CRITICAL ERROR: '{model_key}' is not a known registry key or model filename.{RESET}")
        print(f"   Known models: {list(MODEL_REGISTRY.keys())}")
        sys.exit(1)

    entry = MODEL_REGISTRY[registry_key]
    model_path = entry["artifact_path"]
    scaler_path = entry["scaler_path"]

    print(f"\n{CYAN}{'='*60}{RESET}")
    print(f"{BOLD}🔧 Loading ML Model & Scaler...{RESET}")
    print(f"{CYAN}{'='*60}{RESET}")
    print(f"{CYAN}   Registry key: {registry_key}{RESET}")
    print(f"{CYAN}   Artifact:     {model_path}{RESET}")
    print(f"{CYAN}   Scaler:       {scaler_path}{RESET}")

    if not os.path.exists(model_path):
        print(f"{RED}❌ CRITICAL ERROR: Model file not found: {model_path}{RESET}")
        sys.exit(1)

    is_keras_model = model_path.endswith((".keras", ".h5"))

    try:
        if is_keras_model:
            try:
                from tensorflow.keras.models import load_model as keras_load_model
            except ImportError:
                print(f"{RED}❌ ERROR: TensorFlow not installed. pip install tensorflow{RESET}")
                sys.exit(1)
            MODEL = keras_load_model(model_path)
            CURRENT_MODEL_TYPE = "keras"
            print(f"{GREEN}✅ Keras model loaded{RESET}")
        else:
            MODEL = joblib.load(model_path)
            CURRENT_MODEL_TYPE = "sklearn"
            print(f"{GREEN}✅ Scikit-learn model loaded ({type(MODEL).__name__}){RESET}")

        if scaler_path and os.path.exists(scaler_path):
            SCALER = joblib.load(scaler_path)
            print(f"{GREEN}✅ Scaler loaded{RESET}")
        else:
            print(f"{YELLOW}⚠️  Scaler not found at {scaler_path} — predictions may be inaccurate{RESET}")
            SCALER = None

        CURRENT_MODEL_NAME = registry_key
        expected_feature_names = get_expected_feature_names()
        if expected_feature_names:
            print(f"{CYAN}   Features expected by scaler: {len(expected_feature_names)}{RESET}\n")
        else:
            print(f"{YELLOW}   WARNING: scaler has no feature_names_in_; schema checks limited{RESET}\n")

    except Exception as exc:
        print(f"{RED}❌ CRITICAL ERROR: Failed to load model/scaler!{RESET}")
        print(f"   Error: {exc}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


def create_consumer():
    """Initialize and return Kafka Consumer instance."""
    print(f"{CYAN}{'='*60}{RESET}")
    print(f"{BOLD}📡 Initializing Kafka Consumer...{RESET}")
    print(f"{CYAN}{'='*60}{RESET}")
    
    conf = {
        'bootstrap.servers': KAFKA_BOOTSTRAP_SERVERS,
        'group.id': KAFKA_GROUP_ID,
        'auto.offset.reset': KAFKA_AUTO_OFFSET_RESET,
        'enable.auto.commit': True,
        'auto.commit.interval.ms': 5000,
        'session.timeout.ms': 30000,
        'max.poll.interval.ms': 300000
    }
    
    try:
        consumer = Consumer(conf)
        consumer.subscribe([KAFKA_TOPIC])
        print(f"{GREEN}✅ Consumer connected to Kafka{RESET}")
        print(f"{CYAN}   Bootstrap servers: {KAFKA_BOOTSTRAP_SERVERS}{RESET}")
        print(f"{CYAN}   Topic: {KAFKA_TOPIC}{RESET}")
        print(f"{CYAN}   Group ID: {KAFKA_GROUP_ID}{RESET}\n")
        print(f"{CYAN}   Auto offset reset: {KAFKA_AUTO_OFFSET_RESET}{RESET}\n")
        return consumer
    except Exception as exc:
        print(f"{RED}❌ CRITICAL ERROR: Failed to create Kafka consumer!{RESET}")
        print(f"   Error: {exc}")
        print(f"\n{YELLOW}💡 Make sure Kafka is running: docker-compose up -d{RESET}")
        sys.exit(1)


def process_message(message_value):
    """
    Process a single Kafka message: parse, validate, predict, log.

    Args:
        message_value: Raw message bytes from Kafka

    Returns:
        bool: True if processing successful, False otherwise
    """
    start_time = time.time()

    try:
        message_data = json.loads(message_value.decode("utf-8"))

        timestamp = message_data.get("timestamp", datetime.now().isoformat())
        src_ip = message_data.get("src_ip", "Unknown")
        dst_ip = message_data.get("dst_ip", "Unknown")
        features_dict = message_data.get("features", {})
        producer_id = message_data.get("producer_id", "unknown")

        if not isinstance(features_dict, dict) or not features_dict:
            print(f"{YELLOW}⚠️  Rejected message from {producer_id}: empty or invalid feature payload{RESET}")
            STATS["rejected_messages"] += 1
            return False

        expected_features = get_expected_feature_names()
        incoming_feature_names = list(features_dict.keys())
        features_df = pd.DataFrame([features_dict])
        schema_adjusted = False

        if expected_features:
            missing_features = [col for col in expected_features if col not in features_dict]
            extra_features = [col for col in incoming_feature_names if col not in expected_features]
            shared_features = len(expected_features) - len(missing_features)

            if shared_features == 0:
                print(
                    f"{YELLOW}⚠️  Rejected message from {producer_id}: no overlap with scaler schema "
                    f"(incoming={len(incoming_feature_names)}, expected={len(expected_features)}){RESET}"
                )
                STATS["rejected_messages"] += 1
                return False

            if missing_features or extra_features:
                schema_adjusted = True
                STATS["schema_adjustments"] += 1
                print(
                    f"{CYAN}ℹ️  Schema adjusted from {producer_id}: "
                    f"incoming={len(incoming_feature_names)} expected={len(expected_features)} "
                    f"missing={len(missing_features)} extra={len(extra_features)}{RESET}"
                )

            features_df = features_df.reindex(columns=expected_features, fill_value=0.0)

        try:
            features_scaled = SCALER.transform(features_df)
            features_scaled_df = pd.DataFrame(
                features_scaled,
                columns=features_df.columns,
                index=features_df.index,
            )
        except Exception as exc:
            print(f"{RED}⚠️  Scaling error: {exc}{RESET}")
            features_df = features_df.fillna(0)
            features_scaled = SCALER.transform(features_df)
            features_scaled_df = pd.DataFrame(
                features_scaled,
                columns=features_df.columns,
            )

        class_names = MODEL_REGISTRY.get(CURRENT_MODEL_NAME, {}).get(
            "class_names", ["Benign", "Volumetric", "Semantic"]
        )
        prob_benign = prob_volumetric = prob_semantic = 0.0

        if CURRENT_MODEL_TYPE == "keras":
            features_for_prediction = features_scaled.reshape(
                (features_scaled.shape[0], 1, features_scaled.shape[1])
            )
            prediction_proba = MODEL.predict(features_for_prediction, verbose=0)[0]

            if len(prediction_proba) == 1:
                confidence_score = float(prediction_proba[0])
                prediction = 1 if confidence_score > 0.5 else 0
            else:
                prediction = int(np.argmax(prediction_proba))
                confidence_score = float(prediction_proba[prediction])
                if len(prediction_proba) >= 3:
                    prob_benign, prob_volumetric, prob_semantic = (
                        float(prediction_proba[0]),
                        float(prediction_proba[1]),
                        float(prediction_proba[2]),
                    )
        else:
            prediction = int(MODEL.predict(features_scaled_df)[0])
            try:
                probabilities = MODEL.predict_proba(features_scaled_df)[0]
                confidence_score = float(probabilities[prediction])  # winning class index
                if len(probabilities) >= 3:
                    prob_benign = float(probabilities[0])
                    prob_volumetric = float(probabilities[1])
                    prob_semantic = float(probabilities[2])
                elif len(probabilities) == 2:
                    prob_benign = float(probabilities[0])
                    prob_volumetric = float(probabilities[1])
            except AttributeError:
                confidence_score = float(prediction)

        class_name = class_names[prediction] if prediction < len(class_names) else str(prediction)
        is_attack = prediction > 0
        processing_time_ms = (time.time() - start_time) * 1000

        if not is_attack:
            action = "NONE"
        elif src_ip in WHITELIST_IPS or src_ip == "Unknown":
            action = "ALLOWED"
        else:
            action = "BLOCKED"

        log_entry = {
            "Timestamp": timestamp,
            "Src_IP": src_ip,
            "Dst_IP": dst_ip,
            "Predicted_Label": prediction,
            "Class_Name": class_name,
            "Confidence_Score": round(confidence_score, 4),
            "Prob_Benign": round(prob_benign, 4),
            "Prob_Volumetric": round(prob_volumetric, 4),
            "Prob_Semantic": round(prob_semantic, 4),
            "Model_Used": CURRENT_MODEL_NAME,
            "Model_Type": CURRENT_MODEL_TYPE,
            "Producer_ID": producer_id,
            "Feature_Count": len(features_df.columns),
            "Schema_Adjusted": schema_adjusted,
            "Processing_Time_Ms": round(processing_time_ms, 2),
            "Action": action,
        }

        pd.DataFrame([log_entry]).to_csv(CSV_OUTPUT_PATH, mode="a", header=False, index=False)

        if DB_AVAILABLE:
            if is_attack:
                log_attack(src_ip, action, f"{class_name} detected (confidence: {confidence_score:.2%})")

        STATS["total_processed"] += 1
        if is_attack:
            STATS["attacks_detected"] += 1
        else:
            STATS["clean_traffic"] += 1

        current_time = datetime.now().strftime("%H:%M:%S")
        if is_attack:
            print(f"{RED}{BOLD}🚨 [{current_time}] ALERT: {class_name.upper()} DETECTED!{RESET}")
            print(f"{RED}   Source IP: {src_ip} → Destination: {dst_ip}{RESET}")
            print(f"{RED}   Confidence: {confidence_score:.2%} | Action: {action} | {processing_time_ms:.2f}ms{RESET}")
        else:
            print(f"{GREEN}✅ [{current_time}] Clean Traffic{RESET}", end="")
            print(f"{GREEN} | {src_ip} → {dst_ip} | Confidence: {confidence_score:.2%} | {processing_time_ms:.2f}ms{RESET}")

        return True

    except json.JSONDecodeError as exc:
        print(f"{RED}⚠️  JSON parsing error: {exc}{RESET}")
        STATS["errors"] += 1
        return False
    except Exception as exc:
        print(f"{RED}⚠️  Processing error: {exc}{RESET}")
        import traceback
        traceback.print_exc()
        STATS["errors"] += 1
        return False


def print_statistics():
    """Print consumer statistics."""
    runtime = datetime.now() - STATS["start_time"]
    runtime_seconds = runtime.total_seconds()
    
    print(f"\n{CYAN}{'='*60}{RESET}")
    print(f"{BOLD}📊 CONSUMER STATISTICS{RESET}")
    print(f"{CYAN}{'='*60}{RESET}")
    print(f"   Runtime: {runtime}")
    print(f"   Total Processed: {STATS['total_processed']}")
    print(f"   {RED}Attacks Detected: {STATS['attacks_detected']}{RESET}")
    print(f"   {GREEN}Clean Traffic: {STATS['clean_traffic']}{RESET}")
    print(f"   {YELLOW}Rejected Messages: {STATS['rejected_messages']}{RESET}")
    print(f"   {CYAN}Schema Adjustments: {STATS['schema_adjustments']}{RESET}")
    print(f"   {YELLOW}Errors: {STATS['errors']}{RESET}")
    if runtime_seconds > 0:
        print(f"   Throughput: {STATS['total_processed']/runtime_seconds:.2f} messages/sec")
    print(f"{CYAN}{'='*60}{RESET}\n")


def check_and_reload_model():
    """Check if model config has changed and reload if necessary."""
    global LAST_CONFIG_CHECK, CURRENT_MODEL_NAME
    
    current_time = time.time()
    
    # Only check every CONFIG_CHECK_INTERVAL seconds
    if current_time - LAST_CONFIG_CHECK < CONFIG_CHECK_INTERVAL:
        return
    
    LAST_CONFIG_CHECK = current_time
    
    # Read current config
    if not os.path.exists(ACTIVE_MODEL_CONFIG):
        return
    
    try:
        with open(ACTIVE_MODEL_CONFIG, 'r') as f:
            requested_model = f.read().strip()
        
        # Check if model changed
        if requested_model != CURRENT_MODEL_NAME:
            print(f"\n{YELLOW}{'='*60}{RESET}")
            print(f"{BOLD}{YELLOW}🔄 MODEL SWITCH DETECTED!{RESET}")
            print(f"{YELLOW}   Current: {CURRENT_MODEL_NAME}{RESET}")
            print(f"{YELLOW}   New:     {requested_model}{RESET}")
            print(f"{YELLOW}{'='*60}{RESET}")
            
            # Reload model
            load_model_and_scaler(requested_model)
            
            print(f"{GREEN}✅ Model switch complete! Now using: {CURRENT_MODEL_NAME}{RESET}\n")
    except Exception as e:
        print(f"{RED}⚠️  Error checking model config: {e}{RESET}")


def _heartbeat_worker(stop_event: threading.Event, interval: int = 10):
    """Background thread: stamps consumer alive in DB every `interval` seconds."""
    while not stop_event.wait(interval):
        log_heartbeat("consumer", "alive")


def main():
    """Main consumer loop."""
    print(f"\n{BOLD}{CYAN}╔{'═'*58}╗{RESET}")
    print(f"{BOLD}{CYAN}║{' '*10}  KAFKA CONSUMER - NETWORK IPS{' '*15}║{RESET}")
    print(f"{BOLD}{CYAN}╚{'═'*58}╝{RESET}\n")

    # Initialize components
    load_model_and_scaler()
    initialize_csv_file()
    consumer = create_consumer()

    _hb_stop = threading.Event()
    _hb_thread = threading.Thread(target=_heartbeat_worker, args=(_hb_stop,), daemon=True)
    _hb_thread.start()
    
    print(f"{GREEN}{BOLD}🚀 Consumer is now ACTIVE and listening for messages...{RESET}")
    print(f"{YELLOW}⏹️  Press CTRL+C to stop{RESET}")
    print(f"{CYAN}💡 Model can be changed dynamically via Dashboard{RESET}\n")
    print(f"{CYAN}{'─'*60}{RESET}\n")
    
    message_count = 0
    last_stats_print = time.time()
    
    try:
        while True:
            # Check if model config changed (every 5 seconds)
            check_and_reload_model()
            
            # Poll for messages
            msg = consumer.poll(timeout=1.0)
            
            if msg is None:
                # No message available, continue polling
                continue
            
            if msg.error():
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    # End of partition, not an error
                    continue
                else:
                    print(f"{RED}⚠️  Kafka error: {msg.error()}{RESET}")
                    continue
            
            # Process the message
            message_count += 1
            process_message(msg.value())
            
            # Print statistics every 50 messages or every 30 seconds
            if message_count % 50 == 0 or (time.time() - last_stats_print) > 30:
                print_statistics()
                last_stats_print = time.time()
    
    except KeyboardInterrupt:
        print(f"\n{YELLOW}🛑 Consumer stopped by user{RESET}")
        print_statistics()
    
    except Exception as e:
        print(f"\n{RED}❌ Fatal error in consumer loop: {e}{RESET}")
        import traceback
        traceback.print_exc()
    
    finally:
        _hb_stop.set()
        print(f"{CYAN}⏳ Closing consumer...{RESET}")
        consumer.close()
        print(f"{GREEN}✅ Consumer closed successfully{RESET}")
        print(f"{CYAN}📁 Results saved to: {CSV_OUTPUT_PATH}{RESET}\n")


if __name__ == "__main__":
    main()
