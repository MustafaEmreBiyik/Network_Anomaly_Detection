● Now I have a complete picture. Let me build the execution plan.

● Here is the full sprint execution plan with teaching context at every step.

  ---
  Sprint 8 May — Execution Plan & Learning Guide

  What you're building

  A reliable, observable, end-to-end network intrusion detection pipeline on Windows. Right now the pipeline has the plumbing but it leaks in several places. This sprint makes it
   production-solid.

  The data path:
  run_system.py
    → live_bridge.py  (captures packets → extracts features → publishes to Kafka)
    → Kafka broker    (message queue decoupling producer from consumer)
    → kafka_consumer.py  (subscribes → predicts → writes CSV + DB)
    → dashboard/app.py   (reads CSV + DB → displays live state)

  ---
  What the codebase audit found

  Before touching anything, here is the exact state of each problem:

  ┌───────┬────────────────────────────────┬─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │  ID   │              File              │                                                         Problem                                                         │
  ├───────┼────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ S1-01 │ kafka_consumer.py:283 and :436 │ process_message() defined twice — second silently overwrites first                                                      │
  ├───────┼────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ S1-01 │ live_bridge.py:1233 and :1270  │ main_loop() defined twice — second silently overwrites first                                                            │
  ├───────┼────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ S1-02 │ All three entry points         │ Model paths are hardcoded and inconsistent across run_system.py, kafka_consumer.py, and dashboard/app.py                │
  ├───────┼────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ S1-03 │ kafka_consumer.py              │ Confidence score is hardcoded to predict_proba()[0][1] — always grabs class index 1 (Volumetric), not the winning class │
  ├───────┼────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ S1-04 │ live_bridge.py                 │ On extraction failure, producer sends dummy/fake feature rows into Kafka — contaminates analytics                       │
  ├───────┼────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ S1-05 │ db_manager.py                  │ Only alerts table exists — pipeline_events and service_heartbeats are missing                                           │
  ├───────┼────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ S1-06 │ run_system.py                  │ No preflight checks for Docker, ports, model files, or Python packages                                                  │
  ├───────┼────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ S1-07 │ requirements.txt               │ Runtime scikit-learn==1.7.2, but persisted scaler was serialized with 1.3.0 — warning on every load                     │
  ├───────┼────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ S1-08 │ test/                          │ Only attack traffic generator exists — no replay/smoke tests                                                            │
  └───────┴────────────────────────────────┴─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘

  ---
  Sprint 1 Execution Order (follow this exactly)

  Why this order matters

  Each task is a dependency for the next. You cannot test correct predictions (S1-03) until you have one clean consumer path (S1-01). You cannot build telemetry (S1-05) until the
   registry exists (S1-02). Fixing dependencies last (S1-07) avoids re-fixing broken imports after refactors.

  ---
  S1-01 — Remove duplicate runtime branches

  Priority: P0 | Size: M | Do this first.

  What you'll learn: In Python, when you define a function twice in the same file, the second definition silently replaces the first. No error, no warning. This is one of the
  most dangerous silent bugs in Python.

  What to do:

  In src/kafka_consumer.py:
  - Lines 283–433: first process_message() — this is the one with full schema alignment and probability logic. Keep this.
  - Lines 436–575: second process_message() — this is a legacy branch. Delete this entire block.
  - Check that there is one if __name__ == "__main__" block and one consumer loop.

  In src/live_bridge.py:
  - Lines 1233–1268: first main_loop() — inspect which extraction path it uses.
  - Lines 1270–1341: second main_loop() — this one silently wins right now.
  - Read both carefully. Keep the one that uses the Python API first with CLI fallback and does not generate dummy features. Delete the other.

  Verification: After deleting, grep -n "def process_message" src/kafka_consumer.py should return exactly one line. Same for main_loop in live_bridge.py.

  ---
  S1-02 — Build shared model registry

  Priority: P0 | Size: L

  What you'll learn: A "registry pattern" — a single source of truth that multiple parts of the system read from. Instead of each file knowing which model files exist, one module
   owns that knowledge and exports it.

  What to create:

  New file: src/model_registry.py

  MODEL_REGISTRY = {
      "Random Forest": {
          "display_name": "Random Forest (3-class)",
          "artifact_path": "models/rf_3class_model.pkl",
          "config_path": "models/rf_3class_config.json",
          "scaler_path": "models/scaler_ml_3class.pkl",
          "class_names": ["Benign", "Volumetric", "Semantic"],
          "input_kind": "tabular",
          "input_shape": (20,),
          "live_supported": True,
      },
      "Decision Tree": {
          "display_name": "Decision Tree (3-class)",
          "artifact_path": "models/dt_3class_model.pkl",
          "config_path": None,
          "scaler_path": "models/scaler_ml_3class.pkl",
          "class_names": ["Benign", "Volumetric", "Semantic"],
          "input_kind": "tabular",
          "input_shape": (20,),
          "live_supported": True,
      },
      "XGBoost": {
          "display_name": "XGBoost (3-class)",
          "artifact_path": "models/xgb_3class_model.pkl",
          "config_path": "models/xgb_3class_config.json",
          "scaler_path": "models/scaler_ml_3class.pkl",
          "class_names": ["Benign", "Volumetric", "Semantic"],
          "input_kind": "tabular",
          "input_shape": (20,),
          "live_supported": True,
      },
      "LSTM": {
          "display_name": "LSTM (sequence, 10×20)",
          "artifact_path": "models/lstm_model.keras",
          "config_path": "models/lstm_config.json",
          "scaler_path": "models/scaler_lstm.pkl",
          "class_names": ["Benign", "Volumetric", "Semantic"],
          "input_kind": "sequence",
          "input_shape": (10, 20),
          "live_supported": False,  # enabled in Sprint 2
      },
      "BiLSTM": {
          "display_name": "BiLSTM (sequence, 10×20)",
          "artifact_path": "models/bilstm_model.keras",
          "config_path": "models/bilstm_config.json",
          "scaler_path": "models/scaler_lstm.pkl",
          "class_names": ["Benign", "Volumetric", "Semantic"],
          "input_kind": "sequence",
          "input_shape": (10, 20),
          "live_supported": False,  # enabled in Sprint 2
      },
  }

  LIVE_MODELS = {k: v for k, v in MODEL_REGISTRY.items() if v["live_supported"]}
  DEFAULT_MODEL = "Random Forest"

  Then update each entry point to import from this module instead of using local constants.

  Verification: from src.model_registry import MODEL_REGISTRY should work from project root. Each consumer/dashboard model dropdown should pull from LIVE_MODELS.

  ---
  S1-03 — Correct 3-class prediction output

  Priority: P0 | Size: M

  What you'll learn: predict_proba() returns a probability for every class, ordered by class index. The confidence score must come from the column matching the predicted class
  index, not a hardcoded column.

  The bug in the current consumer:
  # WRONG — always reads column 1 (Volumetric) regardless of what was predicted
  confidence = probabilities[0][1]

  # CORRECT
  predicted_label = model.predict(X_scaled)[0]
  probabilities = model.predict_proba(X_scaled)[0]
  confidence = probabilities[predicted_label]   # index matches the winning class
  prob_benign = probabilities[0]
  prob_volumetric = probabilities[1]
  prob_semantic = probabilities[2]

  Action semantics to implement:
  - predicted_label == 0 (Benign) → Action = "NONE"
  - predicted_label > 0 and IP is whitelisted → Action = "ALLOWED"
  - predicted_label > 0 and IP is not whitelisted → Action = "BLOCKED" or "DETECTED" based on whether firewall actually blocked it

  The v2 CSV columns to emit (replace the current 7-column schema):
  Timestamp, Src_IP, Dst_IP, Predicted_Label, Class_Name, Confidence_Score,
  Prob_Benign, Prob_Volumetric, Prob_Semantic, Model_Used, Model_Type,
  Producer_ID, Feature_Count, Schema_Adjusted, Processing_Time_Ms, Action

  ---
  S1-04 — Lock producer feature contract

  Priority: P0 | Size: M

  What you'll learn: Garbage in, garbage out. If the producer sends fake data when real extraction fails, every downstream component — the consumer, the model, the dashboard, the
   analytics — is silently corrupted. The right failure mode is to log the failure and skip the message entirely.

  Find and remove the dummy feature generation block in live_bridge.py. It looks like:
  # remove this entire block
  dummy_features = {col: 0.0 for col in EXPECTED_FEATURES}
  producer.produce(topic, json.dumps({...dummy_features...}))

  Replace with:
  logger.warning("Extraction failed — skipping Kafka publish for this window")
  # emit telemetry event instead (used in S1-05)

  The producer's authoritative feature list must come from loading the scaler and reading scaler.feature_names_in_. That is the ground truth — not any hardcoded list.

  import joblib
  scaler = joblib.load("models/scaler_ml_3class.pkl")
  FEATURE_CONTRACT = list(scaler.feature_names_in_)  # exactly 20 names

  The produced Kafka message must also include schema_version: "v2" and extraction_method: "api" | "cli".

  ---
  S1-07 — Stabilize dependency versions

  Priority: P0 | Size: M | Do before S1-05 to avoid broken imports

  What you'll learn: Python pickle-based model serialization embeds the scikit-learn version. When you load a .pkl from scikit-learn 1.3.0 using scikit-learn 1.7.2, you get a
  InconsistentVersionWarning. This is non-fatal now but can break in minor version jumps.

  The right fix is to retrain and re-serialize the models using the current runtime version. The alternative (pinning the runtime down to 1.3.x) may break other dependencies.

  Action:
  1. First, load each .pkl and check what version serialized it:
  import joblib, sklearn
  scaler = joblib.load("models/scaler_ml_3class.pkl")
  print(sklearn.__version__)  # runtime version
  # The warning tells you the serialized version
  2. If retraining is feasible: retrain RF/DT/XGB using scikit-learn==1.7.2 and re-save.
  3. If not feasible now: add version pinning to requirements.txt and document the constraint.
  4. Verify the exact live-supported stack:
  scikit-learn==X.Y.Z
  confluent-kafka==X.Y.Z
  streamlit==X.Y.Z
  tensorflow==X.Y.Z
  scapy==X.Y.Z

  ---
  S1-05 — Add true runtime telemetry

  Priority: P0 | Size: L

  What you'll learn: Observability — the ability to understand what a running system is doing without reading its terminal output. You're adding three new database tables that
  serve as structured logs the dashboard can query.

  Extend src/utils/db_manager.py with three new tables:

  # pipeline_events: every error, schema adjustment, model reload, Kafka disconnect
  # service_heartbeats: each service stamps itself alive with a timestamp
  # alerts: already exists — keep it

  def log_pipeline_event(service, severity, summary, details=None):
      # INSERT INTO pipeline_events ...

  def log_heartbeat(service, status, metadata=None):
      # INSERT INTO service_heartbeats (service, timestamp, status) ...

  def fetch_recent_events(limit=50):
      # SELECT * FROM pipeline_events ORDER BY timestamp DESC LIMIT ?

  def get_service_health():
      # SELECT service, MAX(timestamp), status FROM service_heartbeats GROUP BY service

  Each service emits heartbeats on a background thread (every 10 seconds):
  - live_bridge.py → log_heartbeat("producer", "alive")
  - kafka_consumer.py → log_heartbeat("consumer", "alive")
  - dashboard/app.py → log_heartbeat("dashboard", "alive")

  Events to emit (not just print to console):
  - Kafka connect/disconnect
  - Extraction failure (was printing, now also logs to DB)
  - Schema adjustment applied
  - Message rejected
  - Model reload triggered
  - Consumer processing error

  ---
  S1-06 — Add launcher preflight checks

  Priority: P1 | Size: M

  What you'll learn: "Fail fast" — catch configuration problems at startup before they cause silent failures minutes later. A good preflight tells the user exactly what is wrong
  and exactly how to fix it.

  Add to run_system.py before spawning any processes:

  def preflight_checks():
      checks = [
          check_docker_installed,
          check_kafka_port_available,      # socket connect to 9092
          check_model_files_exist,         # from MODEL_REGISTRY
          check_active_model_registered,   # data/active_model.txt in registry
          check_network_interface,         # interface from .env is resolvable
          check_python_imports,            # confluent_kafka, sklearn, tensorflow
          check_no_duplicate_processes,    # already partly implemented
      ]
      for check in checks:
          result = check()
          if not result.ok:
              print(f"[PREFLIGHT FAIL] {result.message}")
              print(f"  Fix: {result.fix_hint}")
              sys.exit(1)

  Each check returns a simple result object. This is also a great place to teach: rather than raising exceptions from checks, return structured results so you can report all
  failures at once if you want.

  ---
  S1-08 — Create smoke and replay coverage

  Priority: P0 | Size: L

  What you'll learn: Replay testing — running the system against a known input and asserting the output is deterministic. This is how you prevent regressions without a live
  network.

  Test files to create under test/:

  test/
    test_producer_extraction.py   — mock cicflowmeter, assert Kafka payload schema
    test_consumer_output.py       — feed a v2 Kafka message, assert CSV row shape
    test_model_registry.py        — assert all registered artifact paths exist
    test_csv_schema.py            — load a v2 CSV, assert all 16 columns present
    test_no_dummy_on_failure.py   — force extraction failure, assert no Kafka publish

  Key pattern for consumer tests:
  # Feed a fake Kafka message and call process_message() directly
  # Assert the CSV row written has correct columns and valid probabilities
  # Assert confidence == probabilities[predicted_label]

  ---
  Sprint 2 Preview (after Sprint 1 exit criteria are met)

  ┌──────────────────────────────────┬────────────────────────────────────────────────────────────────────────────────────────────────┐
  │               Task               │                                   Core concept you'll learn                                    │
  ├──────────────────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ S2-01 Rolling LSTM inference     │ Stateful streaming buffers — accumulate N rows before predicting                               │
  ├──────────────────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ S2-02 Sequence UI state          │ How to surface "warm-up" state to operators so they don't mistake it for failure               │
  ├──────────────────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ S2-03 Model certification matrix │ Evidence-based enablement — a model must prove it works before it appears in the live selector │
  ├──────────────────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ S2-04 Debug dashboard panels     │ Pulling from DB telemetry instead of file modification times                                   │
  ├──────────────────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ S2-06 Recovery scenarios         │ Idempotent consumer restart, Kafka offset semantics, latest vs earliest                        │
  └──────────────────────────────────┴────────────────────────────────────────────────────────────────────────────────────────────────┘

  ---
  Sprint 1 Exit Checklist

  Before declaring Sprint 1 done, verify each of these manually:

  - grep -c "def process_message" src/kafka_consumer.py prints 1
  - grep -c "def main_loop" src/live_bridge.py prints 1
  - from src.model_registry import MODEL_REGISTRY works
  │ S2-06 Recovery scenarios         │ Idempotent consumer restart, Kafka offset semantics, latest vs earliest                        │
  └──────────────────────────────────┴────────────────────────────────────────────────────────────────────────────────────────────────┘

  ---
  Sprint 1 Exit Checklist

  Before declaring Sprint 1 done, verify each of these manually:

  - grep -c "def process_message" src/kafka_consumer.py prints 1
  - grep -c "def main_loop" src/live_bridge.py prints 1
  - from src.model_registry import MODEL_REGISTRY works
  - Producer sends schema_version: "v2" in every message
  - Producer sends nothing when cicflowmeter fails (check consumer CSV — no zero-feature rows)
  - Consumer CSV has all 16 v2 columns
  - confidence_score equals probabilities[predicted_label] (not always index 1)
  - db_manager.py has pipeline_events and service_heartbeats tables
  - run_system.py fails with a clear message if port 9092 is not reachable
  - scikit-learn version warning is gone on model load
  - All smoke tests in test/ pass

  ---
  How we'll work through this

  Recommended approach:
  1. I read the actual duplicate code blocks first before touching anything — so you can see exactly what's being removed and why
  2. We go task by task in S1 order
  3. After each task, you run the verification step so the change is confirmed before we move on
  4. I explain the concept at the point we encounter it in real code, not in the abstract

  Ready to start with S1-01? Type "start S1-01" and I'll read both duplicate blocks, show you exactly what each one does, explain why the second silently wins in Python, and then
   make the surgical cut.

✻ Churned for 3m 23s

※ recap: Building a reliable network intrusion detection pipeline. The plan is ready and we're starting with S1-01, removing duplicate function definitions in kafka_consumer.py
  and live_bridge.py. Type "start S1-01" to begin. (disable recaps in /config)