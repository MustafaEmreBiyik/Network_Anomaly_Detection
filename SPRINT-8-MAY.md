# `sprint-8-may.md`

## Sprint 8 May: Kafka Pipeline Stabilization and Debug-First Dashboard

### Summary
This sprint plan is designed to make the live pipeline reliable end-to-end on the current Windows-based stack:

`run_system.py` -> `src/live_bridge.py` -> Kafka -> `src/kafka_consumer.py` -> `data/live_captured_traffic.csv` -> `src/dashboard/app.py`

The current repo already includes:
- a Kafka/Zookeeper Docker stack pinned to `7.4.0`
- a Windows launcher and startup roadmap
- a live Kafka producer and consumer
- a multi-tab Streamlit dashboard
- runtime model switching
- firewall/logging helpers

The main remaining gaps are:
- duplicate runtime code paths in the producer and consumer
- weak runtime observability
- mismatch between dashboard model options and truly safe live inference paths
- no reliable automated smoke coverage for the live pipeline
- sequence models are selectable but not yet implemented correctly for live rolling inference
- dependency/version drift, especially around `scikit-learn` artifact compatibility

This plan is split into **two execution sprints**:
- **Sprint 1**: harden the live pipeline and make debugging fast
- **Sprint 2**: finish all-model live support and upgrade the dashboard into a trustworthy operator/debug UI

---

## Important Interface Changes

### 1. Shared model registry
Create one shared source of truth used by:
- `run_system.py`
- `src/kafka_consumer.py`
- `src/dashboard/app.py`

Required registry fields:
- `display_name`
- `artifact_path`
- `config_path`
- `scaler_path`
- `class_names`
- `input_kind`
- `input_shape`
- `feature_names`
- `live_supported`

`input_kind` values:
- `tabular`
- `sequence`

Initial live models to register:
- `Random Forest` -> `models/rf_3class_model.pkl`
- `Decision Tree` -> `models/dt_3class_model.pkl`
- `XGBoost` -> `models/xgb_3class_model.pkl`
- `LSTM` -> `models/lstm_model.keras`
- `BiLSTM` -> `models/bilstm_model.keras`

### 2. Kafka message contract
Standardize the producer payload to one versioned message shape:

```json
{
  "timestamp": "ISO-8601",
  "src_ip": "string",
  "dst_ip": "string",
  "features": {},
  "feature_count": 20,
  "producer_id": "string",
  "schema_version": "v2",
  "extraction_method": "api|cli"
}
```

Rules:
- do not send dummy/fake feature rows into Kafka on extraction failure
- publish only real extracted flows
- on extraction failure, emit telemetry/logging instead of synthetic traffic

### 3. Live CSV schema
Upgrade `data/live_captured_traffic.csv` to a stable v2 schema:

- `Timestamp`
- `Src_IP`
- `Dst_IP`
- `Predicted_Label`
- `Class_Name`
- `Confidence_Score`
- `Prob_Benign`
- `Prob_Volumetric`
- `Prob_Semantic`
- `Model_Used`
- `Model_Type`
- `Producer_ID`
- `Feature_Count`
- `Schema_Adjusted`
- `Processing_Time_Ms`
- `Action`

### 4. Runtime telemetry storage
Extend `src/utils/db_manager.py` with:
- `alerts`
- `pipeline_events`
- `service_heartbeats`

Purpose:
- `alerts`: analyst-facing detections and actions
- `pipeline_events`: extraction errors, schema adjustments, model reloads, consumer rejects, Kafka connection issues
- `service_heartbeats`: producer/consumer/dashboard status and freshness

---

## Sprint 1: Pipeline Hardening and Debugging Backbone

### Goal
Make the RF/DT/XGB live path reproducible, observable, and testable with zero fake traffic and clear runtime status.

### Backlog

#### S1-01 Remove duplicate runtime branches
Priority: `P0`  
Estimate: `M`

Work:
- remove duplicate `process_message` definitions from `src/kafka_consumer.py`
- remove duplicate `main_loop` and obsolete producer branches from `src/live_bridge.py`
- keep one authoritative consumer path
- keep one authoritative producer path
- preserve only the active flow extraction path that publishes the deployed 20-feature schema

Acceptance:
- consumer file contains one live message-processing implementation
- producer file contains one live main loop
- no legacy branch can silently override current behavior

#### S1-02 Build shared model registry
Priority: `P0`  
Estimate: `L`

Work:
- replace hardcoded model mappings across launcher, consumer, and dashboard
- add metadata for Decision Tree and XGBoost 3-class artifacts
- mark models with `live_supported`
- use config-driven feature and input-shape loading where available
- dashboard model selector must read from registry, not ad hoc constants

Acceptance:
- one registry drives model selection everywhere
- live selector exposes only registered models
- artifact paths and config paths are consistent across services

#### S1-03 Correct 3-class prediction output
Priority: `P0`  
Estimate: `M`

Work:
- fix consumer probability handling so confidence reflects the predicted class, not hardcoded class index `1`
- emit:
  - predicted label
  - class name
  - per-class probabilities
  - model type
  - schema-adjusted flag
- normalize action semantics:
  - benign -> `NONE`
  - predicted attack and whitelisted -> `ALLOWED`
  - predicted attack and not whitelisted -> `BLOCKED` or `DETECTED` depending on actual firewall action

Acceptance:
- RF/DT/XGB predictions are logged as true 3-class results
- confidence is mathematically aligned with the winning class
- CSV rows are self-describing without dashboard inference hacks

#### S1-04 Lock producer feature contract
Priority: `P0`  
Estimate: `M`

Work:
- use the deployed scaler’s `feature_names_in_` as the authoritative outgoing 20-feature contract
- ensure producer reindexes extracted flow frames exactly to those features
- keep Python API extraction first
- keep CLI extraction fallback second
- record extraction method in Kafka payload
- stop sending dummy feature messages on extraction failure

Acceptance:
- producer only emits real flow-derived messages
- feature order matches deployed scaler schema exactly
- extraction failures do not pollute downstream analytics

#### S1-05 Add true runtime telemetry
Priority: `P0`  
Estimate: `L`

Work:
- write structured events for:
  - Kafka connect/disconnect
  - extraction failure
  - CSV read failure
  - rejected messages
  - schema adjustments
  - model reload
  - consumer processing error
- write heartbeats for:
  - live bridge
  - consumer
  - dashboard
- include timestamp, service name, severity, summary, and optional details blob

Acceptance:
- dashboard status is driven by telemetry, not only file age
- latest failure reason is visible without reading terminal output
- stale services are detectable independently of CSV existence

#### S1-06 Add launcher preflight checks
Priority: `P1`  
Estimate: `M`

Work:
- validate:
  - Docker installed
  - `docker compose` callable
  - Kafka port `9092`
  - required model/scaler files exist
  - active model is registered
  - network interface resolves
  - required Python packages import successfully
  - no duplicate stack processes
- fail fast with actionable messages

Acceptance:
- startup fails early on obvious misconfiguration
- user gets exact fix steps for the failing preflight item

#### S1-07 Stabilize dependency versions
Priority: `P0`  
Estimate: `M`

Work:
- resolve the current `scikit-learn` artifact/runtime mismatch
- default approach: pin runtime to match persisted model/scaler compatibility
- verify versions for:
  - `scikit-learn`
  - `cicflowmeter`
  - `confluent-kafka`
  - `streamlit`
  - `tensorflow`
  - `scapy`
- document exact live-supported package set

Observed current runtime:
- `scikit-learn==1.7.2`
- persisted scaler shows a `1.3.0` compatibility warning

Acceptance:
- no compatibility warning in the validated live environment
- live artifact loading is deterministic

#### S1-08 Create smoke and replay coverage
Priority: `P0`  
Estimate: `L`

Work:
- add replayable tests using existing PCAP fixtures
- test producer extraction path
- test Kafka message schema
- test consumer CSV output schema
- test dashboard data loading against v2 CSV rows
- verify no synthetic rows are produced on extraction failure

Acceptance:
- smoke test can validate the end-to-end RF/DT/XGB path without manual clicking
- failures localize clearly to producer, Kafka, consumer, or dashboard load

### Sprint 1 Exit Criteria
- clean Windows startup from `venv`
- Kafka stack comes up reproducibly
- producer sends only real flow messages
- RF, DT, and XGB run live through one contract
- consumer writes v2 CSV rows
- dashboard displays true service health
- smoke tests pass locally

---

## Sprint 2: All-Model Live Support and Better Dashboard

### Goal
Make all dashboard-selectable models genuinely work live, including LSTM/BiLSTM, and turn the dashboard into a debugging and operator console.

### Backlog

#### S2-01 Implement live rolling sequence inference
Priority: `P0`  
Estimate: `L`

Work:
- add rolling sequence buffers in the consumer for sequence models
- derive sequence length from model config or input shape
- current configs indicate `10 x 20` for both LSTM and BiLSTM
- accumulate live flow rows until the sequence window is full
- perform prediction on the rolling window
- attach prediction result to the last row in the current sequence
- reset logic must not drop all history on every message

Design rules:
- tabular models process one flow at a time
- sequence models process one rolling window at a time
- feature normalization must use the correct scaler before window assembly
- warm-up state must be explicit and visible

Acceptance:
- LSTM and BiLSTM are no longer “selectable but unsafe”
- live inference respects trained `10 x 20` input shape

#### S2-02 Add sequence-mode telemetry and UI state
Priority: `P1`  
Estimate: `M`

Work:
- expose:
  - active model type
  - required sequence size
  - buffered flow count
  - warm-up progress
  - last sequence prediction time
  - sequence buffer health
- dashboard must clearly show when sequence models are still warming up

Acceptance:
- users can tell why sequence predictions are not yet appearing
- warm-up is not mistaken for pipeline failure

#### S2-03 Build model certification matrix
Priority: `P0`  
Estimate: `M`

Work:
- certify:
  - Random Forest
  - Decision Tree
  - XGBoost
  - LSTM
  - BiLSTM
- record for each:
  - artifact load success
  - scaler load success
  - feature contract compatibility
  - input shape compatibility
  - prediction distribution sanity
  - average latency
  - throughput
  - failure reason if unsupported

Acceptance:
- dashboard live selector only shows models that passed certification, or clearly marks uncertified/beta models
- model support is evidence-based, not assumed

#### S2-04 Replace placeholder dashboard states with true debug panels
Priority: `P1`  
Estimate: `M`

Work:
- add dashboard views for:
  - Kafka connectivity
  - producer heartbeat
  - consumer heartbeat
  - latest pipeline events
  - schema-adjustment counts
  - rejected-message feed
  - model-switch history
  - current active model metadata
  - last good extraction time
  - CSV freshness and row delta
- remove or downgrade “coming soon” messaging where real telemetry now exists

Acceptance:
- dashboard can answer “what is broken?” without checking terminals first
- recent failures and service freshness are visible on first load

#### S2-05 Improve operator workflow after telemetry is trustworthy
Priority: `P2`  
Estimate: `M`

Work:
- keep current incident logs, export, and firewall response tools
- add per-detection drill-down:
  - per-class probabilities
  - producer id
  - extraction method
  - model used
  - processing time
  - schema-adjusted status
- clarify action states in logs and UI

Acceptance:
- dashboard supports both debugging and analyst triage without conflating them

#### S2-06 Add restart and recovery scenarios
Priority: `P0`  
Estimate: `M`

Work:
- validate:
  - Kafka restart mid-run
  - consumer restart with same group
  - clean consumer restart with new group and `latest`
  - live bridge extraction failure
  - empty CSV output from extractor
  - dashboard startup with no live data
  - model switch during active traffic
- define expected UI/telemetry state for each scenario

Acceptance:
- recovery behavior is documented and test-backed
- stale or partial failures are visible, not silent

### Sprint 2 Exit Criteria
- all five models run through one live contract
- LSTM/BiLSTM use real rolling sequence windows
- dashboard reflects actual pipeline state
- recovery scenarios are validated
- model switching is operationally safe

---

## Recommended Execution Order

### Sprint 1 order
1. `S1-01` Remove duplicate runtime branches
2. `S1-02` Build shared model registry
3. `S1-03` Correct 3-class prediction output
4. `S1-04` Lock producer feature contract
5. `S1-07` Stabilize dependency versions
6. `S1-05` Add true runtime telemetry
7. `S1-06` Add launcher preflight checks
8. `S1-08` Create smoke and replay coverage

### Sprint 2 order
1. `S2-01` Implement live rolling sequence inference
2. `S2-02` Add sequence-mode telemetry and UI state
3. `S2-03` Build model certification matrix
4. `S2-04` Replace placeholder dashboard states with true debug panels
5. `S2-06` Add restart and recovery scenarios
6. `S2-05` Improve operator workflow

---

## Test Plan

### Unit tests
- model registry resolution
- active model selection validation
- producer feature reindexing
- consumer probability mapping for 3-class outputs
- CSV v2 schema writing
- sequence warm-up buffering
- heartbeat and pipeline event persistence
- whitelist/firewall guard behavior

### Integration tests
- replay PCAP through `src/live_bridge.py`
- validate Kafka message schema
- consume through `src/kafka_consumer.py`
- validate CSV output columns and values
- validate dashboard data loading from v2 CSV schema
- validate telemetry persistence on extraction or consumer failure

### Recovery tests
- restart Kafka during traffic
- restart consumer with same group id
- restart consumer with fresh group id
- force extraction failure
- start dashboard without live traffic
- switch active model during capture

### Manual acceptance
- follow clean-start Windows runbook
- run `test/attack_test.py`
- verify fresh rows in `data/live_captured_traffic.csv`
- verify dashboard counters and status panels move
- verify logs and firewall actions are consistent with real detections
- verify sequence models warm up correctly before predicting

---

## Assumptions and Defaults
- supported deployment target for this sprint is Windows with local Docker and the project `venv`
- debug-first dashboard work takes precedence over cosmetic redesign
- auto-blocking remains conservative; manual unblock and batch response stay available
- binary research artifacts remain in repo but are not treated as primary live models
- backward compatibility should use explicit schema versioning, not silent CSV reuse
- the authoritative live feature contract is the deployed scaler schema, currently 20 features
- LSTM/BiLSTM live inference should follow the trained `10 x 20` rolling sequence shape

---

## Definition of Done
This backlog is complete when:
- the live pipeline is reproducible from a clean start
- Kafka, producer, consumer, and dashboard expose real health status
- no fake fallback traffic contaminates the pipeline
- RF, DT, XGB, LSTM, and BiLSTM are either certified live or explicitly marked unsupported
- dashboard status is trustworthy enough to debug issues without terminal guesswork
- replay and recovery tests are in place and passing
