# Startup Roadmap

This document is the correct startup guide for the current repository state on Windows.

It reflects the actual live pipeline:

1. `test/attack_test.py` generates traffic
2. `src/live_bridge.py` captures packets, extracts flow features, and publishes to Kafka topic `network-traffic`
3. `src/kafka_consumer.py` consumes Kafka messages, runs inference, and appends results to `data/live_captured_traffic.csv`
4. `src/dashboard/app.py` reads live output and renders the dashboard

## Current Recommended Defaults

- Use the project virtual environment at `.\venv\Scripts\python.exe`
- Use `Random Forest` mapped to `rf_3class_model.pkl` for live testing
- Keep `TARGET_IP=192.168.1.1` for repeatable local gateway traffic
- Prefer `NETWORK_INTERFACE=Wi-Fi` in `.env`

Notes:

- `src/live_bridge.py` can now resolve Windows adapter descriptions such as `Intel(R) Wi-Fi 6 AX201 160MHz`, but `Wi-Fi` is still the cleanest value to keep in `.env`
- `data/active_model.txt` controls the model the consumer loads at runtime
- `Random Forest` now resolves to `rf_3class_model.pkl`, not the older binary `rf_model_v1.pkl`

## Files That Matter

- `run_system.py`
  Windows launcher for Docker, consumer, dashboard, and bridge
- `docker-compose.yml`
  Starts Zookeeper and Kafka
- `src/kafka_consumer.py`
  Inference worker and CSV writer
- `src/live_bridge.py`
  Packet capture and Kafka producer
- `src/dashboard/app.py`
  Main Streamlit dashboard
- `data/active_model.txt`
  Active model selector used by the consumer
- `.env`
  Local runtime settings

## Before You Start

Recommended `.env` values:

```env
TARGET_IP=192.168.1.1
NETWORK_INTERFACE=Wi-Fi
WHITELIST_IPS=192.168.1.1,127.0.0.1,0.0.0.0,localhost
```

If the repo does not already have a virtual environment:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```

## Clean Start: Recommended Path

Use this when you want a fully clean startup with no stale Kafka backlog and no duplicate Python processes.

### 1. Stop old local processes

```powershell
Get-CimInstance Win32_Process |
  Where-Object {
    $_.Name -match 'python' -and
    $_.CommandLine -match 'live_bridge|kafka_consumer|streamlit|run_system'
  } |
  ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
```

### 2. Reset Kafka and Zookeeper

```powershell
docker compose down
docker compose up -d
```

### 3. Optional: archive old live output

```powershell
if (Test-Path .\data\live_captured_traffic.csv) {
  Move-Item .\data\live_captured_traffic.csv (".\data\live_captured_traffic.preclean_{0}.csv" -f (Get-Date -Format yyyyMMdd_HHmmss))
}

Remove-Item .\temp_live.csv, .\temp_live.pcap -ErrorAction SilentlyContinue
```

### 4. Start the full stack with the launcher

```powershell
conda deactivate
.\venv\Scripts\python.exe .\run_system.py
```

What `run_system.py` does now:

- forces child services onto the project `venv`
- checks for duplicate running service processes
- starts Docker services
- launches:
  - `src\kafka_consumer.py`
  - `src\dashboard\app.py`
  - `src\live_bridge.py`

### 5. Start the attack generator in a separate terminal

```powershell
.\venv\Scripts\python.exe .\test\attack_test.py --target 192.168.1.1 --fixed-flow --print-every 60
```

## Manual Startup Path

Use this when you want direct control over each service and their logs.

### Terminal 1: Docker

```powershell
docker compose up -d
```

### Terminal 2: Consumer

```powershell
conda deactivate
.\venv\Scripts\Activate.ps1
$env:PYTHONIOENCODING='utf-8'
$env:KAFKA_GROUP_ID='nids-consumer-live'
$env:KAFKA_AUTO_OFFSET_RESET='latest'
.\venv\Scripts\python.exe .\src\kafka_consumer.py
```

### Terminal 3: Live Bridge

Standard mode:

```powershell
.\venv\Scripts\Activate.ps1
$env:PYTHONIOENCODING='utf-8'
.\venv\Scripts\python.exe .\src\live_bridge.py
```

Debug mode with lower buffering:

```powershell
.\venv\Scripts\Activate.ps1
$env:PYTHONIOENCODING='utf-8'
$env:NETWORK_INTERFACE='Wi-Fi'
$env:LIVE_MIN_BUFFER_PACKETS='6'
$env:LIVE_MIN_BUFFER_FLOW_PACKETS='3'
$env:LIVE_CAPTURE_TIMEOUT_SECONDS='2'
.\venv\Scripts\python.exe .\src\live_bridge.py
```

### Terminal 4: Dashboard

```powershell
.\venv\Scripts\Activate.ps1
.\venv\Scripts\python.exe -m streamlit run .\src\dashboard\app.py
```

### Terminal 5: Attack Generator

```powershell
.\venv\Scripts\python.exe .\test\attack_test.py --target 192.168.1.1 --fixed-flow --print-every 60
```

## Fastest Dashboard-Only Path

Use this only when you want the UI and do not need live capture.

```powershell
.\venv\Scripts\Activate.ps1
.\venv\Scripts\python.exe -m streamlit run .\src\dashboard\app.py
```

Important:

- this does not start Kafka
- this does not start the consumer
- this does not start the live bridge
- the dashboard will only show previously captured data unless the pipeline is running elsewhere

## Model Selection

The dashboard model selector writes into `data/active_model.txt`.

Current supported selector values:

- `Random Forest` -> `rf_3class_model.pkl`
- `Decision Tree` -> `dt_model.pkl`
- `XGBoost` -> `xgboost_model.pkl`
- `LSTM` -> `lstm_model.keras`
- `BiLSTM` -> `bilstm_model.keras`

Recommended live model today:

- `Random Forest`

Why:

- it is currently the safest live option in this repo
- it is a real 3-class model
- it avoids the sequence-input caveat that still affects the live LSTM/BiLSTM path

Sequence-model caveat:

- both `lstm_model.keras` and `bilstm_model.keras` expect input shape `(None, 10, 20)`
- the current live consumer path still feeds single-message timesteps, so LSTM/BiLSTM are selectable but are not yet the most trustworthy live inference path

## What Good Startup Looks Like

### `run_system.py`

Expected startup behavior:

- prints launcher Python and service Python
- starts Docker services
- opens separate terminals for consumer, dashboard, and bridge

### `src/live_bridge.py`

Healthy signs:

- `NETWORK_INTERFACE resolved: 'Intel(R) Wi-Fi 6 AX201 160MHz' -> 'Wi-Fi'`
- `Kafka Producer Aktif`
- `Parsed N flow(s) from CSV`
- `N flow(s) sent to Kafka`

### `src/kafka_consumer.py`

Healthy signs:

- `Target Model: rf_3class_model.pkl`
- `Consumer connected to Kafka`
- `Consumer is now ACTIVE and listening for messages`
- repeated `Clean Traffic` or `ALERT: ATTACK DETECTED!`

### `src/dashboard/app.py`

Healthy signs:

- opens at `http://localhost:8501`
- `System Status` shows live data moving
- `Total Flows` increases
- recent rows appear in `data/live_captured_traffic.csv`

## Verification Commands

### Confirm running service processes

```powershell
Get-CimInstance Win32_Process |
  Where-Object {
    $_.Name -match 'python' -and
    $_.CommandLine -match 'live_bridge|kafka_consumer|streamlit|run_system'
  } |
  Select-Object ProcessId, CommandLine
```

### Confirm Kafka is listening

```powershell
Get-NetTCPConnection -LocalPort 9092 -ErrorAction SilentlyContinue |
  Select-Object LocalAddress, LocalPort, State, OwningProcess
```

### Confirm fresh live output

```powershell
Get-Content .\data\live_captured_traffic.csv -Tail 10 -Wait
```

### Confirm the active model file

```powershell
Get-Content .\data\active_model.txt
```

### Confirm Docker services

```powershell
docker ps
```

## Common Failure Points

### 1. Duplicate Python stacks

Symptoms:

- multiple `live_bridge.py`, `kafka_consumer.py`, or Streamlit processes
- mixed `venv` and Anaconda processes
- confusing or stale dashboard output

Fix:

- stop all pipeline Python processes with the cleanup command above
- restart using only `.\venv\Scripts\python.exe`

### 2. Stale Kafka backlog

Symptoms:

- consumer sees old messages
- schema mismatch warnings from older producers
- startup looks active but current attack traffic does not match the dashboard

Fix:

- use `docker compose down` followed by `docker compose up -d`
- or start the consumer with a fresh group id and `KAFKA_AUTO_OFFSET_RESET=latest`

### 3. Wrong network interface

Symptoms:

- `src/live_bridge.py` reports `0 Paket!`
- attack generator runs but the bridge sees nothing

Fix:

- set `.env` to `NETWORK_INTERFACE=Wi-Fi`
- or keep the adapter description if the bridge resolution message confirms it mapped correctly

### 4. Dashboard opens but looks empty

Symptoms:

- UI loads
- live counters do not move
- CSV file timestamps do not update

Fix:

- verify the consumer is running
- verify the bridge is running
- verify Kafka is running
- confirm `data/live_captured_traffic.csv` is getting new rows

### 5. Low attack counts vs packet counts

Symptoms:

- many packets sent by `attack_test.py`
- relatively few rows on the dashboard

Explanation:

- the dashboard counts flows, not packets
- `live_bridge.py` batches packets and extracts flow records
- `12,000` packets becoming `100-300` flows is normal in this pipeline

## Minimal Decision Guide

- Want the cleanest full startup: use the Clean Start path with `run_system.py`
- Want to watch each component directly: use the Manual Startup path
- Want only the UI: use the Dashboard-Only path
- Want the most reliable live model today: use `Random Forest` -> `rf_3class_model.pkl`
