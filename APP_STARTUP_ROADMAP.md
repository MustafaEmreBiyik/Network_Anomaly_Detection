# App Startup Roadmap

Accurate startup guide for Windows. Reflects the current live pipeline.

## Pipeline Overview

```
live_bridge.py  →  Kafka (Docker)  →  kafka_consumer.py  →  CSV  →  dashboard/app.py
 (packet capture)    (broker)         (ML inference)      (data)    (Streamlit UI)
```

## Prerequisites

- Docker Desktop running
- Virtual environment set up at `.\venv\`
- `.env` file present (copy from `.env.example` if missing)

If setting up fresh:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```

Recommended `.env` values:

```env
NETWORK_INTERFACE=Wi-Fi
TARGET_IP=192.168.1.1
WHITELIST_IPS=192.168.1.1,127.0.0.1,0.0.0.0,localhost
```

> Note: `live_bridge.py` auto-resolves Windows adapter descriptions (e.g. `Intel(R) Wi-Fi 6 AX201 160MHz` → `Wi-Fi`), but `Wi-Fi` is the cleanest `.env` value.

---

## Option A: Automated Startup (Recommended)

Launches Docker, consumer, dashboard, and bridge in separate terminals automatically.

```powershell
# Terminal 1 — run once, opens everything
.\venv\Scripts\python.exe .\run_system.py
```

Then start the attack generator in a second terminal:

```powershell
# Terminal 2 — traffic generator
.\venv\Scripts\python.exe .\test\attack_test.py --target 192.168.1.1 --fixed-flow --print-every 60
```

---

## Option B: Manual Startup (Full Control)

Open each terminal separately for direct log access.

### Terminal 1 — Kafka + Zookeeper

```powershell
docker compose up -d
```

Verify Kafka is up:

```powershell
docker ps
```

### Terminal 2 — Kafka Consumer (ML Inference)

```powershell
.\venv\Scripts\Activate.ps1
$env:PYTHONIOENCODING='utf-8'
$env:KAFKA_GROUP_ID='nids-consumer-live'
$env:KAFKA_AUTO_OFFSET_RESET='latest'
.\venv\Scripts\python.exe .\src\kafka_consumer.py
```

Healthy output:
- `Target Model: rf_3class_model.pkl`
- `Consumer connected to Kafka`
- `Consumer is now ACTIVE and listening for messages`
- Repeated `Clean Traffic` or `ALERT: ATTACK DETECTED!`

### Terminal 3 — Live Bridge (Packet Capture → Kafka)

```powershell
.\venv\Scripts\Activate.ps1
$env:PYTHONIOENCODING='utf-8'
.\venv\Scripts\python.exe .\src\live_bridge.py
```

Debug mode (lower buffer thresholds, faster first capture):

```powershell
.\venv\Scripts\Activate.ps1
$env:PYTHONIOENCODING='utf-8'
$env:NETWORK_INTERFACE='Wi-Fi'
$env:LIVE_MIN_BUFFER_PACKETS='6'
$env:LIVE_MIN_BUFFER_FLOW_PACKETS='3'
$env:LIVE_CAPTURE_TIMEOUT_SECONDS='2'
.\venv\Scripts\python.exe .\src\live_bridge.py
```

Healthy output:
- `Kafka Producer Aktif (127.0.0.1:9092)`
- `Parsed N flow(s) from CSV`
- `N flow(s) sent to Kafka (Topic: network-traffic)`

### Terminal 4 — Dashboard

```powershell
.\venv\Scripts\Activate.ps1
.\venv\Scripts\python.exe -m streamlit run .\src\dashboard\app.py
```

Opens at: **http://localhost:8501**

Healthy signs:
- System Status row shows green badges
- Total Flows counter increases
- Recent detections table populates

### Terminal 5 — Traffic / Attack Generator

```powershell
.\venv\Scripts\python.exe .\test\attack_test.py --target 192.168.1.1 --fixed-flow --print-every 60
```

---

## Option C: Dashboard Only (No Live Capture)

Use when you only want to inspect previously captured data.

```powershell
.\venv\Scripts\Activate.ps1
.\venv\Scripts\python.exe -m streamlit run .\src\dashboard\app.py
```

Opens at: **http://localhost:8501**

> Kafka, consumer, and live bridge are NOT started. Dashboard shows only data already in `data/live_captured_traffic.csv`.

---

## Clean Restart

Use when you have stale processes, Kafka backlog, or mixed venv/Anaconda processes.

### 1. Kill old Python pipeline processes

```powershell
Get-CimInstance Win32_Process |
  Where-Object {
    $_.Name -match 'python' -and
    $_.CommandLine -match 'live_bridge|kafka_consumer|streamlit|run_system'
  } |
  ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
```

### 2. Reset Kafka

```powershell
docker compose down
docker compose up -d
```

### 3. Archive old live data (optional)

```powershell
if (Test-Path .\data\live_captured_traffic.csv) {
  Move-Item .\data\live_captured_traffic.csv (".\data\live_captured_traffic.preclean_{0}.csv" -f (Get-Date -Format yyyyMMdd_HHmmss))
}
Remove-Item .\temp_live.csv, .\temp_live.pcap -ErrorAction SilentlyContinue
```

### 4. Start fresh

```powershell
.\venv\Scripts\python.exe .\run_system.py
```

---

## Model Selection

The dashboard sidebar model selector writes to `data/active_model.txt`. The consumer reads it at runtime.

| Display Name   | Model File              | Status         |
|----------------|-------------------------|----------------|
| Random Forest  | `rf_3class_model.pkl`   | **Recommended** |
| Decision Tree  | `dt_3class_model.pkl`   | Stable         |
| XGBoost        | `xgb_3class_model.pkl`  | Stable         |
| LSTM           | `lstm_best.keras`       | Selectable*    |
| BiLSTM         | `bilstm_best.keras`     | Selectable*    |

*LSTM/BiLSTM expect input shape `(None, 10, 20)`. The current live consumer feeds single-timestep messages, so these models are selectable but Random Forest is more reliable for live inference.

To manually set the active model:

```powershell
Set-Content .\data\active_model.txt "Random Forest"
```

---

## Verification Commands

```powershell
# Check which pipeline processes are running
Get-CimInstance Win32_Process |
  Where-Object { $_.Name -match 'python' -and $_.CommandLine -match 'live_bridge|kafka_consumer|streamlit' } |
  Select-Object ProcessId, CommandLine

# Check Kafka is listening on port 9092
Get-NetTCPConnection -LocalPort 9092 -ErrorAction SilentlyContinue |
  Select-Object LocalAddress, LocalPort, State

# Watch live CSV output in real time
Get-Content .\data\live_captured_traffic.csv -Tail 10 -Wait

# Check which model is active
Get-Content .\data\active_model.txt

# Check Docker containers
docker ps
```

---

## Common Failures

### Bridge sees 0 packets

- Set `NETWORK_INTERFACE=Wi-Fi` in `.env`
- Run `.\venv\Scripts\python.exe -c "from scapy.all import show_interfaces; show_interfaces()"` to list valid interface names

### Consumer sees stale/old messages

- Run `docker compose down && docker compose up -d` to reset Kafka
- Or set `KAFKA_AUTO_OFFSET_RESET=latest` before starting the consumer

### Dashboard is empty

- Confirm consumer is running and writing to `data/live_captured_traffic.csv`
- Confirm `Get-Content .\data\live_captured_traffic.csv -Tail 5` shows recent timestamps

### Duplicate processes / mixed venv + Anaconda

- Run the kill command above, then restart using only `.\venv\Scripts\python.exe`
- Never mix `conda` and `venv` environments in the same session

### Low flow count vs packet count

- Normal: 12,000 packets → 100–300 flows. The bridge batches packets and extracts flow records, not individual packets.

---

## Key Files

| File | Purpose |
|------|---------|
| `run_system.py` | Automated launcher for all services |
| `docker-compose.yml` | Starts Zookeeper + Kafka |
| `src/live_bridge.py` | Packet capture → feature extraction → Kafka producer |
| `src/kafka_consumer.py` | Kafka consumer → ML inference → CSV writer |
| `src/dashboard/app.py` | Main SOC Streamlit dashboard |
| `data/active_model.txt` | Active model selector (read by consumer at runtime) |
| `.env` | Local runtime settings (interface, IPs) |
