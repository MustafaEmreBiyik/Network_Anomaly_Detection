<div align="center">

# Network Intrusion Detection System

**A Multi-Model Machine Learning System for Real-Time Network Threat Detection**

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white)](https://python.org)
[![TensorFlow](https://img.shields.io/badge/TensorFlow-2.x-FF6F00?logo=tensorflow&logoColor=white)](https://tensorflow.org)
[![XGBoost](https://img.shields.io/badge/XGBoost-2.1.4-blue)](https://xgboost.readthedocs.io)
[![Kafka](https://img.shields.io/badge/Apache%20Kafka-7.4-231F20?logo=apachekafka&logoColor=white)](https://kafka.apache.org)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)](https://docker.com)
[![Streamlit](https://img.shields.io/badge/Streamlit-Dashboard-FF4B4B?logo=streamlit&logoColor=white)](https://streamlit.io)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

</div>

---

## Overview

This project implements a production-ready **Network Intrusion Detection System (NIDS)** that combines multiple machine learning architectures for comprehensive threat detection. The system supports both **binary** (Normal / Attack) and **3-class** (Benign / Volumetric / Semantic) classification, and is built around a **Kafka streaming pipeline** for real-time inference.

**Models:** Random Forest · XGBoost (GPU) · Decision Tree · BiLSTM · LSTM  
**Dataset:** [CICIDS 2017](https://www.unb.ca/cic/datasets/ids-2017.html) — 2.83M labeled network flows  
**Authors:** Betül Danışmaz · Mustafa Emre Bıyık  
**Advisor:** Dr. Necip Gözüaçık

**Paper:** [IEEE SIU 2026](https://siu2026.pirireis.edu.tr/) - Multi-Class Network Intrusion Detection: Machine and Deep Learning Benchmark with Live Stream Deployment 

---

## Table of Contents

- [Performance Summary](#performance-summary)
- [Features](#features)
- [System Architecture](#system-architecture)
- [Getting Started](#getting-started)
- [Model Details](#model-details)
- [Project Structure](#project-structure)
- [Usage Guide](#usage-guide)
- [Configuration](#configuration)
- [Development](#development)
- [Dependencies](#dependencies)
- [Publications](#publications)
- [License](#license)
- [Acknowledgements](#acknowledgements)

---

## Performance Summary

### 3-Class Classification (Benign / Volumetric / Semantic)

| Model             | Accuracy | Macro Precision | Macro Recall | Macro F1 | Macro ROC-AUC |
| :---------------- | :------: | :-------------: | :----------: | :------: | :-----------: |
| **XGBoost (GPU)** |  97.71%  |     93.62%      |    98.38%    |  95.87%  |    0.9991     |
| **Random Forest** |  97.34%  |     94.43%      |    97.70%    |  95.91%  |    0.9983     |
| **BiLSTM**        |  98.88%  |     97.98%      |    98.02%    |  97.98%  |       —       |
| **LSTM**          |  98.15%  |     95.79%      |    97.13%    |  96.45%  |       —       |
| **Decision Tree** |  97.27%  |     94.26%      |    97.83%    |  95.84%  |       —       |

### Per-Class Performance (3-Class Models)

**Class 0 — Benign (Normal Traffic)**

| Model             | Overall Acc. | Precision | Recall | F1-Score |
| :---------------- | :----------: | :-------: | :----: | :------: |
| **LSTM**          |    98.15%    |  99.23%   | 98.46% |  98.84%  |
| **BiLSTM**        |    98.88%    |  99.48%   | 99.12% |  99.30%  |
| **XGBoost (GPU)** |    97.71%    |  99.79%   | 97.36% |  98.56%  |
| **Decision Tree** |    97.27%    |  99.69%   | 96.90% |  98.28%  |
| **Random Forest** |    97.34%    |  99.69%   | 96.99% |  98.32%  |

**Class 1 — Volumetric (DDoS / DoS / Botnet)**

| Model             | Overall Acc. | Precision | Recall | F1-Score |
| :---------------- | :----------: | :-------: | :----: | :------: |
| **BiLSTM**        |    98.88%    |  95.30%   | 98.60% |  96.92%  |
| **LSTM**          |    98.15%    |  93.62%   | 97.61% |  95.58%  |
| **XGBoost (GPU)** |    97.71%    |  89.64%   | 99.58% |  94.35%  |
| **Random Forest** |    97.34%    |  85.27%   | 99.75% |  91.94%  |
| **Decision Tree** |    97.27%    |  84.96%   | 99.62% |  91.71%  |

**Class 2 — Semantic (Port Scan / Web Attack / Brute Force)**

| Model             | Overall Acc. | Precision | Recall | F1-Score |
| :---------------- | :----------: | :-------: | :----: | :------: |
| **Decision Tree** |    97.27%    |  98.11%   | 96.95% |  97.53%  |
| **Random Forest** |    97.34%    |  98.32%   | 96.61% |  97.46%  |
| **LSTM**          |    98.15%    |  94.53%   | 95.33% |  94.93%  |
| **XGBoost (GPU)** |    97.71%    |  91.44%   | 98.21% |  94.71%  |
| **BiLSTM**        |    98.88%    |  99.16%   | 96.33% |  97.72%  |

> Rows are sorted by F1-Score descending. Semantic (~6% of traffic) is the hardest class to classify.

### Binary Classification (Normal / Attack) — Archived

| Model             | Accuracy | Precision | Recall | F1-Score | ROC-AUC |
| :---------------- | :------: | :-------: | :----: | :------: | :-----: |
| **XGBoost**       |  99.82%  |  99.66%   | 99.28% |  99.47%  | 1.0000  |
| **Random Forest** |  99.73%  |  97.87%   | 99.90% |  98.88%  | 0.9994  |
| **Decision Tree** |  99.60%  |  99.61%   | 98.08% |  98.84%  |    —    |
| **CatBoost**      |  ~99.8%  |  ~99.7%   | ~99.8% |  ~99.8%  |    —    |

> Binary models are preserved in `binary_models/` for reference. The active system uses 3-class classification.

### Inference Performance (10,000-Sample Benchmark)

| Model | Latency (ms/sample) | Throughput (SPS) | Hardware | Source |
| :---------------- | :-----------------: | ---------------: | :------: | :----- |
| **Decision Tree** | 0.0001 | 7,534,659 | CPU | `reports/latency_benchmark.json` |
| **Random Forest** | 0.0031 | 319,398 | CPU | `reports/latency_benchmark.json` |
| **XGBoost (GPU)** | 0.0070 | 142,428 | CUDA | `reports/latency_benchmark.json` |
| **LSTM** | 0.0575 | 17,383 | CUDA | `reports/latency_benchmark.json` |
| **BiLSTM** | 0.1085 | 9,212 | CUDA | `reports/latency_benchmark.json` |

> **Methodology:** Each model timed over 10,000 samples with one warm-up pass (`src/models/benchmark_all_models.py`). Latency = elapsed / N × 1000 ms; Throughput = N / elapsed. DL models use batch size 256; tree models receive the full batch at once.

---

## Features

| Capability                      | Description                                                                                              |
| :------------------------------ | :------------------------------------------------------------------------------------------------------- |
| **Multi-Model Architecture**    | 5 model types — RF, XGBoost, DT, BiLSTM, LSTM — with both 3-class and binary variants                    |
| **Kafka Streaming Pipeline**    | Docker-based Apache Kafka + Zookeeper for real-time message ingestion and processing                     |
| **3-Class Attack Taxonomy**     | Distinguishes Benign, Volumetric (DDoS/DoS/Botnet), and Semantic (PortScan/WebAttack/BruteForce) traffic |
| **GPU-Accelerated Training**    | XGBoost CUDA acceleration provides 15–45× speedup over CPU                                               |
| **Automated Firewall Response** | OS-level IP blocking via Windows Firewall or iptables                                                    |
| **Live Monitoring Dashboard**   | Streamlit-based real-time UI with metrics, attack timeline, and event log                                |
| **One-Command Startup**         | `run_system.py` orchestrates all services (Docker, Kafka, Consumer, Dashboard, Producer)                 |
| **Evaluation Dashboards**       | Per-model executive reports with confusion matrices, ROC curves, and feature importance                  |
| **Dynamic Model Hot-Reload**    | Kafka Consumer detects configuration changes and switches models without restart                         |
| **Data Quality Auditing**       | Automated validation pipelines for both binary and 3-class datasets                                      |

### Attack Classification Taxonomy

| Class | Label          | Attack Types                                                               |
| :---: | :------------- | :------------------------------------------------------------------------- |
|   0   | **Benign**     | Normal network traffic                                                     |
|   1   | **Volumetric** | DDoS, DoS (Slowhttptest, Slowloris, Hulk, GoldenEye), Botnet               |
|   2   | **Semantic**   | Port Scanning, Web Attacks (XSS, SQL Injection), Brute Force, Infiltration |

---

## System Architecture

```
                        ┌───────────────────────┐
                        │   Network Interface   │
                        └───────────┬───────────┘
                                    │
                                    ▼
                        ┌───────────────────────┐
                        │    Scapy Capture       │
                        │   (4-second windows)   │
                        └───────────┬───────────┘
                                    │
                                    ▼
                        ┌───────────────────────┐
                        │    CICFlowMeter        │
                        │   (78 → 20 features)   │
                        └───────────┬───────────┘
                                    │
                                    ▼
                        ┌───────────────────────┐
                        │    Live Bridge         │
                        │   (Kafka Producer)     │
                        └───────────┬───────────┘
                                    │
                             Kafka Topic
                                    │
                                    ▼
                        ┌───────────────────────┐
                        │    Kafka Consumer      │
                        │  (Dynamic Model Load)  │
                        └───────────┬───────────┘
                                    │
                ┌───────────────────┼───────────────────┐
                │                   │                   │
                ▼                   ▼                   ▼
        ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐
        │   XGBoost    │  │ Random Forest│  │   BiLSTM/LSTM    │
        │ 3-Class(GPU) │  │   3-Class    │  │  3-Class (Seq.)  │
        └──────┬───────┘  └──────┬───────┘  └────────┬─────────┘
               │                 │                    │
               └─────────────────┼────────────────────┘
                                 │
                                 ▼
                        ┌───────────────────────┐
                        │   Response Engine      │
                        │  • Firewall Blocking   │
                        │  • SQLite Logging      │
                        │  • Streamlit Dashboard │
                        └───────────────────────┘
```


### Technology Stack

| Layer              | Technology                  | Role                                         |
| :----------------- | :-------------------------- | :------------------------------------------- |
| Packet Capture     | Scapy                       | Raw packet sniffing from network interface   |
| Feature Extraction | CICFlowMeter (Java)         | 78 bidirectional flow features               |
| Preprocessing      | Pandas, scikit-learn        | Scaling, feature selection, sequencing       |
| ML Models          | XGBoost, scikit-learn       | Gradient boosting and tree-based classifiers |
| Deep Learning      | TensorFlow / Keras          | BiLSTM and LSTM temporal models              |
| Streaming          | Apache Kafka + Zookeeper    | Real-time event pipeline (Docker)            |
| Firewall           | Windows Firewall / iptables | Automated OS-level IP blocking               |
| Storage            | SQLite                      | Attack event persistence                     |
| Dashboard          | Streamlit                   | Real-time monitoring interface               |

---

## Getting Started

### Prerequisites

| Requirement      | Notes                                           |
| :--------------- | :---------------------------------------------- |
| Python 3.8+      | Tested on 3.9, 3.10, 3.11                       |
| Docker Desktop   | Required for Kafka + Zookeeper                  |
| Admin privileges | Packet capture and firewall rules               |
| Java 11+         | CICFlowMeter feature extraction                 |
| CUDA GPU         | _Optional_ — accelerates XGBoost and TensorFlow |

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/betuldanismaz/Network_Anomaly_Detection.git
cd Network_Anomaly_Detection/networkdetection

# 2. Create and activate virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1          # Windows
# source venv/bin/activate           # Linux / macOS

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment
copy .env.example .env               # Then edit .env with your settings
```

### Quick Launch

```bash
python run_system.py
```

This single command:

1. Verifies Docker availability
2. Starts Zookeeper + Kafka containers via `docker-compose`
3. Launches **Kafka Consumer** (ML inference engine) in a new terminal
4. Opens **Streamlit Dashboard** at `http://localhost:8501`
5. Starts **Live Bridge Producer** (traffic capture) in a new terminal

> Each service runs in its own terminal window. Close the launcher — services continue running independently.

### Manual Startup (Alternative)

```bash
# Terminal 1 — Infrastructure
docker-compose up -d

# Terminal 2 — Kafka Consumer (ML predictions)
python src/kafka_consumer.py

# Terminal 3 — Live Bridge (traffic capture + Kafka producer)
python src/live_bridge.py

# Terminal 4 — Dashboard
streamlit run src/dashboard/app.py
```

---

## Model Details

### XGBoost — 3-Class (GPU Accelerated)

| Metric            |               Value |
| :---------------- | ------------------: |
| Accuracy          |              97.71% |
| Macro Precision   |              93.62% |
| Macro Recall      |              98.38% |
| Macro F1-Score    |              95.87% |
| Macro ROC-AUC     |              0.9991 |
| Inference Latency |     0.008 ms/sample |
| Throughput        | 126,546 samples/sec |

**Per-Class Breakdown:**

| Class      | Precision | Recall | F1-Score | ROC-AUC |
| :--------- | :-------: | :----: | :------: | :-----: |
| Benign     |  99.79%   | 97.36% |  98.56%  | 0.9988  |
| Volumetric |  89.64%   | 99.58% |  94.35%  | 0.9991  |
| Semantic   |  91.44%   | 98.21% |  94.71%  | 0.9995  |

**Configuration:** XGBoost 2.1.4 · CUDA · `tree_method=hist` · 1000 estimators · max_depth=7 · lr=0.05 · best iteration 857 · `compute_sample_weight(balanced)`

---

### Random Forest — 3-Class

| Metric          |  Value |
| :-------------- | -----: |
| Accuracy        | 97.13% |
| Macro Precision | 93.09% |
| Macro Recall    | 98.23% |
| Macro F1-Score  | 95.43% |
| Macro ROC-AUC   | 0.9983 |

**Per-Class Breakdown:**

| Class      | Precision | Recall | F1-Score | ROC-AUC |
| :--------- | :-------: | :----: | :------: | :-----: |
| Benign     |  99.84%   | 96.58% |  98.19%  | 0.9977  |
| Volumetric |  84.89%   | 99.89% |  91.78%  | 0.9978  |
| Semantic   |  94.53%   | 98.21% |  96.34%  | 0.9994  |

**Configuration:** 50 estimators · max_features=sqrt · Gini criterion · best CV F1 (macro)=0.9367 · training time ~40 min

---

### Decision Tree — 3-Class

| Metric          |  Value |
| :-------------- | -----: |
| Accuracy        | 97.27% |
| Macro Precision | 94.26% |
| Macro Recall    | 97.83% |
| Macro F1-Score  | 95.84% |
| Weighted F1     | 97.35% |

**Per-Class Breakdown:**

| Class      | Precision | Recall | F1-Score |
| :--------- | :-------: | :----: | :------: |
| Benign     |  99.69%   | 96.90% |  98.28%  |
| Volumetric |  84.96%   | 99.62% |  91.71%  |
| Semantic   |  98.11%   | 96.95% |  97.53%  |

**Configuration:** class_weight=balanced · evaluation reports in `reports/decisiontree/`

---

### BiLSTM — 3-Class

| Metric          |  Value |
| :-------------- | -----: |
| Accuracy        | 97.73% |
| Macro Precision | 93.21% |
| Macro Recall    | 97.77% |
| Macro F1-Score  | 95.37% |
| Weighted F1     | 97.76% |

**Per-Class Breakdown:**

| Class      | Precision | Recall | F1-Score | Support |
| :--------- | :-------: | :----: | :------: | ------: |
| Benign     |  99.53%   | 97.63% |  98.57%  | 454,567 |
| Volumetric |  92.94%   | 98.60% |  95.69%  |  76,130 |
| Semantic   |  87.15%   | 97.07% |  91.84%  |  35,383 |

**Architecture:**

```
Input (batch, 10, 20) → BiLSTM(128) → BatchNorm → Dropout(0.3)
                      → BiLSTM(64)  → BatchNorm → Dropout(0.3)
                      → Dense(32, ReLU) → Dropout(0.3)
                      → Dense(3, Softmax)
```

**Training:** 50 epochs (early stopping) · batch size 256 · Adam (lr=0.001) · sparse categorical crossentropy · balanced class weights

---

### LSTM — 3-Class

| Metric          |  Value |
| :-------------- | -----: |
| Accuracy        | 98.15% |
| Macro Precision | 95.79% |
| Macro Recall    | 97.13% |
| Macro F1-Score  | 96.45% |
| Weighted F1     | 98.16% |

**Per-Class Breakdown:**

| Class      | Precision | Recall | F1-Score | Support |
| :--------- | :-------: | :----: | :------: | ------: |
| Benign     |  99.23%   | 98.46% |  98.84%  | 454,567 |
| Volumetric |  93.62%   | 97.61% |  95.58%  |  76,130 |
| Semantic   |  94.53%   | 95.33% |  94.93%  |  35,383 |

**Architecture:** Unidirectional LSTM variant — lower latency, optimized for resource-constrained deployment  
**Training:** 50 epochs (early stopping) · batch size 256 · Adam (lr=0.001) · sparse categorical crossentropy · balanced class weights

---

### Binary Models (Archived)

Binary (Normal / Attack) models are preserved in `binary_models/` for reference:

| Model         | Accuracy | F1-Score | ROC-AUC |
| :------------ | :------: | :------: | :-----: |
| XGBoost       |  99.82%  |  99.47%  | 1.0000  |
| Random Forest |  99.73%  |  98.88%  | 0.9994  |
| Decision Tree |  99.60%  |  98.84%  |    —    |

---

## Project Structure

```
networkdetection/
│
├── run_system.py                         # One-command system orchestrator
├── docker-compose.yml                    # Kafka + Zookeeper containers
├── requirements.txt                      # Python dependencies
├── .env.example                          # Environment variable template
│
├── binary_models/                        # Archived binary classification models
│   ├── rf_optimized_model.pkl
│   ├── xgboost_model.pkl
│   ├── dt_model.pkl
│   ├── dt_rules.txt
│   ├── threshold_xgb.txt
│   └── xgb_config.json
│
├── data/
│   ├── active_model.txt                  # Active model selector
│   ├── original_csv/                     # Raw CICIDS 2017 CSVs
│   ├── processed_ml/                     # 3-class data (train/val/test.csv)
│   ├── processed_lstm/                   # BiLSTM/LSTM sequences (.npy)
│   └── processed_randomforest/           # Binary RF preprocessed data
│
├── models/                               # Active 3-class models
│   ├── rf_3class_model.pkl
│   ├── rf_3class_config.json
│   ├── xgb_3class_model.pkl
│   ├── xgb_3class_config.json
│   ├── dt_3class_model.pkl
│   ├── dt_3class_rules.txt
│   ├── bilstm_best.keras
│   ├── lstm_best.keras
│   ├── scaler_ml_3class.pkl              # MinMaxScaler (3-class)
│   ├── scaler_lstm.pkl                   # MinMaxScaler (LSTM)
│   ├── scaler.pkl                        # MinMaxScaler (binary RF)
│   ├── class_weights.json
│   ├── threshold.txt
│   ├── threshold_config.json
│   ├── shap_explainer.pkl
│   └── pycaret_champion.pkl              # CatBoost (AutoML)
│
├── src/
│   ├── live_bridge.py                    # Kafka Producer — traffic capture
│   ├── kafka_consumer.py                 # Kafka Consumer — ML inference
│   ├── config.py                         # Top-20 feature definitions
│   │
│   ├── capture/
│   │   └── sniffer.py                    # Scapy packet capture
│   │
│   ├── dashboard/
│   │   ├── app.py                        # Streamlit monitoring dashboard
│   │   └── app2.py                       # Alternative dashboard
│   │
│   ├── features/
│   │   ├── preprocess.py                 # Binary RF preprocessing
│   │   ├── preprocess_ml_3class.py       # 3-class ML preprocessing
│   │   ├── preprocess_lstm.py            # BiLSTM/LSTM sequence generation
│   │   └── data_audit_3class.py          # 3-class data quality audit
│   │
│   ├── models/
│   │   ├── train_randomforest.py         # 3-class Random Forest
│   │   ├── train_xgboost.py             # 3-class XGBoost (GPU)
│   │   ├── train_decisiontree.py        # 3-class Decision Tree
│   │   ├── train_bilstm.py              # BiLSTM training
│   │   ├── train_lstm.py                # LSTM training
│   │   ├── evaluate_randomforest.py     # RF evaluation + dashboard
│   │   ├── evaluate_xgboost.py          # XGBoost evaluation + dashboard
│   │   ├── evaluate_decisiontree.py     # DT evaluation + dashboard
│   │   ├── evaluate_bilstm.py           # BiLSTM evaluation
│   │   ├── evaluate_lstm.py             # LSTM evaluation
│   │   ├── binary_train_randomforest.py # Binary RF (legacy)
│   │   ├── binary_train_xgboost.py      # Binary XGBoost (legacy)
│   │   ├── binary_train_dt.py           # Binary DT (legacy)
│   │   ├── analyze_thresholds.py        # Threshold optimization
│   │   └── stress_test.py               # Performance benchmarking
│   │
│   └── utils/
│       ├── db_manager.py                 # SQLite operations
│       ├── firewall_manager.py           # OS-level firewall integration
│       ├── visualize_dt.py               # Decision Tree visualizations
│       ├── visualize_classes.py          # Class distribution plots
│       ├── analyze_class_distribution.py # Class balance analysis
│       ├── data_audit.py                 # Binary data audit
│       ├── data_audit_lstm.py            # LSTM data audit
│       ├── model_optimizer.py            # Threshold optimization
│       ├── xai_engine.py                 # SHAP explainability
│       └── inspect_csv.py               # CSV inspection utility
│
├── reports/
│   ├── randomforest/                     # 3-class RF visualizations
│   ├── xgboost/                          # 3-class XGBoost visualizations
│   ├── decisiontree/                     # 3-class DT visualizations
│   ├── bilstm/                           # BiLSTM evaluation reports
│   ├── lstm/                             # LSTM evaluation reports
│   ├── randomforest_binary/              # Archived binary RF reports
│   ├── xgboost_binary/                   # Archived binary XGBoost reports
│   └── decisiontree_binary/              # Archived binary DT reports
│
├── experiments/                          # AutoML & PyCaret experiments
│   ├── pycaret_setup.ipynb
│   └── results/
│
└── test/
    └── attack_test.py                    # Simulated attack scenarios
```

---

## Usage Guide

### Dashboard

Launch the monitoring dashboard:

```bash
streamlit run src/dashboard/app.py
```

**Features:**

- Real-time event metrics and blocked IP count
- Attack timeline visualization
- Action distribution charts (blocked vs. allowed)
- Filterable event log with source/destination details
- IP unblock interface for false positive management

### Standalone Detection (Without Kafka)

```bash
python src/live_bridge.py
```

Runs the capture-to-prediction pipeline directly without Kafka, suitable for testing and development.

---

## Configuration

### Environment Variables

Create a `.env` file from the provided template:

```env
NETWORK_INTERFACE=Wi-Fi
WHITELIST_IPS=192.168.1.1,127.0.0.1,8.8.8.8
THRESHOLD=0.10774313582858071
```

| Variable            | Description                                                          |
| :------------------ | :------------------------------------------------------------------- |
| `NETWORK_INTERFACE` | Network adapter name (run `python test/check_interfaces.py` to list) |
| `WHITELIST_IPS`     | Comma-separated IPs to exclude from blocking                         |
| `THRESHOLD`         | Decision boundary for binary classification                          |

### Active Model Selection

The Kafka Consumer dynamically loads models based on `data/active_model.txt`. Model hot-reloading is supported — update this file and the consumer switches models automatically without restart.

### Class Mapping

Define attack-to-class mapping in `src/utils/classes_map.json`:

```json
{
  "BENIGN": 0,
  "DDoS": 1,
  "DoS": 1,
  "Bot": 1,
  "PortScan": 2,
  "Web Attack": 2,
  "Brute Force": 2,
  "Infiltration": 2
}
```

---

## Development

### Training Pipeline (3-Class Models)

```bash
# Step 1 — Preprocess raw CICIDS 2017 data into 3-class splits
python src/features/preprocess_ml_3class.py
# Output: data/processed_ml/{train,val,test}.csv

# Step 2 — Train models
python src/models/train_randomforest.py      # Random Forest
python src/models/train_xgboost.py           # XGBoost (GPU-accelerated)
python src/models/train_decisiontree.py      # Decision Tree

# Step 3 — Generate evaluation dashboards
python src/models/evaluate_randomforest.py
python src/models/evaluate_xgboost.py
python src/models/evaluate_decisiontree.py
```

Each evaluation script produces:

- **Executive dashboard** — gauge charts, key metrics, deployment readiness
- **Detailed numeric report** — per-class precision/recall/F1
- **Confusion matrix** — 3×3 heatmap
- **Feature importance** — top-20 ranked features
- **ROC curves** — One-vs-Rest with AUC per class

### Training Pipeline (Deep Learning)

```bash
# Step 1 — Preprocess into LSTM sequences
python src/features/preprocess_lstm.py

# Step 2 — Train
python src/models/train_bilstm.py
python src/models/train_lstm.py

# Step 3 — Evaluate
python src/models/evaluate_bilstm.py
python src/models/evaluate_lstm.py
```

### Binary Models (Legacy)

```bash
python src/models/binary_train_randomforest.py
python src/models/binary_train_xgboost.py
python src/models/binary_train_dt.py
```

### Data Quality Audits

```bash
python src/features/data_audit_3class.py     # 3-class ML data
python src/utils/data_audit.py               # Binary RF data
python src/utils/data_audit_lstm.py           # LSTM sequence data
```

### Stress Testing

```bash
python src/models/stress_test.py
# Reports: throughput (predictions/sec), latency (ms), memory usage
```

---

## Dependencies

### Python Packages

```
numpy
pandas
scikit-learn
tensorflow
xgboost
scapy
streamlit
matplotlib
seaborn
joblib
plotly
python-dotenv
cicflowmeter
confluent-kafka
```

### System Requirements

| Requirement    | Purpose                                                  |
| :------------- | :------------------------------------------------------- |
| Docker Desktop | Kafka + Zookeeper containerized infrastructure           |
| Java 11+       | CICFlowMeter feature extraction                          |
| CUDA Toolkit   | _Optional_ — GPU acceleration for XGBoost and TensorFlow |

```bash
pip install -r requirements.txt
```

---

## Experiments & AutoML

PyCaret was used to benchmark multiple algorithms on binary classification:

- **CatBoost** emerged as top performer (~99.8% accuracy)
- Experiment notebook: `experiments/pycaret_setup.ipynb`
- Results and visualizations: `experiments/results/`

---

## Publications

| Article | Author | Platform | Topic |
| :------ | :----- | :------- | :---- |
| [NIDS v1: The Hidden Data Leakage Problem in CICIDS2017 and How Per-File Stratified Splitting Solves It](https://medium.com/@danismazbetul3/nids-v1-the-hidden-data-leakage-problem-in-cicids2017-and-how-per-file-stratified-splitting-6d9984194d93) | Betül Danışmaz | Medium | Data leakage in CICIDS2017 and the per-file stratified splitting methodology used in this project |

---

## License

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.

---

## Acknowledgements

### Advisor

Special thanks to **Dr. Necip Gözüaçık** for advising and guiding this project.

### Dataset

> Iman Sharafaldin, Arash Habibi Lashkari, and Ali A. Ghorbani, "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization", _4th International Conference on Information Systems Security and Privacy (ICISSP)_, 2018.

**Source:** [CICIDS 2017 — Canadian Institute for Cybersecurity](https://www.unb.ca/cic/datasets/ids-2017.html)

### Tools & Libraries

| Tool                                                       | Purpose                                       |
| :--------------------------------------------------------- | :-------------------------------------------- |
| [Scapy](https://scapy.net/)                                | Packet manipulation and capture               |
| [CICFlowMeter](https://github.com/ahlashkari/CICFlowMeter) | Bidirectional flow feature extraction         |
| [XGBoost](https://xgboost.readthedocs.io/)                 | GPU-accelerated gradient boosting             |
| [scikit-learn](https://scikit-learn.org/)                  | Machine learning algorithms and preprocessing |
| [TensorFlow](https://www.tensorflow.org/)                  | Deep learning framework                       |
| [Apache Kafka](https://kafka.apache.org/)                  | Distributed event streaming                   |
| [Streamlit](https://streamlit.io/)                         | Interactive dashboard framework               |
| [SHAP](https://shap.readthedocs.io/)                       | Model explainability                          |

---

<div align="center">

**Betül Danışmaz · Mustafa Emre Bıyık**  
Advisor: Dr. Necip Gözüaçık

[GitHub Repository](https://github.com/betuldanismaz/Network_Anomaly_Detection)

[![GitHub Stars](https://img.shields.io/github/stars/betuldanismaz/Network_Anomaly_Detection?style=social)](https://github.com/betuldanismaz/Network_Anomaly_Detection)
[![GitHub Forks](https://img.shields.io/github/forks/betuldanismaz/Network_Anomaly_Detection?style=social)](https://github.com/betuldanismaz/Network_Anomaly_Detection)

</div>
