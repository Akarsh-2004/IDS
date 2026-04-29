# Real-Time Network IDS (ML-Based)

A complete, demo-ready Intrusion Detection System pipeline with:

- real-time traffic ingestion (`live` NIC or `pcap` replay)
- flow aggregation and feature mapping
- ML inference (Random Forest)
- severity-based alerting
- live dashboard updates via WebSocket
- persisted event history in SQLite

## Features

- **Realtime engine** with start/stop control
- **Two capture modes**
  - `live` for network interface capture
  - `pcap` for deterministic demo replay
- **Live metrics**
  - packets per second (`pps`)
  - queue depth (backpressure)
  - alerts per minute
- **Live alert table**
  - time, severity, confidence score, source, flow summary
- **API-first backend**
  - REST endpoints + websocket stream
- **One-command startup**
  - `start.ps1` for Windows
  - `start.sh` for Bash/Linux/macOS

## Project Structure

```text
IDS/
├── backend/
│   ├── app.py
│   ├── model_pipeline.py
│   ├── requirements.txt
│   ├── realtime/
│   │   ├── capture.py
│   │   ├── flows.py
│   │   ├── features.py
│   │   ├── pipeline.py
│   │   ├── alerts.py
│   │   ├── metrics.py
│   │   └── store.py
│   └── tests/
├── frontend/
│   └── index.html
├── Train_data.csv
├── Test_data.csv
├── generate_pcap.py
├── start.ps1
└── start.sh
```

## Requirements

- Python 3.10+
- Git

Optional for live capture on Windows:
- Npcap installed
- terminal run as Administrator (if capture permission is blocked)

## Quick Start

### 1) Clone

```bash
git clone https://github.com/Akarsh-2004/IDS.git
cd IDS
```

### 2) Start everything

#### Windows (recommended)

```powershell
.\start.ps1
```

#### Bash/Linux/macOS

```bash
bash ./start.sh
```

This automatically:
1. creates virtual environment (`.venv`) if needed
2. installs dependencies from `backend/requirements.txt`
3. starts backend API on `127.0.0.1:8000`
4. starts frontend dashboard on `127.0.0.1:3000`

### 3) Open

- Dashboard: <http://127.0.0.1:3000>
- API Docs (Swagger): <http://127.0.0.1:8000/docs>

## Demo Mode (Recommended)

For reliable demo alerts, use PCAP mode.

### Generate malicious demo traffic

```powershell
python generate_pcap.py
```

Creates:
- `demo_malicious_traffic.pcap`

### Run realtime engine from dashboard

1. Select mode: `pcap`
2. Enter pcap path, for example:
   `C:\Users\akars\OneDrive\Desktop\IDS-main\IDS-main\demo_malicious_traffic.pcap`
3. Click `Start`

You should see live metrics and alert rows updating.

## API Endpoints

### Core

- `GET /health` - health check
- `GET /schema` - model input schema
- `POST /train` - train model and save artifacts
- `POST /predict` - one-off prediction
- `POST /evaluate` - evaluate on test dataset

### Realtime

- `POST /realtime/start`
  - body:
    - `mode`: `"live"` or `"pcap"`
    - `interface`: required when `mode="live"`
    - `pcap_path`: required when `mode="pcap"`
- `POST /realtime/stop`
- `GET /realtime/status`
- `GET /realtime/events`
- `WS /ws/alerts` - live alert stream

## Model and Artifacts

Saved in `backend/artifacts/`:

- `model.joblib`
- `feature_columns.joblib`
- `model_meta.joblib`
- `events.sqlite3` (alert history)

## Run Tests

```bash
pytest -q backend/tests
```

## Troubleshooting

- **404 in browser console**
  - `favicon.ico` 404 is harmless.
- **No alerts appearing**
  - use `pcap` mode with `demo_malicious_traffic.pcap`
  - stop/start realtime engine to replay
- **Live mode not capturing**
  - install Npcap and run terminal with elevated privileges
  - verify interface name (`Ethernet`, `Wi-Fi`, etc.)
- **Port already in use**
  - free ports `3000` and `8000`, then rerun startup script

## Presentation Checklist

1. Run `.\start.ps1`
2. Open dashboard and `/docs`
3. Start realtime in `pcap` mode
4. Show `pps`, queue depth, alerts/min
5. Show live alert severity and score
