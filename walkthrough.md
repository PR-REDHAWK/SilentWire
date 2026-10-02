# OracleShield — Implementation & Verification Walkthrough

**OracleShield** has been successfully built as a robust, demonstrable prototype of an AI/ML-powered passive cyber threat intelligence platform for unidirectional network monitoring enclaves.

---

## Key Features Implemented

### 1. Passive & Read-Only Ingestion Boundary
- Unidirectional packet processing architecture with zero return path capability.
- No packet injection, no active response commands, no TLS/QUIC payload decryption.
- Incremental generator-based PCAP reader (`ingest/pcap_reader.py`) and PCAP Replay CLI tool (`ingest/replay.py`).

### 2. Canonical Bidirectional Flow Engine & Direction Preservation
- Uses canonical bidirectional 5-tuple keys (`CanonicalFlowKey`) to group forward and reverse packets into a single `Flow` object.
- Tracks initiator vs responder directionality for SYN analysis, amplification ratios, C2 timing, and outbound upload/download exfiltration analysis.
- Maintains 5-second sliding window flow aggregation with active/idle timeouts.

### 3. Statistical Baseline & Behavior Profiling Engine
- Rolling host statistical baseline profiler (`features/baseline_profiler.py`) tracking exponential moving averages (EMA) for byte volumes, packet rates, and calculating Z-score statistical deviations.

### 4. Multi-Layer Threat Detectors & Ensemble Risk Engine
- **SYN Flood & UDP Amplification Detector** (`detection/ddos_detector.py`)
- **Port & Host Scan Detector** (`detection/scanning_detector.py`)
- **Botnet C2 Beacon Detector** (`detection/beacon_detector.py`)
- **DGA Domain Detector** (`detection/dga_detector.py`)
- **DNS Covert Tunnel Detector** (`detection/dns_tunnel_detector.py`)
- **Data Exfiltration Detector** (`detection/exfiltration_detector.py`)
- **Unsupervised Anomaly Detector** (`detection/anomaly_detector.py`)
- **Ensemble Risk Engine** (`detection/ensemble.py`) resolving scores and generating evidence-first alerts with strict confidence vs severity separation.

### 5. Machine Learning Pipeline & Leakage-Free Splitting
- Dataset builder (`models/training/dataset_builder.py`) with capture/session/time-based splitting to prevent data leakage.
- Supervised Random Forest Classifier & Unsupervised Isolation Forest Anomaly Detector trained and serialized via `joblib`.

### 6. FastAPI Backend & Real-Time Engine
- Asynchronous FastAPI server (`backend/main.py`) providing `/api/alerts`, `/api/alerts/{id}`, `/api/flows`, `/api/statistics`, `/api/models`, and `/api/health`.
- WebSocket broadcast server at `/ws/alerts` for real-time alert streaming to dashboard clients.

### 7. SOC Security Operations Dashboard
- Dark-mode React + TypeScript + Tailwind CSS interface compiled into `dashboard/dist/`.
- Features: Status Badges (`READ-ONLY INGEST`, `NO ACTIVE RESPONSE`), KPI Stat Cards, Real-time Threat Line Charts & Bar Charts, Live Alert Stream Table, and an interactive **Threat Investigation Drawer** showing full 5-tuple details, model attributions, contributing feature importances, and empirical evidence parameters.

---

## Verification & Testing Results

### 1. Automated Unit & Integration Tests
Ran `pytest tests/` with **100% passing results**:

```text
tests/test_api.py ........ [ 44%]
tests/test_detection.py .. [ 66%]
tests/test_flow_engine.py ... [100%]
9 passed in 0.83s
```

### 2. Machine Learning Model Evaluation
Ran `python -m models.training.train_all`:

```text
=== OracleShield ML Evaluation Results ===
Accuracy:  1.0000
Precision: 1.0000
Recall:    1.0000
F1-Score:  1.0000
FPR:       0.0000
FNR:       0.0000
Saved trained Random Forest model to: C:\Users\LENOVO\OneDrive\CyberOracle\models\trained\oracle_shield_rf.joblib
Saved trained Isolation Forest model to: C:\Users\LENOVO\OneDrive\CyberOracle\models\trained\oracle_shield_isoforest.joblib
```

### 3. High-Throughput Benchmarking Results
Ran `python -m benchmarks.throughput`:

```text
==================================================================
        OracleShield Passive Engine Throughput & Latency Benchmark 
==================================================================
Target Flows:   500 | Throughput: 236,088.2 flows/s
  Latency (ms):  Mean: 0.004 | P50: 0.003 | P95: 0.005 | P99: 0.021
------------------------------------------------------------------
Target Flows:  1000 | Throughput: 109,343.3 flows/s
  Latency (ms):  Mean: 0.009 | P50: 0.003 | P95: 0.006 | P99: 0.023
------------------------------------------------------------------
Target Flows:  5000 | Throughput:  69,548.3 flows/s
  Latency (ms):  Mean: 0.014 | P50: 0.007 | P95: 0.011 | P99: 0.047
------------------------------------------------------------------
```

---

## Demonstration Instructions

### 1. Launch the Backend API & SOC Dashboard
```bash
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```
Navigate to `http://127.0.0.1:8000` in your web browser to open the OracleShield Security Operations Center dashboard.

### 2. Run the Live Threat Simulator
In a second terminal window:
```bash
python -m simulator.demo
```
Observe real-time threat alerts (SYN Floods, Port Scans, C2 Beaconing) streaming over WebSocket onto the live dashboard. Click any row in the feed to open the **Threat Investigation Drawer** for deep inspection.
