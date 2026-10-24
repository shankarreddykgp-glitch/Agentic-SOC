# AEGIS-SOC: Autonomous Enterprise Multi-Agent Cyber Defense Platform

AEGIS-SOC is a next-generation Autonomous Security Operations Center (SOC) platform engineered with a multi-agent orchestration architecture powered by **LangGraph**, **ChromaDB Vector RAG**, deterministic mathematical anomaly detection (**Shannon Entropy** and **Haversine Velocity**), and **LLM-driven threat correlation**.

---

## ⚡ Key Features

- **4-Node LangGraph Swarm**:
  - `Node 1: Ingestion & Enrichment Agent` — Stream parses authentication events, enriches with MaxMind GeoIP and ASN reputation.
  - `Node 2: Deterministic Anomaly Engine` — Mathematical validation via Shannon Entropy ($H > 4.5\text{ bits}$) and Haversine velocity ($> 900\text{ km/h}$).
  - `Node 3: Semantic Correlation Agent` — ChromaDB Vector RAG matching against MITRE ATT&CK enterprise tactics and Gemini 2.5 LLM reasoning.
  - `Node 4: Sentinel Auditor Agent` — Real-time anti-hallucination verification, consensus auditing, and state validation.
- **Self-Healing State Rewind Engine**:
  - Automatically identifies hallucinated or malformed mitigation recommendations, revokes invalid state transitions, and rewinds to the last known safe consensus checkpoint.
- **Dynamic DEFCON Autonomy Matrix**:
  - Four operating autonomy tiers: **DEFCON 4** (Advisory / L1 Manual), **DEFCON 3** (Guarded / L2 Analyst Approval), **DEFCON 2** (Elevated / L3 Semi-Autonomous), and **DEFCON 1** (Maximum / L4 Fully Autonomous).
- **Interactive Attack Network Topology Graph**:
  - Force-directed interactive network visualization with zoom, pan, and real-time node state inspection.
- **Cryptographic SHA-256 Forensic Incident Exporter**:
  - Generates immutable, digitally signed forensic incident certificates for compliance auditing (ISO-27001 / SOC 2 Type II).

---

## 🏗️ Architecture

```
[ Ingested Auth Events ]
           │
           ▼
┌──────────────────────────────────────┐
│  Node 1: Ingestion & Geo Enrichment  │
└──────────────────┬───────────────────┘
                   │
                   ▼
┌──────────────────────────────────────┐
│  Node 2: Shannon Entropy & Haversine │
└──────────────────┬───────────────────┘
                   │
                   ▼
┌──────────────────────────────────────┐
│  Node 3: ChromaDB RAG & Gemini LLM   │
└──────────────────┬───────────────────┘
                   │
                   ▼
┌──────────────────────────────────────┐
│  Node 4: Sentinel Auditor Consensus  │
└──────────────────┬───────────────────┘
                   │
        [ Validated Mitigation ]
                   │
                   ▼
┌──────────────────────────────────────┐
│  SOAR Engine: Automated IP Quarantine│
│  & OAuth JWT Token Invalidation      │
└──────────────────────────────────────┘
```

---

## 🚀 Quick Start

### 1. Prerequisites
- Python 3.10+
- Git

### 2. Installation
```bash
git clone https://github.com/legit-use/agentic-soc.git
cd agentic-soc
pip install -r requirements.txt
```

### 3. Environment Configuration
Copy the example environment file and add your credentials:
```bash
cp .env.example .env
```
Configure your `.env`:
```ini
GEMINI_API_KEY=your_gemini_api_key_here
PORT=8000
ENVIRONMENT=production
```

### 4. Running the Platform
Launch the ASGI FastAPI server:
```bash
python server.py
```
Open your browser and navigate to:
```
http://localhost:8000
```

---

## 🧪 Real-Time Attack Simulation

To stream live attack scenarios (Brute Force, Credential Stuffing, Impossible Travel, Session Hijack) into the pipeline:
```bash
python tools/real_dataset_streamer.py
```

To run the automated accuracy and latency evaluation suite:
```bash
python tools/evaluate_accuracy.py
```

---

## 📁 Repository Structure

```
├── agents/
│   └── graph_pipeline.py       # LangGraph 4-node swarm & rewind state machine
├── core/
│   ├── autonomy_calibrator.py  # Dynamic DEFCON calibration engine
│   ├── math_engine.py          # Shannon Entropy & Haversine Velocity algorithms
│   ├── mitigation_engine.py    # SOAR playbooks & SHA-256 forensic exporter
│   ├── schemas.py              # Pydantic data schemas & state models
│   └── vector_store.py         # ChromaDB Vector RAG & MITRE ATT&CK index
├── static/
│   ├── index.html              # Cyber Command Theater HUD & interactive topology
│   ├── login.html              # Auth portal
│   └── soc_emblem.png          # Visual branding
├── tools/
│   ├── evaluate_accuracy.py    # Multi-model evaluation suite
│   ├── external_siem_injector.py
│   ├── live_system_sensor.py
│   ├── real_data_streamer.py
│   └── real_dataset_streamer.py # Synthetic & Kaggle RBA stream simulator
├── server.py                   # FastAPI async server & WebSocket handlers
├── test_system.py              # Unit & integration test suite
├── requirements.txt            # Python dependencies
└── README.md                   # Project overview & documentation
```

---

## 📜 License
MIT License. Created for Research & Educational Cybersecurity Defense Engineering.
