# ThreatMapper

A physical-digital threat detection and correlation system that parses security events, maps them to the **MITRE ATT&CK** framework, and correlates digital intrusions with real-world physical access — powered by an ESP32-CAM sensor and a live web dashboard.

---

## Screenshot

> *(Dashboard screenshot coming soon)*

---

## Features

### Phase 1 — Digital Log Parser
- Parses firewall, SSH authentication, and audit logs using regex pattern matching
- Extracts source IPs, usernames, ports, and file paths from raw log lines
- Supports custom log file paths via CLI argument

### Phase 2 — Physical Event Detection
- ESP32-CAM serial bridge reads JSON events in real time over serial
- Detects motion, badge scans, after-hours intrusions, and rogue device connections
- Emits log lines compatible with the threat_mapper parser — no glue code needed

### Phase 3 — MITRE ATT&CK Mapping
- Every event type maps to a MITRE technique ID, name, and tactic
- Covers 8 techniques across 4 tactics: Credential Access, Discovery, Initial Access, Collection
- Helper functions: `all_tactics()`, `techniques_by_tactic(tactic)`

### Phase 4 — Correlation Engine & Threat Scoring
- Rule-based correlator matches physical and digital events within a configurable time window
- Six correlation rules produce `CorrelatedThreat` objects with MITRE mappings and recommended actions
- Scorer aggregates events across digital, physical, and correlated sources into ranked `ThreatScore` objects
- Threat levels: LOW / MEDIUM / HIGH / CRITICAL

### Phase 5 — SOAR (Security Orchestration, Automation, and Response) *(In Progress)*
- Automated response engine triggers actions based on threat score thresholds
- CRITICAL threats → phone alert + auto-generated incident report
- HIGH threats → alert notification + recommended action logged
- Pluggable action system: block IP, send alert, create report
- Runs independently of hardware — responds to any event source (digital, physical, or correlated)

---

## MITRE ATT&CK Coverage

| Event Key | Technique ID | Name | Tactic |
|---|---|---|---|
| `SSH_LOGIN_FAILED` | T1110 | Brute Force | Credential Access |
| `PORT_SCAN` | T1046 | Network Service Scanning | Discovery |
| `HONEYFILE_ACCESSED` | T1083 | File and Directory Discovery | Discovery |
| `MOTION_DETECTED` | T0812 | Device Identification / Physical Recon | Discovery |
| `PHYSICAL_PRESENCE` | T1078 | Valid Accounts / Physical Access | Initial Access |
| `AFTER_HOURS_INTRUSION` | T0867 | Physical Intrusion | Initial Access |
| `CORRELATED_ATTACK` | T1200 | Hardware Additions | Initial Access |
| `HONEYFILE_PHYSICAL_CORRELATION` | T1074 | Data Staged / Insider Threat | Collection |

---

## Tech Stack

| Layer | Technology |
|---|---|
| Core language | Python 3.11+ |
| Web framework | FastAPI + Uvicorn |
| Templating | Jinja2 |
| Physical sensor | ESP32-CAM |
| Firmware | Arduino (C++) |
| Serial bridge | PySerial |
| Reporting | Plain text + REST JSON |

---

## Installation

**Requirements:** Python 3.11+

```bash
git clone https://github.com/guado1983-star/Threat-Mapper.git
cd Threat-Mapper
pip install -r requirements.txt
```

---

## Usage

### Parse a log file

```bash
# Default sample log
python threat_mapper.py

# Custom log file
python threat_mapper.py logs/my_log.log
```

Output includes a parsed event list, event type summary, MITRE mapping table, and ranked threat scores. A timestamped report is saved to `reports/`.

---

### Run the correlation engine

```bash
# Batch mode — correlate the sample log
python -m core.correlator

# Custom log and time window (seconds)
python -m core.correlator --log logs/my_log.log --window 600
```

---

### Run the threat scorer

```bash
python -m core.scorer

python -m core.scorer --log logs/my_log.log
```

---

### Run the SOAR responder

```bash
# Evaluate the sample log and write incident reports for all threats above LOW
python -m core.responder

# With phone alerts via ntfy.sh (install ntfy app, subscribe to your topic)
python -m core.responder --ntfy-topic my-threat-alerts

# Also block CRITICAL source IPs via Windows Firewall (requires admin)
python -m core.responder --ntfy-topic my-threat-alerts --block-ips

# Set minimum alert level (default: HIGH — also alerts on CRITICAL)
python -m core.responder --ntfy-topic my-threat-alerts --min-alert-level CRITICAL

# Set topic via environment variable instead of flag
set NTFY_TOPIC=my-threat-alerts
python -m core.responder
```

SOAR also runs automatically at the end of every `python threat_mapper.py` run,
and is available via the dashboard API at `POST /api/respond`.

---

### Run the web dashboard

```bash
uvicorn dashboard:app --host 127.0.0.1 --port 3000 --reload
```

Then open **http://127.0.0.1:3000** in your browser.

| Endpoint | Description |
|---|---|
| `/` | Live dashboard UI |
| `/api/events` | All parsed events as JSON |
| `/api/summary` | Threat scores, event counts, MITRE breakdown |
| `POST /api/respond` | Trigger SOAR response (returns actions taken) |
| `/api/docs` | Auto-generated Swagger UI |

---

## Project Structure

```
Threat-Mapper/
├── threat_mapper.py       # Log parser and CLI entry point
├── mitre_mapper.py        # MITRE ATT&CK technique lookup
├── dashboard.py           # FastAPI web dashboard
├── core/
│   ├── models.py          # Shared dataclasses (SecurityEvent, PhysicalEvent, CorrelatedThreat, ThreatScore)
│   ├── correlator.py      # Physical + digital correlation engine
│   ├── scorer.py          # Aggregated threat scoring
│   └── responder.py       # SOAR response engine (Phase 5)
├── esp32/
│   └── bridge.py          # ESP32-CAM serial bridge
├── templates/
│   └── index.html         # Dashboard frontend
├── logs/
│   └── sample_attack.log  # Sample log with digital and physical events
└── reports/               # Auto-generated timestamped reports (gitignored)
```

---

## ESP32 Hardware Setup *(Coming Soon)*

Phase 2 physical detection requires an **ESP32-CAM** module connected over USB serial.

> Hardware integration is in progress — parts on order. This section will be updated with:
> - Wiring diagram
> - Arduino firmware source
> - Supported sensor types (PIR motion, door contact, RFID badge reader)
> - Serial protocol reference (JSON over UART at 115200 baud)
> - `python -m esp32.bridge --port COM3` quickstart

Once connected, the bridge feeds physical events directly into the correlation engine in real time alongside live log data.

---

## Author

**guado1983**
- GitHub: [@guado1983-star](https://github.com/guado1983-star)

---

## License

MIT
