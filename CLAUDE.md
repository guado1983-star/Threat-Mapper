# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Install dependencies (Python 3.11+ required)
pip install -r requirements.txt

# Run the full pipeline (parse → correlate → score → SOAR respond)
python threat_mapper.py
python threat_mapper.py logs/my_log.log

# With phone alerts (ntfy.sh) and optional IP blocking (requires admin)
python threat_mapper.py --ntfy-topic my-topic --block-ips

# Run the correlation engine alone
python -m core.correlator
python -m core.correlator --log logs/my_log.log --window 600

# Run the threat scorer alone
python -m core.scorer
python -m core.scorer --log logs/my_log.log

# Run the SOAR responder alone
python -m core.responder
python -m core.responder --ntfy-topic my-topic --block-ips --min-alert-level CRITICAL

# Run the web dashboard
uvicorn dashboard:app --host 127.0.0.1 --port 3000 --reload
# Or: python dashboard.py  (auto-opens browser)

# Run the ESP32 physical bridge
python -m esp32.bridge --port COM3
python -m esp32.bridge --list-ports

# Run tests
pytest
pytest tests/test_fixes.py::TestCorrelator  # single class
```

## Architecture

The system has five phases that build on each other:

```
logs/sample_attack.log
        │
        ▼
threat_mapper.py          # Phase 1: regex parser → list[SecurityEvent]
        │
        ├──► mitre_mapper.py           # Phase 3: event_type → MitreTechnique lookup
        │
        ▼
core/correlator.py        # Phase 2+4: splits SecurityEvents into physical-typed
        │                 #   vs digital, then applies 6 rules within a time window
        │                 #   → list[CorrelatedThreat]
        ▼
core/scorer.py            # Phase 4: merges digital events + physical events +
        │                 #   correlated threats → list[ThreatScore] ranked by score
        ▼
core/responder.py         # Phase 5: SOAR — fires actions per ThreatScore level:
                          #   CRITICAL → phone alert + IP block (opt-in) + incident report
                          #   HIGH     → phone alert + incident report
                          #   MEDIUM   → incident report only
```

**All shared dataclasses live in `core/models.py`** — `SecurityEvent`, `PhysicalEvent`, `CorrelatedThreat`, `ThreatScore`, `ThreatLevel`. The file `models.py` at the root is a stub that redirects imports.

**`dashboard.py`** is a FastAPI app that exposes the full pipeline via REST. Log files are restricted to the `logs/` directory via a path traversal guard before any parse call.

**`esp32/bridge.py`** reads JSON over serial from an ESP32-CAM and formats events into log lines that match `threat_mapper.py`'s existing regex patterns exactly — no glue code is needed in the parser.

### Correlation logic

The correlator (`core/correlator.py`) has two modes:
- **Real-time** (`correlate()`): receives `PhysicalEvent` objects from the ESP32 bridge alongside `SecurityEvent` objects from live log tailing.
- **Batch** (`correlate_from_log()`): splits a mixed `SecurityEvent` list — events with types `MOTION_DETECTED`, `PHYSICAL_PRESENCE`, or `AFTER_HOURS_INTRUSION` are treated as the physical side; all others are digital. This lets a single log file produced by `threat_mapper.py` drive the full pipeline without hardware.

Six frozen `_Rule` objects define what physical + digital event-type combinations trigger a `CorrelatedThreat`, with MITRE mappings and base scores baked in.

### Threat scoring thresholds

| Score | Level    | SOAR actions |
|-------|----------|--------------|
| ≥ 20  | CRITICAL | phone alert (urgent) + IP block (opt-in) + incident report |
| ≥ 10  | HIGH     | phone alert (high) + incident report |
| ≥ 5   | MEDIUM   | incident report only |
| < 5   | LOW      | none |

### Environment variables

| Variable | Effect |
|---|---|
| `NTFY_TOPIC` | Enables phone alerts via ntfy.sh (alternative to `--ntfy-topic`) |
| `THREATMAPPER_API_KEY` | Enables API key auth on dashboard (header: `X-API-Key`); omitting it runs in open-access dev mode |
| `DEBUG` | Set to `1`/`true` to enable debug mode in the dashboard |
