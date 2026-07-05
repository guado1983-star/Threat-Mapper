import ipaddress as _iplib
import os
import re
import secrets
from collections import Counter
from pathlib import Path

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Request, Security
from fastapi.responses import HTMLResponse
from fastapi.security import APIKeyHeader
from fastapi.templating import Jinja2Templates

import mitre_mapper
from core.correlator import correlate_from_log
from core.models import SecurityEvent
from core.responder import respond_to_scores
from core.scorer import score_all
from threat_mapper import parse_log, score_threats

DEFAULT_LOG_FILE = Path(__file__).parent / "logs" / "sample_attack.log"

# Only files inside this directory are permitted via the log= parameter.
_LOGS_DIR = (Path(__file__).parent / "logs").resolve()

# ntfy topic: letters, digits, hyphens, underscores — no path chars.
_NTFY_TOPIC_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

_DEBUG = os.environ.get("DEBUG", "").lower() in ("1", "true", "yes")

app = FastAPI(
    title="ThreatMapper",
    docs_url="/api/docs",
    redoc_url=None,
)
_templates = Jinja2Templates(directory=Path(__file__).parent / "templates")


# ── API key auth ────────────────────────────────────────────────────── #
# Set THREATMAPPER_API_KEY env var to enable.  Without it the server
# runs in open-access dev mode and prints a startup warning.

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def _require_api_key(
    key: str | None = Security(_api_key_header),
) -> None:
    expected = os.environ.get("THREATMAPPER_API_KEY", "")
    if not expected:
        return  # dev mode — no key configured
    if not key or not secrets.compare_digest(key, expected):
        raise HTTPException(status_code=403, detail="Invalid or missing API key")


# ── Helpers ─────────────────────────────────────────────────────────── #

def _load(log: str) -> list[SecurityEvent]:
    try:
        path = Path(log).resolve()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid log path")

    # Path traversal guard — must stay inside logs/
    try:
        path.relative_to(_LOGS_DIR)
    except ValueError:
        raise HTTPException(status_code=403, detail="Log path outside permitted directory")

    if not path.exists():
        raise HTTPException(status_code=404, detail="Log file not found")

    try:
        return parse_log(path)
    except SystemExit:
        raise HTTPException(status_code=500, detail="Failed to parse log file")


def _serialize(events: list) -> list[dict]:
    out = []
    for e in events:
        t = mitre_mapper.map_event(e.event_type)
        out.append({
            "timestamp":        e.timestamp,
            "event_type":       e.event_type,
            "source_ip":        getattr(e, "source_ip",  None),
            "sensor_id":        getattr(e, "sensor_id",  None),
            "badge_id":         getattr(e, "badge_id",   None),
            "zone":             getattr(e, "zone",        None),
            "username":         getattr(e, "username",   None),
            "password_attempt": getattr(e, "password_attempt", None),
            "port":             getattr(e, "port",        None),
            "file_accessed":    getattr(e, "file_accessed", None),
            "mitre_id":     t.technique_id if t else None,
            "mitre_name":   t.name         if t else None,
            "mitre_tactic": t.tactic       if t else None,
        })
    return out


# ── Routes ──────────────────────────────────────────────────────────── #

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    return _templates.TemplateResponse(
        request=request,
        name="index.html",
        context={},
    )


@app.get("/api/events", dependencies=[Depends(_require_api_key)])
async def api_events(log: str = str(DEFAULT_LOG_FILE)):
    events = _load(log)
    return {"total": len(events), "events": _serialize(events)}


@app.get("/api/summary", dependencies=[Depends(_require_api_key)])
async def api_summary(log: str = str(DEFAULT_LOG_FILE)):
    events = _load(log)
    type_counts = Counter(e.event_type for e in events)
    scores = score_threats(events)
    ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)
    ip_counts = Counter(getattr(e, "source_ip", None) for e in events)

    mitre: dict[str, dict] = {}
    for e in events:
        t = mitre_mapper.map_event(e.event_type)
        if t:
            if t.technique_id not in mitre:
                mitre[t.technique_id] = {
                    "technique_id": t.technique_id,
                    "name": t.name,
                    "tactic": t.tactic,
                    "count": 0,
                }
            mitre[t.technique_id]["count"] += 1

    return {
        "total_events": len(events),
        "event_types": dict(type_counts),
        "threat_scores": [
            {"source": src, "score": s, "events": ip_counts[src]}
            for src, s in ranked
        ],
        "mitre_techniques": list(mitre.values()),
    }


@app.post("/api/respond", dependencies=[Depends(_require_api_key)])
async def api_respond(
    log: str = str(DEFAULT_LOG_FILE),
    ntfy_topic: str = "",
    block_ips: bool = False,
):
    if ntfy_topic and not _NTFY_TOPIC_RE.match(ntfy_topic):
        raise HTTPException(
            status_code=400,
            detail="ntfy_topic must be 1-64 alphanumeric characters, hyphens, or underscores",
        )

    events  = _load(log)
    threats = correlate_from_log(events)
    scores  = score_all(digital=events, threats=threats)
    actions = respond_to_scores(
        scores,
        correlated=threats,
        ntfy_topic=ntfy_topic,
        block_ips=block_ips,
    )
    return {
        "sources_actioned": len(actions),
        "total_actions": sum(len(r["actions_taken"]) for r in actions),
        "responses": actions,
    }


if __name__ == "__main__":
    if not os.environ.get("THREATMAPPER_API_KEY"):
        print(
            "\n[WARNING] THREATMAPPER_API_KEY is not set — running in open-access dev mode.\n"
            "          Set the env var to enable API key authentication.\n"
        )
    import threading
    import webbrowser
    threading.Timer(1.5, lambda: webbrowser.open("http://127.0.0.1:3000")).start()
    uvicorn.run("dashboard:app", host="127.0.0.1", port=3000, reload=True)
