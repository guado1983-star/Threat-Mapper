from collections import Counter
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

import mitre_mapper
from core.correlator import correlate_from_log
from core.models import SecurityEvent
from core.responder import respond_to_scores
from core.scorer import score_all
from threat_mapper import parse_log, score_threats

DEFAULT_LOG_FILE = Path(__file__).parent / "logs" / "sample_attack.log"

app = FastAPI(title="ThreatMapper", docs_url="/api/docs")
_templates = Jinja2Templates(directory=Path(__file__).parent / "templates")


def _load(log: str) -> list[SecurityEvent]:
    path = Path(log)
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"Log file not found: {log}")
    try:
        return parse_log(path)
    except SystemExit:
        raise HTTPException(status_code=500, detail="Failed to parse log file")


def _serialize(events: list[SecurityEvent]) -> list[dict]:
    out = []
    for e in events:
        t = mitre_mapper.map_event(e.event_type)
        out.append({
            "timestamp": e.timestamp,
            "event_type": e.event_type,
            "source_ip": e.source_ip,
            "username": e.username,
            "password_attempt": e.password_attempt,
            "port": e.port,
            "file_accessed": e.file_accessed,
            "mitre_id": t.technique_id if t else None,
            "mitre_name": t.name if t else None,
            "mitre_tactic": t.tactic if t else None,
        })
    return out


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    return _templates.TemplateResponse(request=request, name="index.html")


@app.get("/api/events")
async def api_events(log: str = str(DEFAULT_LOG_FILE)):
    events = _load(log)
    return {"total": len(events), "events": _serialize(events)}


@app.get("/api/summary")
async def api_summary(log: str = str(DEFAULT_LOG_FILE)):
    events = _load(log)
    type_counts = Counter(e.event_type for e in events)
    scores = score_threats(events)
    ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)
    ip_counts = Counter(e.source_ip for e in events)

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
            {"ip": ip, "score": s, "events": ip_counts[ip]}
            for ip, s in ranked
        ],
        "mitre_techniques": list(mitre.values()),
    }


@app.post("/api/respond")
async def api_respond(
    log: str = str(DEFAULT_LOG_FILE),
    ntfy_topic: str = "",
    block_ips: bool = False,
):
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
    import threading
    import webbrowser
    threading.Timer(1.5, lambda: webbrowser.open("http://127.0.0.1:3000")).start()
    uvicorn.run("dashboard:app", host="127.0.0.1", port=3000, reload=True)
