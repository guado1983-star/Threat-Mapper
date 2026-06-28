"""
ThreatMapper — SOAR Responder (Phase 5)
========================================
Automated response engine. Evaluates ThreatScore and CorrelatedThreat objects
against configurable thresholds and fires the appropriate actions:

  CRITICAL  →  phone alert (urgent priority) + IP block (opt-in) + incident report
  HIGH      →  phone alert (high priority) + incident report
  MEDIUM    →  incident report only
  LOW       →  no action

Phone alerts use ntfy.sh — free, no account required.
Install the ntfy app on your phone and subscribe to your chosen topic name.
Enable alerts by setting the NTFY_TOPIC env var or passing --ntfy-topic.

IP blocking requires --block-ips flag (disabled by default for safety).
Uses Windows netsh on Windows, iptables on Linux/Mac.

Run standalone:
  python -m core.responder
  python -m core.responder --log logs/sample_attack.log
  python -m core.responder --ntfy-topic my-alerts --block-ips
"""

import argparse
import json
import os
import platform
import subprocess
import sys
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core.models import CorrelatedThreat, ThreatLevel, ThreatScore  # noqa: E402

REPORTS_DIR = Path("reports")
_TS_FMT = "%Y%m%d_%H%M%S"


# ── Threshold mapping (mirrors ThreatScore.label) ─────────────────── #

def _level_from_score(score: int) -> ThreatLevel:
    if score >= 20:
        return ThreatLevel.CRITICAL
    if score >= 10:
        return ThreatLevel.HIGH
    if score >= 5:
        return ThreatLevel.MEDIUM
    return ThreatLevel.LOW


# ── Actions ────────────────────────────────────────────────────────── #

def _notify_phone(
    title: str,
    body: str,
    priority: str,
    ntfy_topic: str,
    ntfy_url: str = "https://ntfy.sh",
) -> bool:
    """Send a push notification via ntfy.sh. Returns True on success."""
    url = f"{ntfy_url}/{ntfy_topic}"
    payload = json.dumps({
        "topic": ntfy_topic,
        "title": title,
        "message": body,
        "priority": priority,
    }).encode()
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status == 200
    except Exception as exc:
        print(f"  [SOAR] Phone alert failed: {exc}")
        return False


def _block_ip(ip: str) -> bool:
    """Block an inbound IP using the platform firewall. Returns True on success."""
    if not ip or ip in ("unknown", "0.0.0.0", ""):
        return False
    try:
        if platform.system() == "Windows":
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name=ThreatMapper-Block-{ip}",
                "dir=in", "action=block",
                f"remoteip={ip}",
            ]
        else:
            cmd = ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]
        subprocess.run(cmd, check=True, capture_output=True)
        return True
    except Exception as exc:
        print(f"  [SOAR] IP block failed for {ip}: {exc}")
        return False


def _write_incident(
    incident_id: str,
    level: ThreatLevel,
    source_id: str,
    summary: str,
    recommended_action: str,
    details: str,
) -> Path:
    """Write a timestamped incident report. Returns the report path."""
    REPORTS_DIR.mkdir(exist_ok=True)
    ts = datetime.now().strftime(_TS_FMT)
    safe_id = incident_id.replace("/", "_").replace(":", "_").replace(".", "_")
    path = REPORTS_DIR / f"incident_{ts}_{safe_id[:12]}.txt"
    lines = [
        "=" * 62,
        "  THREATMAPPER SOAR — Incident Report",
        "=" * 62,
        f"  Incident ID    : {incident_id}",
        f"  Timestamp      : {datetime.now().isoformat()}",
        f"  Threat Level   : {level.label()}",
        f"  Source         : {source_id}",
        "",
        "  Summary",
        "  -------",
        f"  {summary}",
        "",
        "  Recommended Action",
        "  ------------------",
        f"  {recommended_action}",
        "",
        "  Details",
        "  -------",
        details,
        "=" * 62,
    ]
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


# ── Response dispatcher ────────────────────────────────────────────── #

def respond_to_scores(
    scores: list,
    correlated: Optional[list] = None,
    ntfy_topic: str = "",
    ntfy_url: str = "https://ntfy.sh",
    block_ips: bool = False,
    min_alert_level: ThreatLevel = ThreatLevel.HIGH,
) -> list:
    """
    Evaluate a list[ThreatScore] and fire SOAR actions for each source
    that exceeds the LOW threshold.

    Returns a list of response records (one dict per actioned source).
    """
    correlated = correlated or []

    # Map correlated threats to their physical-side source IDs for context
    corr_by_source: dict[str, list[CorrelatedThreat]] = {}
    for t in correlated:
        for pe in t.physical_events:
            src = getattr(pe, "badge_id", None) or getattr(pe, "source_ip", None)
            if src:
                corr_by_source.setdefault(src, []).append(t)

    responses = []

    for ts in scores:
        level = _level_from_score(ts.score)
        if level == ThreatLevel.LOW:
            continue

        source_id = ts.source_id
        top_threat = ts.top_threat or "Unknown"
        record: dict = {
            "source_id": source_id,
            "level": level.name,
            "score": ts.score,
            "actions_taken": [],
        }

        summary = f"Threat source {source_id} — {top_threat} (score {ts.score})"
        related = corr_by_source.get(source_id, [])
        rec_action = (
            related[0].recommended_action
            if related
            else "Investigate the source and review all associated logs."
        )
        detail_lines = [
            f"  Top threat   : {top_threat}",
            f"  Event count  : {ts.event_count}",
            f"  Is physical  : {ts.is_physical}",
        ]
        for ct in related:
            detail_lines.append(f"  Correlated   : {ct.summary} [{ct.mitre_technique_id}]")
        details = "\n".join(detail_lines)

        # Incident report — always written for MEDIUM and above
        rpt = _write_incident(
            incident_id=f"{source_id}-{level.name}",
            level=level,
            source_id=source_id,
            summary=summary,
            recommended_action=rec_action,
            details=details,
        )
        record["actions_taken"].append(f"incident_report:{rpt.name}")
        print(f"  [SOAR] {level.label()}  {source_id}  -> incident: {rpt.name}")

        # Phone alert — HIGH and CRITICAL (or configured min_alert_level)
        if ntfy_topic and level.value >= min_alert_level.value:
            priority = "urgent" if level == ThreatLevel.CRITICAL else "high"
            title = f"[{level.name}] ThreatMapper Alert"
            sent = _notify_phone(title, summary, priority, ntfy_topic, ntfy_url)
            if sent:
                record["actions_taken"].append("phone_alert:sent")
                print(f"  [SOAR] Phone alert sent -> ntfy.sh/{ntfy_topic}")
            else:
                record["actions_taken"].append("phone_alert:failed")

        # IP block — CRITICAL only, opt-in, digital sources only
        if block_ips and level == ThreatLevel.CRITICAL and not ts.is_physical:
            blocked = _block_ip(source_id)
            if blocked:
                record["actions_taken"].append(f"ip_blocked:{source_id}")
                print(f"  [SOAR] Blocked IP: {source_id}")

        responses.append(record)

    return responses


# ── CLI ────────────────────────────────────────────────────────────── #

def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from core.correlator import correlate_from_log
    from core.scorer import score_all
    from threat_mapper import parse_log

    parser = argparse.ArgumentParser(description="ThreatMapper SOAR Responder — Phase 5")
    parser.add_argument(
        "--log",
        default=Path("logs/sample_attack.log"),
        type=Path,
        help="Log file to evaluate (default: logs/sample_attack.log)",
    )
    parser.add_argument(
        "--ntfy-topic",
        default=os.environ.get("NTFY_TOPIC", ""),
        help="ntfy.sh topic for phone alerts (or set NTFY_TOPIC env var)",
    )
    parser.add_argument(
        "--ntfy-url",
        default="https://ntfy.sh",
        help="ntfy server base URL (default: https://ntfy.sh)",
    )
    parser.add_argument(
        "--block-ips",
        action="store_true",
        help="Block CRITICAL source IPs via the platform firewall (requires admin/root)",
    )
    parser.add_argument(
        "--min-alert-level",
        default="HIGH",
        choices=["MEDIUM", "HIGH", "CRITICAL"],
        help="Minimum threat level to trigger a phone alert (default: HIGH)",
    )
    args = parser.parse_args()

    min_level = ThreatLevel[args.min_alert_level]

    events  = parse_log(args.log)
    threats = correlate_from_log(events)
    scores  = score_all(digital=events, threats=threats)

    print(f"\n{'=' * 62}")
    print("  THREATMAPPER  |  Phase 5 — SOAR Responder")
    print(f"{'=' * 62}")
    print(f"  Log      : {args.log}")
    print(f"  Sources  : {len(scores)}  |  Correlated threats: {len(threats)}")
    if args.ntfy_topic:
        print(f"  Phone alerts : ENABLED  ->  ntfy.sh/{args.ntfy_topic}")
    else:
        print("  Phone alerts : DISABLED  (set --ntfy-topic or NTFY_TOPIC env var)")
    print(f"  IP blocking  : {'ENABLED' if args.block_ips else 'DISABLED  (pass --block-ips to enable)'}")
    print(f"  Min alert    : {args.min_alert_level}")
    print(f"{'=' * 62}\n")

    responses = respond_to_scores(
        scores,
        correlated=threats,
        ntfy_topic=args.ntfy_topic,
        ntfy_url=args.ntfy_url,
        block_ips=args.block_ips,
        min_alert_level=min_level,
    )

    total_actions = sum(len(r["actions_taken"]) for r in responses)
    print(f"\n{'=' * 62}")
    if responses:
        print(f"  Sources actioned : {len(responses)}")
        print(f"  Total actions    : {total_actions}")
    else:
        print("  No threats above LOW threshold — no actions taken.")
    print(f"{'=' * 62}\n")


if __name__ == "__main__":
    main()
