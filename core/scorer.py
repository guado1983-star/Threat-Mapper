"""
ThreatMapper — Threat Scorer (Phase 4)
=======================================
Aggregates SecurityEvent, PhysicalEvent, and CorrelatedThreat objects into
ranked ThreatScore objects, one per unique source (IP address or badge ID).

Three focused entry points, plus a combined one:

  score_events(events)          → score SecurityEvent list by source_ip
  score_physical(events)        → score PhysicalEvent list by badge_id / location
  score_correlated(threats)     → attribute CorrelatedThreat scores to physical sources
  score_all(digital, physical, threats) → merge all three into one ranked list

Run from the project root:
  python -m core.scorer
  python -m core.scorer --log logs/sample_attack.log
"""

import argparse
import sys
from pathlib import Path
from typing import Optional

# Allow `python core/scorer.py` in addition to `python -m core.scorer`
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core.models import CorrelatedThreat, PhysicalEvent, SecurityEvent, ThreatScore  # noqa: E402


# ── Weight tables ──────────────────────────────────────────────────── #

# Weights for digital SecurityEvent types
_WEIGHTS_DIGITAL: dict[str, int] = {
    "PORT_SCAN":                     1,
    "SSH_LOGIN_FAILED":              3,
    "HONEYFILE_ACCESSED":           10,
    "CORRELATED_ATTACK":            15,
    "HONEYFILE_PHYSICAL_CORRELATION": 20,
}

# Weights for physical-typed SecurityEvent types (from log parsing)
_WEIGHTS_PHYSICAL_LOG: dict[str, int] = {
    "MOTION_DETECTED":       2,
    "PHYSICAL_PRESENCE":     5,
    "AFTER_HOURS_INTRUSION": 8,
}

# Weights for PhysicalEvent types (from ESP32 bridge, real-time)
_WEIGHTS_ESP32: dict[str, int] = {
    "MOTION":             2,
    "PRESENCE_DETECTED":  5,
    "ENTRY":              3,
    "EXIT":               1,
}

_ALL_PHYSICAL_LOG_TYPES = set(_WEIGHTS_PHYSICAL_LOG)


# ── Internal helpers ───────────────────────────────────────────────── #

def _get(registry: dict, source_id: str, is_physical: bool) -> ThreatScore:
    if source_id not in registry:
        registry[source_id] = ThreatScore(source_id=source_id, is_physical=is_physical)
    return registry[source_id]


def _sorted(registry: dict) -> list:
    return sorted(registry.values(), key=lambda s: s.score, reverse=True)


# ── Public scoring functions ───────────────────────────────────────── #

def score_events(events: list) -> list:
    """
    Score a SecurityEvent list by source_ip.
    Physical-typed events (MOTION_DETECTED, PHYSICAL_PRESENCE,
    AFTER_HOURS_INTRUSION) are flagged is_physical=True.
    Returns list[ThreatScore] sorted by score descending.
    """
    registry: dict[str, ThreatScore] = {}
    for e in events:
        is_physical = e.event_type in _ALL_PHYSICAL_LOG_TYPES
        weight = (
            _WEIGHTS_PHYSICAL_LOG.get(e.event_type)
            or _WEIGHTS_DIGITAL.get(e.event_type)
            or 1
        )
        ts = _get(registry, e.source_ip, is_physical)
        ts.add(e.event_type, weight)
    return _sorted(registry)


def score_physical(events: list) -> list:
    """
    Score PhysicalEvent objects (from esp32.bridge) by badge_id when
    present, otherwise by location.
    Returns list[ThreatScore] sorted by score descending.
    """
    registry: dict[str, ThreatScore] = {}
    for e in events:
        source_id = e.badge_id or e.location
        weight = _WEIGHTS_ESP32.get(e.event_type, 1)
        if e.after_hours:
            weight = max(weight, _WEIGHTS_PHYSICAL_LOG["AFTER_HOURS_INTRUSION"])
        ts = _get(registry, source_id, is_physical=True)
        ts.add(e.event_type, weight)
    return _sorted(registry)


def score_correlated(threats: list) -> list:
    """
    Attribute each CorrelatedThreat's score to the physical-side source
    (badge_id for PhysicalEvent, source_ip for physical-typed SecurityEvent).
    Returns list[ThreatScore] sorted by score descending.
    """
    registry: dict[str, ThreatScore] = {}
    for threat in threats:
        for pe in threat.physical_events:
            # PhysicalEvent has badge_id; SecurityEvent has source_ip
            source_id = getattr(pe, "badge_id", None) or getattr(pe, "source_ip", "unknown")
            ts = _get(registry, source_id, is_physical=True)
            ts.score       += threat.score
            ts.event_count += 1
            if ts.top_threat is None:
                ts.top_threat = threat.summary
    return _sorted(registry)


def score_all(
    digital: Optional[list] = None,
    physical: Optional[list] = None,
    threats: Optional[list] = None,
) -> list:
    """
    Merge scores from SecurityEvents, PhysicalEvents, and CorrelatedThreats
    into a single ranked list[ThreatScore].
    Sources that appear in multiple inputs are combined under one entry.
    """
    registry: dict[str, ThreatScore] = {}

    for ts in score_events(digital or []):
        existing = _get(registry, ts.source_id, ts.is_physical)
        existing.score       += ts.score
        existing.event_count += ts.event_count
        if existing.top_threat is None:
            existing.top_threat = ts.top_threat

    for ts in score_physical(physical or []):
        existing = _get(registry, ts.source_id, ts.is_physical)
        existing.score       += ts.score
        existing.event_count += ts.event_count
        if existing.top_threat is None:
            existing.top_threat = ts.top_threat

    for ts in score_correlated(threats or []):
        existing = _get(registry, ts.source_id, ts.is_physical)
        existing.score       += ts.score
        existing.event_count += ts.event_count
        if existing.top_threat is None:
            existing.top_threat = ts.top_threat

    return _sorted(registry)


# ── CLI ────────────────────────────────────────────────────────────── #

def _print_scores(scores: list) -> None:
    if not scores:
        print("  No scores computed.")
        return
    top = scores[0].score
    for ts in scores:
        flag = "  <<< TOP THREAT" if ts.score == top else ""
        bar  = "#" * min(ts.score, 40)
        kind = "PHY" if ts.is_physical else "DIG"
        print(
            f"  [{kind}]  {ts.source_id:<22}  {ts.label():<18}"
            f"  score: {ts.score:>4}  events: {ts.event_count:>3}  {bar}{flag}"
        )
        if ts.top_threat:
            print(f"           top threat : {ts.top_threat}")


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from core.correlator import correlate_from_log
    from threat_mapper import parse_log

    parser = argparse.ArgumentParser(description="ThreatMapper Scorer — Phase 4")
    parser.add_argument(
        "--log",
        default=Path("logs/sample_attack.log"),
        type=Path,
        help="Log file to score (default: logs/sample_attack.log)",
    )
    args = parser.parse_args()

    events  = parse_log(args.log)
    threats = correlate_from_log(events)
    scores  = score_all(digital=events, threats=threats)

    print(f"\n{'=' * 62}")
    print("  THREATMAPPER  |  Phase 4 — Threat Scores")
    print(f"{'=' * 62}")
    print(f"  Log     : {args.log}")
    print(f"  Events  : {len(events)}  |  Correlated threats : {len(threats)}")
    print(f"  Sources : {len(scores)}")
    print(f"{'=' * 62}\n")
    _print_scores(scores)
    print(f"\n{'=' * 62}\n")


if __name__ == "__main__":
    main()
