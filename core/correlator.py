"""
ThreatMapper — Physical + Digital Correlator (Phase 2)
=======================================================
Correlates PhysicalEvent and SecurityEvent objects within a configurable
time window and applies rule-based matching to produce CorrelatedThreat
objects with MITRE mappings and recommended actions.

Two entry points:

  correlate(physical_events, digital_events)
      Real-time mode.  physical_events come from esp32.bridge (PhysicalEvent);
      digital_events come from threat_mapper.parse_log (SecurityEvent).

  correlate_from_log(events)
      Batch mode.  All events are SecurityEvent objects from a single log
      file that already mixes physical-typed lines (MOTION_DETECTED,
      PHYSICAL_PRESENCE, AFTER_HOURS_INTRUSION) with digital ones.

Both return list[CorrelatedThreat] sorted by score descending.

Run from the project root to test against the sample log:
  python -m core.correlator
  python -m core.correlator --log logs/sample_attack.log --window 600
"""

import argparse
import hashlib
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

# Allow `python core/correlator.py` in addition to `python -m core.correlator`
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core.models import CorrelatedThreat, PhysicalEvent, SecurityEvent, ThreatLevel  # noqa: E402

CORRELATION_WINDOW_SECONDS = 300   # 5 minutes
_TS_FMT = "%Y-%m-%d %H:%M:%S"

# SecurityEvent types that represent physical activity in a log file
_LOG_PHYSICAL_TYPES = {"MOTION_DETECTED", "PHYSICAL_PRESENCE", "AFTER_HOURS_INTRUSION"}


# ── Rule definition ────────────────────────────────────────────────── #

@dataclass(frozen=True)
class _Rule:
    name: str

    # Real-time mode (PhysicalEvent.event_type)
    physical_types: frozenset       # empty = any PhysicalEvent type
    requires_after_hours: bool      # True → only fire when PE.after_hours is set

    # Batch mode (SecurityEvent.event_type for the physical side)
    log_physical_types: frozenset   # empty = any physical-typed SecurityEvent

    # Both modes (SecurityEvent.event_type for the digital side)
    digital_types: frozenset        # empty = any digital SecurityEvent type

    threat_level: ThreatLevel
    mitre_technique_id: str
    mitre_tactic: str
    summary: str
    recommended_action: str
    base_score: int


_RULES: tuple[_Rule, ...] = (
    _Rule(
        name="after_hours_digital",
        physical_types=frozenset({"ENTRY", "PRESENCE_DETECTED"}),
        requires_after_hours=True,
        log_physical_types=frozenset({"AFTER_HOURS_INTRUSION"}),
        digital_types=frozenset(),  # any digital event elevates the threat
        threat_level=ThreatLevel.HIGH,
        mitre_technique_id="T0867",
        mitre_tactic="Initial Access",
        summary="After-hours physical access correlated with digital activity",
        recommended_action=(
            "Review badge access logs, lock down the affected zone, "
            "and notify the security team immediately."
        ),
        base_score=15,
    ),
    _Rule(
        name="insider_honeyfile",
        physical_types=frozenset({"ENTRY", "PRESENCE_DETECTED"}),
        requires_after_hours=False,
        log_physical_types=frozenset({"PHYSICAL_PRESENCE"}),
        digital_types=frozenset({"HONEYFILE_ACCESSED", "HONEYFILE_PHYSICAL_CORRELATION"}),
        threat_level=ThreatLevel.CRITICAL,
        mitre_technique_id="T1074",
        mitre_tactic="Collection",
        summary="Physical presence correlated with honeyfile access — suspected insider threat",
        recommended_action=(
            "Suspend badge access immediately, preserve forensic artefacts, "
            "and escalate to the CISO."
        ),
        base_score=25,
    ),
    _Rule(
        name="motion_port_scan",
        physical_types=frozenset({"MOTION"}),
        requires_after_hours=False,
        log_physical_types=frozenset({"MOTION_DETECTED"}),
        digital_types=frozenset({"PORT_SCAN"}),
        threat_level=ThreatLevel.MEDIUM,
        mitre_technique_id="T1046",
        mitre_tactic="Discovery",
        summary="Physical motion correlated with network port scanning — reconnaissance activity",
        recommended_action=(
            "Dispatch physical security to check the zone; "
            "review network traffic from nearby devices."
        ),
        base_score=8,
    ),
    _Rule(
        name="badge_ssh_brute",
        physical_types=frozenset({"ENTRY", "PRESENCE_DETECTED"}),
        requires_after_hours=False,
        log_physical_types=frozenset({"PHYSICAL_PRESENCE"}),
        digital_types=frozenset({"SSH_LOGIN_FAILED"}),
        threat_level=ThreatLevel.HIGH,
        mitre_technique_id="T1110",
        mitre_tactic="Credential Access",
        summary="Badge entry followed by SSH brute-force — possible stolen credentials or shoulder surfing",
        recommended_action=(
            "Investigate the badge holder's identity; check whether "
            "credentials were shared or observed."
        ),
        base_score=18,
    ),
    _Rule(
        name="hardware_implant",
        physical_types=frozenset(),  # any physical event
        requires_after_hours=False,
        log_physical_types=frozenset(),  # any physical SecurityEvent
        digital_types=frozenset({"CORRELATED_ATTACK"}),
        threat_level=ThreatLevel.CRITICAL,
        mitre_technique_id="T1200",
        mitre_tactic="Initial Access",
        summary="Physical access correlated with unknown device on network — suspected hardware implant",
        recommended_action=(
            "Initiate immediate lockdown; scan the zone for rogue hardware; "
            "preserve all network logs."
        ),
        base_score=30,
    ),
    _Rule(
        name="after_hours_honeyfile",
        physical_types=frozenset({"ENTRY", "PRESENCE_DETECTED"}),
        requires_after_hours=True,
        log_physical_types=frozenset({"AFTER_HOURS_INTRUSION"}),
        digital_types=frozenset({"HONEYFILE_ACCESSED", "HONEYFILE_PHYSICAL_CORRELATION"}),
        threat_level=ThreatLevel.CRITICAL,
        mitre_technique_id="T1074",
        mitre_tactic="Collection",
        summary="After-hours intrusion with honeyfile access — active data exfiltration suspected",
        recommended_action=(
            "Treat as an active incident: initiate IR procedure, "
            "isolate affected systems, and revoke all access in the zone."
        ),
        base_score=35,
    ),
)


# ── Helpers ────────────────────────────────────────────────────────── #

def _parse_ts(ts: str) -> datetime:
    return datetime.strptime(ts, _TS_FMT)


def _within_window(ts_a: str, ts_b: str, window: int) -> bool:
    return abs((_parse_ts(ts_a) - _parse_ts(ts_b)).total_seconds()) <= window


def _threat_id(rule_name: str, anchor_ts: str) -> str:
    return hashlib.sha1(f"{rule_name}:{anchor_ts}".encode()).hexdigest()[:12]


def _build_threat(
    rule: _Rule,
    anchor_ts: str,
    location: str,
    physical: list,
    digital: list,
) -> CorrelatedThreat:
    score = rule.base_score + (len(digital) - 1) * 2  # bonus for multiple digital hits
    return CorrelatedThreat(
        threat_id=_threat_id(rule.name, anchor_ts),
        timestamp=anchor_ts,
        threat_level=rule.threat_level,
        summary=f"{rule.summary} [{location}]",
        mitre_technique_id=rule.mitre_technique_id,
        mitre_tactic=rule.mitre_tactic,
        physical_events=physical,
        digital_events=digital,
        recommended_action=rule.recommended_action,
        score=score,
    )


# ── Public API ─────────────────────────────────────────────────────── #

def correlate(
    physical_events: list,
    digital_events: list,
    window_seconds: int = CORRELATION_WINDOW_SECONDS,
) -> list:
    """
    Real-time mode: correlate ESP32 PhysicalEvents with SecurityEvents.
    Returns list[CorrelatedThreat] sorted by score descending.
    """
    threats: list[CorrelatedThreat] = []
    seen: set[str] = set()

    for p in physical_events:
        nearby = [
            d for d in digital_events
            if _within_window(p.timestamp, d.timestamp, window_seconds)
        ]

        for rule in _RULES:
            if rule.physical_types and p.event_type not in rule.physical_types:
                continue
            if rule.requires_after_hours and not p.after_hours:
                continue

            matched = [
                d for d in nearby
                if not rule.digital_types or d.event_type in rule.digital_types
            ]
            if not matched:
                continue

            tid = _threat_id(rule.name, p.timestamp)
            if tid in seen:
                continue
            seen.add(tid)

            threats.append(_build_threat(rule, p.timestamp, p.location, [p], matched))

    return sorted(threats, key=lambda t: t.score, reverse=True)


def correlate_from_log(
    events: list,
    window_seconds: int = CORRELATION_WINDOW_SECONDS,
) -> list:
    """
    Batch mode: split a mixed SecurityEvent list into physical-typed and
    digital-typed, then apply correlation rules.
    Returns list[CorrelatedThreat] sorted by score descending.
    """
    physical = [e for e in events if e.event_type in _LOG_PHYSICAL_TYPES]
    digital  = [e for e in events if e.event_type not in _LOG_PHYSICAL_TYPES]

    threats: list[CorrelatedThreat] = []
    seen: set[str] = set()

    for p in physical:
        nearby = [
            d for d in digital
            if _within_window(p.timestamp, d.timestamp, window_seconds)
        ]

        for rule in _RULES:
            if rule.log_physical_types and p.event_type not in rule.log_physical_types:
                continue
            # AFTER_HOURS_INTRUSION implies after_hours; no extra flag needed

            matched = [
                d for d in nearby
                if not rule.digital_types or d.event_type in rule.digital_types
            ]
            if not matched:
                continue

            tid = _threat_id(rule.name, p.timestamp)
            if tid in seen:
                continue
            seen.add(tid)

            location = p.username or p.source_ip  # best available location for SecurityEvent
            threats.append(_build_threat(rule, p.timestamp, location, [p], matched))

    return sorted(threats, key=lambda t: t.score, reverse=True)


# ── CLI ────────────────────────────────────────────────────────────── #

def _print_threats(threats: list) -> None:
    if not threats:
        print("  No correlated threats found.")
        return
    for t in threats:
        print(f"\n  [{t.threat_level.label()}]  {t.summary}")
        print(f"  ID         : {t.threat_id}")
        print(f"  Timestamp  : {t.timestamp}")
        print(f"  MITRE      : {t.mitre_technique_id}  [{t.mitre_tactic}]")
        print(f"  Score      : {t.score}")
        print(f"  Physical   : {len(t.physical_events)} event(s)")
        print(f"  Digital    : {len(t.digital_events)} event(s)")
        print(f"  Action     : {t.recommended_action}")


def main() -> None:
    import sys
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    # Ensure project root is on path when run as a script
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from threat_mapper import parse_log

    parser = argparse.ArgumentParser(description="ThreatMapper Correlator — batch mode")
    parser.add_argument(
        "--log",
        default=Path("logs/sample_attack.log"),
        type=Path,
        help="Log file to correlate (default: logs/sample_attack.log)",
    )
    parser.add_argument(
        "--window",
        default=CORRELATION_WINDOW_SECONDS,
        type=int,
        help=f"Correlation window in seconds (default: {CORRELATION_WINDOW_SECONDS})",
    )
    args = parser.parse_args()

    events = parse_log(args.log)
    threats = correlate_from_log(events, window_seconds=args.window)

    print(f"\n{'=' * 62}")
    print("  THREATMAPPER  |  Correlated Threats")
    print(f"{'=' * 62}")
    print(f"  Log      : {args.log}")
    print(f"  Events   : {len(events)}  |  Window: {args.window}s")
    print(f"  Threats  : {len(threats)}")
    print(f"{'=' * 62}")

    _print_threats(threats)
    print(f"\n{'=' * 62}\n")


if __name__ == "__main__":
    main()
