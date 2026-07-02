import argparse
import re
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Optional

import mitre_mapper
from core.models import SecurityEvent

REPORTS_DIR = Path("reports")
LOGINS_DIR = Path("logins")

DEFAULT_LOG_FILE = Path("logs/sample_attack.log")


_SSH_PATTERN = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \[.*?\]\s+SSH_AUTH: Failed login attempt - "
    r"user='(?P<user>[^']+)' password='(?P<password>[^']+)' src=(?P<ip>[\d.]+) port=(?P<port>\d+)"
)

_PORT_PATTERN = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \[.*?\]\s+FIREWALL: Port probe - "
    r"src=(?P<ip>[\d.]+) dst_port=(?P<port>\d+)"
)

_HONEYFILE_PATTERN = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \[.*?\]\s+AUDIT: Honeyfile read - "
    r"file=(?P<file>\S+) user='(?P<user>[^']+)' src=(?P<ip>[\d.]+)"
)

_MOTION_PATTERN = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \[.*?\]\s+PHYSICAL: Motion detected - "
    r"sensor='(?P<sensor>[^']+)' zone='(?P<zone>[^']+)'"
)

_PHYSICAL_PRESENCE_PATTERN = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \[.*?\]\s+ACCESS_CTRL: Badge scan - "
    r"badge_id='(?P<badge>[^']+)' location='(?P<location>[^']+)' result=(?P<result>\w+)"
)

_AFTER_HOURS_PATTERN = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \[.*?\]\s+SECURITY: After-hours intrusion - "
    r"zone='(?P<zone>[^']+)' sensor='(?P<sensor>[^']+)' badge_id='(?P<badge>[^']+)'"
)

_CORRELATED_ATTACK_PATTERN = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \[.*?\]\s+NETWORK: Unknown device - "
    r"mac='(?P<mac>[^']+)' ip=(?P<ip>[\d.]+) zone='(?P<zone>[^']+)' badge_id='(?P<badge>[^']+)'"
)

_HONEYFILE_PHYSICAL_PATTERN = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \[.*?\]\s+AUDIT: Physical-digital correlation - "
    r"file=(?P<file>\S+) badge_id='(?P<badge>[^']+)' zone='(?P<zone>[^']+)'"
)


def _to_port(raw: str) -> Optional[int]:
    value = int(raw)
    return value if 0 <= value <= 65535 else None


def _parse_ssh(line: str) -> Optional[SecurityEvent]:
    m = _SSH_PATTERN.search(line)
    if not m:
        return None
    return SecurityEvent(
        timestamp=m.group("timestamp"),
        event_type="SSH_LOGIN_FAILED",
        source_ip=m.group("ip"),
        username=m.group("user"),
        password_attempt=m.group("password"),
        port=_to_port(m.group("port")),
        raw_line=line,
    )


def _parse_port_scan(line: str) -> Optional[SecurityEvent]:
    m = _PORT_PATTERN.search(line)
    if not m:
        return None
    return SecurityEvent(
        timestamp=m.group("timestamp"),
        event_type="PORT_SCAN",
        source_ip=m.group("ip"),
        port=_to_port(m.group("port")),
        raw_line=line,
    )


def _parse_honeyfile(line: str) -> Optional[SecurityEvent]:
    m = _HONEYFILE_PATTERN.search(line)
    if not m:
        return None
    return SecurityEvent(
        timestamp=m.group("timestamp"),
        event_type="HONEYFILE_ACCESSED",
        source_ip=m.group("ip"),
        username=m.group("user"),
        file_accessed=m.group("file"),
        raw_line=line,
    )


def _parse_motion(line: str) -> Optional[SecurityEvent]:
    m = _MOTION_PATTERN.search(line)
    if not m:
        return None
    return SecurityEvent(
        timestamp=m.group("timestamp"),
        event_type="MOTION_DETECTED",
        source_ip=m.group("sensor"),
        sensor_id=m.group("sensor"),
        zone=m.group("zone"),
        raw_line=line,
    )


def _parse_physical_presence(line: str) -> Optional[SecurityEvent]:
    m = _PHYSICAL_PRESENCE_PATTERN.search(line)
    if not m:
        return None
    return SecurityEvent(
        timestamp=m.group("timestamp"),
        event_type="PHYSICAL_PRESENCE",
        source_ip=m.group("badge"),
        zone=m.group("location"),
        raw_line=line,
    )


def _parse_after_hours(line: str) -> Optional[SecurityEvent]:
    m = _AFTER_HOURS_PATTERN.search(line)
    if not m:
        return None
    return SecurityEvent(
        timestamp=m.group("timestamp"),
        event_type="AFTER_HOURS_INTRUSION",
        source_ip=m.group("badge"),
        sensor_id=m.group("sensor"),
        zone=m.group("zone"),
        raw_line=line,
    )


def _parse_correlated_attack(line: str) -> Optional[SecurityEvent]:
    m = _CORRELATED_ATTACK_PATTERN.search(line)
    if not m:
        return None
    return SecurityEvent(
        timestamp=m.group("timestamp"),
        event_type="CORRELATED_ATTACK",
        source_ip=m.group("ip"),
        zone=m.group("zone"),
        raw_line=line,
    )


def _parse_honeyfile_physical(line: str) -> Optional[SecurityEvent]:
    m = _HONEYFILE_PHYSICAL_PATTERN.search(line)
    if not m:
        return None
    return SecurityEvent(
        timestamp=m.group("timestamp"),
        event_type="HONEYFILE_PHYSICAL_CORRELATION",
        source_ip=m.group("badge"),
        zone=m.group("zone"),
        file_accessed=m.group("file"),
        raw_line=line,
    )


_PARSERS = [_parse_ssh, _parse_port_scan, _parse_honeyfile,
            _parse_motion, _parse_physical_presence, _parse_after_hours,
            _parse_correlated_attack, _parse_honeyfile_physical]


def parse_log(log_path: Path) -> list:
    events = []
    skipped = 0
    try:
        with open(log_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                matched = False
                for parser in _PARSERS:
                    event = parser(line)
                    if event:
                        events.append(event)
                        matched = True
                        break
                if not matched:
                    skipped += 1
    except PermissionError:
        print(f"[!] Permission denied: {log_path}")
        raise SystemExit(1)
    except UnicodeDecodeError as e:
        print(f"[!] Encoding error in {log_path}: {e}")
        raise SystemExit(1)
    except OSError as e:
        print(f"[!] Could not read {log_path}: {e}")
        raise SystemExit(1)

    if skipped:
        print(f"[!] {skipped} line(s) did not match any known pattern and were skipped.\n")
    return events


def _print_events(events: list) -> None:
    print(f"\n{'=' * 62}")
    print("  THREATMAPPER  |  Parsed Security Events")
    print(f"{'=' * 62}\n")

    for i, event in enumerate(events, 1):
        technique = mitre_mapper.map_event(event.event_type)
        print(f"  [{i:03d}]  {event.event_type}")
        print(f"         Timestamp : {event.timestamp}")
        print(f"         Source    : {event.source_ip}")
        if event.sensor_id:
            print(f"         Sensor    : {event.sensor_id}")
        if event.zone:
            print(f"         Zone      : {event.zone}")
        if event.username:
            print(f"         Username  : {event.username}")
        if event.password_attempt:
            print(f"         Password  : {event.password_attempt}")
        if event.port is not None:
            print(f"         Port      : {event.port}")
        if event.file_accessed:
            print(f"         File      : {event.file_accessed}")
        if technique:
            print(f"         MITRE     : {technique.technique_id} -- {technique.name}  [{technique.tactic}]")
        print()


_THREAT_SCORES = {
    "PORT_SCAN": 1,
    "SSH_LOGIN_FAILED": 3,
    "HONEYFILE_ACCESSED": 10,
    "MOTION_DETECTED": 2,
    "PHYSICAL_PRESENCE": 5,
    "AFTER_HOURS_INTRUSION": 8,
    "CORRELATED_ATTACK": 15,
    "HONEYFILE_PHYSICAL_CORRELATION": 20,
}


def score_threats(events: list) -> dict:
    scores: dict[str, int] = {}
    for event in events:
        weight = _THREAT_SCORES.get(event.event_type, 1)
        scores[event.source_ip] = scores.get(event.source_ip, 0) + weight
    return scores


def _print_summary(events: list) -> None:
    print(f"{'=' * 62}")
    print("  SUMMARY")
    print(f"{'=' * 62}")
    print(f"  Total events parsed : {len(events)}\n")

    type_counts = Counter(e.event_type for e in events)
    print("  Event types:")
    for event_type, count in type_counts.most_common():
        bar = "#" * count
        print(f"    {event_type:<25}  {count:>3}  {bar}")

    print()
    ip_counts = Counter(e.source_ip for e in events)
    print("  Sources:")
    for src, count in ip_counts.most_common():
        print(f"    {src:<20}  {count} event(s)")

    print(f"\n{'=' * 62}\n")


def _print_mitre_mapping(events: list) -> None:
    seen_types = dict.fromkeys(e.event_type for e in events)
    print(f"{'=' * 62}")
    print("  MITRE ATT&CK MAPPING")
    print(f"{'=' * 62}")
    for event_type in seen_types:
        technique = mitre_mapper.map_event(event_type)
        if technique:
            print(
                f"  {event_type:<25}  {technique.technique_id}  "
                f"{technique.name:<30}  [{technique.tactic}]"
            )
    print(f"\n{'=' * 62}\n")


def _print_threat_scores(events: list) -> None:
    scores = score_threats(events)
    ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)
    top_score = ranked[0][1] if ranked else 0

    print(f"{'=' * 62}")
    print("  THREAT SCORES  |  Top Attackers")
    print(f"{'=' * 62}")
    scoring = "  ".join(f"{k}=+{v}" for k, v in _THREAT_SCORES.items())
    print(f"  Scoring: {scoring}\n")

    for src, score in ranked:
        flag = "  <<< TOP ATTACKER" if score == top_score else ""
        bar = "#" * min(score, 40)
        print(f"  {src:<20}  score: {score:>4}  {bar}{flag}")

    print(f"\n{'=' * 62}\n")


def save_report(events: list, log_path: Path) -> Path:
    scores = score_threats(events)
    ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)
    top_score = ranked[0][1] if ranked else 0
    type_counts = Counter(e.event_type for e in events)
    ip_counts = Counter(e.source_ip for e in events)
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    timestamp_slug = datetime.now().strftime("%Y%m%d_%H%M%S")

    REPORTS_DIR.mkdir(exist_ok=True)
    report_path = REPORTS_DIR / f"report_{timestamp_slug}.txt"

    lines = [
        "=" * 62,
        "  THREATMAPPER REPORT",
        f"  Generated : {generated_at}",
        f"  Log file  : {log_path}",
        "=" * 62,
        "",
        f"  Total events parsed : {len(events)}",
        "",
        "  Event types:",
    ]
    for event_type, count in type_counts.most_common():
        bar = "#" * count
        lines.append(f"    {event_type:<25}  {count:>3}  {bar}")

    lines += ["", "  Sources:"]
    for src, count in ip_counts.most_common():
        lines.append(f"    {src:<20}  {count} event(s)")

    seen_types = dict.fromkeys(e.event_type for e in events)
    lines += [
        "",
        "=" * 62,
        "  MITRE ATT&CK MAPPING",
        "=" * 62,
    ]
    for event_type in seen_types:
        technique = mitre_mapper.map_event(event_type)
        if technique:
            lines.append(
                f"  {event_type:<25}  {technique.technique_id}  "
                f"{technique.name:<30}  [{technique.tactic}]"
            )

    lines += [
        "",
        "=" * 62,
        "  THREAT SCORES  |  Top Attackers",
        "=" * 62,
        "  Scoring: " + "  ".join(f"{k}=+{v}" for k, v in _THREAT_SCORES.items()),
        "",
    ]
    for src, score in ranked:
        flag = "  <<< TOP ATTACKER" if score == top_score else ""
        bar = "#" * min(score, 40)
        lines.append(f"  {src:<20}  score: {score:>4}  {bar}{flag}")

    lines += ["", "=" * 62, "", "  RAW EVENTS", "=" * 62, ""]
    for i, event in enumerate(events, 1):
        lines.append(f"  [{i:03d}]  {event.event_type}")
        lines.append(f"         Timestamp : {event.timestamp}")
        lines.append(f"         Source    : {event.source_ip}")
        if event.sensor_id:
            lines.append(f"         Sensor    : {event.sensor_id}")
        if event.zone:
            lines.append(f"         Zone      : {event.zone}")
        if event.username:
            lines.append(f"         Username  : {event.username}")
        if event.password_attempt:
            lines.append(f"         Password  : {event.password_attempt}")
        if event.port is not None:
            lines.append(f"         Port      : {event.port}")
        if event.file_accessed:
            lines.append(f"         File      : {event.file_accessed}")
        lines.append("")

    report_path.write_text("\n".join(lines), encoding="utf-8")
    return report_path


if __name__ == "__main__":
    import os
    from core.correlator import correlate_from_log
    from core.responder import respond_to_scores
    from core.scorer import score_all

    parser = argparse.ArgumentParser(description="ThreatMapper - Security log parser")
    parser.add_argument(
        "log_file",
        nargs="?",
        default=DEFAULT_LOG_FILE,
        type=Path,
        help=f"Path to log file (default: {DEFAULT_LOG_FILE})",
    )
    parser.add_argument(
        "--ntfy-topic",
        default=os.environ.get("NTFY_TOPIC", ""),
        help="ntfy.sh topic for phone alerts (or set NTFY_TOPIC env var)",
    )
    parser.add_argument(
        "--block-ips",
        action="store_true",
        help="Block CRITICAL source IPs via the platform firewall (requires admin/root)",
    )
    args = parser.parse_args()

    events = parse_log(args.log_file)

    if not events:
        print("[!] No events parsed. Check log format.")
        raise SystemExit(1)

    _print_events(events)
    _print_summary(events)
    _print_mitre_mapping(events)
    _print_threat_scores(events)

    report_path = save_report(events, args.log_file)
    print(f"[+] Report saved to {report_path}")

    # Phase 5 — SOAR: auto-respond to scored threats    
    threats = correlate_from_log(events)
    scores  = score_all(digital=events, threats=threats)
    print(f"\n{'=' * 62}")
    print("  SOAR — Automated Response")
    print(f"{'=' * 62}\n")
    respond_to_scores(
        scores,
        correlated=threats,
        ntfy_topic=args.ntfy_topic,
        block_ips=args.block_ips,
    )
    print()
