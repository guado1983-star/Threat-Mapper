import argparse
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

DEFAULT_LOG_FILE = Path("logs/sample_attack.log")


@dataclass
class SecurityEvent:
    timestamp: str
    event_type: str
    source_ip: str
    username: Optional[str] = None
    password_attempt: Optional[str] = None
    file_accessed: Optional[str] = None
    port: Optional[int] = None
    raw_line: str = field(default="", repr=False)


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


_PARSERS = [_parse_ssh, _parse_port_scan, _parse_honeyfile]


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
        print(f"  [{i:03d}]  {event.event_type}")
        print(f"         Timestamp : {event.timestamp}")
        print(f"         Source IP : {event.source_ip}")
        if event.username:
            print(f"         Username  : {event.username}")
        if event.password_attempt:
            print(f"         Password  : {event.password_attempt}")
        if event.port is not None:
            print(f"         Port      : {event.port}")
        if event.file_accessed:
            print(f"         File      : {event.file_accessed}")
        print()


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
    print("  Source IPs:")
    for ip, count in ip_counts.most_common():
        print(f"    {ip:<20}  {count} event(s)")

    print(f"\n{'=' * 62}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ThreatMapper - Security log parser")
    parser.add_argument(
        "log_file",
        nargs="?",
        default=DEFAULT_LOG_FILE,
        type=Path,
        help=f"Path to log file (default: {DEFAULT_LOG_FILE})",
    )
    args = parser.parse_args()

    events = parse_log(args.log_file)

    if not events:
        print("[!] No events parsed. Check log format.")
        raise SystemExit(1)

    _print_events(events)
    _print_summary(events)
