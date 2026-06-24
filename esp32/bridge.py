"""
ThreatMapper — ESP32-CAM Physical Bridge (Phase 2)
===================================================
Reads JSON events from an ESP32 device over serial, converts them to
PhysicalEvent objects, appends threat_mapper-compatible log lines, and
calls an optional real-time callback.

ESP32 message protocol (one JSON object per line):
  {"type": "MOTION",            "sensor": "pir_1", "zone": "server_room",  "confidence": 0.85}
  {"type": "PRESENCE_DETECTED", "badge_id": "B001", "location": "entrance", "confidence": 0.92}
  {"type": "ENTRY",             "badge_id": "B001", "location": "entrance", "confidence": 1.0}
  {"type": "EXIT",              "badge_id": "B001", "location": "entrance", "confidence": 1.0}

Run from the project root:
  python -m esp32.bridge
  python -m esp32.bridge --port COM4 --log logs/physical_events.log
  python -m esp32.bridge --list-ports
"""

import argparse
import json
import logging
import sys
from collections.abc import Callable
from datetime import datetime, time
from pathlib import Path
from typing import Optional

import serial
import serial.tools.list_ports

# Allow `python esp32/bridge.py` in addition to `python -m esp32.bridge`
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core.models import PhysicalEvent  # noqa: E402


# ── Configuration ──────────────────────────────────────────────────── #

DEFAULT_PORT     = "COM3"
DEFAULT_BAUD     = 115200
DEFAULT_LOG_FILE = Path("logs/physical_events.log")

BUSINESS_START = time(9, 0)
BUSINESS_END   = time(18, 0)

_KNOWN_TYPES = {"MOTION", "PRESENCE_DETECTED", "ENTRY", "EXIT"}

log = logging.getLogger(__name__)


# ── Helpers ────────────────────────────────────────────────────────── #

def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _is_after_hours() -> bool:
    now     = datetime.now()
    weekday = now.weekday()
    if weekday >= 5:
        return True
    return not (BUSINESS_START <= now.time() < BUSINESS_END)


# ── ESP32 message → PhysicalEvent ─────────────────────────────────── #

def parse_message(raw: str) -> Optional[PhysicalEvent]:
    """Parse one JSON line from the ESP32 into a PhysicalEvent, or None."""
    raw = raw.strip()
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        log.debug("Non-JSON line: %s", raw)
        return None

    event_type = str(data.get("type", "")).upper()
    if event_type not in _KNOWN_TYPES:
        log.warning("Unknown ESP32 event type: %r", event_type)
        return None

    location = data.get("location") or data.get("zone") or "unknown"

    return PhysicalEvent(
        timestamp=_now(),
        event_type=event_type,
        location=location,
        confidence=float(data.get("confidence", 1.0)),
        duration_seconds=int(data.get("duration", 0)),
        after_hours=_is_after_hours(),
        badge_id=data.get("badge_id"),
        raw_data=data,
    )


# ── threat_mapper.py-compatible log line ──────────────────────────── #

def _to_log_line(event: PhysicalEvent) -> str:
    """
    Format a PhysicalEvent as a log line that threat_mapper.py's existing
    regex parsers (_MOTION_PATTERN, _PHYSICAL_PRESENCE_PATTERN,
    _AFTER_HOURS_PATTERN) will match.
    """
    ts    = event.timestamp
    badge = event.badge_id or "unknown"

    if event.event_type == "MOTION":
        sensor = event.raw_data.get("sensor", "cam_1")
        return (
            f"{ts} [INFO] PHYSICAL: Motion detected - "
            f"sensor='{sensor}' zone='{event.location}'"
        )

    if event.event_type == "PRESENCE_DETECTED":
        result = "GRANTED" if event.confidence >= 0.7 else "DENIED"
        return (
            f"{ts} [INFO] ACCESS_CTRL: Badge scan - "
            f"badge_id='{badge}' location='{event.location}' result={result}"
        )

    # ENTRY / EXIT
    if event.after_hours:
        sensor = event.raw_data.get("sensor", "cam_1")
        return (
            f"{ts} [INFO] SECURITY: After-hours intrusion - "
            f"zone='{event.location}' sensor='{sensor}' badge_id='{badge}'"
        )
    result = "GRANTED" if event.event_type == "ENTRY" else "EXIT"
    return (
        f"{ts} [INFO] ACCESS_CTRL: Badge scan - "
        f"badge_id='{badge}' location='{event.location}' result={result}"
    )


# ── Bridge ─────────────────────────────────────────────────────────── #

class ESP32Bridge:
    """
    Opens a serial connection to an ESP32 device, reads events line-by-line,
    appends compatible log lines, and optionally calls a real-time callback.
    """

    def __init__(
        self,
        port: str = DEFAULT_PORT,
        baud: int = DEFAULT_BAUD,
        log_path: Path = DEFAULT_LOG_FILE,
        on_event: Optional[Callable[[PhysicalEvent], None]] = None,
    ):
        self.port     = port
        self.baud     = baud
        self.log_path = log_path
        self.on_event = on_event
        self._serial: Optional[serial.Serial] = None

    def connect(self) -> None:
        log.info("Connecting to ESP32 on %s @ %d baud …", self.port, self.baud)
        self._serial = serial.Serial(self.port, self.baud, timeout=1)
        log.info("Connected.")

    def disconnect(self) -> None:
        if self._serial and self._serial.is_open:
            self._serial.close()
            log.info("Serial port closed.")

    def run(self) -> None:
        """Block and process events until KeyboardInterrupt or serial error."""
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self.connect()
            with open(self.log_path, "a", encoding="utf-8") as logfile:
                while True:
                    raw   = self._serial.readline().decode("utf-8", errors="replace")
                    event = parse_message(raw)
                    if event is None:
                        continue
                    line = _to_log_line(event)
                    logfile.write(line + "\n")
                    logfile.flush()
                    log.info(line)
                    if self.on_event:
                        self.on_event(event)
        except serial.SerialException as exc:
            log.error("Serial error: %s", exc)
            sys.exit(1)
        except KeyboardInterrupt:
            log.info("Bridge stopped.")
        finally:
            self.disconnect()


# ── CLI ────────────────────────────────────────────────────────────── #

def _list_ports() -> None:
    ports = list(serial.tools.list_ports.comports())
    if not ports:
        print("No serial ports detected.")
        return
    print("Available serial ports:")
    for p in ports:
        print(f"  {p.device:<12} {p.description}")


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    parser = argparse.ArgumentParser(description="ThreatMapper ESP32 Physical Bridge")
    parser.add_argument("--port",       default=DEFAULT_PORT,     help=f"Serial port (default: {DEFAULT_PORT})")
    parser.add_argument("--baud",       default=DEFAULT_BAUD,     type=int, help=f"Baud rate (default: {DEFAULT_BAUD})")
    parser.add_argument("--log",        default=DEFAULT_LOG_FILE, type=Path, help="Output log file")
    parser.add_argument("--list-ports", action="store_true",      help="List available serial ports and exit")
    args = parser.parse_args()

    if args.list_ports:
        _list_ports()
        return

    ESP32Bridge(port=args.port, baud=args.baud, log_path=args.log).run()


if __name__ == "__main__":
    main()
