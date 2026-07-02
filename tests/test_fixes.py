"""
Tests for FIX 1-7: sensor_id, badge_id, and zone propagation
across models, bridge, threat_mapper, correlator, and scorer.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.models import CorrelatedThreat, PhysicalEvent, SecurityEvent, ThreatLevel
from core.correlator import correlate, correlate_from_log
from core.scorer import score_correlated, score_physical
from threat_mapper import (
    _parse_after_hours,
    _parse_correlated_attack,
    _parse_honeyfile_physical,
    _parse_motion,
    _parse_physical_presence,
)

try:
    from esp32.bridge import parse_message
    BRIDGE_AVAILABLE = True
except ImportError:
    BRIDGE_AVAILABLE = False

# shared timestamp used across fixtures
TS = "2024-01-15 02:30:00"


# ── Helpers ────────────────────────────────────────────────────────── #

def _digital(event_type="SSH_LOGIN_FAILED", ts=TS) -> SecurityEvent:
    return SecurityEvent(timestamp=ts, event_type=event_type, source_ip="192.168.1.10")


def _physical(event_type="ENTRY", *, zone=None, location="entrance",
              after_hours=False, badge_id=None, sensor_id=None) -> PhysicalEvent:
    return PhysicalEvent(
        timestamp=TS, event_type=event_type, location=location,
        confidence=1.0, after_hours=after_hours,
        zone=zone, badge_id=badge_id, sensor_id=sensor_id,
    )


def _physical_se(event_type="AFTER_HOURS_INTRUSION", *, zone=None,
                 source_ip="B001") -> SecurityEvent:
    return SecurityEvent(timestamp=TS, event_type=event_type,
                         source_ip=source_ip, zone=zone)


# ── FIX 1: Models ──────────────────────────────────────────────────── #

class TestModels:
    def test_physical_event_defaults(self):
        e = PhysicalEvent(timestamp=TS, event_type="MOTION",
                          location="lab", confidence=0.9)
        assert e.sensor_id is None
        assert e.badge_id  is None
        assert e.zone      is None

    def test_physical_event_stores_all_three(self):
        e = PhysicalEvent(timestamp=TS, event_type="MOTION", location="lab",
                          confidence=0.9, sensor_id="pir_1", badge_id="B001",
                          zone="server_room")
        assert e.sensor_id == "pir_1"
        assert e.badge_id  == "B001"
        assert e.zone      == "server_room"

    def test_security_event_defaults(self):
        e = SecurityEvent(timestamp=TS, event_type="MOTION_DETECTED",
                          source_ip="pir_1")
        assert e.sensor_id is None
        assert e.zone      is None

    def test_security_event_stores_sensor_id_and_zone(self):
        e = SecurityEvent(timestamp=TS, event_type="MOTION_DETECTED",
                          source_ip="pir_1", sensor_id="pir_1", zone="server_room")
        assert e.sensor_id == "pir_1"
        assert e.zone      == "server_room"


# ── FIX 2: Bridge parser ────────────────────────────────────────────── #

@pytest.mark.skipif(not BRIDGE_AVAILABLE, reason="pyserial not installed")
class TestBridgeParser:
    def test_motion_sets_sensor_id_and_zone(self):
        raw = '{"type": "MOTION", "sensor": "pir_1", "zone": "server_room", "confidence": 0.85}'
        e = parse_message(raw)
        assert e is not None
        assert e.sensor_id == "pir_1"
        assert e.zone      == "server_room"

    def test_presence_sets_badge_id(self):
        raw = '{"type": "PRESENCE_DETECTED", "badge_id": "B001", "location": "entrance", "confidence": 0.92}'
        e = parse_message(raw)
        assert e is not None
        assert e.badge_id == "B001"

    def test_entry_sets_badge_id(self):
        raw = '{"type": "ENTRY", "badge_id": "B002", "location": "server_room", "confidence": 1.0}'
        e = parse_message(raw)
        assert e is not None
        assert e.badge_id == "B002"

    def test_motion_zone_on_dedicated_field(self):
        raw = '{"type": "MOTION", "sensor": "cam_2", "zone": "lab", "confidence": 0.75}'
        e = parse_message(raw)
        assert e.zone      == "lab"
        assert e.sensor_id == "cam_2"

    def test_unknown_type_returns_none(self):
        assert parse_message('{"type": "UNKNOWN", "confidence": 0.5}') is None

    def test_invalid_json_returns_none(self):
        assert parse_message("not json") is None


# ── FIX 6: Threat-mapper parsers ────────────────────────────────────── #

class TestThreatMapperParsers:
    def test_motion_sensor_id_and_zone(self):
        line = f"{TS} [INFO] PHYSICAL: Motion detected - sensor='pir_1' zone='server_room'"
        e = _parse_motion(line)
        assert e is not None
        assert e.sensor_id == "pir_1"
        assert e.zone      == "server_room"
        assert e.username  is None          # zone must NOT bleed into username

    def test_physical_presence_zone_not_username(self):
        line = f"{TS} [INFO] ACCESS_CTRL: Badge scan - badge_id='B001' location='entrance' result=GRANTED"
        e = _parse_physical_presence(line)
        assert e is not None
        assert e.zone      == "entrance"
        assert e.username  is None          # location must NOT bleed into username
        assert e.source_ip == "B001"

    def test_after_hours_sensor_id_and_zone(self):
        line = f"{TS} [INFO] SECURITY: After-hours intrusion - zone='server_room' sensor='cam_1' badge_id='B003'"
        e = _parse_after_hours(line)
        assert e is not None
        assert e.sensor_id == "cam_1"
        assert e.zone      == "server_room"
        assert e.source_ip == "B003"
        assert e.username  is None

    def test_correlated_attack_zone(self):
        line = f"{TS} [INFO] NETWORK: Unknown device - mac='aa:bb:cc:dd:ee:ff' ip=10.0.0.99 zone='lab' badge_id='B004'"
        e = _parse_correlated_attack(line)
        assert e is not None
        assert e.zone      == "lab"
        assert e.source_ip == "10.0.0.99"
        assert e.username  is None

    def test_honeyfile_physical_zone(self):
        line = f"{TS} [INFO] AUDIT: Physical-digital correlation - file=/secret.txt badge_id='B005' zone='archive'"
        e = _parse_honeyfile_physical(line)
        assert e is not None
        assert e.zone      == "archive"
        assert e.source_ip == "B005"
        assert e.username  is None


# ── FIX 3 + 7: Correlator ───────────────────────────────────────────── #

class TestCorrelator:
    # real-time mode (PhysicalEvent)

    def test_realtime_prefers_zone_over_location(self):
        p = _physical(event_type="ENTRY", zone="server_room",
                      location="entrance", after_hours=True)
        threats = correlate([p], [_digital()])
        assert threats
        assert "server_room" in threats[0].summary
        assert "entrance"    not in threats[0].summary

    def test_realtime_falls_back_to_location_when_no_zone(self):
        p = _physical(event_type="ENTRY", zone=None,
                      location="entrance", after_hours=True)
        threats = correlate([p], [_digital()])
        assert threats
        assert "entrance" in threats[0].summary

    # batch mode (SecurityEvent)

    def test_batch_uses_zone_in_summary(self):
        p = _physical_se(event_type="AFTER_HOURS_INTRUSION", zone="server_room")
        threats = correlate_from_log([p, _digital()])
        assert threats
        assert "server_room" in threats[0].summary

    def test_batch_falls_back_to_source_ip_when_no_zone(self):
        p = _physical_se(event_type="AFTER_HOURS_INTRUSION", zone=None, source_ip="B001")
        threats = correlate_from_log([p, _digital()])
        assert threats
        assert "B001" in threats[0].summary

    def test_no_threats_without_matching_events(self):
        p = _physical(event_type="ENTRY", after_hours=False)
        # PORT_SCAN alone with a non-after-hours ENTRY should not fire after_hours rule
        threats = correlate([p], [_digital("PORT_SCAN")])
        # motion_port_scan rule fires on MOTION, not ENTRY — expect no threat here
        assert all(t.mitre_tactic != "Initial Access"
                   or not t.summary.startswith("After-hours")
                   for t in threats)


# ── FIX 4: Scorer ───────────────────────────────────────────────────── #

class TestScorer:
    def test_score_physical_keys_on_badge_id(self):
        events = [
            _physical(event_type="ENTRY", badge_id="B001"),
            _physical(event_type="ENTRY", badge_id="B001"),
        ]
        scores = score_physical(events)
        ids = [s.source_id for s in scores]
        assert "B001" in ids

    def test_score_physical_keys_on_sensor_id_when_no_badge(self):
        events = [_physical(event_type="MOTION", sensor_id="pir_1")]
        scores = score_physical(events)
        assert any(s.source_id == "pir_1" for s in scores)

    def test_score_physical_badge_beats_sensor(self):
        events = [_physical(event_type="ENTRY", badge_id="B002", sensor_id="cam_1")]
        scores = score_physical(events)
        ids = [s.source_id for s in scores]
        assert "B002" in ids
        assert "cam_1" not in ids

    def test_score_physical_falls_back_to_location(self):
        events = [_physical(event_type="MOTION", location="corridor")]
        scores = score_physical(events)
        assert any(s.source_id == "corridor" for s in scores)

    def test_score_correlated_uses_badge_id(self):
        pe = _physical(event_type="ENTRY", badge_id="B003")
        threat = CorrelatedThreat(
            threat_id="t1", timestamp=TS, threat_level=ThreatLevel.HIGH,
            summary="test", physical_events=[pe], digital_events=[_digital()], score=10,
        )
        scores = score_correlated([threat])
        assert any(s.source_id == "B003" for s in scores)

    def test_score_correlated_uses_sensor_id_when_no_badge(self):
        pe = _physical(event_type="MOTION", sensor_id="pir_2")
        threat = CorrelatedThreat(
            threat_id="t2", timestamp=TS, threat_level=ThreatLevel.MEDIUM,
            summary="test", physical_events=[pe], digital_events=[_digital()], score=8,
        )
        scores = score_correlated([threat])
        assert any(s.source_id == "pir_2" for s in scores)
