"""
ThreatMapper — Shared Models
==============================
All dataclasses used across the full system in one place.
Every module imports from here — no duplication anywhere.
"""

from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


class ThreatLevel(Enum):
    LOW      = 1
    MEDIUM   = 2
    HIGH     = 3
    CRITICAL = 4

    def label(self) -> str:
        labels = {
            ThreatLevel.LOW:      "🟢 LOW",
            ThreatLevel.MEDIUM:   "🟡 MEDIUM",
            ThreatLevel.HIGH:     "🔴 HIGH",
            ThreatLevel.CRITICAL: "🚨 CRITICAL",
        }
        return labels[self]


# ── Digital Events (Phase 1) ───────────────────────────────────────── #

@dataclass
class SecurityEvent:
    """
    A single parsed event from a log file.
    Produced by threat_mapper.py (Phase 1).
    """
    timestamp:        str
    event_type:       str
    source_ip:        str
    username:         Optional[str] = None
    password_attempt: Optional[str] = None
    file_accessed:    Optional[str] = None
    port:             Optional[int] = None
    sensor_id:        Optional[str] = None
    zone:             Optional[str] = None
    raw_line:         str = field(default="", repr=False)


# ── Physical Events (Phase 2 — ESP32) ─────────────────────────────── #

@dataclass
class PhysicalEvent:
    """
    A presence/motion event detected by the ESP32-CAM.
    Produced by esp32/bridge.py (Phase 2).
    """
    timestamp:        str
    event_type:       str          # PRESENCE_DETECTED, MOTION, ENTRY, EXIT
    location:         str          # e.g. "server_room", "entrance"
    confidence:       float        # 0.0 – 1.0
    duration_seconds: int   = 0
    after_hours:      bool  = False
    sensor_id:        Optional[str] = None
    badge_id:         Optional[str] = None
    zone:             Optional[str] = None
    raw_data:         dict  = field(default_factory=dict)


# ── Correlated Threats (Phase 2 — Correlator) ─────────────────────── #

@dataclass
class CorrelatedThreat:
    """
    A threat formed by correlating physical + digital events.
    Produced by core/correlator.py.
    """
    threat_id:           str
    timestamp:           str
    threat_level:        ThreatLevel
    summary:             str
    mitre_technique_id:  Optional[str] = None
    mitre_tactic:        Optional[str] = None
    physical_events:     list = field(default_factory=list)
    digital_events:      list = field(default_factory=list)
    recommended_action:  str  = ""
    score:               int  = 0

    def to_dict(self) -> dict:
        return {
            "threat_id":          self.threat_id,
            "timestamp":          self.timestamp,
            "threat_level":       self.threat_level.name,
            "summary":            self.summary,
            "mitre_technique_id": self.mitre_technique_id,
            "mitre_tactic":       self.mitre_tactic,
            "recommended_action": self.recommended_action,
            "score":              self.score,
            "physical_count":     len(self.physical_events),
            "digital_count":      len(self.digital_events),
        }


# ── Threat Score (Phase 4) ─────────────────────────────────────────── #

@dataclass
class ThreatScore:
    """
    Aggregated score for a single source (IP or badge ID).
    Produced by core/scorer.py (Phase 4).
    """
    source_id:    str
    score:        int = 0
    event_count:  int = 0
    top_threat:   Optional[str] = None
    is_physical:  bool = False

    def add(self, event_type: str, weight: int):
        self.score       += weight
        self.event_count += 1
        if self.top_threat is None:
            self.top_threat = event_type

    def label(self) -> str:
        if self.score >= 20:
            return "🚨 CRITICAL"
        elif self.score >= 10:
            return "🔴 HIGH"
        elif self.score >= 5:
            return "🟡 MEDIUM"
        return "🟢 LOW"
