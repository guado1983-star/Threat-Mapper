from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class MitreTechnique:
    technique_id: str
    name: str
    tactic: str


_TECHNIQUE_MAP: dict[str, MitreTechnique] = {

    # ── Phase 1 & 3 — Digital Events ──────────────────────────────────
    "SSH_LOGIN_FAILED": MitreTechnique(
        technique_id="T1110",
        name="Brute Force",
        tactic="Credential Access",
    ),
    "PORT_SCAN": MitreTechnique(
        technique_id="T1046",
        name="Network Service Scanning",
        tactic="Discovery",
    ),
    "HONEYFILE_ACCESSED": MitreTechnique(
        technique_id="T1083",
        name="File and Directory Discovery",
        tactic="Discovery",
    ),

    # ── Phase 2 — Physical Events ──────────────────────────────────────
    "PHYSICAL_PRESENCE": MitreTechnique(
        technique_id="T1078",
        name="Valid Accounts / Physical Access",
        tactic="Initial Access",
    ),
    "AFTER_HOURS_INTRUSION": MitreTechnique(
        technique_id="T0867",
        name="Physical Intrusion",
        tactic="Initial Access",
    ),
    "CORRELATED_ATTACK": MitreTechnique(
        technique_id="T1200",
        name="Hardware Additions",
        tactic="Initial Access",
    ),
    "MOTION_DETECTED": MitreTechnique(
        technique_id="T0812",
        name="Device Identification / Physical Recon",
        tactic="Discovery",
    ),
    "HONEYFILE_PHYSICAL_CORRELATION": MitreTechnique(
        technique_id="T1074",
        name="Data Staged / Insider Threat",
        tactic="Collection",
    ),
}


def map_event(event_type: str) -> Optional[MitreTechnique]:
    return _TECHNIQUE_MAP.get(event_type)


def technique_table() -> dict[str, MitreTechnique]:
    return dict(_TECHNIQUE_MAP)


def all_tactics() -> list[str]:
    """Return unique list of all tactics covered."""
    return list(dict.fromkeys(t.tactic for t in _TECHNIQUE_MAP.values()))


def techniques_by_tactic(tactic: str) -> dict[str, MitreTechnique]:
    """Return all techniques under a specific tactic."""
    return {k: v for k, v in _TECHNIQUE_MAP.items() if v.tactic == tactic}
