from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class MitreTechnique:
    technique_id: str
    name: str
    tactic: str


_TECHNIQUE_MAP: dict[str, MitreTechnique] = {
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
}


def map_event(event_type: str) -> Optional[MitreTechnique]:
    return _TECHNIQUE_MAP.get(event_type)


def technique_table() -> dict[str, MitreTechnique]:
    return dict(_TECHNIQUE_MAP)
