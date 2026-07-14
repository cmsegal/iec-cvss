from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Set


# ----------------------------
# IEC 62443
# ----------------------------

class FR(Enum):
    IAC = "IAC"
    UC = "UC"
    SI = "SI"
    DC = "DC"
    RDF = "RDF"
    TRE = "TRE"
    RA = "RA"


@dataclass
class State:
    levels: Dict[str, Dict[FR, int]]

    def level(self, zone: str, fr: FR) -> int:
        return self.levels[zone].get(fr, 0)

    def set_level(self, zone: str, fr: FR, value: int):
        self.levels[zone][fr] = value

    def copy(self) -> "State":
        return State(
            {
                zone: dict(levels)
                for zone, levels in self.levels.items()
            }
        )

    def cap_with(self, other: "State") -> "State":
        """Computes the componentwise minimum of this state and `other`.

        This is used to compute s_bar_{z,f} = min(s^T_{z,f}, s^C_{z,f}) -- the
        reporting cap on achieved level from Appendix A.
        """
        capped: Dict[str, Dict[FR, int]] = {}
        for zone, levels in self.levels.items():
            other_levels = other.levels.get(zone, {})
            capped[zone] = {
                fr: min(v, other_levels.get(fr, v))
                for fr, v in levels.items()
            }
        return State(capped)


# ----------------------------
# CVSS
# ----------------------------

class MAV(Enum): # Modified Attack Vector
    NETWORK = "N"
    ADJACENT = "A"
    LOCAL = "L"


class MPR(Enum): # Modified Privileges Required
    NONE = "N"
    LOW = "L"
    HIGH = "H"


class Requirement(Enum): # C, I and A requirements
    LOW = "L"
    MEDIUM = "M"
    HIGH = "H"


@dataclass
class CVSSVector:
    mav: MAV
    mpr: MPR

    cr: Requirement
    ir: Requirement
    ar: Requirement

    env_score: float  # E(v_c): the environmental score, recomputed by G each iteration


# ----------------------------
# Vulnerability evidence (part of kappa, the configuration context referred to by the paper)
# ----------------------------

@dataclass
class Vulnerability:
    id: str
    zone: str                # z(c): zone of the vulnerable asset
    base_cvss_str: str       # vendor/base CVSS string -- fixed, never mutated
    affected_frs: Set[FR]
    propagated_to: Set[str]
    upstream_path: List[str]