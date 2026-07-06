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

    score: float  # E(v_c): the *environmental* score, recomputed by G each iteration


# ----------------------------
# Vulnerability evidence (part of kappa, the configuration context referred to by the paper)
# ----------------------------

@dataclass
class Vulnerability:
    id: str
    zone: str                # z(c): zone of the vulnerable asset
    base_score: float        # v^B: vendor/base CVSS score -- fixed, never mutated
    affected_frs: Set[FR]    # M_{c,.}: which FRs are affected by this vulnerability
    propagated_to: Set[str]  # D_{c,.}: zones whose achieved level this can downgrade
    upstream_path: List[str]  # Pi(c): zones from the nearest untrusted entry
    # point to z(c), inclusive of z(c) itself. Used by G to compute
    # r_c(s) = min_{z in Pi(c)} s_{z,RDF} -- the mechanism that lets an
    # upstream boundary failure raise the environmental severity of a
    # *downstream* vulnerability.