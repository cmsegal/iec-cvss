"""
Reproduces the blueprint case study.
"""

from model import FR, State, Vulnerability
from alg import alg


ZONES = ["Boundary", "TerminalBus", "PlantBus", "PackageUnit"]

# Manual-derived / target cap s_bar per zone (IAC, UC, SI, RDF, RA, DC).
_TARGET = {
    "Boundary":    {FR.IAC: 3, FR.UC: 3, FR.SI: 3, FR.RDF: 3, FR.RA: 2, FR.DC: 3},
    "TerminalBus": {FR.IAC: 2, FR.UC: 2, FR.SI: 3, FR.RDF: 2, FR.RA: 3, FR.DC: 2},
    "PlantBus":    {FR.IAC: 2, FR.UC: 2, FR.SI: 3, FR.RDF: 3, FR.RA: 4, FR.DC: 1},
    "PackageUnit": {FR.IAC: 2, FR.UC: 2, FR.SI: 3, FR.RDF: 3, FR.RA: 3, FR.DC: 1},
}

target = State({z: dict(levels) for z, levels in _TARGET.items()})
capability = State({z: dict(levels) for z, levels in _TARGET.items()})

# Vulnerability evidence.
vulnerabilities = [
    Vulnerability(
        id="V1",
        zone="Boundary",
        base_cvss_str="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        affected_frs={FR.RDF, FR.RA},
        propagated_to={"Boundary", "PlantBus", "PackageUnit"},
        upstream_path=["Boundary"],
    ),
    Vulnerability(
        id="V2",
        zone="TerminalBus",
        base_cvss_str="CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:L/I:L/A:L",
        affected_frs={FR.IAC, FR.UC, FR.SI},
        propagated_to={"TerminalBus"},
        upstream_path=["Boundary", "TerminalBus"],
    ),
    Vulnerability(
        id="V3",
        zone="PackageUnit",
        base_cvss_str="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        affected_frs={FR.SI, FR.RA},
        propagated_to={"PackageUnit"},
        upstream_path=["Boundary", "PlantBus", "PackageUnit"],
    ),
]


def triple(state: State, zone: str) -> tuple[int, int, int]:
    return (state.level(zone, FR.RDF), state.level(zone, FR.RA), state.level(zone, FR.SI))


if __name__ == "__main__":
    achieved, vectors, iterations, trace = alg(target, capability, vulnerabilities)

    print(f"Converged after {iterations} iteration(s).\n")
    print(f"{'Iter':<5}{'Boundary':<14}{'PlantBus':<14}{'PackageUnit':<14}  CVSS-E (V1, V2, V3)")
    for i, (state, vecs) in enumerate(trace, start=1):
        b = triple(state, "Boundary")
        p = triple(state, "PlantBus")
        u = triple(state, "PackageUnit")
        scores = tuple(round(vecs[v].env_score, 2) for v in ("V1", "V2", "V3"))
        print(f"{i:<5}{str(b):<14}{str(p):<14}{str(u):<14}  {scores}")