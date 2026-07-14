from cvss import CVSS3
from model import MAV, MPR, Requirement, State, Vulnerability, CVSSVector, FR


def attack_vector_from_level(level: int) -> MAV:
    """Computes CVSS MAV metric from the given IEC level."""
    if level <= 1:
        return MAV.NETWORK
    if level == 2:
        return MAV.ADJACENT
    return MAV.LOCAL


def privileges_required_from_level(level: int) -> MPR:
    """Computes CVSS MPR metric from the given IEC level."""
    if level <= 1:
        return MPR.NONE
    if level == 2:
        return MPR.LOW
    return MPR.HIGH


def cia_requirement_from_level(level: int) -> Requirement:
    """Computes CVSS impact requirement (CR, IR or AR) metric from the given IEC level."""
    if level <= 1:
        return Requirement.LOW
    if level == 2:
        return Requirement.MEDIUM
    return Requirement.HIGH


def q(score: float) -> int:
    """Discrete penalty classes based on the Appendix."""
    if score >= 8.0:
        return 2
    if score >= 4.0:
        return 1
    return 0


# ---------------------------------------------------------------------------------------------------
# CVSS 3.1 environmental score computation
# ---------------------------------------------------------------------------------------------------

def environmental_score_cvss31(base_vector_str: str, vector: CVSSVector) -> float:
    """
    Computes the CVSS v3.1 Environmental Score.
    
    :param base_vector_str: The vendor-provided CVSS 3.1 base vector.
                            e.g., "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    :param vector: Environmental CVSS vector containing modified scores (MAV, MPR, CR, IR, AR)
    """
    # 1. Parse the original base vector
    cvss_obj = CVSS3(base_vector_str)
    
    # 2. Overwrite the environmental metrics using the values supplied by G
    # CVSS3 expects metrics to be in their standard short form (e.g., MAV: "N", "A", "L")
    cvss_obj.metrics['MAV'] = vector.mav.value  # "N", "A", or "L"
    cvss_obj.metrics['MPR'] = vector.mpr.value  # "N", "L", or "H"
    cvss_obj.metrics['CR']  = vector.cr.value   # "L", "M", or "H"
    cvss_obj.metrics['IR']  = vector.ir.value   # "L", "M", or "H"
    cvss_obj.metrics['AR']  = vector.ar.value   # "L", "M", or "H"
    
    # 3. Recalculate and return environmental score
    cvss_obj.compute_environmental_score()
    return cvss_obj.environmental_score


def G(
    achieved: State,
    target: State,
    vulnerabilities: list[Vulnerability],
) -> dict[str, CVSSVector]:

    vectors = {}

    for v in vulnerabilities:
        # MinRDF_c(s) = minimum value of achieved RDF over the upstream path Upstream(c).
        path = v.upstream_path or [v.zone]
        min_rdf = min(achieved.level(z, FR.RDF) for z in path)

        # LocalAC_c(s) = minimum among the local zone's IAC and UC (Appendix A.3).
        local_ac = min(
            achieved.level(v.zone, FR.IAC),
            achieved.level(v.zone, FR.UC),
        )

        vector = CVSSVector(
            mav=attack_vector_from_level(min_rdf),
            mpr=privileges_required_from_level(local_ac),
            cr=cia_requirement_from_level(target.level(v.zone, FR.DC)),
            ir=cia_requirement_from_level(target.level(v.zone, FR.SI)),
            ar=cia_requirement_from_level(target.level(v.zone, FR.RA)),
            env_score=0.0,
        )
        vector.env_score = environmental_score_cvss31(v.base_cvss_str, vector)

        vectors[v.id] = vector

    return vectors


def F(
    target: State,
    capability: State,
    vectors: dict[str, CVSSVector],
    vulnerabilities: list[Vulnerability],
) -> State:

    # s_bar_{z,f} = min(s^T_{z,f}, s^C_{z,f}) -- the reporting cap.
    # The achieved level should not exceed what's supported
    # (capability) or what's required (target).
    cap = target.cap_with(capability)

    # P_{z,f} = min(4, max_c D_{c,z} M_{c,f} q(v_c))
    penalties: dict[tuple[str, FR], int] = {}
    for v in vulnerabilities:
        p = q(vectors[v.id].env_score)
        for zone in v.propagated_to:
            for fr in v.affected_frs:
                key = (zone, fr)
                penalties[key] = min(4, max(penalties.get(key, 0), p))

    new_state = cap.copy()
    for zone, levels in cap.levels.items():
        for fr in levels:
            penalty = penalties.get((zone, fr), 0)
            new_state.set_level(zone, fr, max(0, cap.level(zone, fr) - penalty))

    return new_state


def _vectors_equal(a: dict, b: dict) -> bool:
    if a.keys() != b.keys():
        return False
    return all(
        (a[k].mav, a[k].mpr, a[k].cr, a[k].ir, a[k].ar, round(a[k].env_score, 6))
        == (b[k].mav, b[k].mpr, b[k].cr, b[k].ir, b[k].ar, round(b[k].env_score, 6))
        for k in a
    )


def alg(
    target: State,
    capability: State,
    vulnerabilities: list[Vulnerability],
):
    """Algorithm 2. Returns (achieved, vectors, iterations, trace)."""

    vectors: dict[str, CVSSVector] = {}
    achieved = target.cap_with(capability)  # s^0 = s_bar

    iterations = 0
    trace = []

    while True:
        previous_state = achieved.copy()
        previous_vectors = vectors

        vectors = G(achieved, target, vulnerabilities)
        achieved = F(target, capability, vectors, vulnerabilities)

        iterations += 1
        trace.append((achieved.copy(), dict(vectors)))

        if (
            achieved.levels == previous_state.levels
            and _vectors_equal(vectors, previous_vectors)
        ):
            break

    return achieved, vectors, iterations, trace