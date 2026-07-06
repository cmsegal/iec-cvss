from model import MAV, MPR, Requirement, State, Vulnerability, CVSSVector, FR


def alpha(rdf_level: int) -> MAV:
    if rdf_level <= 1:
        return MAV.NETWORK
    if rdf_level == 2:
        return MAV.ADJACENT
    return MAV.LOCAL


def pi(iac_uc_level: int) -> MPR:
    if iac_uc_level <= 1:
        return MPR.NONE
    if iac_uc_level == 2:
        return MPR.LOW
    return MPR.HIGH


def eta(target_level: int) -> Requirement:
    if target_level <= 1:
        return Requirement.LOW
    if target_level == 2:
        return Requirement.MEDIUM
    return Requirement.HIGH


def q(score: float) -> int:
    """Discrete penalty classes based on the Appendix."""
    if score >= 9.0:
        return 2
    if score >= 4.0:
        return 1
    return 0


# ---------------------------------------------------------------------------------------------------
# Environmental score computation (just an example; this should be replaced with a real CVSS scorer)
# ---------------------------------------------------------------------------------------------------

_MAV_BONUS = {MAV.LOCAL: 0.0, MAV.ADJACENT: 1.0, MAV.NETWORK: 2.0}
_MPR_BONUS = {MPR.HIGH: 0.0, MPR.LOW: 0.75, MPR.NONE: 1.5}
_REQ_BONUS = {Requirement.LOW: 0.0, Requirement.MEDIUM: 0.25, Requirement.HIGH: 0.5}


def environmental_score(base_score: float, vector: CVSSVector) -> float:
    """Note: this should be replaced by a real CVSS scoring function."""
    bonus = (
        _MAV_BONUS[vector.mav]
        + _MPR_BONUS[vector.mpr]
        + max(_REQ_BONUS[vector.cr], _REQ_BONUS[vector.ir], _REQ_BONUS[vector.ar])
    )
    return min(10.0, base_score + bonus)


def G(
    achieved: State,
    target: State,
    vulnerabilities: list[Vulnerability],
) -> dict[str, CVSSVector]:

    vectors = {}

    for v in vulnerabilities:
        # r_c(s) = min over the upstream path Pi(c) of achieved RDF.
        path = v.upstream_path or [v.zone]
        rdf = min(achieved.level(z, FR.RDF) for z in path)

        # a_c(s) is local by definition (Appendix A.3).
        iac_uc = min(
            achieved.level(v.zone, FR.IAC),
            achieved.level(v.zone, FR.UC),
        )

        vector = CVSSVector(
            mav=alpha(rdf),
            mpr=pi(iac_uc),
            cr=eta(target.level(v.zone, FR.DC)),
            ir=eta(target.level(v.zone, FR.SI)),
            ar=eta(target.level(v.zone, FR.RA)),
            score=0.0,
        )
        vector.score = environmental_score(v.base_score, vector)

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
        p = q(vectors[v.id].score)
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
        (a[k].mav, a[k].mpr, a[k].cr, a[k].ir, a[k].ar, round(a[k].score, 6))
        == (b[k].mav, b[k].mpr, b[k].cr, b[k].ir, b[k].ar, round(b[k].score, 6))
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