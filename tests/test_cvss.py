# tests/test_cvss.py
"""
CVSS scoring engine tests.

Run with:
    python -m pytest tests/test_cvss.py -v -s

The -s flag lets print() output appear alongside pass/fail results.
"""

from utils.helpers import (
    score_xxe,
    score_graphql_introspection,
    score_jwt_none_alg,
    score_idor,
    score_wsdl_exposure,
    score_jwt_weak_secret,
    score_rate_limit_missing,
    score_mass_assignment,
    FindingContext,
    compute_cvss_score,
)


def _show(label: str, result: dict):
    """Print a formatted one-line summary of a CVSS result."""
    print(
        f"\n  [{result['label']:<12}] "
        f"score={result['score']:<4}  "
        f"{label}\n"
        f"           vector : {result['vector']}\n"
        f"           reason : {result['justification']}"
    )


# ── Test 1 ─────────────────────────────────────────────────

def test_xxe_is_high():
    """
    XXE exposing internal file paths scores 8.0 High.
    Reaches Critical only when credentials are exfiltrated directly.
    """
    result = score_xxe(auth_required=False)
    _show("SOAP XXE (internal_paths)", result)

    assert result["score"] >= 7.0
    assert result["label"] in ("High", "Critical")


# ── Test 2 ─────────────────────────────────────────────────

def test_xxe_with_credential_exfil_is_critical():
    """
    XXE that exfiltrates credentials directly must score Critical (>=9.0).
    This is the worst-case XXE scenario.
    """
    result = compute_cvss_score(FindingContext(
        protocol="SOAP",
        vuln_type="xxe_credential_exfil",
        auth_required=False,
        data_exposed="credentials",
        privilege_escalation=True,
        attack_complexity="low",
        affects_availability=False,
    ))
    _show("SOAP XXE (credentials exfiltrated)", result)

    assert result["score"] >= 9.0
    assert result["label"] == "Critical"


# ── Test 3 ─────────────────────────────────────────────────

def test_introspection_is_high():
    """
    GraphQL introspection enabled scores 7.1 High.
    No auth required + network accessible pushes it above Medium.
    """
    result = score_graphql_introspection()
    _show("GraphQL Introspection Enabled", result)

    assert result["score"] >= 7.0
    assert result["label"] == "High"


# ── Test 4 ─────────────────────────────────────────────────

def test_jwt_none_is_critical():
    """
    JWT alg:none attack completely bypasses authentication.
    Must score Critical (>=9.0).
    """
    result = score_jwt_none_alg()
    _show("JWT alg:none bypass", result)

    assert result["score"] >= 9.0
    assert result["label"] == "Critical"


# ── Test 5 ─────────────────────────────────────────────────

def test_auth_reduces_idor_score():
    """
    Unauthenticated IDOR must score higher than authenticated IDOR.
    Proves that Privileges Required metric is working correctly.
    """
    no_auth   = score_idor(auth_required=False)
    with_auth = score_idor(auth_required=True)

    _show("IDOR — no auth required", no_auth)
    _show("IDOR — auth required",    with_auth)

    print(
        f"\n  Score gap: {no_auth['score']} (no auth) "
        f"vs {with_auth['score']} (auth required)"
    )

    assert no_auth["score"] > with_auth["score"]


# ── Test 6 ─────────────────────────────────────────────────

def test_high_complexity_reduces_score():
    """
    JWT weak secret requires offline brute-force (AC:High).
    Must score lower than JWT alg:none (AC:Low).
    Proves Attack Complexity metric is working correctly.
    """
    none_alg    = score_jwt_none_alg()
    weak_secret = score_jwt_weak_secret()

    _show("JWT alg:none   (AC:Low)",  none_alg)
    _show("JWT weak secret (AC:High)", weak_secret)

    print(
        f"\n  Score gap: {none_alg['score']} (AC:Low) "
        f"vs {weak_secret['score']} (AC:High)"
    )

    assert none_alg["score"] > weak_secret["score"]


# ── Test 7 ─────────────────────────────────────────────────

def test_vector_string_format():
    """
    Every result must contain a valid CVSS:3.1 vector string.
    """
    result = score_xxe()
    _show("Vector string format check", result)

    assert result["vector"].startswith("CVSS:3.1/AV:")
    assert "/AC:" in result["vector"]
    assert "/PR:" in result["vector"]
    assert "/C:"  in result["vector"]


# ── Test 8 ─────────────────────────────────────────────────

def test_all_finders_produce_valid_scores():
    """
    Smoke test: every convenience wrapper must return a score
    between 0.0 and 10.0 with a non-empty label.
    """
    wrappers = [
        ("score_xxe",                   score_xxe()),
        ("score_wsdl_exposure",         score_wsdl_exposure()),
        ("score_graphql_introspection", score_graphql_introspection()),
        ("score_jwt_none_alg",          score_jwt_none_alg()),
        ("score_jwt_weak_secret",       score_jwt_weak_secret()),
        ("score_idor (no auth)",        score_idor(auth_required=False)),
        ("score_idor (auth)",           score_idor(auth_required=True)),
        ("score_mass_assignment",       score_mass_assignment(auth_required=True, escalation=True)),
        ("score_rate_limit_missing",    score_rate_limit_missing()),
    ]

    print()
    print(f"  {'Wrapper':<35} {'Score':>6}  {'Severity':<12} Vector")
    print(f"  {'-'*35} {'-'*6}  {'-'*12} {'-'*45}")

    for label, result in wrappers:
        print(
            f"  {label:<35} {result['score']:>6}  "
            f"{result['label']:<12} {result['vector']}"
        )
        assert 0.0 <= result["score"] <= 10.0
        assert result["label"] in ("Critical", "High", "Medium", "Low", "Informational")
        assert result["justification"]
