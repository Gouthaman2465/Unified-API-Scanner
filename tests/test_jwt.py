"""
tests/test_jwt.py — Unit Tests for JWT Security Analysis Module
Phase 13 — Aegis-API Unified Framework

Tests cover:
  - Token decoding (valid, malformed, Bearer prefix)
  - Missing exp claim detection
  - Excessive token lifetime detection
  - alg:none detection
  - HS256 informational flag
  - Sensitive claim detection
  - alg:none forged token generation
  - Complete analyse_jwt() integration
"""

import base64
import json
import time
try:
    import pytest
except ImportError:
    pytest = None

# ── Helpers to build test tokens without a crypto library ──────────────────

def _b64url_encode(data: dict) -> str:
    """Encodes a dict as Base64URL without padding."""
    raw = json.dumps(data, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _make_token(header: dict, payload: dict, signature: str = "fakesig") -> str:
    """Assembles a JWT string from header dict, payload dict, and signature string."""
    return f"{_b64url_encode(header)}.{_b64url_encode(payload)}.{signature}"


# ── Shared token fixtures ───────────────────────────────────────────────────

def make_valid_token():
    """Standard token — short-lived, HS256, no sensitive claims."""
    now = int(time.time())
    return _make_token(
        {"alg": "HS256", "typ": "JWT"},
        {"sub": "user_123", "role": "user", "iat": now, "exp": now + 900},
    )


def make_no_exp_token():
    """Token with no expiration claim."""
    return _make_token(
        {"alg": "HS256", "typ": "JWT"},
        {"sub": "user_123", "role": "user"},
    )


def make_long_exp_token():
    """Token with a 60-day lifetime (too long)."""
    now = int(time.time())
    return _make_token(
        {"alg": "HS256", "typ": "JWT"},
        {"sub": "user_123", "iat": now, "exp": now + 86400 * 60},
    )


def make_alg_none_token():
    """Token that already declares alg=none."""
    return _make_token(
        {"alg": "none", "typ": "JWT"},
        {"sub": "attacker", "role": "admin"},
        "",  # empty signature
    )


def make_sensitive_token():
    """Token that contains sensitive fields in the payload."""
    now = int(time.time())
    return _make_token(
        {"alg": "HS256", "typ": "JWT"},
        {"sub": "user_123", "exp": now + 900, "password": "hunter2", "api_key": "sk-abc123"},
    )


# ── Import module under test ────────────────────────────────────────────────

from scanners.jwt import (
    analyse_jwt,
    check_algorithm,
    check_missing_expiration,
    check_sensitive_claims,
    check_alg_none_bypass,
    _decode_token_parts,
    _build_alg_none_token,
)


# ═══════════════════════════════════════════════════════════════════════════
# 1. DECODING TESTS
# ═══════════════════════════════════════════════════════════════════════════

class TestTokenDecoding:

    def test_valid_token_decodes_correctly(self):
        token = make_valid_token()
        header, payload, sig = _decode_token_parts(token)
        assert header["alg"] == "HS256"
        assert "sub" in payload
        assert sig == "fakesig"

    def test_malformed_token_raises_value_error(self):
        with pytest.raises(ValueError, match="Expected 3 token parts"):
            _decode_token_parts("not.a.valid.jwt.at.all.with.too.many.parts")

    def test_missing_parts_raises_value_error(self):
        with pytest.raises(ValueError):
            _decode_token_parts("onlyone")

    def test_bearer_prefix_stripped_by_analyse(self):
        token = "Bearer " + make_valid_token()
        result = analyse_jwt(token)
        assert result["status"] == "ok"
        assert result["header"]["alg"] == "HS256"

    def test_bearer_lowercase_prefix_stripped(self):
        token = "bearer " + make_valid_token()
        result = analyse_jwt(token)
        assert result["status"] == "ok"

    def test_invalid_token_returns_error_status(self):
        result = analyse_jwt("not_a_jwt_at_all")
        assert result["status"] == "error"
        assert result["error"] is not None


# ═══════════════════════════════════════════════════════════════════════════
# 2. ALGORITHM CHECKS
# ═══════════════════════════════════════════════════════════════════════════

class TestAlgorithmChecks:

    def test_alg_none_detected_as_critical(self):
        header = {"alg": "none", "typ": "JWT"}
        finding = check_algorithm(header)
        assert finding is not None
        assert finding["severity"] == "Critical"
        assert "none" in finding["check"].lower()
        assert finding["owasp"] == "API2:2023"

    def test_alg_None_uppercase_detected(self):
        # Some libraries case-fold differently
        header = {"alg": "None", "typ": "JWT"}
        finding = check_algorithm(header)
        assert finding is not None
        assert finding["severity"] == "Critical"

    def test_alg_hs256_returns_informational(self):
        header = {"alg": "HS256", "typ": "JWT"}
        finding = check_algorithm(header)
        assert finding is not None
        assert finding["severity"] == "Informational"

    def test_alg_rs256_returns_no_finding(self):
        header = {"alg": "RS256", "typ": "JWT"}
        finding = check_algorithm(header)
        assert finding is None

    def test_missing_alg_field_returns_no_finding(self):
        # Empty alg should not crash
        header = {"typ": "JWT"}
        finding = check_algorithm(header)
        assert finding is None

    def test_alg_none_in_full_analyse(self):
        token = make_alg_none_token()
        result = analyse_jwt(token)
        assert result["status"] == "ok"
        severities = [f["severity"] for f in result["findings"]]
        assert "Critical" in severities


# ═══════════════════════════════════════════════════════════════════════════
# 3. EXPIRATION CHECKS
# ═══════════════════════════════════════════════════════════════════════════

class TestExpirationChecks:

    def test_missing_exp_returns_medium_finding(self):
        payload = {"sub": "user_1", "role": "user"}
        finding = check_missing_expiration(payload)
        assert finding is not None
        assert finding["severity"] == "Medium"
        assert "exp" in finding["check"].lower() or "expir" in finding["check"].lower()

    def test_valid_short_exp_returns_no_finding(self):
        now = int(time.time())
        payload = {"sub": "user_1", "iat": now, "exp": now + 900}
        finding = check_missing_expiration(payload)
        assert finding is None

    def test_excessive_exp_returns_low_finding(self):
        now = int(time.time())
        payload = {"sub": "user_1", "iat": now, "exp": now + 86400 * 60}
        finding = check_missing_expiration(payload)
        assert finding is not None
        assert finding["severity"] == "Low"
        assert "days" in finding["description"].lower() or "day" in finding["evidence"]

    def test_no_exp_in_full_analyse(self):
        token = make_no_exp_token()
        result = analyse_jwt(token)
        checks = [f["check"] for f in result["findings"]]
        # Should contain an exp-related finding
        assert any("exp" in c.lower() or "expir" in c.lower() for c in checks)

    def test_long_exp_in_full_analyse(self):
        token = make_long_exp_token()
        result = analyse_jwt(token)
        severities = [f["severity"] for f in result["findings"]]
        assert "Low" in severities


# ═══════════════════════════════════════════════════════════════════════════
# 4. SENSITIVE CLAIM CHECKS
# ═══════════════════════════════════════════════════════════════════════════

class TestSensitiveClaimChecks:

    def test_password_field_detected(self):
        payload = {"sub": "user_1", "password": "s3cr3t"}
        finding = check_sensitive_claims(payload)
        assert finding is not None
        assert finding["severity"] == "High"
        assert "password" in str(finding["evidence"])

    def test_api_key_field_detected(self):
        payload = {"sub": "user_1", "api_key": "sk-1234"}
        finding = check_sensitive_claims(payload)
        assert finding is not None
        assert "api_key" in str(finding["evidence"])

    def test_uppercase_sensitive_key_detected(self):
        # Case-insensitive check
        payload = {"sub": "user_1", "PASSWORD": "letmein"}
        finding = check_sensitive_claims(payload)
        assert finding is not None

    def test_clean_payload_returns_no_finding(self):
        payload = {"sub": "user_1", "role": "admin", "org": "acme"}
        finding = check_sensitive_claims(payload)
        assert finding is None

    def test_sensitive_token_in_full_analyse(self):
        token = make_sensitive_token()
        result = analyse_jwt(token)
        high_findings = [f for f in result["findings"] if f["severity"] == "High"]
        sensitive_finding = next(
            (f for f in high_findings if "sensitive" in f["check"].lower()), None
        )
        assert sensitive_finding is not None


# ═══════════════════════════════════════════════════════════════════════════
# 5. alg:none BYPASS TOKEN GENERATION
# ═══════════════════════════════════════════════════════════════════════════

class TestAlgNoneBypassGeneration:

    def test_forged_token_has_three_parts(self):
        payload = {"sub": "user_1", "role": "admin"}
        forged = _build_alg_none_token(payload)
        parts = forged.split(".")
        assert len(parts) == 3

    def test_forged_token_has_empty_signature(self):
        payload = {"sub": "user_1"}
        forged = _build_alg_none_token(payload)
        assert forged.endswith(".")  # trailing dot = empty signature

    def test_forged_token_header_declares_alg_none(self):
        payload = {"sub": "user_1"}
        forged = _build_alg_none_token(payload)
        header_b64 = forged.split(".")[0]
        # Add padding and decode
        padding = 4 - len(header_b64) % 4
        if padding != 4:
            header_b64 += "=" * padding
        import base64
        header = json.loads(base64.urlsafe_b64decode(header_b64))
        assert header["alg"] == "none"

    def test_forged_token_payload_matches_original(self):
        payload = {"sub": "attacker", "role": "superadmin"}
        forged = _build_alg_none_token(payload)
        payload_b64 = forged.split(".")[1]
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += "=" * padding
        import base64
        decoded_payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        assert decoded_payload["role"] == "superadmin"

    def test_bypass_check_always_generates_finding(self):
        payload = {"sub": "user_1"}
        finding = check_alg_none_bypass(payload)
        assert finding is not None
        assert "forged_token" in finding
        assert finding["forged_token"] is not None

    def test_full_analyse_includes_forged_token_in_result(self):
        token = make_valid_token()
        result = analyse_jwt(token)
        assert result["forged_alg_none_token"] is not None
        assert result["forged_alg_none_token"].endswith(".")


# ═══════════════════════════════════════════════════════════════════════════
# 6. PROTOCOL CONTEXT TESTS
# ═══════════════════════════════════════════════════════════════════════════

class TestProtocolContext:

    def test_graphql_protocol_label_stored(self):
        result = analyse_jwt(make_valid_token(), protocol="GraphQL")
        assert result["protocol"] == "GraphQL"

    def test_rest_protocol_label_stored(self):
        result = analyse_jwt(make_valid_token(), protocol="REST")
        assert result["protocol"] == "REST"


# ═══════════════════════════════════════════════════════════════════════════
# 7. INTEGRATION — full analyse_jwt() output structure
# ═══════════════════════════════════════════════════════════════════════════

class TestAnalyseJwtIntegration:

    def test_result_has_required_keys(self):
        result = analyse_jwt(make_valid_token())
        for key in ("status", "protocol", "header", "payload", "findings",
                    "forged_alg_none_token", "error"):
            assert key in result, f"Missing key: {key}"

    def test_valid_token_status_ok(self):
        result = analyse_jwt(make_valid_token())
        assert result["status"] == "ok"
        assert result["error"] is None

    def test_findings_is_list(self):
        result = analyse_jwt(make_valid_token())
        assert isinstance(result["findings"], list)

    def test_every_finding_has_required_fields(self):
        result = analyse_jwt(make_sensitive_token())
        for f in result["findings"]:
            for field in ("check", "severity", "owasp", "description",
                          "evidence", "remediation"):
                assert field in f, f"Finding missing field: {field}"

    def test_owasp_always_api2(self):
        result = analyse_jwt(make_sensitive_token())
        for f in result["findings"]:
            assert f["owasp"] == "API2:2023"

    def test_severity_values_are_valid(self):
        valid = {"Critical", "High", "Medium", "Low", "Informational"}
        result = analyse_jwt(make_sensitive_token())
        for f in result["findings"]:
            assert f["severity"] in valid, f"Unknown severity: {f['severity']}"

    def test_no_exp_token_generates_multiple_findings(self):
        # No-exp token should have at least: exp finding + bypass finding
        result = analyse_jwt(make_no_exp_token())
        assert len(result["findings"]) >= 2

    def test_header_payload_populated_in_result(self):
        result = analyse_jwt(make_valid_token())
        assert result["header"].get("alg") == "HS256"
        assert "sub" in result["payload"]
