"""
scanners/jwt.py — JWT Security Analysis Module
Protocols: REST + GraphQL (shared)
OWASP Mapping: API2:2023 — Broken Authentication

This module analyses a JWT token for the following weaknesses:
  1. Missing expiration claim (exp)
  2. Weak or dangerous algorithm (none / HS256)
  3. Sensitive data in the payload (passwords, secrets, PII)
  4. alg:none bypass candidate (forged unsigned token)
  5. Algorithm confusion candidate (HS256 signed with public key string)

It does NOT require the secret key to be known.
All checks are performed on the decoded (but unverified) token.

Usage:
    from scanners.jwt import analyse_jwt
    result = analyse_jwt(token_string, protocol="REST")
"""

import base64
import hashlib
import hmac
import json
import logging
import time
from typing import Optional

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────

# Payload fields that should never appear in a JWT (readable by anyone)
SENSITIVE_CLAIM_NAMES = {
    "password", "passwd", "secret", "private_key",
    "api_key", "apikey", "credit_card", "ssn",
    "pin", "cvv", "token",
}

# Algorithms we flag as dangerous
WEAK_ALGORITHMS  = {"none", "None", "NONE"}

# Symmetric algorithms — acceptable but informational
MEDIUM_ALGORITHMS = {"HS256"}

# Tokens valid longer than this are flagged (30 days in seconds)
MAX_ACCEPTABLE_LIFETIME_SECONDS = 86400 * 30


# ─────────────────────────────────────────────────────────────
# INTERNAL HELPERS
# ─────────────────────────────────────────────────────────────

def _base64url_decode(segment: str) -> bytes:
    """
    Decodes a Base64URL-encoded string, adding required padding.

    JWT uses Base64URL (no padding, + -> -, / -> _).
    Python's base64 decoder requires padding, so we add = characters.
    """
    padding = 4 - len(segment) % 4
    if padding != 4:
        segment += "=" * padding
    return base64.urlsafe_b64decode(segment)


def _decode_token_parts(token: str) -> tuple:
    """
    Splits a JWT into header, payload, and signature.
    Decodes header and payload from Base64URL to Python dicts.

    A JWT is: base64url(header) . base64url(payload) . base64url(signature)

    Returns:
        (header_dict, payload_dict, raw_signature_string)

    Raises:
        ValueError if the token does not have exactly 3 parts.
    """
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError(
            f"Expected 3 token parts separated by '.', got {len(parts)}. "
            "Is this a valid JWT?"
        )

    header  = json.loads(_base64url_decode(parts[0]))
    payload = json.loads(_base64url_decode(parts[1]))
    sig     = parts[2]

    return header, payload, sig


def _build_alg_none_token(payload: dict) -> str:
    """
    Constructs a forged JWT with alg=none and an empty signature.

    The alg:none attack works when a JWT library fails to reject tokens
    that claim to use no algorithm. The attacker strips the signature,
    sets alg=none, and the server trusts the payload without verification.

    The dot at the end of the token must be present — it represents
    the empty signature field.
    """
    header_b64 = base64.urlsafe_b64encode(
        json.dumps({"alg": "none", "typ": "JWT"}, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()

    payload_b64 = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()

    # Signature is empty but the trailing dot is required by the JWT spec
    return f"{header_b64}.{payload_b64}."


def _build_alg_confusion_token(payload: dict, public_key_guess: str = "public_key") -> str:
    """
    Constructs a forged JWT using algorithm confusion (RS256 -> HS256).

    The attack:
      - Server uses RS256 and verifies with its public key
      - Attacker changes alg to HS256 and signs with the public key as the HMAC secret
      - A vulnerable library uses the same key material for both HMAC and RSA verification
        without checking the algorithm mismatch

    This function demonstrates the forged token structure.
    It uses a placeholder public key string; in a real test the actual public key
    (often exposed at /.well-known/jwks.json) would be used.
    """
    header_b64 = base64.urlsafe_b64encode(
        json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()

    payload_b64 = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()

    signing_input = f"{header_b64}.{payload_b64}".encode()
    sig_bytes = hmac.new(public_key_guess.encode(), signing_input, hashlib.sha256).digest()
    sig_b64   = base64.urlsafe_b64encode(sig_bytes).rstrip(b"=").decode()

    return f"{header_b64}.{payload_b64}.{sig_b64}"


# ─────────────────────────────────────────────────────────────
# INDIVIDUAL CHECK FUNCTIONS
# ─────────────────────────────────────────────────────────────

def check_algorithm(header: dict) -> Optional[dict]:
    """
    Checks the alg claim for dangerous or weak algorithms.

    alg=none: No signature, token is entirely forgeable — Critical.
    alg=HS256: Symmetric; informational if secret is strong, dangerous if weak.
    """
    alg = header.get("alg", "")

    if alg in WEAK_ALGORITHMS:
        return {
            "check":       "Dangerous Algorithm: none",
            "severity":    "Critical",
            "owasp":       "API2:2023",
            "description": (
                "The token declares alg='none', meaning no cryptographic signature. "
                "Any server that accepts this token is critically vulnerable. "
                "An attacker can forge any payload without knowing any secret."
            ),
            "evidence":    f"Header alg field: '{alg}'",
            "remediation": (
                "Explicitly reject alg='none' in your JWT library configuration. "
                "Use a whitelist of allowed algorithms (e.g. RS256 only). "
                "Never trust the 'alg' claim from untrusted input."
            ),
        }

    if alg in MEDIUM_ALGORITHMS:
        return {
            "check":       "Symmetric Algorithm (HS256) in Use",
            "severity":    "Informational",
            "owasp":       "API2:2023",
            "description": (
                "The token uses HS256 (HMAC-SHA256), a symmetric algorithm. "
                "Security depends entirely on secret strength. "
                "Weak secrets (common words, short strings) can be brute-forced offline "
                "once an attacker captures any token."
            ),
            "evidence":    f"Header alg field: '{alg}'",
            "remediation": (
                "Use RS256 (asymmetric) for production APIs. "
                "If staying with HS256, the secret must be >= 256 bits, "
                "cryptographically random, and stored in a secret manager."
            ),
        }

    return None


def check_missing_expiration(payload: dict) -> Optional[dict]:
    """
    Checks whether the token has an exp (expiration) claim.

    A JWT without exp never expires. If stolen, it grants access forever.
    Even tokens with very long lifetimes are flagged.
    """
    if "exp" not in payload:
        return {
            "check":       "Missing Expiration Claim (exp)",
            "severity":    "Medium",
            "owasp":       "API2:2023",
            "description": (
                "The token has no 'exp' (expiration time) claim. "
                "Stolen tokens remain valid indefinitely. "
                "Credential revocation becomes impossible without a token blacklist."
            ),
            "evidence":    f"Payload keys: {sorted(payload.keys())}",
            "remediation": (
                "Always include an 'exp' claim when issuing JWTs. "
                "Recommended token lifetime: 15 minutes for access tokens, "
                "7 days for refresh tokens with rotation."
            ),
        }

    # Token has exp — check if lifetime is too long
    exp = payload["exp"]
    iat = payload.get("iat", int(time.time()))
    lifetime_seconds = exp - iat

    if lifetime_seconds > MAX_ACCEPTABLE_LIFETIME_SECONDS:
        days = lifetime_seconds // 86400
        return {
            "check":       "Excessive Token Lifetime",
            "severity":    "Low",
            "owasp":       "API2:2023",
            "description": (
                f"The token has a lifetime of approximately {days} day(s). "
                "Long-lived tokens expand the window of exploitation if stolen."
            ),
            "evidence":    f"iat={iat}, exp={exp}, lifetime={lifetime_seconds}s ({days} days)",
            "remediation": (
                "Shorten token lifetimes to 15–60 minutes for access tokens. "
                "Use refresh token rotation for persistent sessions."
            ),
        }

    return None


def check_sensitive_claims(payload: dict) -> Optional[dict]:
    """
    Checks whether the payload contains fields that should never be in a JWT.

    JWTs are Base64-encoded — not encrypted. The payload is completely readable
    to anyone who captures the token: browser history, server logs,
    intercepting proxies, network traffic dumps.
    """
    found = [key for key in payload if key.lower() in SENSITIVE_CLAIM_NAMES]

    if found:
        return {
            "check":       "Sensitive Data Stored in JWT Payload",
            "severity":    "High",
            "owasp":       "API2:2023",
            "description": (
                f"The JWT payload contains potentially sensitive fields: {found}. "
                "JWT payloads are Base64URL-encoded, not encrypted. "
                "Anyone who obtains the token can read these values immediately."
            ),
            "evidence":    f"Sensitive fields detected: {found}",
            "remediation": (
                "Remove all sensitive data from JWT payloads. "
                "Include only non-sensitive identifiers (user ID, role name). "
                "If encrypted payloads are required, use JWE (JSON Web Encryption)."
            ),
        }

    return None


def check_alg_none_bypass(payload: dict) -> dict:
    """
    Generates an alg:none forged token as attack evidence.

    This check always returns a finding — it demonstrates that the
    attack can be attempted. Whether the server accepts this token
    must be verified manually by submitting it to an authenticated endpoint.

    The forged token is included in the finding so the tester can
    immediately use it during a live assessment or demo.
    """
    forged = _build_alg_none_token(payload)

    return {
        "check":         "alg:none Bypass Token Generated",
        "severity":      "High",
        "owasp":         "API2:2023",
        "description":   (
            "A forged token with alg='none' was constructed from this token's payload. "
            "Submit it to an authenticated endpoint. "
            "If the server returns a 200 response instead of 401, "
            "the server is accepting unsigned tokens — a critical authentication bypass."
        ),
        "evidence":      f"Forged token (first 120 chars): {forged[:120]}...",
        "forged_token":  forged,
        "remediation":   (
            "Explicitly configure your JWT library to reject alg='none'. "
            "Example in PyJWT: jwt.decode(token, key, algorithms=['RS256']) — "
            "never pass algorithms=['none'] or an empty algorithms list."
        ),
    }


# ─────────────────────────────────────────────────────────────
# MAIN ENTRY POINT
# ─────────────────────────────────────────────────────────────

def analyse_jwt(token: str, protocol: str = "REST") -> dict:
    """
    Runs all JWT security checks on the provided token string.

    This function is called by both the REST and GraphQL scanner chains
    because both protocols use Bearer JWT authentication.

    Args:
        token:    Raw JWT string. Accepts "Bearer <token>" format.
        protocol: "REST" or "GraphQL" — used in report context only.

    Returns:
        {
            "status":                "ok" | "error",
            "protocol":              str,
            "header":                dict,
            "payload":               dict,
            "findings":              list[dict],
            "forged_alg_none_token": str | None,
            "error":                 str | None,
        }
    """
    # Strip "Bearer " prefix if the full Authorization header value was passed
    clean = token.strip()
    if clean.lower().startswith("bearer "):
        clean = clean[7:].strip()

    result = {
        "status":                "ok",
        "protocol":              protocol,
        "header":                {},
        "payload":               {},
        "findings":              [],
        "forged_alg_none_token": None,
        "error":                 None,
    }

    # ── Decode the token ──────────────────────────────────────
    try:
        header, payload, _ = _decode_token_parts(clean)
    except Exception as exc:
        result["status"] = "error"
        result["error"]  = str(exc)
        logger.error("[JWT] Failed to decode token: %s", exc)
        return result

    result["header"]  = header
    result["payload"] = payload

    logger.info(
        "[JWT] Decoded — alg=%s, claims=%s",
        header.get("alg", "?"),
        list(payload.keys()),
    )

    # ── Run all checks ────────────────────────────────────────
    findings = []

    for check_fn in [check_algorithm, check_missing_expiration, check_sensitive_claims]:
        finding = check_fn(header if check_fn == check_algorithm else payload)
        if finding:
            findings.append(finding)

    # alg:none bypass is always generated as attack evidence
    none_finding = check_alg_none_bypass(payload)
    findings.append(none_finding)
    result["forged_alg_none_token"] = none_finding.get("forged_token")

    result["findings"] = findings

    logger.info("[JWT] %d finding(s) — protocol=%s", len(findings), protocol)

    return result


# ─────────────────────────────────────────────────────────────
# CONSOLE OUTPUT (used by main.py)
# ─────────────────────────────────────────────────────────────

def print_jwt_findings(result: dict) -> None:
    """
    Prints a structured JWT analysis summary to stdout.

    Called by main.py after analyse_jwt() returns.
    """
    if result["status"] == "error":
        print(f"\n[JWT] ERROR: {result['error']}")
        return

    sev_icon = {
        "Critical":      "[CRITICAL]",
        "High":          "[HIGH]    ",
        "Medium":        "[MEDIUM]  ",
        "Low":           "[LOW]     ",
        "Informational": "[INFO]    ",
    }

    print(f"\n{'=' * 60}")
    print(f"  JWT Security Analysis  [{result['protocol']}]")
    print(f"{'=' * 60}")
    print(f"  alg   : {result['header'].get('alg', 'N/A')}")
    print(f"  typ   : {result['header'].get('typ', 'N/A')}")
    print(f"  claims: {list(result['payload'].keys())}")

    exp = result["payload"].get("exp")
    if exp:
        remaining = exp - int(time.time())
        if remaining > 0:
            hrs = remaining // 3600
            print(f"  expiry: {hrs}h {(remaining % 3600)//60}m remaining")
        else:
            print(f"  expiry: EXPIRED {abs(remaining) // 60} minutes ago")
    else:
        print(f"  expiry: NONE — token never expires!")

    print(f"\n  Findings ({len(result['findings'])}):")
    for i, f in enumerate(result["findings"], 1):
        icon = sev_icon.get(f["severity"], "[?]")
        print(f"\n  {i}. {icon} {f['check']}")
        print(f"       OWASP : {f['owasp']}")
        print(f"       Detail: {f['description']}")
        print(f"       Fix   : {f['remediation']}")
    print()
