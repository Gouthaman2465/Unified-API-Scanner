# utils/helpers.py
"""
Utility helpers for Aegis-API.

Sections:
    1. OWASP API Top 10 Mappings
    2. Dynamic CVSS v3.1 Scoring Engine      ← Phase 16
    3. Default Wordlists
    4. Wordlist Loader
    5. Parameter Candidate Builder           ← Phase 15
    6. General Utilities
"""

import math
import sys
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ============================================================
# SECTION 1 — OWASP API TOP 10 MAPPINGS
# ============================================================

OWASP_MAP = {
    "API1": {
        "id": "API1:2023",
        "name": "Broken Object Level Authorization (BOLA/IDOR)",
        "description": (
            "APIs fail to verify that the requesting user has permission "
            "to access the requested object."
        ),
    },
    "API2": {
        "id": "API2:2023",
        "name": "Broken Authentication",
        "description": (
            "Authentication mechanisms are implemented incorrectly or missing."
        ),
    },
    "API3": {
        "id": "API3:2023",
        "name": "Broken Object Property Level Authorization",
        "description": (
            "APIs expose more object properties than the user should access "
            "(Mass Assignment / Excessive Data Exposure)."
        ),
    },
    "API4": {
        "id": "API4:2023",
        "name": "Unrestricted Resource Consumption",
        "description": (
            "APIs do not limit client consumption of resources such as "
            "network, CPU, memory, or storage."
        ),
    },
    "API5": {
        "id": "API5:2023",
        "name": "Broken Function Level Authorization",
        "description": (
            "APIs expose administrative or privileged functions "
            "to unauthorized users."
        ),
    },
    "API6": {
        "id": "API6:2023",
        "name": "Unrestricted Access to Sensitive Business Flows",
        "description": (
            "APIs expose business flows without restricting "
            "automated abuse or excessive usage."
        ),
    },
    "API7": {
        "id": "API7:2023",
        "name": "Server Side Request Forgery (SSRF) / Security Misconfiguration",
        "description": (
            "APIs are misconfigured in ways that expose sensitive information "
            "or allow unintended access."
        ),
    },
    "API8": {
        "id": "API8:2023",
        "name": "Security Misconfiguration",
        "description": (
            "APIs and supporting systems are insecurely configured."
        ),
    },
    "API9": {
        "id": "API9:2023",
        "name": "Improper Inventory Management",
        "description": (
            "Deprecated, unmanaged, or undocumented API versions "
            "increase attack surface."
        ),
    },
    "API10": {
        "id": "API10:2023",
        "name": "Unsafe Consumption of APIs",
        "description": (
            "APIs trust external services without proper validation "
            "or sanitization."
        ),
    },
}


def map_owasp(category_key: str) -> dict:
    """
    Returns the OWASP API Top 10 entry for the given key.

    Example:
        map_owasp("API1")
    """
    return OWASP_MAP.get(
        category_key,
        {
            "id": "UNKNOWN",
            "name": "Uncategorized",
            "description": "No OWASP mapping available.",
        },
    )


# ============================================================
# SECTION 2 — DYNAMIC CVSS v3.1 SCORING ENGINE
#
# Replaces the old additive calculate_cvss() approximation.
# Implements the official CVSS v3.1 base score formula from:
# https://www.first.org/cvss/v3.1/specification-document
#
# All scanner modules must call compute_cvss_score() or one
# of the convenience wrappers below instead of hardcoding scores.
# ============================================================

# ── Severity label enum ────────────────────────────────────
# Using an Enum prevents typos like "critical" vs "Critical"
# scattered across the codebase.

class Severity(Enum):
    CRITICAL      = "Critical"
    HIGH          = "High"
    MEDIUM        = "Medium"
    LOW           = "Low"
    INFORMATIONAL = "Informational"


# ── Finding context dataclass ──────────────────────────────
# Every scanner module creates one of these and passes it to
# compute_cvss_score(). This replaces loose function arguments
# with a typed, documented contract.

@dataclass
class FindingContext:
    """
    Describes the context of a discovered vulnerability.
    Used to compute a dynamic CVSS v3.1 base score.

    Attributes:
        protocol             : "REST", "SOAP", or "GRAPHQL"
        vuln_type            : Short identifier e.g. "idor", "xxe", "jwt_none_alg"
        auth_required        : True if the endpoint requires authentication to exploit
        data_exposed         : Category of exposed data — see _DATA_TO_CONFIDENTIALITY
        privilege_escalation : True if the attacker can gain elevated access
        attack_complexity    : "low" = trivial to exploit; "high" = conditions must align
        network_accessible   : True if reachable from the internet (default: True)
        user_interaction     : True if a victim must take an action (rare in API vulns)
        affects_availability : True if the attack can crash or degrade the service
    """
    protocol:             str
    vuln_type:            str
    auth_required:        bool
    data_exposed:         str    # "credentials" | "pii" | "schema" | "internal_paths" | "none"
    privilege_escalation: bool
    attack_complexity:    str    # "low" | "high"
    network_accessible:   bool = True
    user_interaction:     bool = False
    affects_availability: bool = False


# ── CVSS v3.1 metric weight tables ────────────────────────
# These values come directly from the official specification.
# Do not modify — they are internationally standardised.

_AV_WEIGHTS = {
    "network":  0.85,   # Attacker is on the internet
    "adjacent": 0.62,   # Attacker must be on the same network segment
    "local":    0.55,   # Attacker needs a local shell or GUI session
    "physical": 0.20,   # Attacker requires physical hardware access
}

_AC_WEIGHTS = {
    "low":  0.77,   # No special conditions required to exploit
    "high": 0.44,   # Exploit requires conditions outside attacker's control
}

# Scope Unchanged weights (API vulnerabilities almost never change scope)
_PR_WEIGHTS = {
    "none": 0.85,   # No account needed at all
    "low":  0.62,   # Normal authenticated user account is sufficient
    "high": 0.27,   # Administrative or privileged account required
}

_UI_WEIGHTS = {
    "none":     1.0,    # Attacker acts alone — no victim interaction required
    "required": 0.85,   # A victim must perform an action for the exploit to work
}

_CIA_WEIGHTS = {
    "none": 0.0,
    "low":  0.22,
    "high": 0.56,
}

# Maps the data_exposed field to a CVSS Confidentiality impact level.
# Credentials and PII are the most sensitive data an API can leak.
_DATA_TO_CONFIDENTIALITY = {
    "credentials":    "high",   # Passwords, session tokens, API keys
    "pii":            "high",   # Names, emails, addresses, national IDs
    "financial_data": "high",   # Card numbers, bank details
    "internal_paths": "low",    # File paths, server names revealed in errors
    "schema":         "low",    # GraphQL schema dump or WSDL structure
    "none":           "none",   # No sensitive data exposed directly
}


# ── Core formula helpers ───────────────────────────────────

def _round_up(value: float) -> float:
    """
    CVSS requires ceiling rounding to one decimal place.
    This is NOT standard Python rounding.
    Example: 4.02 → 4.1 (not 4.0)
    """
    return math.ceil(value * 10) / 10


def _compute_base_score(
    av: float, ac: float, pr: float, ui: float,
    c: float, i: float, a: float,
) -> float:
    """
    Applies the CVSS v3.1 base score formula.
    Scope is treated as Unchanged, which is correct for API vulnerabilities.

    Formula source:
        ISS  = 1 - [(1 - C) × (1 - I) × (1 - A)]
        Impact       = 6.42 × ISS                   (Scope Unchanged)
        Exploitability = 8.22 × AV × AC × PR × UI
        BaseScore    = round_up(min(Impact + Exploitability, 10))
    """
    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    impact         = 6.42 * iss if iss > 0 else 0.0
    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0

    return _round_up(min(impact + exploitability, 10.0))


# ── CVSS vector string builder ─────────────────────────────

def _build_vector_string(
    av: str, ac: str, pr: str,
    ui_required: bool, c: str, i: str, a: str,
) -> str:
    """
    Produces a standardised CVSS v3.1 vector string.
    Example: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N
    """
    av_map = {"network": "N", "adjacent": "A", "local": "L", "physical": "P"}
    lh_map = {"none": "N", "low": "L", "high": "H"}

    return (
        f"CVSS:3.1"
        f"/AV:{av_map.get(av, 'N')}"
        f"/AC:{lh_map.get(ac, 'L')}"
        f"/PR:{lh_map.get(pr, 'N')}"
        f"/UI:{'R' if ui_required else 'N'}"
        f"/S:U"
        f"/C:{lh_map.get(c, 'N')}"
        f"/I:{lh_map.get(i, 'N')}"
        f"/A:{lh_map.get(a, 'N')}"
    )


# ── Plain English justification builder ───────────────────

def _build_justification(
    ctx: FindingContext, score: float, severity: Severity,
) -> str:
    """
    Returns a one-paragraph plain English explanation of the score.
    This text is printed in PDF reports alongside the CVSS vector.
    """
    parts = [
        f"This {ctx.protocol} finding ({ctx.vuln_type}) scored "
        f"{score} ({severity.value})."
    ]

    if not ctx.auth_required:
        parts.append("No authentication is required to exploit this vulnerability.")
    else:
        parts.append("Exploitation requires a valid user account (low privileges).")

    if ctx.data_exposed in ("credentials", "pii", "financial_data"):
        parts.append(
            f"The attack exposes {ctx.data_exposed}, "
            f"resulting in High confidentiality impact."
        )
    elif ctx.data_exposed in ("schema", "internal_paths"):
        parts.append(
            f"The attack exposes {ctx.data_exposed} (Low confidentiality impact)."
        )

    if ctx.privilege_escalation:
        parts.append(
            "Successful exploitation enables privilege escalation, "
            "raising integrity impact to High."
        )

    if ctx.attack_complexity == "high":
        parts.append(
            "The exploit requires specific conditions to succeed, "
            "which reduces the overall score."
        )

    if ctx.affects_availability:
        parts.append(
            "The attack can degrade or crash the service "
            "(Low availability impact)."
        )

    return " ".join(parts)


# ── Score → severity label ─────────────────────────────────

def _score_to_severity(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    elif score >= 7.0:
        return Severity.HIGH
    elif score >= 4.0:
        return Severity.MEDIUM
    elif score > 0.0:
        return Severity.LOW
    else:
        return Severity.INFORMATIONAL


# ── Public API ─────────────────────────────────────────────

def compute_cvss_score(ctx: FindingContext) -> dict:
    """
    Computes a dynamic CVSS v3.1 base score for a finding.

    This is the function all scanner modules should call.

    Args:
        ctx: FindingContext describing the vulnerability's context.

    Returns:
        {
            "score":         float   — 0.0 to 10.0
            "severity":      Severity enum value
            "label":         str     — human-readable severity
            "vector":        str     — CVSS:3.1/AV:N/AC:L/...
            "justification": str     — plain English explanation
        }
    """
    # Attack Vector: network-accessible APIs are the most dangerous
    av_key = "network" if ctx.network_accessible else "local"
    av     = _AV_WEIGHTS[av_key]

    # Attack Complexity
    ac_key = ctx.attack_complexity.lower()
    ac     = _AC_WEIGHTS.get(ac_key, _AC_WEIGHTS["low"])

    # Privileges Required: unauthenticated = None, authenticated = Low
    pr_key = "none" if not ctx.auth_required else "low"
    pr     = _PR_WEIGHTS[pr_key]

    # User Interaction: almost always None for API vulnerabilities
    ui = _UI_WEIGHTS["required"] if ctx.user_interaction else _UI_WEIGHTS["none"]

    # Confidentiality impact derived from what data was exposed
    c_key = _DATA_TO_CONFIDENTIALITY.get(ctx.data_exposed, "none")
    c     = _CIA_WEIGHTS[c_key]

    # Integrity impact: privilege escalation = attacker can modify data
    i_key = "high" if ctx.privilege_escalation else "low"
    i     = _CIA_WEIGHTS[i_key]

    # Availability impact: denial-of-service capability
    a_key = "low" if ctx.affects_availability else "none"
    a     = _CIA_WEIGHTS[a_key]

    score    = _compute_base_score(av, ac, pr, ui, c, i, a)
    severity = _score_to_severity(score)
    vector   = _build_vector_string(av_key, ac_key, pr_key, ctx.user_interaction, c_key, i_key, a_key)
    justification = _build_justification(ctx, score, severity)

    return {
        "score":         score,
        "severity":      severity,
        "label":         severity.value,
        "vector":        vector,
        "justification": justification,
    }


# ── Convenience wrappers ───────────────────────────────────
# One wrapper per scanner module. Import these instead of
# constructing FindingContext manually every time.

def score_idor(auth_required: bool, data_exposed: str = "pii") -> dict:
    """REST IDOR/BOLA — OWASP API1"""
    return compute_cvss_score(FindingContext(
        protocol="REST",
        vuln_type="idor",
        auth_required=auth_required,
        data_exposed=data_exposed,
        privilege_escalation=False,
        attack_complexity="low",
    ))


def score_mass_assignment(auth_required: bool, escalation: bool = False) -> dict:
    """REST Mass Assignment — OWASP API3"""
    return compute_cvss_score(FindingContext(
        protocol="REST",
        vuln_type="mass_assignment",
        auth_required=auth_required,
        data_exposed="pii" if escalation else "none",
        privilege_escalation=escalation,
        attack_complexity="low",
    ))


def score_xxe(auth_required: bool = False) -> dict:
    """SOAP XXE Injection — OWASP API8"""
    return compute_cvss_score(FindingContext(
        protocol="SOAP",
        vuln_type="xxe",
        auth_required=auth_required,
        data_exposed="internal_paths",
        privilege_escalation=False,
        attack_complexity="low",
        affects_availability=True,
    ))


def score_wsdl_exposure() -> dict:
    """SOAP WSDL Exposed — OWASP API7"""
    return compute_cvss_score(FindingContext(
        protocol="SOAP",
        vuln_type="wsdl_exposure",
        auth_required=False,
        data_exposed="schema",
        privilege_escalation=False,
        attack_complexity="low",
    ))


def score_graphql_introspection() -> dict:
    """GraphQL Introspection Enabled — OWASP API7"""
    return compute_cvss_score(FindingContext(
        protocol="GRAPHQL",
        vuln_type="introspection_enabled",
        auth_required=False,
        data_exposed="schema",
        privilege_escalation=False,
        attack_complexity="low",
    ))


def score_graphql_depth_attack() -> dict:
    """GraphQL Depth Limit Missing — OWASP API4"""
    return compute_cvss_score(FindingContext(
        protocol="GRAPHQL",
        vuln_type="depth_limit_missing",
        auth_required=False,
        data_exposed="none",
        privilege_escalation=False,
        attack_complexity="low",
        affects_availability=True,
    ))


def score_graphql_batch_abuse(auth_required: bool = False) -> dict:
    """GraphQL Batching / Alias Rate-Limit Bypass — OWASP API4"""
    return compute_cvss_score(FindingContext(
        protocol="GRAPHQL",
        vuln_type="batch_abuse",
        auth_required=auth_required,
        data_exposed="credentials" if not auth_required else "none",
        privilege_escalation=not auth_required,
        attack_complexity="low",
        affects_availability=True,
    ))


def score_jwt_none_alg() -> dict:
    """JWT alg:none bypass — OWASP API2"""
    return compute_cvss_score(FindingContext(
        protocol="REST",
        vuln_type="jwt_none_alg",
        auth_required=False,   # alg:none bypasses authentication entirely
        data_exposed="credentials",
        privilege_escalation=True,
        attack_complexity="low",
    ))


def score_jwt_weak_secret() -> dict:
    """JWT weak HMAC secret — OWASP API2"""
    return compute_cvss_score(FindingContext(
        protocol="REST",
        vuln_type="jwt_weak_secret",
        auth_required=False,
        data_exposed="credentials",
        privilege_escalation=True,
        attack_complexity="high",  # Requires offline brute-force effort
    ))


def score_rate_limit_missing(auth_required: bool = False) -> dict:
    """REST rate limit absent — OWASP API4"""
    return compute_cvss_score(FindingContext(
        protocol="REST",
        vuln_type="rate_limit_missing",
        auth_required=auth_required,
        data_exposed="none",
        privilege_escalation=False,
        attack_complexity="low",
        affects_availability=True,
    ))


def score_ws_security_missing() -> dict:
    """SOAP WS-Security header absent — OWASP API2"""
    return compute_cvss_score(FindingContext(
        protocol="SOAP",
        vuln_type="ws_security_missing",
        auth_required=False,
        data_exposed="credentials",
        privilege_escalation=True,
        attack_complexity="low",
    ))


# ── Backwards-compatibility shim ──────────────────────────
# The old calculate_cvss() is kept so any existing scanner
# modules that still call it do not break.
# Remove this after all scanners are updated to use
# compute_cvss_score() or the convenience wrappers above.

def calculate_cvss(
    protocol: str,
    auth_required: bool,
    data_exposed: str,
    privilege_escalation: bool,
    attack_complexity: str = "Low",
) -> dict:
    """
    Deprecated. Use compute_cvss_score() instead.

    This shim translates the old additive arguments into a
    FindingContext and forwards to the real formula.
    Retained so existing scanner modules do not break.
    """
    # Normalise the old data_exposed vocabulary to the new one
    _legacy_data_map = {
        "service_contract":    "schema",
        "admin_operation_name":"schema",
        "object_reference":    "pii",
        "file_content":        "internal_paths",
        "credentials":         "credentials",
        "pii":                 "pii",
        "financial_data":      "financial_data",
        "tokens":              "credentials",
    }
    normalised_data = _legacy_data_map.get(data_exposed, "none")

    ctx = FindingContext(
        protocol=protocol,
        vuln_type="legacy_call",
        auth_required=auth_required,
        data_exposed=normalised_data,
        privilege_escalation=privilege_escalation,
        attack_complexity=attack_complexity.lower(),
    )
    result = compute_cvss_score(ctx)

    # Return the same keys the old function returned so callers
    # do not need changing yet.
    return {
        "score":         result["score"],
        "severity":      result["label"],
        "justification": result["justification"],
    }


# ============================================================
# SECTION 3 — DEFAULT WORDLISTS
# ============================================================

# Common numeric object identifiers used in labs such as crAPI
DEFAULT_ID_WORDLIST = [
    "1", "2", "3", "4", "5",
    "10", "20", "50", "100",
]

# Common mass-assignment / privilege-related parameters
DEFAULT_PARAM_WORDLIST = [
    "role",
    "is_admin",
    "admin",
    "access_level",
    "credit",
    "isAdmin",
]


# ============================================================
# SECTION 4 — WORDLIST LOADER
# ============================================================

def load_wordlist(filepath, default):
    """
    Loads a wordlist from a plain-text file (one entry per line).

    Falls back to the provided default list if:
        - filepath is None
        - the file does not exist
        - the file is empty
        - the file cannot be read

    Args:
        filepath (str | None): Path to wordlist file.
        default  (list):       Default fallback list.

    Returns:
        list: Loaded entries.
    """
    if filepath is None:
        print(
            f"[*] No wordlist file provided. "
            f"Using built-in default ({len(default)} entries)."
        )
        return default

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            entries = [line.strip() for line in f if line.strip()]

        if not entries:
            print(
                f"[!] Wordlist file '{filepath}' is empty. "
                f"Falling back to default."
            )
            return default

        print(f"[+] Loaded {len(entries)} entries from '{filepath}'.")
        return entries

    except FileNotFoundError:
        print(
            f"[-] Wordlist file not found: '{filepath}'. "
            f"Falling back to default."
        )
        return default

    except IOError as e:
        print(
            f"[-] Error reading '{filepath}': {e}. "
            f"Falling back to default."
        )
        return default


# ============================================================
# SECTION 5 — PARAMETER CANDIDATE BUILDER   (Phase 15)
# ============================================================

def build_param_candidate_list(
    discovered: list,
    wordlist: list,
    override: bool = False,
    protocol: str = "GraphQL",
    user_wordlist_path: str = None,
) -> list:
    """
    Unified parameter list builder.

    Priority rules:
        1. If override=True (user passed -p flag), use the file wordlist only.
        2. Otherwise, merge schema-discovered params with the default wordlist,
           deduplicated, and return the enriched list.

    Args:
        discovered        : params auto-discovered from the API spec or schema
        wordlist          : default wordlist (DEFAULT_PARAM_WORDLIST)
        override          : True if user explicitly supplied -p flag
        protocol          : "REST", "SOAP", or "GraphQL" (used for logging)
        user_wordlist_path: path to -p file, or None

    Returns:
        Final deduplicated list of parameter name strings.
    """
    if override and user_wordlist_path:
        try:
            with open(user_wordlist_path, "r") as fh:
                custom = [line.strip() for line in fh if line.strip()]
            print(
                f"[+] [{protocol}] Using user-supplied parameter wordlist: "
                f"{len(custom)} entries from '{user_wordlist_path}'."
            )
            return custom
        except FileNotFoundError:
            print(
                f"[!] [{protocol}] Could not open wordlist '{user_wordlist_path}'. "
                f"Falling back to auto-discovery merge."
            )

    merged    = list(set(discovered or []) | set(wordlist or []))
    new_count = len(set(discovered or []) - set(wordlist or []))

    if new_count > 0:
        new_params = ", ".join(set(discovered or []) - set(wordlist or []))
        print(
            f"[+] [{protocol}] Parameter discovery enriched the wordlist with "
            f"{new_count} schema-specific param(s): {new_params}."
        )
    else:
        print(
            f"[*] [{protocol}] No new schema params found; "
            f"using default wordlist ({len(merged)} entries)."
        )

    return merged


# ============================================================
# SECTION 6 — GENERAL UTILITIES
# ============================================================

def safe_get(dictionary, key, default=None):
    """
    Safely fetches a key from a dictionary.
    Returns default if the input is not a dict or key is absent.
    """
    if not isinstance(dictionary, dict):
        return default
    return dictionary.get(key, default)


def print_banner(title: str):
    """
    Prints a formatted section banner to stdout.

    Example output:
        ========
        TITLE
        ========
    """
    line = "=" * len(title)
    print(f"\n{line}")
    print(title)
    print(f"{line}\n")


def exit_error(message: str, code: int = 1):
    """
    Prints an error message and exits the process.

    Args:
        message (str): Error description.
        code    (int): Exit code (default 1).
    """
    print(f"[-] {message}")
    sys.exit(code)
    
    
    
    
# ============================================================
# SECTION 7 — OWASP API TOP 10 MAPPING ENGINE          Phase 17
#
# Connects every scanner finding to the correct OWASP API
# Security Top 10 (2023) category, with protocol-aware
# context explaining HOW the vulnerability manifests in
# REST vs SOAP vs GraphQL.
#
# Public functions:
#   tag_finding_with_owasp()     ← enriches one finding dict
#   build_owasp_coverage_table() ← produces report summary
# ============================================================


# ── Mapping: vuln_type → OWASP API category key ───────────
# Every vuln_type string used across all scanner modules must
# have an entry here. Add new entries as new modules are built.
# Keys match the vuln_type field in FindingContext (Section 2).

VULN_TO_OWASP_KEY = {
    # REST scanners
    "idor":                "API1",
    "mass_assignment":     "API3",
    "rate_limit_missing":  "API4",
    "jwt_none_alg":        "API2",
    "jwt_weak_secret":     "API2",
    "jwt_missing_exp":     "API2",
    "jwt_sensitive_claim": "API2",

    # SOAP scanners
    "wsdl_exposure":       "API8",
    "xxe":                 "API8",
    "xml_injection":       "API8",
    "ws_security_missing": "API2",

    # GraphQL scanners
    "introspection_enabled": "API8",
    "depth_limit_missing":   "API4",
    "field_auth_bypass":     "API1",
    "batch_abuse":           "API4",

    # Shared / legacy
    "legacy_call":         "API8",
}


# ── Protocol-aware context strings ────────────────────────
# Same OWASP category, different mechanism per protocol.
# These short sentences appear in PDF reports under the
# OWASP section so reviewers understand the protocol-specific risk.
#
# Key structure: (protocol_uppercase, vuln_type)
#
# Protocols are stored in uppercase to match FindingContext.protocol.

PROTOCOL_OWASP_CONTEXT = {
    # ── API1: BOLA / IDOR ──────────────────────────────────
    ("REST",    "idor"): (
        "REST: Attacker increments or fuzzes a numeric object ID in the URL "
        "path (e.g. /api/users/1235/orders) to access another user's resources."
    ),
    ("GRAPHQL", "idor"): (
        "GraphQL: Attacker changes the id argument in a query field "
        "(e.g. user(id: \"1235\")) to retrieve data belonging to another user."
    ),
    ("SOAP",    "idor"): (
        "SOAP: Attacker modifies the object identifier inside the XML request body "
        "(e.g. <userId>1235</userId>) to retrieve another user's records."
    ),
    ("GRAPHQL", "field_auth_bypass"): (
        "GraphQL: Attacker requests sensitive fields (role, isAdmin, email) "
        "that the schema exposes but the resolver fails to protect "
        "at the field level, returning data the user is not authorised to see."
    ),

    # ── API2: Broken Authentication ────────────────────────
    ("REST",    "jwt_none_alg"): (
        "REST: The server accepts a JWT token with alg:none in the header, "
        "meaning the signature is not verified. Attacker forges an arbitrary "
        "identity claim without knowing any secret."
    ),
    ("GRAPHQL", "jwt_none_alg"): (
        "GraphQL: JWT passed via Authorization or X-Auth-Token header is accepted "
        "with alg:none, allowing identity forgery on any GraphQL mutation or query "
        "that requires authentication."
    ),
    ("REST",    "jwt_weak_secret"): (
        "REST: The HMAC secret used to sign JWT tokens is short or common, "
        "allowing offline brute-force to recover the secret and forge tokens."
    ),
    ("GRAPHQL", "jwt_weak_secret"): (
        "GraphQL: Same as REST — weak HMAC secret on JWT allows forged tokens "
        "to be used in GraphQL authenticated queries and mutations."
    ),
    ("REST",    "jwt_missing_exp"): (
        "REST: JWT token has no exp (expiration) claim, meaning stolen tokens "
        "remain valid indefinitely — there is no natural token rotation."
    ),
    ("REST",    "jwt_sensitive_claim"): (
        "REST: JWT payload contains sensitive data (passwords, PII, internal IDs) "
        "that is Base64-encoded but not encrypted — readable by anyone who "
        "intercepts the token."
    ),
    ("SOAP",    "ws_security_missing"): (
        "SOAP: The WS-Security header is absent from the SOAP envelope. "
        "This header carries authentication tokens and message signing for SOAP. "
        "Without it, any caller can invoke operations as an anonymous user."
    ),

    # ── API3: Mass Assignment ──────────────────────────────
    ("REST",    "mass_assignment"): (
        "REST: Attacker adds unexpected fields to a PUT or PATCH request body "
        "(e.g. role, isAdmin) that the server binds directly to the object model, "
        "silently escalating privileges or corrupting data."
    ),
    ("GRAPHQL", "mass_assignment"): (
        "GraphQL: Attacker injects extra input arguments into a mutation "
        "(e.g. updateUser(role: \"admin\")) that the resolver passes directly "
        "to the data layer without validating the caller's right to set those fields."
    ),

    # ── API4: Resource Consumption ─────────────────────────
    ("REST",    "rate_limit_missing"): (
        "REST: The endpoint returns HTTP 200 for every request regardless of "
        "request volume. No HTTP 429 is returned. Attacker can brute-force "
        "credentials, enumerate IDs, or flood the server without restriction."
    ),
    ("GRAPHQL", "depth_limit_missing"): (
        "GraphQL: Server processes arbitrarily deep nested queries without error. "
        "A deeply nested query (depth 15–20) can trigger exponential resolver calls, "
        "exhausting CPU and memory and causing denial of service."
    ),
    ("GRAPHQL", "batch_abuse"): (
        "GraphQL: Server processes a batched request containing many operations "
        "or aliased queries in a single HTTP request. Attacker uses aliases to "
        "send 50+ login attempts counted as one request by rate limiters."
    ),

    # ── API8: Security Misconfiguration ───────────────────
    ("SOAP",    "wsdl_exposure"): (
        "SOAP: The WSDL file is publicly accessible at ?wsdl without authentication. "
        "WSDL is the complete blueprint of all operations, parameters, and endpoints. "
        "Exposing it reduces attacker reconnaissance effort to zero."
    ),
    ("SOAP",    "xxe"): (
        "SOAP: The XML parser processes a DOCTYPE declaration containing an "
        "external entity reference, allowing the attacker to read local files "
        "(e.g. /etc/passwd), internal network URLs, or cause denial of service "
        "via entity expansion (Billion Laughs attack)."
    ),
    ("SOAP",    "xml_injection"): (
        "SOAP: Unsanitised user input inside the SOAP XML body allows injection "
        "of additional XML elements or attributes, manipulating the operation's "
        "behaviour or bypassing input validation."
    ),
    ("GRAPHQL", "introspection_enabled"): (
        "GraphQL: The introspection query is enabled in production. Introspection "
        "returns the complete API schema — every type, query, mutation, and field. "
        "This removes all reconnaissance effort for an attacker."
    ),
    ("REST",    "legacy_call"): (
        "REST: A legacy scanner finding without specific OWASP context. "
        "Review the finding description for details."
    ),
}


# ── Coverage matrix: which OWASP categories each protocol covers ──
# This defines the authoritative list of what Aegis-API tests per protocol.
# Used to generate the coverage table in PDF reports and the README.
#
# Structure: { "PROTOCOL": { "OWASP_KEY": [list of vuln_types tested] } }
#
# Only vuln_types that are fully implemented should appear here.
# Add entries as new scanner modules are completed.

PROTOCOL_COVERAGE = {
    "REST": {
        "API1": ["idor"],
        "API2": ["jwt_none_alg", "jwt_weak_secret", "jwt_missing_exp", "jwt_sensitive_claim"],
        "API3": ["mass_assignment"],
        "API4": ["rate_limit_missing"],
    },
    "SOAP": {
        "API2": ["ws_security_missing"],
        "API8": ["wsdl_exposure", "xxe", "xml_injection"],
    },
    "GRAPHQL": {
        "API1": ["field_auth_bypass"],
        "API2": ["jwt_none_alg", "jwt_weak_secret"],
        "API3": ["mass_assignment"],
        "API4": ["depth_limit_missing", "batch_abuse"],
        "API8": ["introspection_enabled"],
    },
}


# ── Public function 1: enrich a single finding ─────────────

def tag_finding_with_owasp(finding: dict) -> dict:
    """
    Enriches a finding dictionary with OWASP API Top 10 data.

    Call this in every scanner module just before appending
    a finding to the results list. It adds four new keys:

        owasp_id          — e.g. "API1:2023"
        owasp_name        — e.g. "Broken Object Level Authorization (BOLA/IDOR)"
        owasp_description — general description from OWASP_MAP
        protocol_context  — protocol-specific explanation of the mechanism

    The function reads two keys that every finding dict must
    already contain:
        "vuln_type"  — e.g. "idor", "xxe", "jwt_none_alg"
        "protocol"   — e.g. "REST", "SOAP", "GRAPHQL"

    If either key is missing the function returns the finding
    unchanged with an UNKNOWN OWASP tag rather than crashing.

    Args:
        finding: A finding dict produced by any scanner module.

    Returns:
        The same dict with OWASP fields added (mutated in-place
        AND returned for chaining convenience).

    Example:
        finding = {
            "protocol": "REST",
            "vuln_type": "idor",
            "url": "http://target/api/users/1234",
            "score": 8.5,
        }
        finding = tag_finding_with_owasp(finding)
        # finding["owasp_id"] → "API1:2023"
    """
    vuln_type = finding.get("vuln_type", "").lower()
    protocol  = finding.get("protocol",  "").upper()

    # Look up which OWASP category this vulnerability belongs to
    owasp_key = VULN_TO_OWASP_KEY.get(vuln_type, None)

    if owasp_key is None:
        # Vuln type is not in the map — do not crash; tag as unknown
        finding.update({
            "owasp_id":          "UNKNOWN",
            "owasp_name":        "Uncategorised",
            "owasp_description": (
                f"No OWASP mapping found for vuln_type='{vuln_type}'. "
                f"Add it to VULN_TO_OWASP_KEY in utils/helpers.py."
            ),
            "protocol_context":  "No protocol context available.",
        })
        return finding

    # Retrieve the full OWASP entry from OWASP_MAP (Section 1)
    owasp_entry = map_owasp(owasp_key)

    # Retrieve the protocol-specific context sentence
    context_key     = (protocol, vuln_type)
    protocol_context = PROTOCOL_OWASP_CONTEXT.get(
        context_key,
        (
            f"{protocol}: No specific context defined for '{vuln_type}'. "
            f"Refer to {owasp_entry['id']} in the OWASP API Security Top 10."
        ),
    )

    finding.update({
        "owasp_id":          owasp_entry["id"],
        "owasp_name":        owasp_entry["name"],
        "owasp_description": owasp_entry["description"],
        "protocol_context":  protocol_context,
    })

    return finding


# ── Public function 2: build coverage summary for reports ─

def build_owasp_coverage_table(protocols_tested: list) -> dict:
    """
    Builds an OWASP coverage summary for the PDF report and README.

    Returns a nested dict describing which OWASP API categories
    were tested per protocol during this scan run.

    Args:
        protocols_tested: List of protocol strings that were scanned,
                          e.g. ["REST", "GRAPHQL"] or ["REST", "SOAP", "GRAPHQL"]

    Returns:
        {
            "REST": {
                "API1": {"status": "tested",   "vuln_types": ["idor"]},
                "API2": {"status": "tested",   "vuln_types": [...]},
                "API8": {"status": "not_tested", "vuln_types": []},
                ...
            },
            "GRAPHQL": { ... },
            ...
        }

    The report generator uses "status" to colour rows in the
    coverage table: green = tested, grey = not tested.

    Example usage in utils/reporting.py:
        table = build_owasp_coverage_table(["REST", "SOAP", "GRAPHQL"])
        for protocol, categories in table.items():
            for owasp_key, info in categories.items():
                print(protocol, owasp_key, info["status"])
    """
    # All possible OWASP keys in the 2023 list
    all_owasp_keys = [f"API{n}" for n in range(1, 11)]

    coverage_table = {}

    for protocol in protocols_tested:
        protocol_upper = protocol.upper()

        # What this protocol actually covers (from PROTOCOL_COVERAGE)
        protocol_coverage = PROTOCOL_COVERAGE.get(protocol_upper, {})

        protocol_table = {}
        for owasp_key in all_owasp_keys:
            vuln_types_tested = protocol_coverage.get(owasp_key, [])
            protocol_table[owasp_key] = {
                "owasp_id":    OWASP_MAP.get(owasp_key, {}).get("id",   owasp_key),
                "owasp_name":  OWASP_MAP.get(owasp_key, {}).get("name", "Unknown"),
                "status":      "tested" if vuln_types_tested else "not_tested",
                "vuln_types":  vuln_types_tested,
            }

        coverage_table[protocol_upper] = protocol_table

    return coverage_table


# ── Public function 3: filter findings by OWASP category ──

def get_findings_by_owasp(findings: list, owasp_key: str) -> list:
    """
    Filters a flat list of enriched findings by OWASP category.

    Use in reporting.py to group findings under OWASP headings
    in Section 3 (Detailed Findings) of the PDF report.

    Args:
        findings:  List of finding dicts — must already be enriched
                   by tag_finding_with_owasp().
        owasp_key: Category key to filter on, e.g. "API1", "API2".

    Returns:
        Subset of findings whose owasp_id starts with the given key.

    Example:
        api1_findings = get_findings_by_owasp(all_findings, "API1")
    """
    target_id = OWASP_MAP.get(owasp_key, {}).get("id", "")
    return [
        f for f in findings
        if f.get("owasp_id", "").startswith(owasp_key)
    ]


# ── Public function 4: print coverage table to stdout ─────

def print_owasp_coverage_table(protocols_tested: list) -> None:
    """
    Prints a human-readable OWASP coverage table to stdout.

    Called from main.py at the end of a scan to show the user
    which OWASP categories were covered. Also useful for demos.

    Example output:
        OWASP API TOP 10 COVERAGE
        ─────────────────────────────────────────────────────────
        Category   REST         SOAP         GraphQL
        ─────────────────────────────────────────────────────────
        API1       ✓ tested     –            ✓ tested
        API2       ✓ tested     ✓ tested     ✓ tested
        API3       ✓ tested     –            ✓ tested
        API4       ✓ tested     –            ✓ tested
        API5       –            –            –
        ...
    """
    table = build_owasp_coverage_table(protocols_tested)
    all_owasp_keys = [f"API{n}" for n in range(1, 11)]

    # Header
    print("\nOWASP API TOP 10 COVERAGE")
    separator = "─" * (12 + 15 * len(protocols_tested))
    print(separator)

    header = f"{'Category':<10}"
    for p in protocols_tested:
        header += f"  {p.upper():<13}"
    print(header)
    print(separator)

    # Rows
    for owasp_key in all_owasp_keys:
        row = f"{owasp_key:<10}"
        for protocol in protocols_tested:
            protocol_upper = protocol.upper()
            status = table.get(protocol_upper, {}).get(owasp_key, {}).get("status", "not_tested")
            cell = "✓ tested" if status == "tested" else "–"
            row += f"  {cell:<13}"
        print(row)

    print(separator)
    print(f"Protocols scanned: {', '.join(p.upper() for p in protocols_tested)}\n")
