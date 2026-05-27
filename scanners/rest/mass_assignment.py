"""
scanners/rest/mass_assignment.py

OWASP API3 — Broken Object Property Level Authorization
Protocol: REST

Tests whether a REST API endpoint accepts and persists
user-supplied fields that should be server-controlled only.

Method:
  1. GET baseline object state before any injection
  2. PUT with injected privileged fields added to the normal payload
  3. GET the object again after injection
  4. Diff before and after states
  5. Flag as vulnerable only if injected fields persisted
"""

import requests
from utils.logger import log_finding
from utils.helpers import calculate_cvss, map_owasp


# These are fields that normal users should never be able to set.
# If any of these appear in a post-injection response with changed
# values, it is a confirmed mass assignment vulnerability.
PRIVILEGED_FIELD_CANDIDATES = [
    "role", "isAdmin", "is_admin", "admin",
    "balance", "credit", "accountStatus", "account_status",
    "verified", "emailVerified", "email_verified",
    "subscriptionTier", "subscription_tier",
    "permissions", "scope", "accessLevel", "access_level",
]


def flatten_json(obj: dict, parent_key: str = "", sep: str = ".") -> dict:
    """
    Recursively flatten a nested JSON dict into a single-level dict.

    Example:
        {"user": {"role": "admin"}} → {"user.role": "admin"}

    This lets us compare deeply nested fields without recursive logic
    in the diffing step.
    """
    flat = {}
    for key, value in obj.items():
        full_key = f"{parent_key}{sep}{key}" if parent_key else key
        if isinstance(value, dict):
            flat.update(flatten_json(value, full_key, sep))
        else:
            flat[full_key] = value
    return flat


# Fields that contain raw binary/base64 data — useless for diffing,
# destructive to reports. Strip them before storing state.
BINARY_FIELDS = {"profileVideo", "profile_pic_url", "picture_url",
                 "avatar", "thumbnail", "image", "photo", "video_data",
                 "video_url"}  # video_url also contains base64 in crAPI


def get_object_state(session: requests.Session, url: str) -> dict:
    try:
        response = session.get(url, timeout=10)
        response.raise_for_status()
        raw = response.json()
        if isinstance(raw, dict):
            # Strip binary/base64 fields before flattening
            cleaned = {k: v for k, v in raw.items()
                      if k not in BINARY_FIELDS}
            return flatten_json(cleaned)
        return {}
    except (requests.RequestException, ValueError):
        return {}


def build_injection_payload(
    baseline: dict,
    extra_fields: dict | None = None
) -> dict:
    payload = {k.split(".")[-1]: v for k, v in baseline.items()}

    # Inject privileged candidates
    for field in PRIVILEGED_FIELD_CANDIDATES:
        payload[field] = "injected_by_aegis"

    # Also inject a sentinel into writable-looking baseline fields
    # so we can detect if the server accepts writes to them
    SKIP_READONLY = {"id", "profileVideo", "profile_pic_url",
                     "created_at", "authorid", "CreatedAt", "email"}
    for key in list(payload.keys()):
        if key not in SKIP_READONLY and key not in PRIVILEGED_FIELD_CANDIDATES:
            payload[key] = f"aegis_test_{key}"

    if extra_fields:
        payload.update(extra_fields)

    return payload


def diff_states(before: dict, after: dict, injected_keys: list) -> dict:
    changed_fields = {}

    for key in after:
        before_val = before.get(key)
        after_val = after[key]
        if before_val != after_val:
            changed_fields[key] = {
                "before": before_val,
                "after": after_val
            }

    # Count ALL persisted changes — both injected privileged fields
    # AND baseline fields whose sentinel value stuck
    injected_fields_persisted = []
    for k, v in changed_fields.items():
        after_val = v["after"]
        # Matched a privileged candidate
        if any(k.endswith(ik) for ik in injected_keys):
            injected_fields_persisted.append(k)
        # OR it's a baseline field we overwrote with our sentinel
        elif isinstance(after_val, str) and after_val.startswith("aegis_test_"):
            injected_fields_persisted.append(k)

    total_checked = len(injected_keys) + len(
        [k for k in changed_fields if k not in injected_keys]
    )
    if not total_checked:
        confidence_score = 0.0
    else:
        confidence_score = round(
            (len(injected_fields_persisted) / max(len(injected_keys), 1)) * 100, 1
        )

    return {
        "changed_fields": changed_fields,
        "injected_fields_persisted": injected_fields_persisted,
        "confidence_score": confidence_score,
    }


def discover_object_url(session: requests.Session, list_endpoint: str) -> str | None:
    """
    Hit a collection endpoint (e.g. /user/videos) and extract the URL
    of the first object that belongs to the authenticated user.

    Returns the full object URL like /identity/api/v2/user/videos/47,
    or None if the list is empty or non-JSON.
    """
    try:
        response = session.get(list_endpoint, timeout=10)
        response.raise_for_status()
        data = response.json()

        # Handle both list response and wrapped response
        if isinstance(data, list) and data:
            first_item = data[0]
        elif isinstance(data, dict):
            for key in data:
                if isinstance(data[key], list) and data[key]:
                    first_item = data[key][0]
                    break
            else:
                return None
        else:
            return None

        item_id = first_item.get("id")
        if item_id is None:
            return None

        return f"{list_endpoint.rstrip('/')}/{item_id}"

    except (requests.RequestException, ValueError):
        return None


def run_mass_assignment_scan(
    session: requests.Session,
    target_url: str,
    extra_fields: dict | None = None,
) -> list[dict]:
    """
    Main entry point for REST mass assignment scanning.

    Parameters:
        session     : authenticated requests.Session (JWT headers pre-set)
        target_url  : the REST object endpoint, e.g. /api/v2/user/42
        extra_fields: optional dict of extra fields to inject (from -p flag)

    Returns:
        List of finding dicts. Empty list = nothing confirmed.
    """

    findings = []

    print(
        f"[MASS_ASSIGN] Starting state-verified scan on: "
        f"{target_url}"
    )

    # ── STEP 1: Capture baseline state before any injection ──────────────
    print(
        f"[MASS_ASSIGN] Fetching baseline state "
        f"(GET {target_url})"
    )

    baseline_state = get_object_state(
        session,
        target_url
    )

    if not baseline_state:
        print(
            f"[MASS_ASSIGN] Could not read baseline state. "
            f"Skipping {target_url}"
        )
        return findings

    print(
        f"[MASS_ASSIGN] Baseline captured. "
        f"Fields: {list(baseline_state.keys())}"
    )

    # ── STEP 2: Build and send the injection payload ──────────────────────
    payload = build_injection_payload(
        baseline_state,
        extra_fields
    )

    injected_keys = list(PRIVILEGED_FIELD_CANDIDATES)

    if extra_fields:
        injected_keys += list(extra_fields.keys())

    print(
        f"[MASS_ASSIGN] Sending injected PUT/PATCH "
        f"with {len(injected_keys)} extra fields"
    )

    put_response = None

    for method in ["PUT", "PATCH"]:
        try:
            put_response = session.request(
                method,
                target_url,
                json=payload,
                timeout=10
            )

            print(
                f"[MASS_ASSIGN] "
                f"{method} response: "
                f"HTTP {put_response.status_code}"
            )

            if put_response.status_code != 405:
                break

        except requests.RequestException as err:
            print(
                f"[MASS_ASSIGN] "
                f"{method} request failed: {err}"
            )
            return findings

    if put_response is None:
        return findings

    # ── STEP 3: Read state again after injection ──────────────────────────
    print(
        f"[MASS_ASSIGN] Re-fetching state after injection "
        f"(GET {target_url})"
    )

    post_injection_state = get_object_state(
        session,
        target_url
    )

    # DEBUG — shows truncated state so base64 blobs don't flood terminal
    safe_state = {
        k: (v[:80] + "...[truncated]" if isinstance(v, str) and len(v) > 80 else v)
        for k, v in post_injection_state.items()
    }
    print(f"[MASS_ASSIGN-DEBUG] Post-injection raw state: {safe_state}")

    # DEBUG — shows exactly what diff_states will compare
    print(f"[DIFF-DEBUG] before: {baseline_state}")
    print(f"[DIFF-DEBUG] after:  {post_injection_state}")

    if not post_injection_state:
        print(
            f"[MASS_ASSIGN] Could not read post-injection state. "
            f"Cannot confirm finding."
        )
        return findings

    # ── STEP 4: Diff the two states ───────────────────────────────────────
    diff = diff_states(
        baseline_state,
        post_injection_state,
        injected_keys
    )
    # ── RESTORE: Reset server state back to original values ──────────────
    # Without this, the next scan sees our sentinel as the baseline
    # and diff always returns 0%.
    restore_payload = {k.split(".")[-1]: v for k, v in baseline_state.items()}
    try:
        session.request("PUT", target_url, json=restore_payload, timeout=10)
        print(f"[MASS_ASSIGN] State restored to original values.")
    except requests.RequestException:
        print(f"[MASS_ASSIGN] WARNING: Could not restore original state on {target_url}")

    print(
        f"[MASS_ASSIGN] Diff complete. "
        f"Confidence: {diff['confidence_score']}% | "
        f"Persisted fields: "
        f"{diff['injected_fields_persisted']}"
    )

    # ── STEP 5: Build finding only if injection actually persisted ────────
    if diff["injected_fields_persisted"]:

        severity = "High"

        if diff["confidence_score"] >= 80:
            severity = "Critical"

        finding = {
            "title": (
                "Mass Assignment — "
                "Privileged Field Injection Confirmed"
            ),

            "protocol": "REST",

            "owasp": map_owasp("API3"),

            "cvss": calculate_cvss(
                protocol="REST",
                auth_required=True,
                data_exposed=True,
                privilege_escalation=True,
            ),

            "severity": severity,

            "target_url": target_url,

            "confidence_score": diff["confidence_score"],

            "injected_fields_persisted":
                diff["injected_fields_persisted"],

            "changed_fields":
                diff["changed_fields"],

            "put_status_code":
                put_response.status_code,

            "evidence": {
                "baseline_state":
                    baseline_state,

                "injected_payload":
                    payload,

                "post_injection_state":
                    post_injection_state,

                "diff":
                    diff["changed_fields"],
            },

            "remediation": (
                "Implement an explicit allowlist of fields "
                "that users are permitted to update. "
                "Use a DTO (Data Transfer Object) or "
                "serializer that only maps known-safe fields. "
                "Never bind raw request bodies directly "
                "onto ORM models."
            ),
        }

        findings.append(finding)

        log_finding(finding)

        print(
            f"[MASS_ASSIGN] "
            f"*** CONFIRMED VULNERABILITY *** "
            f"Severity: {severity} | "
            f"Fields: "
            f"{diff['injected_fields_persisted']}"
        )

    else:
        print(
            f"[MASS_ASSIGN] No persisted injection detected. "
            f"Server appears to filter privileged fields correctly."
        )

    return findings
