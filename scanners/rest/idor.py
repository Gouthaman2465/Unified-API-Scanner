# scanners/rest/idor.py
# Protocol: REST
# Purpose: Test API endpoints for IDOR (Insecure Direct Object Reference)
#          by comparing authorized vs unauthorized responses using
#          similarity ratio instead of keyword matching.

import requests
import logging
from difflib import SequenceMatcher
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, urlunparse

logger = logging.getLogger(__name__)

# If unauthorized response similarity to authorized response
# exceeds this threshold, we flag it as potential IDOR.
SIMILARITY_THRESHOLD = 0.80

# HTTP status codes that suggest the server enforced authorization correctly
REJECTION_CODES = {401, 403, 404}


def run_idor_scan(
    base_url: str,
    endpoints: List[Dict],
    auth_token: Optional[str],
    session: requests.Session
) -> List[Dict[str, Any]]:
    """
    Main entry point for IDOR scanning.

    For each endpoint that contains an ID parameter:
    1. Fetch the resource as an authenticated user
    2. Fetch the same resource without authentication
    3. Compare responses using similarity ratio
    4. Flag as IDOR if unauthorized response is too similar to authorized one

    endpoints: list of dicts from swagger parser, each with 'path' and 'method'
    auth_token: Bearer token for authenticated requests
    """
    findings = []

    id_endpoints = [e for e in endpoints if contains_id_parameter(e["path"])]
    logger.info(f"Testing {len(id_endpoints)} endpoints with ID parameters for IDOR")

    for endpoint in id_endpoints:
        url = build_test_url(base_url, endpoint["path"])
        if not url:
            continue

        logger.info(f"Testing IDOR on {endpoint['method'].upper()} {url}")

        finding = test_single_endpoint(url, auth_token, session)
        if finding:
            findings.append(finding)

    return findings


def test_single_endpoint(
    url: str,
    auth_token: Optional[str],
    session: requests.Session
) -> Optional[Dict[str, Any]]:
    """
    Test one endpoint for IDOR by comparing
    authenticated vs unauthenticated responses.

    Returns a finding dict if IDOR is detected, None otherwise.
    """
    # Step 1 — fetch baseline as authenticated user
    auth_headers = build_auth_headers(auth_token)
    auth_response = send_request(url, auth_headers, session)

    if auth_response is None:
        return None

    # If the authenticated request itself fails, skip this endpoint
    if auth_response.status_code in REJECTION_CODES:
        logger.debug(f"Authenticated request rejected at {url} — skipping")
        return None

    # Step 2 — fetch same resource without authentication.
    # IMPORTANT: passing headers={"Authorization": None} explicitly removes the
    # Authorization key for this request only, overriding the session's default.
    # Passing {} does NOT strip it — the session header still gets merged in.
    unauth_response = send_request(url, {"Authorization": None}, session)

    if unauth_response is None:
        return None

    # Step 3 — if server properly rejected unauthorized request, no IDOR
    if unauth_response.status_code in REJECTION_CODES:
        logger.debug(f"Unauthorized request correctly rejected at {url}")
        return None

    # Step 4 — compare the two responses
    similarity = calculate_similarity(
        auth_response.text,
        unauth_response.text
    )

    logger.debug(f"Similarity ratio at {url}: {similarity:.2f}")

    if similarity >= SIMILARITY_THRESHOLD:
        logger.warning(f"Potential IDOR detected at {url} — similarity: {similarity:.2f}")
        return build_finding(url, auth_response, unauth_response, similarity)

    return None


def calculate_similarity(text_a: str, text_b: str) -> float:
    """
    Calculate how similar two response bodies are.
    Returns a float between 0.0 (completely different) and 1.0 (identical).

    Uses SequenceMatcher which compares character sequences.
    We cap comparison at 5000 characters to keep it fast on large responses.
    """
    # Truncate to avoid slow comparison on very large responses
    a = text_a[:5000]
    b = text_b[:5000]

    return SequenceMatcher(None, a, b).ratio()


def contains_id_parameter(path: str) -> bool:
    """
    Check if an API path contains an ID-like parameter.

    Matches patterns like:
    /api/users/{id}
    /api/orders/{orderId}
    /api/vehicles/{vehicle_id}
    """
    import re
    # Match curly brace parameters containing 'id' (case insensitive)
    return bool(re.search(r'\{[^}]*id[^}]*\}', path, re.IGNORECASE))


def build_test_url(base_url: str, path: str) -> Optional[str]:
    """
    Replace path parameters with a test ID value.

    /api/users/{userId} becomes /api/users/2
    We use ID=2 as a common test value for vulnerable labs.
    """
    import re
    # Replace any {paramName} with test value 2
    test_path = re.sub(r'\{[^}]+\}', '2', path)
    return base_url.rstrip('/') + test_path


def build_auth_headers(auth_token: Optional[str]) -> Dict[str, str]:
    """Build request headers with or without Bearer token."""
    headers = {"Content-Type": "application/json"}
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"
    return headers


def send_request(
    url: str,
    headers: Dict,
    session: requests.Session
) -> Optional[requests.Response]:
    """Send a GET request and return the response, or None on failure."""
    try:
        return session.get(url, headers=headers, timeout=10)
    except requests.RequestException as e:
        logger.error(f"Request failed for {url}: {e}")
        return None


def build_finding(
    url: str,
    auth_response: requests.Response,
    unauth_response: requests.Response,
    similarity: float
) -> Dict[str, Any]:
    """Build a structured finding dictionary for the report."""
    return {
        "title": "Insecure Direct Object Reference (IDOR)",
        "protocol": "REST",
        "owasp": "API1:2023 - Broken Object Level Authorization",
        "severity": "High",
        "cvss_score": 8.1,
        "description": (
            "The API endpoint returns the same resource data to both "
            "authenticated and unauthenticated requests. "
            "This indicates the server is not enforcing object-level "
            "authorization checks."
        ),
        "evidence": {
            "url": url,
            "similarity_ratio": round(similarity, 2),
            "auth_status_code": auth_response.status_code,
            "unauth_status_code": unauth_response.status_code,
            "auth_response_preview": auth_response.text[:300],
            "unauth_response_preview": unauth_response.text[:300]
        },
        "remediation": (
            "Implement object-level authorization checks on every API endpoint. "
            "Verify that the requesting user owns or has permission to access "
            "the requested resource before returning data. "
            "Never rely solely on the client to restrict which IDs are requested."
        )
    }
