"""
scanners/rest/rate_limit.py — Rate Limit Detection Module
Protocol   : REST
OWASP      : API4:2023 — Unrestricted Resource Consumption

This module tests whether a REST API enforces rate limiting by sending
a configurable burst of rapid HTTP requests and analysing the response
pattern. It measures:

  1. Whether HTTP 429 (Too Many Requests) is ever returned
  2. At what request number 429 first appears (the threshold)
  3. Whether the API continues to return valid data even after 429
     (soft limit — logged but not blocked)
  4. Per-request response timing

OWASP API4 context:
  Without rate limiting an API is vulnerable to:
    - Credential stuffing (automated password guessing at scale)
    - Brute-force attacks on OTP / PINs
    - Denial of service via resource exhaustion
    - Enumeration attacks that need many requests

Usage:
    from scanners.rest.rate_limit import run_rate_limit_scan
    findings = run_rate_limit_scan(session, target_url, endpoint_path, burst_count=50)
"""

import logging
import time
from typing import Optional

import requests

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# CONSTANTS
# ---------------------------------------------------------------------------

# Default number of requests in a single burst test
DEFAULT_BURST_COUNT = 50

# Minimum delay between requests in seconds (0 = fire as fast as possible)
# Set to 0 for realistic burst simulation (credential stuffing has no delay)
REQUEST_DELAY_SECONDS = 0.0

# HTTP status codes that indicate a valid, processed response
SUCCESS_STATUS_CODES = {200, 201}

# HTTP status code for rate limiting
RATE_LIMIT_STATUS_CODE = 429

# Endpoints most commonly targeted in credential stuffing / brute-force
# Used as fallback when no specific path is provided
DEFAULT_TEST_ENDPOINTS = [
    "/identity/api/auth/login",       # crAPI login endpoint
    "/api/login",
    "/api/auth/login",
    "/login",
]


# ---------------------------------------------------------------------------
# CORE BURST FUNCTION
# ---------------------------------------------------------------------------

def send_burst(
    session: requests.Session,
    url: str,
    method: str = "GET",
    body: Optional[dict] = None,
    burst_count: int = DEFAULT_BURST_COUNT,
) -> list[dict]:
    """
    Fires `burst_count` identical requests as fast as possible to `url`.

    Each request result is recorded as a dictionary containing:
      - request_number : sequence number (1-based)
      - status_code    : HTTP status code returned
      - response_time_ms : how long the server took to respond
      - is_success     : True if status_code is in SUCCESS_STATUS_CODES
      - is_rate_limited: True if status_code is 429

    Args:
        session     : Authenticated requests.Session (with headers/proxies already set)
        url         : Full URL to send requests to
        method      : HTTP method — "GET" or "POST"
        body        : Optional JSON body dict (for POST login endpoints)
        burst_count : Total number of requests to fire

    Returns:
        List of result dicts, one per request.
    """
    results = []

    logger.info("[Rate Limit] Starting burst of %d requests → %s", burst_count, url)

    for i in range(1, burst_count + 1):
        start_time = time.monotonic()

        try:
            if method.upper() == "POST":
                response = session.post(url, json=body, timeout=10, verify=False)
            else:
                response = session.get(url, timeout=10, verify=False)

            elapsed_ms = int((time.monotonic() - start_time) * 1000)

            result = {
                "request_number":   i,
                "status_code":      response.status_code,
                "response_time_ms": elapsed_ms,
                "is_success":       response.status_code in SUCCESS_STATUS_CODES,
                "is_rate_limited":  response.status_code == RATE_LIMIT_STATUS_CODE,
            }

            logger.debug(
                "[Rate Limit] Request %d/%d → HTTP %d (%dms)",
                i, burst_count, response.status_code, elapsed_ms
            )

        except requests.exceptions.Timeout:
            elapsed_ms = int((time.monotonic() - start_time) * 1000)
            result = {
                "request_number":   i,
                "status_code":      None,
                "response_time_ms": elapsed_ms,
                "is_success":       False,
                "is_rate_limited":  False,
            }
            logger.warning("[Rate Limit] Request %d timed out after %dms", i, elapsed_ms)

        except requests.exceptions.RequestException as exc:
            result = {
                "request_number":   i,
                "status_code":      None,
                "response_time_ms": 0,
                "is_success":       False,
                "is_rate_limited":  False,
            }
            logger.warning("[Rate Limit] Request %d failed: %s", i, exc)

        results.append(result)

        # Configurable delay between requests (default 0 = fastest possible)
        if REQUEST_DELAY_SECONDS > 0:
            time.sleep(REQUEST_DELAY_SECONDS)

    return results


# ---------------------------------------------------------------------------
# ANALYSIS FUNCTION
# ---------------------------------------------------------------------------

def analyse_burst_results(results: list[dict]) -> dict:
    """
    Analyses the raw burst results to determine rate limiting behaviour.

    Looks for three distinct patterns:

    Pattern A — No rate limiting at all:
      429 is never returned across all requests.
      This is the most severe finding.

    Pattern B — Soft rate limit (leaky bucket / sliding window):
      429 is returned at some point but success responses also appear
      AFTER the 429. The limit exists but doesn't stop processing.

    Pattern C — Hard rate limit:
      429 is returned from request N onwards and no further success
      responses are seen. This is the correct behaviour.

    Args:
        results: List of per-request result dicts from send_burst()

    Returns:
        Analysis dict with:
          - rate_limited       : bool — was 429 ever seen?
          - threshold          : int | None — request number where 429 first appeared
          - soft_limit         : bool — did success responses appear after the first 429?
          - total_requests     : int
          - success_count      : int
          - rate_limit_count   : int
          - avg_response_ms    : int
          - pattern            : "none" | "soft" | "hard"
    """
    total = len(results)
    success_count     = sum(1 for r in results if r["is_success"])
    rate_limit_count  = sum(1 for r in results if r["is_rate_limited"])

    # Find the request number where 429 first appeared
    threshold = None
    for r in results:
        if r["is_rate_limited"]:
            threshold = r["request_number"]
            break

    rate_limited = threshold is not None

    # Check for soft limit: success responses AFTER the first 429
    soft_limit = False
    if rate_limited:
        post_limit_results = [r for r in results if r["request_number"] > threshold]
        soft_limit = any(r["is_success"] for r in post_limit_results)

    # Calculate average response time (only for requests that got a response)
    timed_results = [r for r in results if r["response_time_ms"] > 0]
    avg_response_ms = (
        int(sum(r["response_time_ms"] for r in timed_results) / len(timed_results))
        if timed_results else 0
    )

    # Classify the pattern
    if not rate_limited:
        pattern = "none"          # No rate limit — most severe
    elif soft_limit:
        pattern = "soft"          # Limit exists but requests still succeed after it
    else:
        pattern = "hard"          # Correct — blocked after threshold

    return {
        "rate_limited":      rate_limited,
        "threshold":         threshold,
        "soft_limit":        soft_limit,
        "total_requests":    total,
        "success_count":     success_count,
        "rate_limit_count":  rate_limit_count,
        "avg_response_ms":   avg_response_ms,
        "pattern":           pattern,
    }


# ---------------------------------------------------------------------------
# FINDING BUILDER
# ---------------------------------------------------------------------------

def build_finding(url: str, analysis: dict, burst_count: int) -> Optional[dict]:
    """
    Converts the analysis dict into the unified Aegis-API finding format.

    Only generates a finding if a vulnerability was detected.
    Pattern "hard" = correct behaviour = no finding.

    Finding severity:
      "none" pattern → High  (no rate limiting at all — credential stuffing trivially possible)
      "soft" pattern → Medium (limit exists but doesn't stop abuse — partial protection only)

    Args:
        url      : The endpoint that was tested
        analysis : Output from analyse_burst_results()
        burst_count: Number of requests sent

    Returns:
        Finding dict in unified format, or None if no vulnerability found.
    """
    pattern = analysis["pattern"]

    if pattern == "hard":
        # Hard rate limit correctly enforced — no finding
        logger.info("[Rate Limit] Hard rate limit detected at request %d — no vulnerability", analysis["threshold"])
        return None

    if pattern == "none":
        severity    = "High"
        title       = "No Rate Limiting Detected (OWASP API4)"
        description = (
            f"The endpoint {url} returned no HTTP 429 response across {burst_count} rapid requests. "
            "There is no detectable rate limit. An attacker can send unlimited automated requests, "
            "enabling credential stuffing, brute-force of OTPs or PINs, "
            "and resource exhaustion attacks at full network speed."
        )
        evidence_summary = (
            f"Sent {burst_count} requests | "
            f"Success responses: {analysis['success_count']} | "
            f"429 responses: 0 | "
            f"Avg response time: {analysis['avg_response_ms']}ms"
        )
        remediation = (
            "Implement server-side rate limiting on all authentication and "
            "sensitive action endpoints. Recommended approach: sliding window counter "
            "with a limit of 5–10 attempts per IP per minute. "
            "Return HTTP 429 with a Retry-After header. "
            "Consider account lockout after N failures and CAPTCHA for login endpoints."
        )

    else:  # pattern == "soft"
        severity    = "Medium"
        title       = "Soft Rate Limit — Requests Succeed After 429 (OWASP API4)"
        description = (
            f"The endpoint {url} returned HTTP 429 at request #{analysis['threshold']}, "
            "but continued to return success responses after the rate limit was triggered. "
            "This indicates a 'leaky bucket' or misconfigured rate limit that logs or signals "
            "rate limiting without actually blocking further requests. "
            "An attacker can observe the 429 responses and simply continue sending requests."
        )
        evidence_summary = (
            f"Sent {burst_count} requests | "
            f"First 429 at request #{analysis['threshold']} | "
            f"Success responses after 429: detected | "
            f"Total 429 responses: {analysis['rate_limit_count']} | "
            f"Avg response time: {analysis['avg_response_ms']}ms"
        )
        remediation = (
            "Ensure the rate limiting middleware BLOCKS processing after the threshold "
            "is reached, not just signals 429 while continuing to process the request. "
            "Audit your rate limiter configuration — middleware order matters. "
            "The rate limit check must run before authentication and business logic."
        )

    return {
        "type":     "rate_limit",
        "title":    title,
        "protocol": "REST",
        "owasp":    "API4:2023",
        "url":      url,
        "status":   str(analysis.get("threshold") or "N/A"),
        "evidence": {
            "detail":        description,
            "severity":      severity,
            "remediation":   remediation,
            "raw":           evidence_summary,
            "pattern":       pattern,
            "threshold":     analysis["threshold"],
            "burst_count":   burst_count,
            "success_count": analysis["success_count"],
            "avg_ms":        analysis["avg_response_ms"],
        },
    }


# ---------------------------------------------------------------------------
# MAIN ENTRY POINT (called by main.py)
# ---------------------------------------------------------------------------

def run_rate_limit_scan(
    session: requests.Session,
    base_url: str,
    endpoint_path: Optional[str] = None,
    burst_count: int = DEFAULT_BURST_COUNT,
) -> list[dict]:
    """
    Full rate limit scan entry point. Called from the REST scanner chain in main.py.

    Workflow:
      1. Determine which endpoint(s) to test
      2. Send burst of requests via send_burst()
      3. Analyse results via analyse_burst_results()
      4. Build finding via build_finding() if vulnerable
      5. Return list of findings (0 or 1 finding per endpoint)

    Args:
        session       : Authenticated requests.Session
        base_url      : Target base URL (e.g. http://127.0.0.1:8888)
        endpoint_path : Specific path to test. If None, tests DEFAULT_TEST_ENDPOINTS.
        burst_count   : Number of requests per burst (default: 50)

    Returns:
        List of finding dicts (empty list if no vulnerability detected).
    """
    findings = []

    # Decide which endpoints to test
    if endpoint_path:
        endpoints_to_test = [endpoint_path]
    else:
        endpoints_to_test = DEFAULT_TEST_ENDPOINTS

    for path in endpoints_to_test:
        # Construct the full URL — avoid double slashes
        url = base_url.rstrip("/") + "/" + path.lstrip("/")

        logger.info("[Rate Limit] Testing endpoint: %s (burst=%d)", url, burst_count)
        print(f"[*] Rate limit test → {url} ({burst_count} requests)")

        # Step 1: Send the burst
        raw_results = send_burst(
            session=session,
            url=url,
            method="GET",
            burst_count=burst_count,
        )

        # Step 2: Analyse the results
        analysis = analyse_burst_results(raw_results)

        # Step 3: Print a concise summary to stdout
        _print_burst_summary(url, analysis, burst_count)

        # Step 4: Build finding if vulnerable
        finding = build_finding(url, analysis, burst_count)
        if finding:
            print(f"[!] FINDING: {finding['title']}")
            print(f"    Endpoint  : {url}")
            print(f"    Pattern   : {analysis['pattern'].upper()}")
            print(f"    Threshold : {analysis['threshold'] or 'Never triggered'}")
            print(f"    OWASP     : {finding['owasp']}")
            findings.append(finding)
        else:
            print(f"[-] Rate limit correctly enforced at request #{analysis['threshold']}")

        # Only test the first reachable endpoint from the default list
        # to avoid flooding targets unnecessarily.
        #
        # WHY we check responded_count, not success_count:
        # Login endpoints return 401 (not 200) because our session
        # sends GET without credentials. success_count would always
        # be 0, causing all fallback endpoints to be tested.
        # Instead we break on the first endpoint that actually responds
        # (any status code other than a connection error / None).
        responded_count = sum(1 for r in raw_results if r["status_code"] is not None)
        if not endpoint_path and responded_count > 0:
            break

    logger.info("[Rate Limit] Scan complete — %d finding(s)", len(findings))
    return findings


# ---------------------------------------------------------------------------
# CONSOLE SUMMARY HELPER
# ---------------------------------------------------------------------------

def _print_burst_summary(url: str, analysis: dict, burst_count: int) -> None:
    """
    Prints a human-readable burst test summary table to stdout.

    Shows the pattern, threshold, counts, and timing in a format
    that is easy to read during a live interview demo.
    """
    pattern_label = {
        "none": "NO RATE LIMIT DETECTED",
        "soft": "SOFT RATE LIMIT (bypass possible)",
        "hard": "HARD RATE LIMIT (correctly enforced)",
    }.get(analysis["pattern"], analysis["pattern"].upper())

    print(f"\n  {'─' * 54}")
    print(f"  Rate Limit Burst Results")
    print(f"  {'─' * 54}")
    print(f"  Endpoint      : {url}")
    print(f"  Burst size    : {burst_count} requests")
    print(f"  Result        : {pattern_label}")
    print(f"  First 429 at  : request #{analysis['threshold'] or 'never'}")
    print(f"  Successes     : {analysis['success_count']}/{burst_count}")
    print(f"  429 responses : {analysis['rate_limit_count']}")
    print(f"  Avg resp time : {analysis['avg_response_ms']}ms")
    print(f"  {'─' * 54}\n")
