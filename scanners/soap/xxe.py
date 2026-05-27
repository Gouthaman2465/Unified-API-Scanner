# scanners/soap/xxe.py
#
# Phase 8 — XXE Injection Scanner (SOAP)
# Protocol: SOAP only
# OWASP: API7 (Security Misconfiguration) — XML External Entity processing
# CVSS: Critical (9.0–10.0) for confirmed in-band file read
#       High (7.0–8.9) for confirmed blind SSRF indicator
#
# This module:
#   1. Loads XXE payload templates from payloads/soap/xxe_payloads.xml
#   2. Substitutes real operation/parameter names discovered by the WSDL parser
#   3. Sends each crafted SOAP request to the target endpoint
#   4. Detects in-band XXE by checking response fields for file content markers
#   5. Detects blind XXE by measuring response timing anomalies
#   6. Returns structured findings for the reporting module

import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional
import requests

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Path to the XXE payload template file (relative to project root).
PAYLOAD_FILE = Path(__file__).parent.parent.parent / "payloads" / "soap" / "xxe_payloads.xml"

# If a SOAP response takes longer than this (seconds), we flag it as a
# possible blind XXE / SSRF indicator. The SSRF payload points to a
# non-routable IP (192.0.2.1) so the server will time out trying to connect.
BLIND_TIMING_THRESHOLD_SECONDS = 5.0

# SOAP response HTTP timeout. Set higher than the blind threshold so the
# request doesn't get killed before we can measure the delay.
REQUEST_TIMEOUT_SECONDS = 15

# ---------------------------------------------------------------------------
# Data helpers
# ---------------------------------------------------------------------------

def _strip_namespace(tag: str) -> str:
    """
    Remove the XML namespace prefix from an element tag.

    xml.etree.ElementTree prefixes tags with the namespace URI like:
        {http://schemas.xmlsoap.org/soap/envelope/}Body
    We only want:
        Body

    Args:
        tag: Raw element tag string from ElementTree.

    Returns:
        Tag name without the namespace prefix.
    """
    # Tags with namespaces look like {namespace}localname.
    # split("}") gives ["namespace", "localname"] — we take the last part.
    if "}" in tag:
        return tag.split("}")[-1]
    return tag


def _extract_all_text_values(xml_string: str) -> list[str]:
    """
    Walk every element in an XML response and collect all non-empty text
    values.

    We use this to search for XXE markers anywhere in the response without
    having to know the specific field names in advance. This matters because
    different SOAP operations return different element structures.

    Args:
        xml_string: Raw XML response body as a string.

    Returns:
        List of non-empty text strings found in all elements.
    """
    values = []
    try:
        root = ET.fromstring(xml_string)
        for elem in root.iter():
            if elem.text and elem.text.strip():
                values.append(elem.text.strip())
    except ET.ParseError:
        # If the response isn't valid XML at all, just treat it as raw text.
        # Some servers return HTML error pages or partial XML on XXE failure.
        values.append(xml_string)
    return values


# ---------------------------------------------------------------------------
# Payload loading
# ---------------------------------------------------------------------------

def load_xxe_payloads() -> list[dict]:
    """
    Load all XXE payload templates from the XML payload file.

    The payload file (payloads/soap/xxe_payloads.xml) stores each payload
    as an XML element with:
        id          — unique identifier string
        type        — "file_read" or "ssrf"
        blind       — "true" if this is a blind/timing payload
        description — human readable description
        detection_marker — what to look for in response (or "BLIND_TIMING")
        body        — the SOAP envelope template with HTML-escaped XML

    The body is stored HTML-escaped in the file so it doesn't break the
    outer XML structure. We unescape it here before use.

    Returns:
        List of payload dicts, each with keys:
            id, type, blind (bool), description, detection_marker, body
    """
    if not PAYLOAD_FILE.exists():
        raise FileNotFoundError(
            f"XXE payload file not found at {PAYLOAD_FILE}. "
            "Make sure payloads/soap/xxe_payloads.xml exists."
        )

    payloads = []
    tree = ET.parse(PAYLOAD_FILE)
    root = tree.getroot()

    for payload_elem in root.findall("payload"):
        # Read the body text and unescape HTML entities back to XML characters.
        # The payload file stores < as &lt; and > as &gt; to stay valid XML.
        raw_body = payload_elem.findtext("body", default="").strip()
        unescaped_body = (
            raw_body
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&amp;", "&")
        )

        payloads.append({
            "id":               payload_elem.get("id", "unknown"),
            "type":             payload_elem.get("type", "unknown"),
            "blind":            payload_elem.get("blind", "false") == "true",
            "description":      payload_elem.findtext("description", default=""),
            "detection_marker": payload_elem.findtext("detection_marker", default=""),
            "body":             unescaped_body,
        })

    return payloads


# ---------------------------------------------------------------------------
# Payload injection
# ---------------------------------------------------------------------------

def _build_soap_request(
    template_body: str,
    namespace: str,
    operation: str,
    param_name: str,
) -> str:
    """
    Substitute real WSDL-discovered values into a payload template.

    The templates use three placeholder strings:
        {{NAMESPACE}}  → SOAP target namespace from WSDL (e.g. http://fakebank.local/soap)
        {{OPERATION}}  → SOAP operation name from WSDL (e.g. GetUser)
        {{PARAM}}      → parameter element name from WSDL (e.g. userId)

    Args:
        template_body: Raw payload body with placeholder strings.
        namespace:     SOAP namespace URI extracted from the WSDL.
        operation:     SOAP operation name to inject into.
        param_name:    The XML element name of the parameter to inject.

    Returns:
        Fully substituted SOAP request body string ready to POST.
    """
    return (
        template_body
        .replace("{{NAMESPACE}}", namespace)
        .replace("{{OPERATION}}", operation)
        .replace("{{PARAM}}", param_name)
    )


# ---------------------------------------------------------------------------
# Detection logic
# ---------------------------------------------------------------------------

def _detect_in_band_xxe(
    response_text: str,
    detection_marker: str,
    baseline_values: list[str],
) -> dict:
    """
    Check if a known file content marker appears in the SOAP response.

    Strategy:
    - Extract all text values from the response XML
    - Check if any field contains the detection_marker string (e.g. "root:")
    - Also compare against baseline to detect any value that changed
      unexpectedly (used for FIELD_VALUE_CHANGED marker)

    Args:
        response_text:     Raw SOAP response XML as string.
        detection_marker:  String to search for (from payload template).
        baseline_values:   Text values from a clean (no payload) baseline request.

    Returns:
        Dict with keys:
            confirmed (bool): True if XXE confirmed
            evidence  (str):  The field value or snippet that triggered detection
    """
    response_values = _extract_all_text_values(response_text)

    # Strategy 1: direct marker match (e.g. "root:" from /etc/passwd)
    if detection_marker not in ("BLIND_TIMING", "FIELD_VALUE_CHANGED"):
        for value in response_values:
            if detection_marker in value:
                return {
                    "confirmed": True,
                    "evidence": value[:500],  # Cap evidence at 500 chars
                }

    # Strategy 2: field value changed vs baseline (hostname payload)
    if detection_marker == "FIELD_VALUE_CHANGED" and baseline_values:
        for value in response_values:
            if value not in baseline_values and len(value) > 0:
                # A field returned something different from the baseline.
                # This is weaker evidence — flag as possible rather than confirmed.
                return {
                    "confirmed": False,
                    "possible": True,
                    "evidence": f"Field changed from baseline: {value[:200]}",
                }

    return {"confirmed": False}


def _detect_blind_xxe_timing(elapsed_seconds: float) -> dict:
    """
    Check if a response took long enough to suggest the server tried to
    make an outbound connection (SSRF via blind XXE).

    The SSRF payload points to 192.0.2.1 (TEST-NET — non-routable by RFC 5737).
    A vulnerable server will attempt the connection and wait until its own
    TCP timeout fires, adding several seconds to the response time.

    A non-vulnerable server (parser blocks external entities) returns instantly.

    Args:
        elapsed_seconds: How long the request took in seconds.

    Returns:
        Dict with keys:
            confirmed (bool): True if timing anomaly detected
            elapsed   (float): Measured response time
    """
    if elapsed_seconds >= BLIND_TIMING_THRESHOLD_SECONDS:
        return {
            "confirmed": True,
            "elapsed":   round(elapsed_seconds, 2),
        }
    return {"confirmed": False, "elapsed": round(elapsed_seconds, 2)}


# ---------------------------------------------------------------------------
# Baseline request
# ---------------------------------------------------------------------------

def _send_baseline_request(
    session: requests.Session,
    endpoint_url: str,
    namespace: str,
    operation: str,
    param_name: str,
    soap_action: str,
    logger=None,
) -> tuple[str, list[str]]:
    """
    Send a clean (no XXE) SOAP request to capture the normal response.

    We need a baseline so we can compare response field values after
    injecting payloads. This lets us detect "field changed" style XXE
    even when we don't know what file content looks like.

    Args:
        session:      requests.Session with proxy/retry config.
        endpoint_url: SOAP service URL.
        namespace:    SOAP target namespace.
        operation:    SOAP operation name.
        param_name:   Parameter element name.
        soap_action:  SOAPAction header value.
        logger:       Optional audit logger from utils/logger.py.

    Returns:
        Tuple of (raw_response_text, list_of_field_values).
        Returns ("", []) if the baseline request fails.
    """
    # Build a benign SOAP request — just send the literal string "baseline_test"
    # as the parameter value. We don't care about the actual result.
    clean_body = (
        f'<?xml version="1.0" encoding="UTF-8"?>'
        f'<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
        f'  <soap:Body>'
        f'    <{operation} xmlns="{namespace}">'
        f'      <{param_name}>baseline_test</{param_name}>'
        f'    </{operation}>'
        f'  </soap:Body>'
        f'</soap:Envelope>'
    )

    headers = {
        "Content-Type": "text/xml; charset=utf-8",
        "SOAPAction":   f'"{soap_action}"',
    }

    try:
        response = session.post(
            endpoint_url,
            data=clean_body.encode("utf-8"),
            headers=headers,
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        baseline_text = response.text
        baseline_values = _extract_all_text_values(baseline_text)

        if logger:
            logger.log(
                url=endpoint_url,
                method="POST",
                status_code=response.status_code,
                finding="BASELINE",
                detail=f"Baseline captured for {operation}/{param_name}",
            )

        return baseline_text, baseline_values

    except requests.RequestException as exc:
        if logger:
            logger.log(
                url=endpoint_url,
                method="POST",
                status_code=0,
                finding="BASELINE_ERROR",
                detail=str(exc),
            )
        return "", []


# ---------------------------------------------------------------------------
# Main scanner entry point
# ---------------------------------------------------------------------------

def scan_xxe(
    session: requests.Session,
    endpoint_url: str,
    operations: list[dict],
    logger=None,
) -> list[dict]:
    """
    Run XXE injection tests against all SOAP operations discovered by the
    WSDL parser.

    This is the function called by main.py (or the orchestrator) after
    the WSDL parser has finished. It receives the list of operations and
    their parameters, then:
        1. Loads all XXE payload templates
        2. For each operation+parameter combination:
           a. Sends a baseline request
           b. Injects each payload variant
           c. Checks for in-band or blind XXE indicators
        3. Returns all confirmed and possible findings

    Args:
        session:      requests.Session (with proxy/auth config from main.py)
        endpoint_url: The SOAP service endpoint URL (from WSDL <service>)
        operations:   List of operation dicts from wsdl_parser.py.
                      Each dict must have:
                          name        (str)  — operation name e.g. "GetUser"
                          namespace   (str)  — target namespace e.g. "http://..."
                          soap_action (str)  — SOAPAction header value
                          params      (list) — list of parameter name strings
        logger:       Optional audit logger instance from utils/logger.py.

    Returns:
        List of finding dicts. Each finding has:
            scanner        (str)  — "XXE"
            protocol       (str)  — "SOAP"
            owasp          (str)  — OWASP category
            severity       (str)  — "Critical" or "High"
            operation      (str)  — which SOAP operation triggered it
            param          (str)  — which parameter was injected
            payload_id     (str)  — which payload template was used
            payload_type   (str)  — "file_read" or "ssrf"
            blind          (bool) — True if timing-based detection
            evidence       (str)  — response snippet or timing info
            endpoint       (str)  — target URL
    """
    findings = []

    # Load all XXE payload templates from disk.
    try:
        payloads = load_xxe_payloads()
    except FileNotFoundError as exc:
        print(f"[XXE] ERROR: {exc}")
        return findings

    print(f"[XXE] Loaded {len(payloads)} payload templates.")
    print(f"[XXE] Testing {len(operations)} SOAP operation(s) at {endpoint_url}")

    for operation in operations:
        op_name    = operation.get("name", "")
        namespace  = operation.get("namespace", "")
        soap_action = operation.get("soap_action", "")
        params     = operation.get("params", [])

        if not params:
            print(f"[XXE] Operation '{op_name}' has no parameters — skipping.")
            continue

        # Test each parameter separately. XXE only fires in the injected field.
        for param_name in params:
            print(f"[XXE] Testing operation='{op_name}' param='{param_name}'")

            # Capture a clean baseline response for this operation+parameter.
            _, baseline_values = _send_baseline_request(
                session=session,
                endpoint_url=endpoint_url,
                namespace=namespace,
                operation=op_name,
                param_name=param_name,
                soap_action=soap_action,
                logger=logger,
            )

            # Now inject each payload variant.
            for payload in payloads:
                # Substitute real values into the template placeholders.
                injected_body = _build_soap_request(
                    template_body=payload["body"],
                    namespace=namespace,
                    operation=op_name,
                    param_name=param_name,
                )

                headers = {
                    "Content-Type": "text/xml; charset=utf-8",
                    "SOAPAction":   f'"{soap_action}"',
                }

                # Measure response time for blind XXE detection.
                start_time = time.time()
                try:
                    response = session.post(
                        endpoint_url,
                        data=injected_body.encode("utf-8"),
                        headers=headers,
                        timeout=REQUEST_TIMEOUT_SECONDS,
                    )
                    elapsed = time.time() - start_time
                    response_text = response.text
                    status_code = response.status_code

                except requests.Timeout:
                    # A timeout itself is strong evidence of blind XXE/SSRF —
                    # the server spent all its time trying to connect outbound.
                    elapsed = REQUEST_TIMEOUT_SECONDS
                    response_text = ""
                    status_code = 0

                except requests.RequestException as exc:
                    print(f"[XXE] Request failed for {op_name}/{param_name}: {exc}")
                    continue

                # --- Detection ---

                if payload["blind"]:
                    # Timing-based detection for blind SSRF payload.
                    timing_result = _detect_blind_xxe_timing(elapsed)
                    if timing_result["confirmed"]:
                        finding = {
                            "scanner":      "XXE",
                            "protocol":     "SOAP",
                            "owasp":        "API7 — Security Misconfiguration",
                            "severity":     "High",
                            "operation":    op_name,
                            "param":        param_name,
                            "payload_id":   payload["id"],
                            "payload_type": payload["type"],
                            "blind":        True,
                            "evidence": (
                                f"Response time {timing_result['elapsed']}s exceeded "
                                f"threshold {BLIND_TIMING_THRESHOLD_SECONDS}s. "
                                f"Server may have attempted outbound connection "
                                f"to SSRF probe address."
                            ),
                            "endpoint": endpoint_url,
                        }
                        findings.append(finding)
                        print(
                            f"[XXE] POSSIBLE BLIND XXE — {op_name}/{param_name} "
                            f"({timing_result['elapsed']}s response time)"
                        )
                else:
                    # In-band detection: look for file content in response fields.
                    detection_result = _detect_in_band_xxe(
                        response_text=response_text,
                        detection_marker=payload["detection_marker"],
                        baseline_values=baseline_values,
                    )

                    if detection_result.get("confirmed"):
                        finding = {
                            "scanner":      "XXE",
                            "protocol":     "SOAP",
                            "owasp":        "API7 — Security Misconfiguration",
                            "severity":     "Critical",
                            "operation":    op_name,
                            "param":        param_name,
                            "payload_id":   payload["id"],
                            "payload_type": payload["type"],
                            "blind":        False,
                            "evidence":     detection_result["evidence"],
                            "endpoint":     endpoint_url,
                        }
                        findings.append(finding)
                        print(
                            f"[XXE] *** CONFIRMED IN-BAND XXE *** "
                            f"operation='{op_name}' param='{param_name}' "
                            f"payload='{payload['id']}'"
                        )
                        print(f"[XXE] Evidence: {detection_result['evidence'][:200]}")

                    elif detection_result.get("possible"):
                        # Weaker signal — field changed but no known marker found.
                        finding = {
                            "scanner":      "XXE",
                            "protocol":     "SOAP",
                            "owasp":        "API7 — Security Misconfiguration",
                            "severity":     "Medium",
                            "operation":    op_name,
                            "param":        param_name,
                            "payload_id":   payload["id"],
                            "payload_type": payload["type"],
                            "blind":        False,
                            "evidence":     detection_result["evidence"],
                            "endpoint":     endpoint_url,
                        }
                        findings.append(finding)
                        print(
                            f"[XXE] Possible XXE (field value changed) "
                            f"— {op_name}/{param_name}"
                        )

                # Log every attempt to the audit CSV regardless of result.
                if logger:
                    logger.log(
                        url=endpoint_url,
                        method="POST",
                        status_code=status_code,
                        finding="XXE_ATTEMPT",
                        detail=(
                            f"op={op_name} param={param_name} "
                            f"payload={payload['id']} elapsed={elapsed:.2f}s"
                        ),
                    )

    print(f"[XXE] Scan complete. {len(findings)} finding(s) recorded.")
    return findings
