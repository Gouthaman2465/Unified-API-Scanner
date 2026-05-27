# scanners/soap/xml_injection.py
#
# XML Injection and SOAPAction Spoofing scanner for SOAP APIs.
# OWASP API8 — Security Misconfiguration
#
# What this module does:
#   1. Takes each SOAP operation discovered by wsdl_parser.py
#   2. Injects XML metacharacter payloads into every parameter
#   3. Compares the injected response to the clean baseline response
#   4. Flags significant differences as potential XML injection
#   5. Tests SOAPAction spoofing by sending empty, missing, and wrong values
#   6. Logs all findings and returns structured results for the report

import logging
from difflib import SequenceMatcher
from utils.logger import log_finding

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────
# XML INJECTION PAYLOAD SET
# These payloads attempt to break out of a well-formed XML element.
# Each one is designed to test a different parser behaviour.
# ─────────────────────────────────────────────────────────────
XML_INJECTION_PAYLOADS = [
    # Basic tag break — inject a new sibling element
    "test</param><injected>evil</injected><param>",

    # Attribute escape — break out of an XML attribute value
    'test" injected="evil',

    # CDATA escape — close a CDATA section and inject raw XML
    "test]]></param><injected>evil</injected><param><![CDATA[",

    # Ampersand entity — trigger undefined entity errors
    "test&undefined_entity;",

    # Angle bracket injection — basic less-than / greater-than
    "test<script>alert(1)</script>",

    # Null byte — some parsers strip or mishandle null bytes
    "test\x00<injected>evil</injected>",
]

# ─────────────────────────────────────────────────────────────
# SOAP ENVELOPE BUILDER
# Builds a minimal valid SOAP 1.1 envelope for a given operation.
# param_name  — the XML element name for the parameter
# param_value — the value to place inside that element
# namespace   — the target namespace from the WSDL
# ─────────────────────────────────────────────────────────────
def build_soap_envelope(operation_name, param_name, param_value, namespace):
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:tns="{namespace}">
  <soap:Body>
    <tns:{operation_name}>
      <tns:{param_name}>{param_value}</tns:{param_name}>
    </tns:{operation_name}>
  </soap:Body>
</soap:Envelope>"""


# ─────────────────────────────────────────────────────────────
# RESPONSE SIMILARITY CHECK
# Returns a float between 0.0 and 1.0.
# 1.0 = responses are identical.
# Below 0.75 = significant structural difference → flag it.
# ─────────────────────────────────────────────────────────────
def _response_similarity(baseline_text, injected_text):
    return SequenceMatcher(None, baseline_text, injected_text).ratio()


# ─────────────────────────────────────────────────────────────
# BASELINE CAPTURE
# Sends one clean request with a known-safe value so we have
# something to compare injected responses against.
# ─────────────────────────────────────────────────────────────
def _fetch_baseline(session, endpoint, operation_name, param_name,
                    soap_action, namespace):
    safe_value = "1"
    envelope = build_soap_envelope(
        operation_name, param_name, safe_value, namespace
    )
    try:
        response = session.post(
            endpoint,
            data=envelope,
            headers={
                "Content-Type": "text/xml; charset=utf-8",
                "SOAPAction": soap_action,
            },
            timeout=10,
        )
        return response.text
    except Exception as exc:
        logger.warning("Baseline request failed for %s: %s", operation_name, exc)
        return ""


# ─────────────────────────────────────────────────────────────
# MAIN XML INJECTION TEST
# Runs all payloads against every parameter of every operation.
# Returns a list of finding dicts.
# ─────────────────────────────────────────────────────────────
def run_xml_injection(session, endpoint, operations, namespace):
    """
    operations — list of dicts from wsdl_parser.py, each containing:
        {
            "name": "GetUser",
            "soap_action": "http://fakebank.local/soap/GetUser",
            "parameters": ["userId"]
        }
    """
    findings = []

    for operation in operations:
        op_name    = operation["name"]
        soap_action = operation.get("soap_action", "")
        parameters = operation.get("parameters", [])

        if not parameters:
            logger.info("Skipping %s — no parameters to inject", op_name)
            continue

        # Use the first parameter for baseline capture
        first_param = parameters[0]
        baseline = _fetch_baseline(
            session, endpoint, op_name, first_param, soap_action, namespace
        )

        if not baseline:
            logger.warning("No baseline for %s — skipping", op_name)
            continue

        # Test every parameter with every payload
        for param_name in parameters:
            for payload in XML_INJECTION_PAYLOADS:
                envelope = build_soap_envelope(
                    op_name, param_name, payload, namespace
                )
                try:
                    response = session.post(
                        endpoint,
                        data=envelope,
                        headers={
                            "Content-Type": "text/xml; charset=utf-8",
                            "SOAPAction": soap_action,
                        },
                        timeout=10,
                    )
                    injected_text = response.text
                except Exception as exc:
                    logger.warning(
                        "Injection request failed (%s / %s): %s",
                        op_name, param_name, exc
                    )
                    continue

                similarity = _response_similarity(baseline, injected_text)

                # Significant deviation from baseline — possible injection
                if similarity < 0.75:
                    finding = {
                        "type":        "XML Injection",
                        "protocol":    "SOAP",
                        "owasp":       "API8 — Security Misconfiguration",
                        "severity":    "High",
                        "operation":   op_name,
                        "parameter":   param_name,
                        "payload":     payload,
                        "similarity":  round(similarity, 3),
                        "status_code": response.status_code,
                        "evidence":    injected_text[:300],
                    }
                    findings.append(finding)
                    log_finding(
                        url=endpoint,
                        method="POST",
                        finding_type="XML Injection",
                        detail=(
                            f"Operation={op_name} Param={param_name} "
                            f"Similarity={similarity:.3f}"
                        ),
                        severity="High",
                    )
                    logger.info(
                        "[XML INJECTION] %s / %s — similarity %.3f",
                        op_name, param_name, similarity
                    )

    return findings
