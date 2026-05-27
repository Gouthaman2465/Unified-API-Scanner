# scanners/soap/ws_security.py
#
# WS-Security and SOAPAction spoofing scanner for SOAP APIs.
# OWASP API2 — Broken Authentication
# OWASP API8 — Security Misconfiguration
#
# What this module does:
#   1. Sends a SOAP request with no WS-Security header — checks if accepted
#   2. Sends a SOAP request with PasswordText UsernameToken — checks if accepted
#   3. Sends a SOAP request with no Timestamp/Nonce — checks replay risk
#   4. Tests SOAPAction header spoofing (empty, missing, wrong value)
#   5. Logs all findings and returns structured results for the report

import logging
from utils.logger import log_finding

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────
# SOAP ENVELOPE — NO AUTHENTICATION HEADER
# A bare minimum envelope with no security at all.
# If the server accepts this, WS-Security is not enforced.
# ─────────────────────────────────────────────────────────────
NO_AUTH_ENVELOPE = """<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetUser xmlns="http://fakebank.local/soap">
      <userId>1</userId>
    </GetUser>
  </soap:Body>
</soap:Envelope>"""


# ─────────────────────────────────────────────────────────────
# SOAP ENVELOPE — PLAINTEXT USERNAMETOKEN
# Uses PasswordText (unencrypted password).
# If the server accepts this, credentials travel in plaintext.
# ─────────────────────────────────────────────────────────────
PLAINTEXT_AUTH_ENVELOPE = """<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope
    xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
    xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
  <soap:Header>
    <wsse:Security>
      <wsse:UsernameToken>
        <wsse:Username>admin</wsse:Username>
        <wsse:Password
            Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">
          admin123
        </wsse:Password>
      </wsse:UsernameToken>
    </wsse:Security>
  </soap:Header>
  <soap:Body>
    <GetUser xmlns="http://fakebank.local/soap">
      <userId>1</userId>
    </GetUser>
  </soap:Body>
</soap:Envelope>"""


# ─────────────────────────────────────────────────────────────
# SOAP ENVELOPE — NO TIMESTAMP (REPLAY RISK)
# A WS-Security header with a UsernameToken but no Created/Expires
# timestamp and no Nonce.  Without these, a captured request can
# be replayed by an attacker indefinitely.
# ─────────────────────────────────────────────────────────────
NO_TIMESTAMP_ENVELOPE = """<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope
    xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
    xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
  <soap:Header>
    <wsse:Security>
      <wsse:UsernameToken>
        <wsse:Username>admin</wsse:Username>
        <wsse:Password
            Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">
          hashedpassword
        </wsse:Password>
      </wsse:UsernameToken>
    </wsse:Security>
  </soap:Header>
  <soap:Body>
    <GetUser xmlns="http://fakebank.local/soap">
      <userId>1</userId>
    </GetUser>
  </soap:Body>
</soap:Envelope>"""


# ─────────────────────────────────────────────────────────────
# HELPER — SEND SOAP REQUEST AND CAPTURE RESULT
# Returns (status_code, response_text) or (None, "") on failure.
# ─────────────────────────────────────────────────────────────
def _send_soap(session, endpoint, envelope, soap_action):
    try:
        response = session.post(
            endpoint,
            data=envelope,
            headers={
                "Content-Type": "text/xml; charset=utf-8",
                "SOAPAction":   soap_action,
            },
            timeout=10,
        )
        return response.status_code, response.text
    except Exception as exc:
        logger.warning("SOAP request failed: %s", exc)
        return None, ""


# ─────────────────────────────────────────────────────────────
# HELPER — CHECK IF RESPONSE LOOKS LIKE A SUCCESS
# A SOAP fault always contains <Fault> in the body.
# If there is no Fault and the status is 200, the server
# processed the request — which is the vulnerable outcome
# for our authentication tests.
# ─────────────────────────────────────────────────────────────
def _is_success_response(status_code, body):
    if status_code is None:
        return False
    if status_code != 200:
        return False
    # A SOAP fault means the server rejected the request
    if "<Fault>" in body or "<faultstring>" in body.lower():
        return False
    return True


# ─────────────────────────────────────────────────────────────
# TEST 1 — MISSING WS-SECURITY HEADER
# If a request with no Security header is processed successfully,
# the server does not enforce authentication at all.
# OWASP API2 — Broken Authentication
# ─────────────────────────────────────────────────────────────
def check_missing_ws_security(session, endpoint):
    soap_action = "http://fakebank.local/soap/GetUser"
    status, body = _send_soap(session, endpoint, NO_AUTH_ENVELOPE, soap_action)

    if _is_success_response(status, body):
        finding = {
            "type":      "Missing WS-Security",
            "protocol":  "SOAP",
            "owasp":     "API2 — Broken Authentication",
            "severity":  "Critical",
            "detail":    "Server accepted SOAP request with no authentication header.",
            "evidence":  body[:300],
        }
        log_finding(finding)
        logger.info("[WS-SECURITY] CRITICAL — No auth header accepted by server")
        return finding

    logger.info("[WS-SECURITY] Server correctly rejected unauthenticated request")
    return None


# ─────────────────────────────────────────────────────────────
# TEST 2 — PLAINTEXT PASSWORD IN WS-SECURITY
# If the server accepts a PasswordText UsernameToken, credentials
# travel unencrypted in every SOAP request over the network.
# OWASP API2 — Broken Authentication
# ─────────────────────────────────────────────────────────────
def check_plaintext_credentials(session, endpoint):
    soap_action = "http://fakebank.local/soap/GetUser"
    status, body = _send_soap(
        session, endpoint, PLAINTEXT_AUTH_ENVELOPE, soap_action
    )

    if _is_success_response(status, body):
        finding = {
            "type":     "WS-Security PasswordText Accepted",
            "protocol": "SOAP",
            "owasp":    "API2 — Broken Authentication",
            "severity": "High",
            "detail":   (
                "Server accepted PasswordText (plaintext) UsernameToken. "
                "Credentials are transmitted unencrypted in every request."
            ),
            "evidence": body[:300],
        }
        log_finding(finding)
        logger.info("[WS-SECURITY] HIGH — Plaintext password accepted")
        return finding

    logger.info("[WS-SECURITY] Server rejected plaintext password")
    return None


# ─────────────────────────────────────────────────────────────
# TEST 3 — NO TIMESTAMP / NONCE (REPLAY ATTACK RISK)
# A WS-Security token without a timestamp and nonce can be
# captured and replayed by an attacker.
# OWASP API2 — Broken Authentication
# ─────────────────────────────────────────────────────────────
def check_replay_risk(session, endpoint):
    soap_action = "http://fakebank.local/soap/GetUser"
    status, body = _send_soap(
        session, endpoint, NO_TIMESTAMP_ENVELOPE, soap_action
    )

    if _is_success_response(status, body):
        finding = {
            "type":     "WS-Security No Timestamp",
            "protocol": "SOAP",
            "owasp":    "API2 — Broken Authentication",
            "severity": "Medium",
            "detail":   (
                "Server accepted a WS-Security token with no Created timestamp "
                "or Nonce. This allows captured tokens to be replayed."
            ),
            "evidence": body[:300],
        }
        log_finding(finding)
        logger.info("[WS-SECURITY] MEDIUM — No timestamp/nonce replay risk")
        return finding

    logger.info("[WS-SECURITY] Server enforced timestamp/nonce correctly")
    return None


# ─────────────────────────────────────────────────────────────
# TEST 4 — SOAPACTION SPOOFING
# Tests three spoofing scenarios:
#   A. Empty SOAPAction header
#   B. Missing SOAPAction header entirely
#   C. Wrong SOAPAction pointing to a different operation
# If the server processes any of these, routing is based on the
# XML body only, and the SOAPAction header is not validated.
# OWASP API8 — Security Misconfiguration
# ─────────────────────────────────────────────────────────────
def check_soapaction_spoofing(session, endpoint):
    findings = []

    test_cases = [
        # (label, soap_action_value, include_header)
        ("Empty SOAPAction",   "",                                      True),
        ("Missing SOAPAction", None,                                    False),
        ("Wrong SOAPAction",   "http://fakebank.local/soap/AdminReset", True),
    ]

    for label, action_value, include_header in test_cases:
        headers = {"Content-Type": "text/xml; charset=utf-8"}

        if include_header and action_value is not None:
            headers["SOAPAction"] = action_value
        # If include_header is False, we deliberately omit the SOAPAction key

        try:
            response = session.post(
                endpoint,
                data=NO_AUTH_ENVELOPE,
                headers=headers,
                timeout=10,
            )
            status = response.status_code
            body   = response.text
        except Exception as exc:
            logger.warning("SOAPAction spoof request failed (%s): %s", label, exc)
            continue

        if _is_success_response(status, body):
            finding = {
                "type":      "SOAPAction Spoofing",
                "protocol":  "SOAP",
                "owasp":     "API8 — Security Misconfiguration",
                "severity":  "Medium",
                "detail":    (
                    f"{label}: Server processed request without validating "
                    f"the SOAPAction header."
                ),
                "evidence":  body[:300],
            }
            findings.append(finding)
            log_finding(finding)
            logger.info("[SOAPACTION] MEDIUM — %s accepted by server", label)
        else:
            logger.info(
                "[SOAPACTION] Server correctly rejected %s", label
            )

    return findings


# ─────────────────────────────────────────────────────────────
# ORCHESTRATOR — RUN ALL WS-SECURITY TESTS
# Called by main.py for the SOAP scanner chain.
# Returns a list of finding dicts (empty list if nothing found).
# ─────────────────────────────────────────────────────────────
def run_ws_security_checks(session, endpoint):
    findings = []

    result = check_missing_ws_security(session, endpoint)
    if result:
        findings.append(result)

    result = check_plaintext_credentials(session, endpoint)
    if result:
        findings.append(result)

    result = check_replay_risk(session, endpoint)
    if result:
        findings.append(result)

    spoof_findings = check_soapaction_spoofing(session, endpoint)
    findings.extend(spoof_findings)

    return findings
