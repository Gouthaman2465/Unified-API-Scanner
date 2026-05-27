# tests/soap/test_ws_security.py
#
# Run: python -m pytest tests/soap/test_ws_security.py -v
# Requires: python fake_soap_server.py running in another terminal

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import requests
from scanners.soap.ws_security import (
    check_missing_ws_security,
    check_plaintext_credentials,
    check_replay_risk,
    check_soapaction_spoofing,
    run_ws_security_checks,
)

SOAP_ENDPOINT = "http://127.0.0.1:8000/soap"


def test_server_reachable():
    session = requests.Session()
    response = session.get("http://127.0.0.1:8000/?wsdl", timeout=3)
    assert "BankingService" in response.text
    print("[TEST] Fake SOAP server is reachable.")


def test_missing_ws_security_finding():
    """Fake server accepts all requests — must flag Critical finding."""
    session  = requests.Session()
    finding = check_missing_ws_security(session, SOAP_ENDPOINT)


    print(f"\n[TEST] Missing WS-Security finding: {finding}")

    assert finding is not None, (
        "Expected Critical finding — fake server should accept "
        "unauthenticated request."
    )
    assert finding["severity"]  == "Critical"
    assert finding["protocol"]  == "SOAP"
    assert "API2"               in finding["owasp"]
    print("[TEST] PASS — Missing WS-Security detected correctly.")


def test_plaintext_credentials_finding():
    """Fake server accepts PasswordText — must flag High finding."""
    session  = requests.Session()
    finding = check_plaintext_credentials(session, SOAP_ENDPOINT)


    print(f"\n[TEST] Plaintext credentials finding: {finding}")

    assert finding is not None, (
        "Expected High finding — fake server should accept plaintext password."
    )
    assert finding["severity"] == "High"
    print("[TEST] PASS — PasswordText acceptance detected correctly.")


def test_replay_risk_finding():
    """Fake server accepts no-timestamp token — must flag Medium finding."""
    session  = requests.Session()
    finding = check_replay_risk(session, SOAP_ENDPOINT)


    print(f"\n[TEST] Replay risk finding: {finding}")

    assert finding is not None, (
        "Expected Medium finding — fake server should accept "
        "token without timestamp."
    )
    assert finding["severity"] == "Medium"
    print("[TEST] PASS — Replay risk detected correctly.")


def test_soapaction_spoofing_findings():
    """Fake server ignores SOAPAction — all 3 spoof cases must fire."""
    session  = requests.Session()
    findings = check_soapaction_spoofing(session, SOAP_ENDPOINT)


    print(f"\n[TEST] SOAPAction spoofing findings: {len(findings)}")
    for f in findings:
        print(f"  [{f['severity']}] {f['detail']}")

    assert len(findings) == 3, (
        f"Expected 3 SOAPAction spoofing findings, got {len(findings)}. "
        "Fake server should process empty, missing, and wrong SOAPAction."
    )
    print("[TEST] PASS — All 3 SOAPAction spoof cases detected.")


def test_run_all_ws_security_checks():
    """
    Run the full orchestrator and confirm total finding count.
    Fake server → 1 Critical + 1 High + 1 Medium + 3 Medium spoof = 6 total.
    """
    session  = requests.Session()
    findings = run_ws_security_checks(session, SOAP_ENDPOINT)

    print(f"\n[TEST] Total WS-Security findings: {len(findings)}")
    for f in findings:
        print(f"  [{f['severity']:8}] {f['type']}")

    assert len(findings) >= 4, (
        f"Expected at least 4 WS-Security findings, got {len(findings)}."
    )

    severities = [f["severity"] for f in findings]
    assert "Critical" in severities, "Missing Critical finding"
    assert "High"     in severities, "Missing High finding"
    assert "Medium"   in severities, "Missing Medium finding"

    print("[TEST] PASS — Full WS-Security check suite passed.")


if __name__ == "__main__":
    test_server_reachable()
    test_missing_ws_security_finding()
    test_plaintext_credentials_finding()
    test_replay_risk_finding()
    test_soapaction_spoofing_findings()
    test_run_all_ws_security_checks()
