# tests/soap/test_xxe.py
#
# Phase 8 test — Run this AFTER starting fake_soap_server.py in a separate
# terminal:
#
#   Terminal 1:  python fake_soap_server.py
#   Terminal 2:  python -m pytest tests/soap/test_xxe.py -v
#            OR: python tests/soap/test_xxe.py
#
# Expected results:
#   linux_passwd payload  → CONFIRMED (fake server echoes root:x:0:0 in username field)
#   windows_winini        → NOT confirmed (fake server doesn't echo [fonts])
#   ssrf_http             → Possible blind (fake server responds instantly → no timing hit)
#   linux_hostname        → Possible (field value changed from baseline)

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import requests
from scanners.soap.xxe import scan_xxe, load_xxe_payloads

# ---------------------------------------------------------------------------
# Mock operations list — simulates what wsdl_parser.py would return
# for the fake_soap_server.py BankingService WSDL
# ---------------------------------------------------------------------------
MOCK_OPERATIONS = [
    {
        "name":        "GetUser",
        "namespace":   "http://fakebank.local/soap",
        "soap_action": "http://fakebank.local/soap/GetUser",
        "params":      ["userId"],
    },
    {
        "name":        "CreateOrder",
        "namespace":   "http://fakebank.local/soap",
        "soap_action": "http://fakebank.local/soap/CreateOrder",
        "params":      ["userId", "product", "quantity"],
    },
]

SOAP_ENDPOINT = "http://127.0.0.1:8000/soap"


def test_payload_loading():
    """Verify payload file loads correctly and all 4 payloads are present."""
    payloads = load_xxe_payloads()
    assert len(payloads) == 4, f"Expected 4 payloads, got {len(payloads)}"
    ids = [p["id"] for p in payloads]
    assert "linux_passwd" in ids
    assert "ssrf_http" in ids
    print(f"[TEST] Payload loading OK — {len(payloads)} payloads loaded.")


def test_xxe_against_fake_server():
    """
    Full integration test against fake_soap_server.py.
    Requires the fake server to be running on http://127.0.0.1:8000.
    """
    session = requests.Session()

    # Confirm the fake server is reachable before running the scan.
    try:
        probe = session.get("http://127.0.0.1:8000/?wsdl", timeout=3)
        assert "BankingService" in probe.text, "Fake server WSDL not found"
        print("[TEST] Fake SOAP server is reachable.")
    except Exception as exc:
        print(f"[TEST] SKIP — Fake SOAP server not running: {exc}")
        print("       Start it with: python fake_soap_server.py")
        return

    # Run the scanner.
    findings = scan_xxe(
        session=session,
        endpoint_url=SOAP_ENDPOINT,
        operations=MOCK_OPERATIONS,
        logger=None,
    )

    print(f"\n[TEST] Total findings: {len(findings)}")
    for f in findings:
        print(
            f"  [{f['severity'].upper()}] {f['operation']}/{f['param']} "
            f"— payload={f['payload_id']} blind={f['blind']}"
        )
        print(f"  Evidence: {f['evidence'][:150]}")
        print()

    # The fake server echoes XXE_VULNERABLE_RESPONSE for any DOCTYPE request.
    # That response contains "root:x:0:0:root:/root:/bin/bash" in <username>.
    # So linux_passwd should be confirmed for GetUser/userId.
    confirmed = [f for f in findings if f["severity"] == "Critical"]
    assert len(confirmed) >= 1, (
        "Expected at least 1 Critical XXE finding from linux_passwd payload. "
        "Check that fake_soap_server.py is running and returning XXE_VULNERABLE_RESPONSE."
    )

    print("[TEST] PASS — At least 1 confirmed Critical XXE finding detected.")


if __name__ == "__main__":
    test_payload_loading()
    test_xxe_against_fake_server()
