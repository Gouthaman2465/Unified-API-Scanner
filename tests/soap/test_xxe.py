import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import requests
from scanners.soap.xxe import scan_xxe, load_xxe_payloads

MOCK_OPERATIONS = [
    {
        "name":        "GetUser",
        "namespace":   "http://fakebank.local/soap",
        "soap_action": "http://fakebank.local/soap/GetUser",
        "params":      ["userId"],
    },
]

SOAP_ENDPOINT = "http://127.0.0.1:8000/soap"

def test_payload_loading():
    payloads = load_xxe_payloads()
    assert len(payloads) == 4
    print(f"[TEST] Payload loading OK — {len(payloads)} payloads loaded.")

def test_xxe_against_fake_server():
    session = requests.Session()
    try:
        probe = session.get("http://127.0.0.1:8000/?wsdl", timeout=3)
        assert "BankingService" in probe.text
        print("[TEST] Fake SOAP server is reachable.")
    except Exception as exc:
        print(f"[TEST] SKIP — Fake SOAP server not running: {exc}")
        return

    findings = scan_xxe(
        session=session,
        endpoint_url=SOAP_ENDPOINT,
        operations=MOCK_OPERATIONS,
        logger=None,
    )

    print(f"\n[TEST] Total findings: {len(findings)}")
    for f in findings:
        print(f"  [{f['severity'].upper()}] {f['operation']}/{f['param']} — payload={f['payload_id']}")
        print(f"  Evidence: {f['evidence'][:150]}")

    confirmed = [f for f in findings if f["severity"] == "Critical"]
    assert len(confirmed) >= 1, "Expected at least 1 Critical finding"
    print("\n[TEST] PASS — Confirmed Critical XXE finding detected.")

if __name__ == "__main__":
    test_payload_loading()
    test_xxe_against_fake_server()
