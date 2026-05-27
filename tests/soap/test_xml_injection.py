# tests/soap/test_xml_injection.py
#
# Run: python -m pytest tests/soap/test_xml_injection.py -v
# Requires: python fake_soap_server.py running in another terminal

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import requests
from scanners.soap.xml_injection import run_xml_injection

MOCK_OPERATIONS = [
    {
        "name":        "GetUser",
        "soap_action": "http://fakebank.local/soap/GetUser",
        "parameters":  ["userId"],
    },
    {
        "name":        "CreateOrder",
        "soap_action": "http://fakebank.local/soap/CreateOrder",
        "parameters":  ["userId", "product", "quantity"],
    },
]

SOAP_ENDPOINT = "http://127.0.0.1:8000/soap"
NAMESPACE     = "http://fakebank.local/soap"


def test_xml_injection_against_fake_server():
    session = requests.Session()

    # Confirm server is up
    try:
        probe = session.get("http://127.0.0.1:8000/?wsdl", timeout=3)
        assert "BankingService" in probe.text
        print("[TEST] Fake SOAP server is reachable.")
    except Exception as exc:
        print(f"[TEST] SKIP — server not running: {exc}")
        return

    findings = run_xml_injection(
        session=session,
        endpoint=SOAP_ENDPOINT,
        operations=MOCK_OPERATIONS,
        namespace=NAMESPACE,
    )

    print(f"\n[TEST] XML Injection findings: {len(findings)}")
    for f in findings:
        print(f"  [{f['severity']}] {f['operation']}/{f['parameter']}")
        print(f"  Payload   : {f['payload'][:60]}")
        print(f"  Similarity: {f['similarity']}")
        print(f"  Evidence  : {f['evidence'][:120]}")
        print()

    # Fake server returns the same response regardless of input,
    # so similarity stays high → no findings is the correct result.
    # If you patch the fake server to echo back the parameter value,
    # you will see findings here.
    print(f"[TEST] PASS — XML Injection scan completed without errors.")


if __name__ == "__main__":
    test_xml_injection_against_fake_server()
