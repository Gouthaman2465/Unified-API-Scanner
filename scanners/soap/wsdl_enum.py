# scanners/soap/wsdl_enum.py
# SOAP WSDL enumeration scanner.
# Checks if WSDL is publicly accessible (information disclosure),
# lists all discovered operations, and flags sensitive-looking operations.
# Protocol: SOAP only
# OWASP: API7 — Security Misconfiguration (WSDL exposure)
#        API1 — BOLA risk indicator (ID parameters discovered)

from discovery.wsdl_parser import fetch_wsdl, parse_wsdl, build_soap_skeleton
from utils.logger import log_event
from utils.helpers import map_owasp, calculate_cvss

# Operation names that suggest privileged or sensitive functionality.
# Discovering these in a public WSDL is a significant finding.
SENSITIVE_OPERATION_KEYWORDS = [
    "admin", "reset", "delete", "purge", "config",
    "internal", "debug", "root", "superuser", "grant",
    "revoke", "impersonate", "sudo", "privilege"
]

# Parameter names that suggest direct object reference (IDOR risk)
IDOR_PARAMETER_KEYWORDS = [
    "id", "userid", "user_id", "accountid", "account_id",
    "customerid", "orderid", "recordid", "patientid"
]


def run_wsdl_enumeration(base_url: str, proxies: dict = None) -> list:
    """
    Main entry point for WSDL enumeration.
    Fetches WSDL, parses it, and returns a list of findings.
    Each finding is a dict the reporting module can consume directly.

    Returns: list of finding dicts, empty list if nothing found.
    """
    findings = []

    print("\n[*] Starting WSDL Enumeration")
    print(f"[*] Target: {base_url}")

    # Step 1: Try to fetch the WSDL
    wsdl_xml = fetch_wsdl(base_url, proxies=proxies)

    if not wsdl_xml:
        print("[-] WSDL not accessible. Target may not be SOAP or WSDL is protected.")
        return findings

    # Step 2: WSDL being accessible at all is a finding
    wsdl_exposure_finding = {
        "title":       "WSDL Publicly Accessible — Service Contract Exposed",
        "protocol":    "SOAP",
        "owasp":       map_owasp("API7"),
        "cvss":        calculate_cvss(protocol="SOAP", auth_required=False,
                                      data_exposed="service_contract",
                                      privilege_escalation=False),
        "severity":    "Medium",
        "description": (
            "The WSDL document is publicly accessible without authentication. "
            "WSDL exposes the complete service contract including all operation "
            "names, parameter names, data types, and endpoint URLs. Attackers "
            "use this information to map the attack surface before targeting "
            "individual operations."
        ),
        "evidence":    f"WSDL retrieved from: {base_url}?wsdl",
        "remediation": (
            "Restrict WSDL access to authenticated and authorized clients only. "
            "If WSDL must be public, ensure no internal or admin operations are "
            "listed. Consider returning a sanitized WSDL for public consumption."
        )
    }
    findings.append(wsdl_exposure_finding)
    log_event("WSDL_EXPOSURE", base_url + "?wsdl", 200, "WSDL publicly accessible")

    # Step 3: Parse the WSDL to extract operations and parameters
    wsdl_data = parse_wsdl(wsdl_xml)

    endpoint   = wsdl_data.get("endpoint", base_url)
    namespace  = wsdl_data.get("namespace", "")
    operations = wsdl_data.get("operations", [])

    print(f"[+] Service endpoint: {endpoint}")
    print(f"[+] Target namespace: {namespace}")
    print(f"[+] Operations discovered: {len(operations)}")

    for op in operations:
        print(f"    → {op['name']} | SOAPAction: {op['soap_action']}")
        for param in op.get("parameters", []):
            print(f"       param: {param['name']} ({param['type']})")

    # Step 4: Flag sensitive-sounding operations
    for op in operations:
        op_name_lower = op["name"].lower()

        for keyword in SENSITIVE_OPERATION_KEYWORDS:
            if keyword in op_name_lower:
                finding = {
                    "title":    f"Sensitive Operation Exposed in WSDL: {op['name']}",
                    "protocol": "SOAP",
                    "owasp":    map_owasp("API7"),
                    "cvss":     calculate_cvss(
                                    protocol="SOAP",
                                    auth_required=False,
                                    data_exposed="admin_operation_name",
                                    privilege_escalation=True
                                ),
                    "severity": "High",
                    "description": (
                        f"The operation '{op['name']}' is publicly listed in the WSDL "
                        f"and its name suggests privileged or administrative functionality. "
                        f"SOAPAction: {op['soap_action']}. "
                        f"An attacker can attempt to call this operation directly."
                    ),
                    "evidence": (
                        f"Operation name: {op['name']}\n"
                        f"SOAPAction: {op['soap_action']}\n"
                        f"Parameters: {[p['name'] for p in op.get('parameters', [])]}"
                    ),
                    "remediation": (
                        "Remove internal and admin operations from the public-facing WSDL. "
                        "Apply authentication and authorization checks at the operation level, "
                        "not just at the network perimeter."
                    ),
                    "soap_skeleton": build_soap_skeleton(op, namespace)
                }
                findings.append(finding)
                log_event(
                    "SENSITIVE_OPERATION",
                    f"{base_url}#{op['name']}",
                    0,
                    f"Sensitive operation found: {op['name']}"
                )
                break  # One finding per operation is enough

    # Step 5: Flag operations with IDOR-risk parameters
    for op in operations:
        for param in op.get("parameters", []):
            param_name_lower = param["name"].lower()
            for keyword in IDOR_PARAMETER_KEYWORDS:
                if keyword in param_name_lower:
                    finding = {
                        "title":    f"IDOR Risk Parameter in Operation: {op['name']}",
                        "protocol": "SOAP",
                        "owasp":    map_owasp("API1"),
                        "cvss":     calculate_cvss(
                                        protocol="SOAP",
                                        auth_required=True,
                                        data_exposed="object_reference",
                                        privilege_escalation=False
                                    ),
                        "severity": "Medium",
                        "description": (
                            f"The operation '{op['name']}' accepts a parameter "
                            f"'{param['name']}' which appears to be a direct object "
                            f"reference. If authorization is not enforced server-side, "
                            f"an attacker can enumerate IDs to access other users' data."
                        ),
                        "evidence": (
                            f"Operation: {op['name']}\n"
                            f"Parameter: {param['name']} (type: {param['type']})\n"
                            f"SOAPAction: {op['soap_action']}"
                        ),
                        "remediation": (
                            "Validate that the authenticated user is authorized to access "
                            "the requested object ID on every SOAP operation call. "
                            "Do not rely on obscurity of IDs."
                        ),
                        "soap_skeleton": build_soap_skeleton(op, namespace)
                    }
                    findings.append(finding)
                    log_event(
                        "IDOR_RISK_PARAM",
                        f"{base_url}#{op['name']}.{param['name']}",
                        0,
                        f"IDOR-risk parameter: {param['name']}"
                    )
                    break

    print(f"\n[+] WSDL enumeration complete. {len(findings)} findings.")
    return findings
