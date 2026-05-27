# discovery/wsdl_parser.py
# Fetches and parses a SOAP WSDL document.
# Extracts all operations, their parameters, SOAPAction values,
# and the service endpoint URL.
# Protocol: SOAP only
# Used by: scanners/soap/wsdl_enum.py, scanners/soap/xxe.py

import requests
import xml.etree.ElementTree as ET
from utils.logger import log_event

# XML namespace URIs used in WSDL documents.
# ElementTree requires full namespace URI in curly braces, not the prefix.
WSDL_NS   = "http://schemas.xmlsoap.org/wsdl/"
SOAP_NS   = "http://schemas.xmlsoap.org/wsdl/soap/"
XSD_NS    = "http://www.w3.org/2001/XMLSchema"
SOAP12_NS = "http://schemas.xmlsoap.org/wsdl/soap12/"


def fetch_wsdl(base_url: str, proxies: dict = None, timeout: int = 10) -> str | None:
    """
    Attempts to retrieve the WSDL document from a SOAP service.
    Tries both ?wsdl and ?WSDL suffixes (some servers are case-sensitive).

    Returns the raw WSDL XML string, or None if not found.
    """
    # Servers may respond to ?wsdl or ?WSDL — try both
    suffixes = ["?wsdl", "?WSDL"]

    for suffix in suffixes:
        url = base_url.rstrip("/") + suffix
        try:
            response = requests.get(
                url,
                proxies=proxies,
                timeout=timeout,
                verify=False  # Lab environments often use self-signed certs
            )

            # A valid WSDL response must be XML — check Content-Type
            content_type = response.headers.get("Content-Type", "")
            if response.status_code == 200 and (
                "xml" in content_type or response.text.strip().startswith("<?xml")
            ):
                print(f"[+] WSDL found at: {url}")
                log_event("WSDL_FETCH", url, response.status_code, "WSDL document retrieved")
                return response.text

        except requests.exceptions.RequestException as e:
            print(f"[-] Could not reach {url}: {e}")

    print("[-] No WSDL document found at this target.")
    return None


def parse_wsdl(wsdl_xml: str) -> dict:
    """
    Parses a WSDL XML string and extracts:
    - Service endpoint URL
    - All operations with their SOAPAction values
    - All input parameters per operation (from XSD types)

    Returns a structured dict the scanner modules can consume.
    """
    try:
        root = ET.fromstring(wsdl_xml)
    except ET.ParseError as e:
        print(f"[-] WSDL XML parsing failed: {e}")
        return {}

    result = {
        "endpoint":   None,
        "namespace":  root.attrib.get("targetNamespace", ""),
        "operations": []
    }

    # --- Extract the service endpoint URL ---
    # Look for <soap:address location="..."/> inside <wsdl:service>
    for port in root.iter(f"{{{WSDL_NS}}}port"):
        for addr in port:
            if addr.tag in (
                f"{{{SOAP_NS}}}address",
                f"{{{SOAP12_NS}}}address"
            ):
                result["endpoint"] = addr.attrib.get("location")
                break

    # --- Extract SOAPAction values from the binding section ---
    # Build a map: operation_name -> soapAction value
    soap_action_map = {}
    for binding in root.iter(f"{{{WSDL_NS}}}binding"):
        for op in binding.iter(f"{{{WSDL_NS}}}operation"):
            op_name = op.attrib.get("name", "")
            # The <soap:operation> child carries the soapAction attribute
            for child in op:
                if child.tag in (
                    f"{{{SOAP_NS}}}operation",
                    f"{{{SOAP12_NS}}}operation"
                ):
                    soap_action_map[op_name] = child.attrib.get("soapAction", "")

    # --- Extract operations from portType ---
    # portType lists all operations the service exposes
    for port_type in root.iter(f"{{{WSDL_NS}}}portType"):
        for op in port_type.iter(f"{{{WSDL_NS}}}operation"):
            op_name = op.attrib.get("name", "")
            operation = {
                "name":        op_name,
                "soap_action": soap_action_map.get(op_name, ""),
                "parameters":  []
            }
            result["operations"].append(operation)

    # --- Extract input parameters from XSD type definitions ---
    # Each <xsd:element> inside <xsd:complexType><xsd:sequence> is a parameter
    # We build a map: element_name -> list of parameter names
    param_map = {}
    for schema in root.iter(f"{{{XSD_NS}}}schema"):
        for element in schema.iter(f"{{{XSD_NS}}}element"):
            element_name = element.attrib.get("name", "")
            params = []
            # Walk into complexType -> sequence to find child elements
            for child_elem in element.iter(f"{{{XSD_NS}}}element"):
                param_name = child_elem.attrib.get("name", "")
                param_type = child_elem.attrib.get("type", "xsd:string")
                if param_name and param_name != element_name:
                    params.append({
                        "name": param_name,
                        "type": param_type
                    })
            if params:
                param_map[element_name] = params

    # Match parameters to operations by convention:
    # Operation "GetUser" uses input element "GetUserRequest"
    for operation in result["operations"]:
        request_element = operation["name"] + "Request"
        if request_element in param_map:
            operation["parameters"] = param_map[request_element]

    return result


def build_soap_skeleton(operation: dict, namespace: str) -> str:
    """
    Builds a minimal valid SOAP request XML body for a given operation.
    Uses placeholder values for each parameter.
    This skeleton is what XXE and injection modules inject payloads into.

    Example output for GetUser with userId parameter:
    <soap:Envelope ...>
      <soap:Body>
        <GetUser xmlns="...">
          <userId>1</userId>
        </GetUser>
      </soap:Body>
    </soap:Envelope>
    """
    op_name = operation["name"]
    params  = operation.get("parameters", [])

    # Build the inner parameter XML lines
    param_lines = []
    for param in params:
        pname = param["name"]
        ptype = param.get("type", "xsd:string")

        # Use a sensible default value based on the parameter type
        if "int" in ptype.lower():
            default_val = "1"
        elif "bool" in ptype.lower():
            default_val = "false"
        else:
            default_val = "test"

        param_lines.append(f"      <{pname}>{default_val}</{pname}>")

    params_xml = "\n".join(param_lines)

    skeleton = f"""<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope
    xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
    xmlns:tns="{namespace}">
  <soap:Body>
    <tns:{op_name}>
{params_xml}
    </tns:{op_name}>
  </soap:Body>
</soap:Envelope>"""

    return skeleton



# ─────────────────────────────────────────────────────────────────────────────
# PHASE 15 — addition to discovery/wsdl_parser.py
# Paste this function at the BOTTOM of your existing wsdl_parser.py
# ─────────────────────────────────────────────────────────────────────────────


def extract_wsdl_param_names(wsdl_result: dict) -> list:
    """
    Flatten all parameter names from every WSDL operation into a single
    deduplicated list, ready for injection testing.

    Args:
        wsdl_result: dict returned by parse_wsdl() — expected structure:
                     { "operations": [ { "params": ["ParamA", "ParamB"] }, ... ] }

    Returns:
        Deduplicated list of parameter name strings across all operations.
    """
    all_params = []

    operations = wsdl_result.get("operations", []) if wsdl_result else []
    for operation in operations:
        params = operation.get("params", []) or []
        all_params.extend(params)

    return list(set(all_params))


def extract_soap_params(
    target_url: str,
    wsdl_findings: list = None,
    proxies: dict = None,
    session=None,
) -> list:
    """
    Phase 15 — SOAP parameter discovery.
    Uses stdlib xml.etree.ElementTree (no lxml dependency).
    """
    import xml.etree.ElementTree as ET

    discovered = []

    # ── Source 1: Pull params from already-parsed wsdl_findings ──────────────
    if wsdl_findings:
        for finding in wsdl_findings:
            for p in finding.get("parameters", []):
                if isinstance(p, dict):
                    name = p.get("name", "")
                    if name:
                        discovered.append(name)
                elif isinstance(p, str) and p:
                    discovered.append(p)
            for p in finding.get("params", []):
                if isinstance(p, str) and p:
                    discovered.append(p)

    # ── Source 2: Re-fetch WSDL if nothing found ─────────────────────────────
    if not discovered:
        wsdl_url = target_url.rstrip("/") + "?wsdl"
        try:
            if session:
                resp = session.get(wsdl_url, timeout=10)
            else:
                resp = requests.get(
                    wsdl_url,
                    proxies=proxies or {},
                    timeout=10,
                    verify=False,
                )
            resp.raise_for_status()
            root = ET.fromstring(resp.content)

            for msg in root.iter(f"{{{WSDL_NS}}}message"):
                for part in msg.iter(f"{{{WSDL_NS}}}part"):
                    name = part.get("name")
                    if name:
                        discovered.append(name)

        except Exception as e:
            print(f"[wsdl_parser] extract_soap_params failed: {e}")

    return list({p for p in discovered if p})
