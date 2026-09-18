import argparse
import csv
import logging
import os
import sys
import json
from datetime import datetime

import requests
import urllib3
from fpdf import FPDF
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from utils.reporting import generate_report

from discovery.protocol_detector import detect_protocol, DetectionResult

from discovery.swagger_parser import (
    fetch_swagger_spec,
    extract_endpoints,
    filter_idor_candidates,
    filter_mass_assignment_candidates,
    build_test_url,
)

from utils.helpers import (
    load_wordlist,
    DEFAULT_ID_WORDLIST,
    DEFAULT_PARAM_WORDLIST,
    tag_finding_with_owasp,
    print_owasp_coverage_table,
    build_param_candidate_list,
)

from scanners.soap.wsdl_enum import run_wsdl_enumeration

from scanners.graphql.introspection import (
    check_introspection,
    get_schema_for_other_modules,
)

from scanners.graphql.depth_limit import run_depth_limit_scan
from scanners.graphql.field_auth import run_field_auth_scan
from scanners.graphql.batch_abuse import check_batch_abuse

from scanners.rest.idor import test_single_endpoint
from scanners.jwt import analyse_jwt, print_jwt_findings
from scanners.rest.rate_limit import run_rate_limit_scan

from discovery.swagger_parser import discover_rest_params
from discovery.wsdl_parser import extract_soap_params
from discovery.graphql_schema import extract_graphql_input_args


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)

logger = logging.getLogger(__name__)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="aegis-api",
        description="Aegis-API — Unified API Security Scanner (REST | SOAP | GraphQL)"
    )

    parser.add_argument(
        "-t",
        "--target",
        required=True,
        help="Base URL of the target API"
    )

    parser.add_argument(
        "-a",
        "--auth",
        required=False,
        default=None,
        help="JWT token for authentication (omit 'Bearer ' prefix)"
    )

    parser.add_argument(
        "--protocol",
        required=False,
        default="auto",
        choices=["auto", "rest", "soap", "graphql"],
        help="API protocol to scan. 'auto' runs detection first (default: auto)"
    )

    parser.add_argument(
        "-w",
        "--wordlist",
        required=False,
        help="Path to ID wordlist for IDOR testing"
    )

    parser.add_argument(
        "-p",
        "--params",
        required=False,
        help="Path to parameter wordlist for mass assignment testing"
    )

    parser.add_argument(
        "--proxy",
        required=False,
        default="http://127.0.0.1:8080",
        help="Proxy URL for traffic interception"
    )

    parser.add_argument(
        "--no-proxy",
        action="store_true",
        help="Disable proxy routing entirely"
    )

    parser.add_argument(
        "--ci-mode",
        action="store_true",
        help="Enable CI/CD mode: output GitHub Actions annotations and set exit code based on findings."
    )

    parser.add_argument(
        "--fail-threshold",
        required=False,
        default="high",
        choices=["critical", "high", "medium", "low"],
        help="Minimum severity level that causes the pipeline to fail (default: high)."
    )

    return parser.parse_args()


def build_session(
    jwt_token: str | None,
    proxy_url: str | None = None
) -> requests.Session:

    session = requests.Session()

    headers = {
        "Content-Type": "application/json",
        "User-Agent": "AegisAPI/2.0"
    }

    if jwt_token:
        headers["Authorization"] = f"Bearer {jwt_token}"

    session.headers.update(headers)

    if proxy_url:
        session.proxies.update({
            "http": proxy_url,
            "https": proxy_url
        })

    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=[
            "HEAD",
            "GET",
            "PUT",
            "POST",
            "DELETE",
            "OPTIONS"
        ]
    )

    adapter = HTTPAdapter(max_retries=retry_strategy)

    session.mount("http://", adapter)
    session.mount("https://", adapter)

    return session


def append_to_audit_log(
    filename: str = "audit_log.csv",
    timestamp: str = None,
    method: str = None,
    url: str = None,
    status_code: int = None,
    payload: str = None
) -> None:

    file_exists = os.path.isfile(filename)

    row = [
        timestamp or datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        method or "N/A",
        url or "N/A",
        str(status_code) if status_code is not None else "N/A",
        str(payload) if payload else "None"
    ]

    try:
        with open(
            filename,
            mode="a",
            newline="",
            encoding="utf-8"
        ) as f:

            writer = csv.writer(f)

            if not file_exists:
                writer.writerow([
                    "Timestamp",
                    "Method",
                    "URL",
                    "Status Code",
                    "Payload"
                ])

            writer.writerow(row)

    except IOError as e:
        logger.error("Error writing to audit log: %s", e)


def check_connectivity(
    session: requests.Session,
    target_url: str
) -> bool:

    try:
        response = session.get(
            target_url.rstrip("/"),
            timeout=5,
            verify=False
        )

        logger.info(
            "Target reachable — status: %s",
            response.status_code
        )

        print(
            f"[+] Target reachable. Status: {response.status_code}"
        )

        return True

    except requests.exceptions.RequestException as e:

        logger.error(
            "Cannot reach target: %s",
            e
        )

        print(
            f"[-] Cannot reach target: {e}"
        )

        return False


def scan_mass_assignment(
    session: requests.Session,
    target_url: str,
    endpoint: str,
    base_payload: dict,
    param_wordlist: list
) -> list:

    print(
        "\n[*] Starting mass assignment scan (OWASP API3)"
    )

    url = f"{target_url.rstrip('/')}{endpoint}"

    findings = []

    for param in param_wordlist:

        test_payload = base_payload.copy()
        test_payload[param] = True

        print(
            f"[*] Injecting parameter '{param}' into {url}"
        )

        try:

            response = session.put(
                url,
                json=test_payload,
                timeout=5,
                verify=False
            )

            append_to_audit_log(
                method="PUT",
                url=url,
                status_code=response.status_code,
                payload=f"injected_param={param}"
            )

            if response.status_code in [200, 201]:

                print(
                    f"[!] Potential mass assignment: "
                    f"server accepted '{param}' "
                    f"(status {response.status_code})"
                )

                findings.append({
                    "type": "Mass Assignment",
                    "protocol": "REST",
                    "owasp": (
                        "API3:2023 - "
                        "Broken Object Property Level Authorization"
                    ),
                    "url": url,
                    "injected_param": param,
                    "status": response.status_code,
                    "evidence": {
                        "injected_parameter": param,
                        "response_status": response.status_code
                    }
                })

            else:

                print(
                    f"[-] Parameter '{param}' rejected "
                    f"(status {response.status_code})"
                )

        except requests.exceptions.RequestException as e:

            print(
                f"[!] Request failed while testing "
                f"'{param}': {e}"
            )

            continue

    return findings


_FALLBACK_IDOR_ENDPOINT = "/workshop/api/shop/orders/{id}"

_FALLBACK_MA_ENDPOINT = "/identity/api/v2/user/videos/1"

_FALLBACK_MA_BASE_PAYLOAD = {
    "videoName": "test",
    "conversionParams": "-vcodec libx264"
}


def _run_swagger_discovery(
    session: requests.Session,
    target_url: str
) -> tuple[list, list, list]:

    print(
        "\n[*] Starting Swagger/OpenAPI discovery..."
    )

    spec_result = fetch_swagger_spec(
        target_url,
        session
    )

    if not spec_result:

        print(
            "[*] No OpenAPI spec found — "
            "falling back to hardcoded endpoints."
        )

        idor_targets = [
            {
                "method": "GET",
                "path": _FALLBACK_IDOR_ENDPOINT,
                "path_params": ["id"],
                "body_fields": []
            }
        ]

        mass_targets = [
            {
                "method": "PUT",
                "path": _FALLBACK_MA_ENDPOINT,
                "path_params": [],
                "body_fields": list(
                    _FALLBACK_MA_BASE_PAYLOAD.keys()
                )
            }
        ]

        return [], idor_targets, mass_targets

    all_endpoints = extract_endpoints(
        spec_result["spec"]
    )

    idor_targets = filter_idor_candidates(
        all_endpoints
    )

    mass_targets = filter_mass_assignment_candidates(
        all_endpoints
    )

    print(
        f"[+] Spec discovered at : {spec_result['url']}"
    )

    print(
        f"[+] Total endpoints    : {len(all_endpoints)}"
    )

    print(
        f"[+] IDOR candidates    : {len(idor_targets)}"
    )

    print(
        f"[+] Mass-assign targets: {len(mass_targets)}"
    )

    swagger_finding = {
        "type": "Security Misconfiguration",
        "protocol": "REST",
        "owasp": "API7:2023 - Security Misconfiguration",
        "url": spec_result["url"],
        "status": 200,
        "evidence": {
            "detail": (
                f"OpenAPI spec publicly accessible at "
                f"{spec_result['url']}"
            ),
            "endpoint_count": len(all_endpoints),
        }
    }

    return [
        swagger_finding
    ], idor_targets, mass_targets


def run_rest_scan(
    args: argparse.Namespace
) -> list:

    if not args.auth:

        print(
            "[!] REST scanning requires a JWT token. "
            "Use -a / --auth."
        )

        sys.exit(1)

    proxy = None if args.no_proxy else args.proxy

    session = build_session(
        args.auth,
        proxy_url=proxy
    )

    if not check_connectivity(
        session,
        args.target
    ):
        sys.exit(1)

    print(
        "\n[*] JWT Security Analysis (OWASP API2)"
    )

    jwt_result = analyse_jwt(
        args.auth,
        protocol="REST"
    )

    print_jwt_findings(
        jwt_result
    )

    jwt_report_findings = []

    for f in jwt_result.get(
        "findings",
        []
    ):

        jwt_report_findings.append({
            "type": f["check"],
            "title": f["check"],
            "protocol": "REST",
            "owasp": f["owasp"],
            "url": args.target,
            "status": "N/A",
            "evidence": {
                "detail": f["description"],
                "severity": f["severity"],
                "remediation": f["remediation"],
                "raw": f.get("evidence", ""),
            },
        })

    id_wordlist = load_wordlist(
        args.wordlist,
        DEFAULT_ID_WORDLIST
    )

    param_wordlist = load_wordlist(
        args.params,
        DEFAULT_PARAM_WORDLIST
    )

    swagger_findings, idor_targets, mass_targets = (
        _run_swagger_discovery(
            session,
            args.target
        )
    )

    print(
        "\n[*] REST Parameter Discovery"
    )

    auto_rest_params = discover_rest_params(
        session=session,
        base_url=args.target,
        mass_targets=mass_targets,
    )

    final_param_wordlist = build_param_candidate_list(
        discovered=auto_rest_params,
        wordlist=param_wordlist,
        override=bool(args.params),
    )

    print(
        f"[+] Parameter candidates: "
        f"{len(final_param_wordlist)} "
        f"({'user override' if args.params else 'auto-discovered + defaults'})"
    )

    if auto_rest_params:

        print(
            f"[+] Auto-discovered params: "
            f"{auto_rest_params}"
        )

    print(
        "\n[*] Starting IDOR scan (OWASP API1 — BOLA)"
    )

    idor_results = []

    for target in idor_targets:

        path_template = target["path"]

        url = build_test_url(
            args.target,
            path_template,
            param_value="2"
        )

        finding = test_single_endpoint(
            url,
            args.auth,
            session
        )

        if finding:

            print(
                f"[!] FINDING: {finding['title']}"
            )

            print(
                f"    URL     : "
                f"{finding['evidence']['url']}"
            )

            print(
                f"    Auth status   : "
                f"{finding['evidence']['auth_status_code']}"
            )

            print(
                f"    Unauth status : "
                f"{finding['evidence']['unauth_status_code']}"
            )

            print(
                f"    Similarity    : "
                f"{finding['evidence']['similarity_ratio']}"
            )

            print(
                f"    OWASP   : "
                f"{finding['owasp']}"
            )

            idor_results.append(
                finding
            )

        else:

            print(
                f"[-] No IDOR detected at {url}"
            )

    print(
        f"[*] IDOR scan complete — "
        f"{len(idor_results)} finding(s)"
    )

    ma_results = []

    for target in mass_targets:

        if target.get("body_fields"):

            base_payload = {
                field: "test"
                for field in target["body_fields"]
            }

        else:

            base_payload = (
                _FALLBACK_MA_BASE_PAYLOAD.copy()
            )

        results = scan_mass_assignment(
            session,
            args.target,
            target["path"],
            base_payload,
            final_param_wordlist,
        )

        ma_results.extend(
            results
        )

    print(
        f"[*] Mass assignment scan complete — "
        f"{len(ma_results)} finding(s)"
    )

    print(
        "\n[*] Rate Limit Detection (OWASP API4)"
    )

    rate_limit_results = run_rate_limit_scan(
        session=session,
        base_url=args.target,
        endpoint_path=None,
        burst_count=50,
    )

    print(
        f"[*] Rate limit scan complete — "
        f"{len(rate_limit_results)} finding(s)"
    )

    return (
        swagger_findings
        + jwt_report_findings
        + idor_results
        + ma_results
        + rate_limit_results
    )


def run_soap_scan(
    args: argparse.Namespace
) -> list:

    print(
        "\n[*] Protocol: SOAP — "
        "Starting SOAP scan chain"
    )

    proxy = None if args.no_proxy else args.proxy

    proxies = (
        {
            "http": proxy,
            "https": proxy
        }
        if proxy
        else None
    )

    param_wordlist = load_wordlist(
        args.params,
        DEFAULT_PARAM_WORDLIST
    )

    findings = []

    wsdl_findings = run_wsdl_enumeration(
        args.target,
        proxies=proxies
    )

    findings.extend(
        wsdl_findings
    )

    print(
        "\n[*] SOAP Parameter Discovery "
        "(WSDL input elements)"
    )

    auto_soap_params = extract_soap_params(
        target_url=args.target,
        wsdl_findings=wsdl_findings,
        proxies=proxies,
    )

    final_soap_params = build_param_candidate_list(
        discovered=auto_soap_params,
        wordlist=param_wordlist,
        override=bool(args.params),
    )

    print(
        f"[+] SOAP parameter candidates: "
        f"{len(final_soap_params)} "
        f"({'user override' if args.params else 'auto-discovered + defaults'})"
    )

    if auto_soap_params:

        print(
            f"[+] Auto-discovered WSDL elements: "
            f"{auto_soap_params}"
        )

    for finding in findings:

        if finding.get(
            "type"
        ) == "WSDL Operation Discovered":

            finding.setdefault(
                "evidence",
                {}
            )

            finding["evidence"][
                "param_candidates"
            ] = final_soap_params

    print(
        f"\n[*] SOAP scan complete — "
        f"{len(findings)} finding(s)"
    )

    return findings


def run_graphql_scan(
    args: argparse.Namespace
) -> list:

    print(
        "\n[*] Protocol: GraphQL — "
        "Starting GraphQL scan chain"
    )

    proxy = None if args.no_proxy else args.proxy

    proxies = (
        {
            "http": proxy,
            "https": proxy
        }
        if proxy
        else None
    )

    session = build_session(
        jwt_token=args.auth,
        proxy_url=proxy
    )

    param_wordlist = load_wordlist(
        args.params,
        DEFAULT_PARAM_WORDLIST
    )

    if not check_connectivity(
        session,
        args.target
    ):
        sys.exit(1)

    findings = []

    if args.auth:

        print(
            "\n[*] JWT Security Analysis (OWASP API2)"
        )

        jwt_result = analyse_jwt(
            args.auth,
            protocol="GraphQL"
        )

        print_jwt_findings(
            jwt_result
        )

        for f in jwt_result.get(
            "findings",
            []
        ):

            findings.append({
                "type": f["check"],
                "title": f["check"],
                "protocol": "GraphQL",
                "owasp": f["owasp"],
                "url": args.target,
                "status": "N/A",
                "evidence": {
                    "detail": f["description"],
                    "severity": f["severity"],
                    "remediation": f["remediation"],
                    "raw": f.get("evidence", ""),
                },
            })

    else:

        print(
            "\n[*] JWT Analysis skipped "
            "(no --auth token provided)"
        )

    print(
        "\n[*] GraphQL Introspection Scanner"
    )

    introspection_findings = check_introspection(
        args.target,
        session
    )

    findings.extend(
        introspection_findings
    )

    print(
        f"[*] Introspection scan complete — "
        f"{len(introspection_findings)} finding(s)"
    )

    schema = get_schema_for_other_modules(
        args.target,
        session
    )

    print(
        "\n[*] GraphQL Parameter Discovery "
        "(INPUT_OBJECT arguments)"
    )

    auto_graphql_params = extract_graphql_input_args(
        schema
    )

    final_graphql_params = build_param_candidate_list(
        discovered=auto_graphql_params,
        wordlist=param_wordlist,
        override=bool(args.params),
    )

    print(
        f"[+] GraphQL parameter candidates: "
        f"{len(final_graphql_params)} "
        f"({'user override' if args.params else 'auto-discovered + defaults'})"
    )

    if auto_graphql_params:

        print(
            f"[+] Auto-discovered input args: "
            f"{auto_graphql_params}"
        )

    type_map = {}

    if schema is not None:

        for gql_type in schema.types:

            if gql_type.fields:

                type_map[
                    gql_type.name
                ] = {
                    f.name: f.type_name
                    for f in gql_type.fields
                }

    print(
        "\n[*] GraphQL Depth Limit Scanner"
    )

    depth_findings = run_depth_limit_scan(
        session=session,
        target_url=args.target,
        type_map=type_map,
        audit_logger=None,
    )

    findings.extend(
        depth_findings
    )

    print(
        f"[*] Depth limit scan complete — "
        f"{len(depth_findings)} finding(s)"
    )

    raw_schema: dict = {
        "types": []
    }

    query_names: list = []

    if schema is not None:

        raw_types = []

        for gql_type in schema.types:

            raw_types.append({
                "name": gql_type.name,
                "kind": gql_type.kind,
                "fields": [
                    {
                        "name": f.name,
                        "type": {
                            "name": f.type_name
                        }
                    }
                    for f in gql_type.fields
                ]
            })

        raw_schema = {
            "types": raw_types
        }

        for gql_type in schema.types:

            if gql_type.name == schema.query_type:

                query_names = [
                    f.name
                    for f in gql_type.fields
                ]

                break

    print(
        "\n[*] GraphQL Field Auth Scanner"
    )

    field_findings = run_field_auth_scan(
        url=args.target,
        session=session,
        schema=schema,
        token=args.auth,
        param_candidates=final_graphql_params,
    )

    findings.extend(
        field_findings
    )

    print(
        f"[*] Field auth scan complete — "
        f"{len(field_findings)} finding(s)"
    )

    print(
        "\n[*] GraphQL Batch Abuse Scanner"
    )

    batch_findings = check_batch_abuse(
        args.target,
        session,
        schema=schema,
        param_candidates=final_graphql_params,
    )

    findings.extend(
        batch_findings
    )

    print(
        f"[*] Batch abuse scan complete — "
        f"{len(batch_findings)} finding(s)"
    )

    print(
        f"\n[*] GraphQL scan chain complete — "
        f"{len(findings)} total finding(s)"
    )

    return findings


def resolve_protocol(
    args: argparse.Namespace
) -> DetectionResult:

    if args.protocol != "auto":

        logger.info(
            "Protocol manually specified: %s",
            args.protocol.upper()
        )

        return DetectionResult(
            protocol=args.protocol.upper(),
            confidence="HIGH",
            signals=[
                "Protocol manually specified via "
                "--protocol flag"
            ],
            base_url=args.target
        )

    print(
        "[*] Running protocol auto-detection...\n"
    )

    proxy = None if args.no_proxy else args.proxy

    result = detect_protocol(
        args.target,
        proxy=proxy
    )

    print(
        f"[+] Protocol detected : "
        f"{result.protocol}"
    )

    print(
        f"[+] Confidence        : "
        f"{result.confidence}"
    )

    print(
        "[+] Evidence signals  :"
    )

    for signal in result.signals:

        print(
            f"      - {signal}"
        )

    print()

    return result


def route_to_scanner(
    result: DetectionResult,
    args: argparse.Namespace
) -> list:

    protocol = result.protocol

    if protocol == "REST":

        logger.info(
            "Routing to REST scanner chain"
        )

        return run_rest_scan(
            args
        )

    elif protocol == "SOAP":

        logger.info(
            "Routing to SOAP scanner chain"
        )

        return run_soap_scan(
            args
        )

    elif protocol == "GRAPHQL":

        logger.info(
            "Routing to GraphQL scanner chain"
        )

        return run_graphql_scan(
            args
        )

    else:

        print(
            "[!] Protocol could not be determined automatically."
        )

        print(
            "    Re-run with "
            "--protocol rest / soap / graphql "
            "to specify manually."
        )

        sys.exit(1)


class VaptReport(FPDF):

    def header(self):

        self.set_font(
            "Arial",
            "B",
            15
        )

        self.cell(
            0,
            10,
            "Aegis-API Unified Security Assessment Report",
            border=0,
            ln=1,
            align="C"
        )

        self.ln(5)

    def footer(self):

        self.set_y(-15)

        self.set_font(
            "Arial",
            "I",
            8
        )

        self.cell(
            0,
            10,
            f"Page {self.page_no()}",
            border=0,
            align="C"
        )


def generate_pdf_report(
    findings: list,
    output_path: str = "reports/VAPT_Report.pdf"
) -> None:

    print(
        f"\n[*] Generating PDF report: "
        f"{output_path}"
    )

    os.makedirs(
        os.path.dirname(output_path),
        exist_ok=True
    )

    pdf = VaptReport()

    pdf.add_page()

    def _safe(text: str) -> str:

        return (
            str(text)
            .replace("\u2014", "-")
            .replace("\u2013", "-")
            .replace("\u2018", "'")
            .replace("\u2019", "'")
            .replace("\u201c", '"')
            .replace("\u201d", '"')
            .replace("\u2026", "...")
            .encode(
                "latin-1",
                errors="replace"
            )
            .decode("latin-1")
        )

    if not findings:

        pdf.set_font(
            "Arial",
            size=12
        )

        pdf.cell(
            0,
            10,
            "Scan complete. No vulnerabilities found.",
            ln=True
        )

    else:

        for finding in findings:

            pdf.set_font(
                "Arial",
                "B",
                13
            )

            pdf.set_text_color(
                180,
                0,
                0
            )

            finding_name = (
                finding.get("type")
                or finding.get(
                    "title",
                    "Unknown Finding"
                )
            )

            pdf.cell(
                0,
                10,
                f"Finding: {_safe(finding_name)}",
                ln=True
            )

            pdf.set_font(
                "Arial",
                size=10
            )

            pdf.set_text_color(
                0,
                0,
                0
            )

            pdf.cell(
                0,
                6,
                f"Protocol: "
                f"{_safe(finding.get('protocol', 'N/A'))}",
                ln=True
            )

            pdf.cell(
                0,
                6,
                f"OWASP: "
                f"{_safe(finding.get('owasp', 'N/A'))}",
                ln=True
            )

            pdf.cell(
                0,
                6,
                f"URL: "
                f"{_safe(finding.get('url', 'N/A'))}",
                ln=True
            )

            pdf.cell(
                0,
                6,
                f"Status: "
                f"{_safe(finding.get('status', 'N/A'))}",
                ln=True
            )

            cvss_score = finding.get(
                "cvss_score",
                "N/A"
            )

            cvss_label = finding.get(
                "severity",
                "N/A"
            )

            cvss_vector = finding.get(
                "cvss_vector",
                "N/A"
            )

            pdf.cell(
                0,
                6,
                f"CVSS Score : "
                f"{_safe(str(cvss_score))} "
                f"({_safe(cvss_label)})",
                ln=True
            )

            pdf.cell(
                0,
                6,
                f"CVSS Vector: "
                f"{_safe(cvss_vector)}",
                ln=True
            )

    try:

        pdf.output(
            output_path
        )

        print(
            f"[+] PDF report written to: "
            f"{output_path}"
        )

    except Exception as e:

        logger.error(
            "Failed to write PDF report: %s",
            e
        )

        print(
            f"[-] Failed to write PDF report: {e}"
        )


def save_evidence_file(
    findings: list,
    output_path: str = "reports/evidence.txt"
) -> None:

    print(
        f"[*] Writing evidence file: "
        f"{output_path}"
    )

    os.makedirs(
        os.path.dirname(output_path),
        exist_ok=True
    )

    try:

        with open(
            output_path,
            "w",
            encoding="utf-8"
        ) as f:

            f.write(
                "=" * 60
                + "\n"
            )

            f.write(
                f"Aegis-API Evidence File — "
                f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            )

            f.write(
                "=" * 60
                + "\n\n"
            )

            if not findings:

                f.write(
                    "No findings to record.\n"
                )

                return

            for finding in findings:

                finding_name = (
                    finding.get("type")
                    or finding.get(
                        "title",
                        "Unknown Finding"
                    )
                )

                f.write(
                    f"Type:     {finding_name}\n"
                )

                f.write(
                    f"Protocol: "
                    f"{finding.get('protocol', 'N/A')}\n"
                )

                f.write(
                    f"OWASP:    "
                    f"{finding.get('owasp', 'N/A')}\n"
                )

                f.write(
                    f"URL:      "
                    f"{finding.get('url', 'N/A')}\n"
                )

                f.write(
                    f"Status:   "
                    f"{finding.get('status', 'N/A')}\n"
                )

                f.write(
                    "Evidence:\n"
                )

                f.write(
                    json.dumps(
                        finding.get(
                            "evidence",
                            {}
                        ),
                        indent=2
                    )
                )

                f.write(
                    "\n"
                    + "-" * 60
                    + "\n\n"
                )

        print(
            f"[+] Evidence written to: "
            f"{output_path}"
        )

    except IOError as e:

        logger.error(
            "Error writing evidence file: %s",
            e
        )

        print(
            f"[-] Error writing evidence file: {e}"
        )


def main() -> None:

    args = parse_arguments()

    print(
        f"\n{'=' * 57}"
    )

    print(
        "      AEGIS-API — Unified API Security Scanner"
    )

    print(
        "        REST  |  SOAP  |  GraphQL"
    )

    print(
        f"{'=' * 57}\n"
    )

    print(
        f"[*] Target   : {args.target}"
    )

    print(
        f"[*] Protocol : {args.protocol}"
    )

    if not args.no_proxy:

        print(
            f"[*] Proxy    : {args.proxy}"
        )

    print()

    detection_result = resolve_protocol(
        args
    )

    all_findings = route_to_scanner(
        detection_result,
        args
    )

    print(
        f"\n[*] Scan complete — "
        f"{len(all_findings)} total finding(s)"
    )

    for finding in all_findings:

        tag_finding_with_owasp(
            finding
        )

    protocols_scanned = list({
        f.get(
            "protocol",
            "REST"
        )
        for f in all_findings
    })

    print_owasp_coverage_table(
        protocols_scanned
    )

    save_evidence_file(
        all_findings
    )

    target_urls = {
        detection_result.protocol.capitalize():
        args.target
    }

    tool_config = {
        "target": args.target,
        "protocol": args.protocol,
        "proxy": (
            args.proxy
            if not args.no_proxy
            else "disabled"
        ),
        "auth_provided": bool(
            args.auth
        ),
        "wordlist": (
            args.wordlist
            or "default"
        ),
        "params": (
            args.params
            or "default"
        ),
    }

    raw_logs = []

    try:

        with open(
            "reports/evidence.txt",
            encoding="utf-8"
        ) as f:

            raw_logs = f.readlines()

    except FileNotFoundError:

        pass

    generate_report(
        findings=all_findings,
        target_urls=target_urls,
        tool_config=tool_config,
        raw_logs=raw_logs,
        output_dir="reports",
    )

    from utils.ci_reporter import run_ci_report

    run_ci_report(
        findings=all_findings,
        protocol=detection_result.protocol,
        fail_threshold=args.fail_threshold,
    )


if __name__ == "__main__":
    main()
