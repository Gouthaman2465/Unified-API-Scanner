"""
main.py — Aegis-API Unified Framework Entry Point

Flow:
  1. Parse CLI arguments
  2. Detect or accept protocol (Phase 2)
  3. Route to correct scanner chain
  4. Run scans (REST, SOAP, GraphQL)
  5. Generate unified report

Protocols supported: REST (active), SOAP (Phase 4+), GraphQL (Phase 5+)

Phase 15 additions:
  - REST  : discover_rest_params() extracts field names from swagger spec +
            live JSON responses; build_param_candidate_list() merges them with
            the default wordlist (or the user's -p override) before mass
            assignment scanning begins.
  - SOAP  : extract_soap_params() pulls XML element names from every WSDL
            operation discovered in Phase 4; the merged list feeds into the
            XXE / XML-injection modules.
  - GraphQL: extract_graphql_input_args() reads INPUT_OBJECT argument names
            from the introspection schema and feeds them into the field-auth
            and batch-abuse modules.
  In all three protocols the -p / --params flag acts as a hard override:
  when it is provided the user's wordlist replaces auto-discovered params
  entirely.
"""

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
    tag_finding_with_owasp,        # ← Phase 17
    print_owasp_coverage_table,    # ← Phase 17
)
from scanners.soap.wsdl_enum import run_wsdl_enumeration
from scanners.graphql.introspection import check_introspection, get_schema_for_other_modules
from scanners.graphql.depth_limit import run_depth_limit_scan
from scanners.graphql.field_auth import run_field_auth_scan
from scanners.graphql.batch_abuse import check_batch_abuse
from scanners.rest.idor import test_single_endpoint
from scanners.jwt import analyse_jwt, print_jwt_findings
from scanners.rest.rate_limit import run_rate_limit_scan
from discovery.wsdl_parser import extract_soap_params   # Phase 15




# ── Phase 15 imports ──────────────────────────────────────────────────────
# REST  : discover_rest_params extracts field names from spec + JSON bodies.
# SOAP  : extract_soap_params pulls XML element names from WSDL operations.
# GraphQL: extract_graphql_input_args reads INPUT_OBJECT arg names from schema.
# All three feed into build_param_candidate_list in utils/helpers.py which
# merges auto-discovered names with the default wordlist (or the -p override).
from discovery.swagger_parser import discover_rest_params
from discovery.wsdl_parser import extract_soap_params          # Phase 15
from discovery.graphql_schema import extract_graphql_input_args # Phase 15
from utils.helpers import build_param_candidate_list
# ─────────────────────────────────────────────────────────────────────────

from utils.reporting import generate_report

# Suppress SSL warnings when routing through Burp Suite proxy
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# All modules share this logger — output goes to the same stream
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# CLI ARGUMENT PARSING
# ---------------------------------------------------------------------------

def parse_arguments() -> argparse.Namespace:
    """
    Define and parse all CLI arguments for Aegis-API.

    Phase 2 adds:
      --protocol  auto/rest/soap/graphql (default: auto)

    Phase 18 adds:
      --ci-mode        Enable GitHub Actions annotation output + exit code gate
      --fail-threshold Minimum severity that fails the CI pipeline (default: high)

    Existing arguments preserved:
      -t / --target   Base URL of the target API
      -a / --auth     JWT token for authenticated scanning
      -w / --wordlist ID wordlist for IDOR testing
      -p / --params   Parameter wordlist for mass assignment testing
      --proxy         Proxy URL for traffic interception
      --no-proxy      Disable proxy routing entirely
    """
    parser = argparse.ArgumentParser(
        prog="aegis-api",
        description="Aegis-API — Unified API Security Scanner (REST | SOAP | GraphQL)"
    )
    parser.add_argument(
        "-t", "--target", required=True,
        help="Base URL of the target API (e.g. http://127.0.0.1:8888)"
    )
    parser.add_argument(
        "-a", "--auth", required=False, default=None,
        help="JWT token for authentication (omit 'Bearer ' prefix)"
    )
    parser.add_argument(
        "--protocol", required=False, default="auto",
        choices=["auto", "rest", "soap", "graphql"],
        help="API protocol to scan. 'auto' runs detection first (default: auto)"
    )
    parser.add_argument(
        "-w", "--wordlist", required=False,
        help="Path to ID wordlist for IDOR testing"
    )
    parser.add_argument(
        "-p", "--params", required=False,
        help="Path to parameter wordlist for mass assignment testing"
    )
    parser.add_argument(
        "--proxy", required=False, default="http://127.0.0.1:8080",
        help="Proxy URL for traffic interception (default: Burp at 127.0.0.1:8080)"
    )
    parser.add_argument(
        "--no-proxy", action="store_true",
        help="Disable proxy routing entirely"
    )
    parser.add_argument(
        "--ci-mode", action="store_true",
        help="Enable CI/CD mode: output GitHub Actions annotations and set exit code based on findings."
    )
    parser.add_argument(
        "--fail-threshold", required=False, default="high",
        choices=["critical", "high", "medium", "low"],
        help="Minimum severity level that causes the pipeline to fail (default: high)."
    )
    return parser.parse_args()
    
    
# ---------------------------------------------------------------------------
# HTTP SESSION
# ---------------------------------------------------------------------------

def build_session(jwt_token: str | None, proxy_url: str | None = None) -> requests.Session:
    """
    Build a persistent HTTP session with authentication headers,
    optional proxy routing, and exponential backoff retry logic.

    429 is intentionally excluded from the retry list — rate limit
    responses are findings, not transient errors to be silently retried.

    Args:
        jwt_token  : JWT bearer token, or None for unauthenticated scanning
        proxy_url  : Proxy URL string, or None to skip proxy

    Returns:
        Configured requests.Session instance
    """
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
        # 429 excluded — rate limit signals must be detected, not retried
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "PUT", "POST", "DELETE", "OPTIONS"]
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


# ---------------------------------------------------------------------------
# AUDIT LOGGING
# ---------------------------------------------------------------------------

def append_to_audit_log(filename: str = "audit_log.csv", timestamp: str = None,
                         method: str = None, url: str = None,
                         status_code: int = None, payload: str = None) -> None:
    """
    Append one HTTP transaction to the CSV audit log.
    Writes the header row only if the file does not already exist.

    Args:
        filename    : Path to the CSV audit log file
        timestamp   : ISO timestamp string (defaults to now)
        method      : HTTP method string (GET, POST, PUT, etc.)
        url         : Full request URL
        status_code : HTTP response status code
        payload     : Payload or parameter string for evidence
    """
    file_exists = os.path.isfile(filename)
    row = [
        timestamp or datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        method or "N/A",
        url or "N/A",
        str(status_code) if status_code is not None else "N/A",
        str(payload) if payload else "None"
    ]
    try:
        with open(filename, mode='a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow(["Timestamp", "Method", "URL", "Status Code", "Payload"])
            writer.writerow(row)
    except IOError as e:
        logger.error("Error writing to audit log: %s", e)


# ---------------------------------------------------------------------------
# CONNECTIVITY CHECK
# ---------------------------------------------------------------------------

def check_connectivity(session: requests.Session, target_url: str) -> bool:
    """
    Send a lightweight GET to the target root to verify connectivity
    before starting any scan. Does not assume any specific path.

    Args:
        session    : Configured requests.Session
        target_url : Base URL of the target

    Returns:
        True if target responds, False if unreachable
    """
    try:
        response = session.get(target_url.rstrip("/"), timeout=5, verify=False)
        logger.info("Target reachable — status: %s", response.status_code)
        print(f"[+] Target reachable. Status: {response.status_code}")
        return True
    except requests.exceptions.RequestException as e:
        logger.error("Cannot reach target: %s", e)
        print(f"[-] Cannot reach target: {e}")
        return False


# ---------------------------------------------------------------------------
# REST SCANNER CHAIN
# ---------------------------------------------------------------------------

# scan_idor() removed in Phase 6 — replaced by scanners/rest/idor.py (heuristic diffing engine)

def scan_mass_assignment(session: requests.Session, target_url: str,
                          endpoint: str, base_payload: dict,
                          param_wordlist: list) -> list:
    """
    Test for Mass Assignment by injecting extra parameters into a PUT request
    and checking if the server accepts them.

    Note: Phase 4 will upgrade this to full state verification (GET before/after).
    Currently flags on status code only.

    Maps to: OWASP API3:2023 — Broken Object Property Level Authorization

    Args:
        session        : Authenticated requests.Session
        target_url     : Base URL of the target
        endpoint       : Specific endpoint path to target
        base_payload   : Legitimate request body to build on
        param_wordlist : List of privileged parameter names to inject

    Returns:
        List of finding dicts
    """
    print("\n[*] Starting mass assignment scan (OWASP API3)")
    url = f"{target_url.rstrip('/')}{endpoint}"
    findings = []

    for param in param_wordlist:
        test_payload = base_payload.copy()
        test_payload[param] = True
        print(f"[*] Injecting parameter '{param}' into {url}")

        try:
            response = session.put(url, json=test_payload, timeout=5, verify=False)
            append_to_audit_log(method="PUT", url=url,
                                 status_code=response.status_code,
                                 payload=f"injected_param={param}")

            if response.status_code in [200, 201]:
                print(f"[!] Potential mass assignment: server accepted '{param}' "
                      f"(status {response.status_code})")
                findings.append({
                    "type": "Mass Assignment",
                    "protocol": "REST",
                    "owasp": "API3:2023 - Broken Object Property Level Authorization",
                    "url": url,
                    "injected_param": param,
                    "status": response.status_code,
                    "evidence": {
                        "injected_parameter": param,
                        "response_status": response.status_code
                    }
                })
            else:
                print(f"[-] Parameter '{param}' rejected (status {response.status_code})")

        except requests.exceptions.RequestException as e:
            print(f"[!] Request failed while testing '{param}': {e}")
            continue

    return findings


# ---------------------------------------------------------------------------
# SWAGGER / OPENAPI DISCOVERY  (Phase 2)
# ---------------------------------------------------------------------------

# Hardcoded fallbacks used when no OpenAPI spec is discovered.
# These target crAPI's known endpoint layout and are replaced by
# spec-derived paths when discovery succeeds.
_FALLBACK_IDOR_ENDPOINT   = "/workshop/api/shop/orders/{id}"
_FALLBACK_MA_ENDPOINT     = "/identity/api/v2/user/videos/1"
_FALLBACK_MA_BASE_PAYLOAD = {"videoName": "test", "conversionParams": "-vcodec libx264"}


def _run_swagger_discovery(session: requests.Session, target_url: str) -> tuple[list, list, list]:
    """
    Attempt Swagger/OpenAPI spec discovery against the target.

    On success:
      - Parses the spec to extract all endpoints
      - Filters IDOR candidates (GET paths with path parameters)
      - Filters mass assignment candidates (PUT/PATCH paths with body fields)
      - Returns a swagger_exposure finding so the report flags the open spec

    On failure:
      - Falls back to the hardcoded crAPI endpoint constants above
      - Returns an empty swagger_findings list (nothing to flag)

    Args:
        session    : Authenticated requests.Session (already built)
        target_url : Base URL of the target

    Returns:
        Tuple of (swagger_findings, idor_targets, mass_targets) where:
          swagger_findings : [] or [{"type": "Security Misconfiguration", ...}]
          idor_targets     : list of endpoint dicts for scan_idor()
          mass_targets     : list of endpoint dicts for scan_mass_assignment()
    """
    print("\n[*] Starting Swagger/OpenAPI discovery...")
    spec_result = fetch_swagger_spec(target_url, session)

    if not spec_result:
        print("[*] No OpenAPI spec found — falling back to hardcoded endpoints.")
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
                "body_fields": list(_FALLBACK_MA_BASE_PAYLOAD.keys())
            }
        ]
        return [], idor_targets, mass_targets

    # Spec found — parse and filter
    all_endpoints = extract_endpoints(spec_result["spec"])
    idor_targets  = filter_idor_candidates(all_endpoints)
    mass_targets  = filter_mass_assignment_candidates(all_endpoints)

    print(f"[+] Spec discovered at : {spec_result['url']}")
    print(f"[+] Total endpoints    : {len(all_endpoints)}")
    print(f"[+] IDOR candidates    : {len(idor_targets)}")
    print(f"[+] Mass-assign targets: {len(mass_targets)}")

    # Flag the exposed spec as API7 — Security Misconfiguration
    swagger_finding = {
        "type": "Security Misconfiguration",
        "protocol": "REST",
        "owasp": "API7:2023 - Security Misconfiguration",
        "url": spec_result["url"],
        "status": 200,
        "evidence": {
            "detail": f"OpenAPI spec publicly accessible at {spec_result['url']}",
            "endpoint_count": len(all_endpoints),
        }
    }

    return [swagger_finding], idor_targets, mass_targets


def run_rest_scan(args: argparse.Namespace) -> list:
    """
    Orchestrates the full REST scanner chain.

    Phase 2  : Swagger/OpenAPI discovery builds the endpoint target lists.
    Phase 13 : JWT security analysis runs first so auth weaknesses lead the report.
    Phase 14 : Rate limit detection (burst testing against login endpoint).
    Phase 15 : Parameter discovery runs after swagger discovery.
               discover_rest_params() probes each mass-assignment target endpoint,
               parses the JSON response body, and merges the field names found with
               the names extracted from the swagger spec's requestBody/parameter
               definitions. The merged candidate list feeds directly into
               scan_mass_assignment(), replacing the plain DEFAULT_PARAM_WORDLIST.
               If the user passed -p / --params, that wordlist overrides the
               auto-discovered candidates entirely (override=True path).

    Args:
        args : Parsed CLI arguments namespace

    Returns:
        List of all findings from all REST scan modules
    """
    if not args.auth:
        print("[!] REST scanning requires a JWT token. Use -a / --auth.")
        sys.exit(1)

    proxy = None if args.no_proxy else args.proxy
    session = build_session(args.auth, proxy_url=proxy)

    if not check_connectivity(session, args.target):
        sys.exit(1)

    # ── Phase 13: JWT Security Analysis (OWASP API2) ──────────────────
    print("\n[*] Phase 13 — JWT Security Analysis (OWASP API2)")
    jwt_result = analyse_jwt(args.auth, protocol="REST")
    print_jwt_findings(jwt_result)

    jwt_report_findings = []
    for f in jwt_result.get("findings", []):
        jwt_report_findings.append({
            "type":     f["check"],
            "title":    f["check"],
            "protocol": "REST",
            "owasp":    f["owasp"],
            "url":      args.target,
            "status":   "N/A",
            "evidence": {
                "detail":      f["description"],
                "severity":    f["severity"],
                "remediation": f["remediation"],
                "raw":         f.get("evidence", ""),
            },
        })
    # ──────────────────────────────────────────────────────────────────

    id_wordlist    = load_wordlist(args.wordlist, DEFAULT_ID_WORDLIST)
    param_wordlist = load_wordlist(args.params,   DEFAULT_PARAM_WORDLIST)

    # ── Phase 2: Swagger discovery ─────────────────────────────────────
    swagger_findings, idor_targets, mass_targets = _run_swagger_discovery(
        session, args.target
    )
    # ──────────────────────────────────────────────────────────────────

    # ── Phase 15: REST Parameter Discovery ────────────────────────────
    # discover_rest_params() does two things:
    #   1. Reads requestBody / parameter field names from the swagger spec
    #      (if spec discovery succeeded).
    #   2. Sends a live GET to each mass-assignment target endpoint and
    #      parses every key in the returned JSON object as a candidate
    #      parameter name (response-field extraction).
    # The union of those two sources is the auto-discovered candidate list.
    #
    # build_param_candidate_list() then decides the final list:
    #   - override=True  → user passed -p; ignore auto-discovered names,
    #                       use only the user's wordlist.
    #   - override=False → merge auto-discovered names with the default
    #                       wordlist, deduplicate, preserve order.
    print("\n[*] Phase 15 — REST Parameter Discovery")
    auto_rest_params = discover_rest_params(
        session=session,
        base_url=args.target,
        mass_targets=mass_targets,
    )
    final_param_wordlist = build_param_candidate_list(
        discovered=auto_rest_params,
        wordlist=param_wordlist,
        override=bool(args.params),   # True when user passed -p explicitly
    )
    print(f"[+] Parameter candidates: {len(final_param_wordlist)} "
          f"({'user override' if args.params else 'auto-discovered + defaults'})")
    if auto_rest_params:
        print(f"[+] Auto-discovered params: {auto_rest_params}")
    # ──────────────────────────────────────────────────────────────────

    # ── IDOR scan using heuristic diffing engine (Phase 6) ────────────
    print("\n[*] Starting IDOR scan (OWASP API1 — BOLA)")
    idor_results = []
    for target in idor_targets:
        path_template = target["path"]
        url = build_test_url(args.target, path_template, param_value="2")

        finding = test_single_endpoint(url, args.auth, session)
        if finding:
            print(f"[!] FINDING: {finding['title']}")
            print(f"    URL     : {finding['evidence']['url']}")
            print(f"    Auth status   : {finding['evidence']['auth_status_code']}")
            print(f"    Unauth status : {finding['evidence']['unauth_status_code']}")
            print(f"    Similarity    : {finding['evidence']['similarity_ratio']}")
            print(f"    OWASP   : {finding['owasp']}")
            idor_results.append(finding)
        else:
            print(f"[-] No IDOR detected at {url}")

    print(f"[*] IDOR scan complete — {len(idor_results)} finding(s)")
    # ──────────────────────────────────────────────────────────────────

    # ── Mass assignment scan (now uses Phase 15 candidate list) ────────
    # final_param_wordlist replaces the plain DEFAULT_PARAM_WORDLIST that
    # was used in Phase 14 and earlier. It contains auto-discovered field
    # names from the spec + live responses (or the user's -p override).
    ma_results = []
    for target in mass_targets:
        if target.get("body_fields"):
            base_payload = {field: "test" for field in target["body_fields"]}
        else:
            base_payload = _FALLBACK_MA_BASE_PAYLOAD.copy()

        results = scan_mass_assignment(
            session, args.target, target["path"], base_payload,
            final_param_wordlist,   # ← Phase 15: enriched candidate list
        )
        ma_results.extend(results)

    print(f"[*] Mass assignment scan complete — {len(ma_results)} finding(s)")
    # ──────────────────────────────────────────────────────────────────

    # ── Phase 14: Rate Limit Detection (OWASP API4) ───────────────────
    print("\n[*] Phase 14 — Rate Limit Detection (OWASP API4)")
    rate_limit_results = run_rate_limit_scan(
        session=session,
        base_url=args.target,
        endpoint_path=None,
        burst_count=50,
    )
    print(f"[*] Rate limit scan complete — {len(rate_limit_results)} finding(s)")
    # ──────────────────────────────────────────────────────────────────

    return swagger_findings + jwt_report_findings + idor_results + ma_results + rate_limit_results


# ---------------------------------------------------------------------------
# SOAP SCANNER CHAIN
# ---------------------------------------------------------------------------

def run_soap_scan(args: argparse.Namespace) -> list:
    """
    SOAP scanner chain — orchestrates all SOAP scan phases.

    Phase 4  : WSDL enumeration (information disclosure + operation discovery).
    Phase 15 : Parameter discovery from WSDL.
               extract_soap_params() reads every <element> and <part> from
               the WSDL input message definitions and returns their names as
               parameter candidates. These feed into the XXE and XML-injection
               modules (Phases 8 and 9) so they know which XML fields to target
               instead of guessing.
               If the user passed -p, that wordlist overrides auto-discovery.

    Future phases will add:
      - XXE injection (Phase 8)
      - XML injection + WS-Security analysis (Phase 9)

    Args:
        args : Parsed CLI arguments namespace

    Returns:
        List of all findings from all SOAP scan modules
    """
    print("\n[*] Protocol: SOAP — Starting SOAP scan chain")

    proxy = None if args.no_proxy else args.proxy
    proxies = {"http": proxy, "https": proxy} if proxy else None

    param_wordlist = load_wordlist(args.params, DEFAULT_PARAM_WORDLIST)

    findings = []

    # ── Phase 4: WSDL enumeration ──────────────────────────────────────
    wsdl_findings = run_wsdl_enumeration(args.target, proxies=proxies)
    findings.extend(wsdl_findings)
    # ──────────────────────────────────────────────────────────────────

    # ── Phase 15: SOAP Parameter Discovery ────────────────────────────
    # extract_soap_params() parses each discovered WSDL operation finding
    # for its input element names. For example, a getUserById operation
    # will have an element named "userId" — that name is a candidate for
    # XXE injection and XML-injection payloads.
    # build_param_candidate_list() merges with defaults or honours -p override.
    print("\n[*] Phase 15 — SOAP Parameter Discovery (WSDL input elements)")
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
    print(f"[+] SOAP parameter candidates: {len(final_soap_params)} "
          f"({'user override' if args.params else 'auto-discovered + defaults'})")
    if auto_soap_params:
        print(f"[+] Auto-discovered WSDL elements: {auto_soap_params}")

    # Attach the discovered parameter list to every WSDL operation finding
    # so that Phase 8 (XXE) and Phase 9 (XML injection) can consume it
    # without re-parsing the WSDL themselves.
    for finding in findings:
        if finding.get("type") == "WSDL Operation Discovered":
            finding.setdefault("evidence", {})
            finding["evidence"]["param_candidates"] = final_soap_params
    # ──────────────────────────────────────────────────────────────────

    print(f"\n[*] SOAP scan complete — {len(findings)} finding(s)")
    return findings


# ---------------------------------------------------------------------------
# GRAPHQL SCANNER CHAIN
# ---------------------------------------------------------------------------

def run_graphql_scan(args: argparse.Namespace) -> list:
    """
    GraphQL scanner chain — orchestrates all GraphQL scan phases.

    Phase 5  : Introspection abuse + field suggestion probing.
    Phase 10 : Query depth limit attack (OWASP API4).
    Phase 11 : Field-level authorization bypass (OWASP API1 + API2).
    Phase 12 : Batch abuse — array batching + alias rate-limit bypass.
    Phase 13 : JWT security analysis (shared with REST).
    Phase 15 : GraphQL parameter discovery from introspection schema.
               extract_graphql_input_args() walks every INPUT_OBJECT type in
               the schema and collects all argument names. These are the fields
               that callers can supply to mutations and queries — exactly the
               fields to target for mass-assignment-style injection via GraphQL
               mutations (OWASP API3) and field-auth bypass (OWASP API1/API2).
               The enriched list replaces the plain DEFAULT_PARAM_WORDLIST fed
               to run_field_auth_scan and check_batch_abuse.
               If the user passed -p, that wordlist overrides auto-discovery.

    Args:
        args : Parsed CLI arguments namespace

    Returns:
        List of all findings from all GraphQL scan modules
    """
    print("\n[*] Protocol: GraphQL — Starting GraphQL scan chain")

    proxy = None if args.no_proxy else args.proxy
    proxies = {"http": proxy, "https": proxy} if proxy else None

    session = build_session(jwt_token=args.auth, proxy_url=proxy)
    param_wordlist = load_wordlist(args.params, DEFAULT_PARAM_WORDLIST)

    if not check_connectivity(session, args.target):
        sys.exit(1)

    findings = []

    # ── Phase 13: JWT Security Analysis (OWASP API2) ──────────────────
    if args.auth:
        print("\n[*] Phase 13 — JWT Security Analysis (OWASP API2)")
        jwt_result = analyse_jwt(args.auth, protocol="GraphQL")
        print_jwt_findings(jwt_result)

        for f in jwt_result.get("findings", []):
            findings.append({
                "type":     f["check"],
                "title":    f["check"],
                "protocol": "GraphQL",
                "owasp":    f["owasp"],
                "url":      args.target,
                "status":   "N/A",
                "evidence": {
                    "detail":      f["description"],
                    "severity":    f["severity"],
                    "remediation": f["remediation"],
                    "raw":         f.get("evidence", ""),
                },
            })
    else:
        print("\n[*] Phase 13 — JWT Analysis skipped (no --auth token provided)")
    # ──────────────────────────────────────────────────────────────────

    # ── Phase 5: Introspection abuse ──────────────────────────────────
    print("\n[*] Phase 5 — GraphQL Introspection Scanner")
    introspection_findings = check_introspection(args.target, session)
    findings.extend(introspection_findings)
    print(f"[*] Phase 5 complete — {len(introspection_findings)} finding(s)")

    # Fetch schema once — all downstream modules consume the same object.
    # Returns None when introspection is disabled; modules handle None safely.
    schema = get_schema_for_other_modules(args.target, session)
    # ──────────────────────────────────────────────────────────────────

    # ── Phase 15: GraphQL Parameter Discovery ─────────────────────────
    # extract_graphql_input_args() walks the schema's types list and
    # collects argument names from every INPUT_OBJECT. These represent the
    # actual fields the API accepts in mutations and queries — far richer
    # than a generic wordlist.
    # Example: a CreateUserInput type exposes { username, email, role, isAdmin }
    # and all four names become injection candidates for field-auth bypass.
    print("\n[*] Phase 15 — GraphQL Parameter Discovery (INPUT_OBJECT arguments)")
    auto_graphql_params = extract_graphql_input_args(schema)
    final_graphql_params = build_param_candidate_list(
        discovered=auto_graphql_params,
        wordlist=param_wordlist,
        override=bool(args.params),
    )
    print(f"[+] GraphQL parameter candidates: {len(final_graphql_params)} "
          f"({'user override' if args.params else 'auto-discovered + defaults'})")
    if auto_graphql_params:
        print(f"[+] Auto-discovered input args: {auto_graphql_params}")
    # ──────────────────────────────────────────────────────────────────

    # ── Phase 10: Query depth limit attack (OWASP API4) ───────────────
    print("\n[*] Phase 10 — GraphQL Depth Limit Scanner")
    type_map = {}
    if schema is not None:
        for gql_type in schema.types:
            if gql_type.fields:
                type_map[gql_type.name] = {f.name: f.type_name for f in gql_type.fields}

    depth_findings = run_depth_limit_scan(
        session=session,
        target_url=args.target,
        type_map=type_map,
        audit_logger=None,
    )
    findings.extend(depth_findings)
    print(f"[*] Phase 10 complete — {len(depth_findings)} finding(s)")
    # ──────────────────────────────────────────────────────────────────

    # ── Phase 11: Field-level authorization bypass (OWASP API1 + API2) ─
    # Phase 15 enriches the param candidates passed here so field_auth.py
    # tests every input argument the schema actually exposes, not just the
    # six entries in DEFAULT_PARAM_WORDLIST.
    print("\n[*] Phase 11 — GraphQL Field Auth Scanner")
    raw_schema: dict = {"types": []}
    query_names: list = []
    if schema is not None:
        raw_types = []
        for gql_type in schema.types:
            raw_types.append({
                "name": gql_type.name,
                "kind": gql_type.kind,
                "fields": [
                    {"name": f.name, "type": {"name": f.type_name}}
                    for f in gql_type.fields
                ]
            })
        raw_schema = {"types": raw_types}
        for gql_type in schema.types:
            if gql_type.name == schema.query_type:
                query_names = [f.name for f in gql_type.fields]
                break

    field_findings = run_field_auth_scan(
        url=args.target,
        session=session,
        schema=schema,
        token=args.auth,
        param_candidates=final_graphql_params,  # ← Phase 15: enriched list
    )
    findings.extend(field_findings)
    print(f"[*] Phase 11 complete — {len(field_findings)} finding(s)")
    # ──────────────────────────────────────────────────────────────────

    # ── Phase 12: Batch abuse (OWASP API4 + API2) ─────────────────────
    # Phase 15 passes the enriched param list so batch_abuse.py can
    # identify input fields the login mutation actually accepts.
    print("\n[*] Phase 12 — GraphQL Batch Abuse Scanner")
    batch_findings = check_batch_abuse(
        args.target,
        session,
        schema=schema,
        param_candidates=final_graphql_params,  # ← Phase 15: enriched list
    )
    findings.extend(batch_findings)
    print(f"[*] Phase 12 complete — {len(batch_findings)} finding(s)")
    # ──────────────────────────────────────────────────────────────────

    print(f"\n[*] GraphQL scan chain complete — {len(findings)} total finding(s)")
    return findings


# ---------------------------------------------------------------------------
# PROTOCOL ROUTER
# ---------------------------------------------------------------------------

def resolve_protocol(args: argparse.Namespace) -> DetectionResult:
    """
    Determines the target protocol by either:
      - Accepting the user's explicit --protocol flag (rest/soap/graphql), OR
      - Running auto-detection via protocol_detector.py (when --protocol auto)

    Args:
        args : Parsed CLI arguments namespace

    Returns:
        DetectionResult with resolved protocol, confidence, and signals
    """
    if args.protocol != "auto":
        logger.info("Protocol manually specified: %s", args.protocol.upper())
        return DetectionResult(
            protocol=args.protocol.upper(),
            confidence="HIGH",
            signals=["Protocol manually specified via --protocol flag"],
            base_url=args.target
        )

    print("[*] Running protocol auto-detection...\n")
    proxy = None if args.no_proxy else args.proxy
    result = detect_protocol(args.target, proxy=proxy)

    print(f"[+] Protocol detected : {result.protocol}")
    print(f"[+] Confidence        : {result.confidence}")
    print("[+] Evidence signals  :")
    for signal in result.signals:
        print(f"      - {signal}")
    print()

    return result


def route_to_scanner(result: DetectionResult, args: argparse.Namespace) -> list:
    """
    Routes to the correct scanner chain based on the resolved protocol.

    Args:
        result : DetectionResult from resolve_protocol()
        args   : Parsed CLI arguments namespace

    Returns:
        List of all findings from the selected scanner chain
    """
    protocol = result.protocol

    if protocol == "REST":
        logger.info("Routing to REST scanner chain")
        return run_rest_scan(args)

    elif protocol == "SOAP":
        logger.info("Routing to SOAP scanner chain")
        return run_soap_scan(args)

    elif protocol == "GRAPHQL":
        logger.info("Routing to GraphQL scanner chain")
        return run_graphql_scan(args)

    else:
        print("[!] Protocol could not be determined automatically.")
        print("    Re-run with --protocol rest / soap / graphql to specify manually.")
        sys.exit(1)


# ---------------------------------------------------------------------------
# REPORT GENERATION
# ---------------------------------------------------------------------------

class VaptReport(FPDF):
    """PDF report template with header and footer for all protocols."""

    def header(self):
        self.set_font("Arial", "B", 15)
        self.cell(
            0, 10,
            "Aegis-API Unified Security Assessment Report",
            border=0, ln=1, align="C"
        )
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font("Arial", "I", 8)
        self.cell(0, 10, f"Page {self.page_no()}", border=0, align="C")


def generate_pdf_report(findings: list,
                         output_path: str = "reports/VAPT_Report.pdf") -> None:
    """
    Generate a PDF report listing all findings with OWASP mapping.
    Includes a protocol column on each finding (added in Phase 2).

    Phase 19 will replace this with the full unified report structure
    (executive summary, scope, detailed findings, remediation table, appendix).

    Args:
        findings    : List of finding dicts from all scanner chains
        output_path : File path for the output PDF
    """
    print(f"\n[*] Generating PDF report: {output_path}")
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    pdf = VaptReport()
    pdf.add_page()

    def _safe(text: str) -> str:
        """
        Replace characters that latin-1 cannot encode.
        fpdf 1.7.2 encodes all text as latin-1 internally.
        Any character above U+00FF crashes the PDF writer.
        """
        return (
            str(text)
            .replace("\u2014", "-")
            .replace("\u2013", "-")
            .replace("\u2018", "'")
            .replace("\u2019", "'")
            .replace("\u201c", '"')
            .replace("\u201d", '"')
            .replace("\u2026", "...")
            .encode("latin-1", errors="replace")
            .decode("latin-1")
        )

    if not findings:
        pdf.set_font("Arial", size=12)
        pdf.cell(0, 10, "Scan complete. No vulnerabilities found.", ln=True)
    else:
        for finding in findings:
            pdf.set_font("Arial", "B", 13)
            pdf.set_text_color(180, 0, 0)

            finding_name = finding.get("type") or finding.get("title", "Unknown Finding")
            pdf.cell(0, 10, f"Finding: {_safe(finding_name)}", ln=True)

            pdf.set_font("Arial", size=10)
            pdf.set_text_color(0, 0, 0)

            pdf.cell(0, 6, f"Protocol: {_safe(finding.get('protocol', 'N/A'))}", ln=True)
            pdf.cell(0, 6, f"OWASP: {_safe(finding.get('owasp', 'N/A'))}", ln=True)
            pdf.cell(0, 6, f"URL: {_safe(finding.get('url', 'N/A'))}", ln=True)
            pdf.cell(0, 6, f"Status: {_safe(finding.get('status', 'N/A'))}", ln=True)

            # Phase 16 — read dynamic CVSS score attached by the scanner module.
            # compute_cvss_score() runs inside each scanner (idor.py, xxe.py, etc.)
            # main.py only reads what the scanner already put in the finding dict.
            cvss_score  = finding.get("cvss_score",  "N/A")
            cvss_label  = finding.get("severity",    "N/A")
            cvss_vector = finding.get("cvss_vector", "N/A")
            pdf.cell(0, 6, f"CVSS Score : {_safe(str(cvss_score))} ({_safe(cvss_label)})", ln=True)
            pdf.cell(0, 6, f"CVSS Vector: {_safe(cvss_vector)}", ln=True)

    try:
        pdf.output(output_path)
        print(f"[+] PDF report written to: {output_path}")
    except Exception as e:
        logger.error("Failed to write PDF report: %s", e)
        print(f"[-] Failed to write PDF report: {e}")


def save_evidence_file(findings: list,
                        output_path: str = "reports/evidence.txt") -> None:
    """
    Write raw request/response evidence for each finding to a text file.

    Args:
        findings    : List of finding dicts from all scanner chains
        output_path : File path for the evidence text file
    """
    print(f"[*] Writing evidence file: {output_path}")
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("=" * 60 + "\n")
            f.write(
                f"Aegis-API Evidence File — "
                f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            )
            f.write("=" * 60 + "\n\n")

            if not findings:
                f.write("No findings to record.\n")
                return

            for finding in findings:
                finding_name = finding.get("type") or finding.get("title", "Unknown Finding")
                f.write(f"Type:     {finding_name}\n")
                f.write(f"Protocol: {finding.get('protocol', 'N/A')}\n")
                f.write(f"OWASP:    {finding.get('owasp', 'N/A')}\n")
                f.write(f"URL:      {finding.get('url', 'N/A')}\n")
                f.write(f"Status:   {finding.get('status', 'N/A')}\n")
                f.write("Evidence:\n")
                f.write(json.dumps(finding.get("evidence", {}), indent=2))
                f.write("\n" + "-" * 60 + "\n\n")

        print(f"[+] Evidence written to: {output_path}")
    except IOError as e:
        logger.error("Error writing evidence file: %s", e)
        print(f"[-] Error writing evidence file: {e}")


# ---------------------------------------------------------------------------
# ENTRY POINT
# ---------------------------------------------------------------------------
def main() -> None:
    """
    Aegis-API entry point.
    """
    args = parse_arguments()

    print(f"\n{'='*57}")
    print("      AEGIS-API — Unified API Security Scanner")
    print("        REST  |  SOAP  |  GraphQL")
    print(f"{'='*57}\n")

    print(f"[*] Target   : {args.target}")
    print(f"[*] Protocol : {args.protocol}")

    if not args.no_proxy:
        print(f"[*] Proxy    : {args.proxy}")

    print()

    # Step 1: Detect or accept protocol
    detection_result = resolve_protocol(args)

    # Step 2: Route to correct scanner chain
    all_findings = route_to_scanner(detection_result, args)
    print(f"\n[*] Scan complete — {len(all_findings)} total finding(s)")

    # ── Phase 17: Enrich every finding with OWASP data ────────────────
    for finding in all_findings:
        tag_finding_with_owasp(finding)

    protocols_scanned = list({f.get("protocol", "REST") for f in all_findings})
    print_owasp_coverage_table(protocols_scanned)
    # ──────────────────────────────────────────────────────────────────


    # Step 3: Generate reports
    # save_evidence_file() runs first so the raw log text exists on disk
    # before generate_report() reads it back for the appendix section.
    save_evidence_file(all_findings)

    # Build target_urls from the detected protocol so the cover page
    # and scope section display the correct protocol label and URL.
    target_urls = {detection_result.protocol.capitalize(): args.target}

    # Capture CLI config for the appendix — gives the report reader
    # full reproducibility context without them having to guess how
    # the scan was run.
    tool_config = {
        "target":        args.target,
        "protocol":      args.protocol,
        "proxy":         args.proxy if not args.no_proxy else "disabled",
        "auth_provided": bool(args.auth),
        "wordlist":      args.wordlist or "default",
        "params":        args.params  or "default",
    }

    # Read the evidence file back as raw lines for the appendix.
    raw_logs = []
    try:
        with open("reports/evidence.txt", encoding="utf-8") as f:
            raw_logs = f.readlines()
    except FileNotFoundError:
        pass

    # Phase 19 — five-section unified VAPT report.
    generate_report(
        findings=all_findings,
        target_urls=target_urls,
        tool_config=tool_config,
        raw_logs=raw_logs,
        output_dir="reports",
    )

    # ── Phase 18: CI/CD Gate ──────────────────────────────────────────
    # run_ci_report() only activates when the CI environment variable is
    # set to "true" (GitHub Actions sets this automatically on every runner).
    # It emits GitHub annotations, prints a summary, then calls sys.exit()
    # with code 1 if any finding meets or exceeds --fail-threshold.
    # This must be the last call in main() because it calls sys.exit().
    from utils.ci_reporter import run_ci_report
    run_ci_report(
        findings=all_findings,
        protocol=detection_result.protocol,
        fail_threshold=args.fail_threshold, 
    )
    # ──────────────────────────────────────────────────────────────────


if __name__ == "__main__":
    main()
