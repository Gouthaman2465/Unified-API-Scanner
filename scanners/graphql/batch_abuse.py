# scanners/graphql/batch_abuse.py
# Protocol: GraphQL
# Phase 12: GraphQL Batch Abuse + Alias-Based Rate Limit Bypass
#
# OWASP Mappings:
#   API4:2023 - Unrestricted Resource Consumption (batching processes unlimited ops)
#   API2:2023 - Broken Authentication (login endpoints abusable via batching)
#
# Lab: DVGA (Damn Vulnerable GraphQL Application)
#   docker pull dolevf/dvga
#   docker run -p 5013:5013 dolevf/dvga
#   Target: http://localhost:5013/graphql

import time
import json
import logging
from typing import Optional, List, Dict, Any, Tuple

import requests

logger = logging.getLogger(__name__)


# ============================================================
# CONSTANTS
# ============================================================

# How many operations to put in the batch test.
# 10 is enough to prove the concept without hammering real servers.
# In a real pentest you might go up to 50 or 100.
BATCH_SIZE = 10

# If the server processed more than this fraction of batch requests
# without triggering rate limiting, we flag it as vulnerable.
VULNERABLE_THRESHOLD = 0.5  # 50%

# Dummy credentials for the batch login test.
# These won't actually succeed — we are testing whether the server
# PROCESSES them at all, not whether they log in.
DUMMY_EMAIL_TEMPLATE = "testuser{i}@aegis-scan.test"
DUMMY_PASSWORD = "AegisTestPassword123!"


# ============================================================
# PAYLOAD BUILDERS
# ============================================================

def build_array_batch_payload(query: str, count: int) -> List[Dict]:
    """
    Builds a JSON array of identical GraphQL operations.

    Array batching means sending a Python list of dicts —
    when serialized as JSON, this becomes [ {...}, {...}, ... ].

    Most GraphQL servers support this format natively.
    The server is expected to return a JSON array of responses,
    one per operation.

    Args:
        query:  A GraphQL query or mutation string.
        count:  How many copies to put in the batch.

    Returns:
        A Python list of dicts (serialize with json.dumps before sending).
    """
    return [{"query": query} for _ in range(count)]


def build_alias_batch_mutation(
    mutation_name: str,
    email_field: str,
    password_field: str,
    count: int
) -> str:
    """
    Builds a single GraphQL mutation document that calls the same
    mutation many times using aliases.

    Alias batching packs multiple operations into ONE GraphQL document,
    bypassing HTTP-level rate limiters entirely.

    Example output (count=3):
        mutation {
          attempt0: login(email: "testuser0@...", password: "...") { token }
          attempt1: login(email: "testuser1@...", password: "...") { token }
          attempt2: login(email: "testuser2@...", password: "...") { token }
        }

    Args:
        mutation_name:  The GraphQL mutation field (e.g., "login").
        email_field:    The argument name for the email/username.
        password_field: The argument name for the password.
        count:          Number of alias attempts to generate.

    Returns:
        A complete GraphQL mutation document string.
    """
    lines = []

    for i in range(count):
        email = DUMMY_EMAIL_TEMPLATE.format(i=i)
        # Each line is: aliasN: mutationName(email: "...", password: "...") { token }
        line = (
            f'  attempt{i}: {mutation_name}'
            f'({email_field}: "{email}", {password_field}: "{DUMMY_PASSWORD}") '
            f'{{ token }}'
        )
        lines.append(line)

    mutation_body = "mutation {\n" + "\n".join(lines) + "\n}"
    return mutation_body


def build_generic_alias_batch(
    query_field: str,
    count: int
) -> str:
    """
    Builds a generic alias batch query when no login mutation is available.

    Used when we cannot identify a login-specific mutation from the schema.
    Tests any available query field with aliases to confirm the server
    processes unlimited aliases per document.

    Args:
        query_field:  Any valid GraphQL query field name from the schema.
        count:        Number of aliases to send.

    Returns:
        A complete GraphQL query document string.
    """
    lines = []

    for i in range(count):
        line = f'  alias{i}: {query_field} {{ __typename }}'
        lines.append(line)

    return "query {\n" + "\n".join(lines) + "\n}"


# ============================================================
# LOGIN MUTATION DETECTION
# ============================================================

# Keywords that suggest a mutation is authentication-related.
# We check these against mutation names found in the schema.
AUTH_MUTATION_KEYWORDS = [
    "login", "signin", "sign_in", "authenticate",
    "auth", "logon", "token", "session"
]

# Common argument name patterns for email/username fields.
EMAIL_ARG_KEYWORDS = ["email", "username", "user", "login", "identifier"]

# Common argument name patterns for password fields.
PASSWORD_ARG_KEYWORDS = ["password", "passwd", "pass", "secret", "credential"]


def find_login_mutation(schema: Optional[Any]) -> Optional[Dict[str, str]]:
    """
    Searches the parsed GraphQL schema for a mutation that looks
    like a login or authentication operation.

    We look for mutations whose name contains one of the
    AUTH_MUTATION_KEYWORDS and that have both an email/username
    argument and a password argument.

    Args:
        schema: A GraphQLSchema object returned by graphql_schema.py,
                or None if introspection is disabled.

    Returns:
        A dict like:
          {
            "name": "login",
            "email_field": "email",
            "password_field": "password"
          }
        or None if no suitable mutation is found.
    """
    if schema is None:
        logger.info("[batch_abuse] No schema available — cannot detect login mutation.")
        return None

    for gql_type in schema.types:
        # Only look at mutation types
        if gql_type.name != schema.mutation_type:
            continue

        for field in gql_type.fields:
            # Check if the field name looks like an auth operation
            field_name_lower = field.name.lower()
            is_auth = any(kw in field_name_lower for kw in AUTH_MUTATION_KEYWORDS)

            if not is_auth:
                continue

            # Try to identify email and password arguments
            email_arg = None
            password_arg = None

            for arg in field.args:
                arg_lower = arg.name.lower()
                if any(kw in arg_lower for kw in EMAIL_ARG_KEYWORDS):
                    email_arg = arg.name
                if any(kw in arg_lower for kw in PASSWORD_ARG_KEYWORDS):
                    password_arg = arg.name

            # We need both arguments to be identifiable
            if email_arg and password_arg:
                logger.info(
                    "[batch_abuse] Found login mutation: %s(%s, %s)",
                    field.name, email_arg, password_arg
                )
                return {
                    "name": field.name,
                    "email_field": email_arg,
                    "password_field": password_arg
                }

    logger.info("[batch_abuse] No login mutation detected in schema.")
    return None


def find_any_query_field(schema: Optional[Any]) -> Optional[str]:
    """
    Returns the name of any available query field from the schema.

    Used as a fallback when no login mutation is found — we still
    want to test whether alias batching is possible at all.

    Args:
        schema: A GraphQLSchema object, or None.

    Returns:
        A field name string, or None.
    """
    if schema is None:
        return None

    for gql_type in schema.types:
        if gql_type.name == schema.query_type:
            if gql_type.fields:
                return gql_type.fields[0].name

    return None


# ============================================================
# TEST 1: ARRAY BATCH SUPPORT
# ============================================================

def run_array_batch_test(
    target_url: str,
    session: requests.Session
) -> Dict[str, Any]:
    """
    Tests whether the server accepts an array of GraphQL operations
    in a single POST request.

    This is the most common form of batching. A vulnerable server
    will return a JSON array of results, one per operation.
    A protected server will return an error or reject the array format.

    We use a harmless introspection probe (__typename) as the operation
    so we do not need authentication or valid mutations.

    Args:
        target_url: The GraphQL endpoint URL.
        session:    An authenticated requests.Session.

    Returns:
        A dict containing the test result:
          {
            "supported": bool,
            "operations_sent": int,
            "operations_processed": int,
            "status_code": int,
            "raw_response": str
          }
    """
    # A harmless probe — just asks for the root type name.
    probe_query = "{ __typename }"

    # Build an array of BATCH_SIZE identical probe operations.
    batch_payload = build_array_batch_payload(probe_query, BATCH_SIZE)

    logger.info(
        "[batch_abuse] Sending array batch of %d operations to %s",
        BATCH_SIZE, target_url
    )

    try:
        response = session.post(
            target_url,
            json=batch_payload,  # requests serializes the list as a JSON array
            timeout=15
        )

        raw_text = response.text[:500]  # Truncate for logging

        # A server that supports array batching returns a JSON array.
        # Each element in the array corresponds to one operation.
        operations_processed = 0
        supported = False

        if response.status_code == 200:
            try:
                parsed = response.json()
                if isinstance(parsed, list):
                    # Count how many responses have a "data" key — these were processed.
                    operations_processed = sum(
                        1 for item in parsed if isinstance(item, dict) and "data" in item
                    )
                    if operations_processed > 0:
                        supported = True
            except (ValueError, TypeError):
                pass  # Response was not valid JSON

        return {
            "supported": supported,
            "operations_sent": BATCH_SIZE,
            "operations_processed": operations_processed,
            "status_code": response.status_code,
            "raw_response": raw_text
        }

    except requests.exceptions.RequestException as err:
        logger.error("[batch_abuse] Array batch request failed: %s", err)
        return {
            "supported": False,
            "operations_sent": BATCH_SIZE,
            "operations_processed": 0,
            "status_code": 0,
            "raw_response": str(err)
        }


# ============================================================
# TEST 2: ALIAS BATCH SUPPORT
# ============================================================

def run_alias_batch_test(
    target_url: str,
    session: requests.Session,
    schema: Optional[Any]
) -> Dict[str, Any]:
    """
    Tests whether the server processes unlimited aliases in a single query.

    Alias batching is harder to defend against than array batching because
    it looks like a single, valid GraphQL operation — the server has to
    inspect the alias count to detect abuse.

    We try two approaches in order:
      1. If a login mutation is found, build an alias batch against it.
      2. Otherwise use a generic query field with aliases.

    Args:
        target_url: The GraphQL endpoint URL.
        session:    An authenticated requests.Session.
        schema:     Parsed GraphQL schema (or None).

    Returns:
        A dict containing the test result including the alias_count,
        whether the server processed all aliases, and the mutation
        targeted (if any).
    """
    # Try to find a login mutation to target specifically
    login_info = find_login_mutation(schema)

    if login_info:
        # Build an alias batch targeting the login mutation
        query_doc = build_alias_batch_mutation(
            mutation_name=login_info["name"],
            email_field=login_info["email_field"],
            password_field=login_info["password_field"],
            count=BATCH_SIZE
        )
        target_operation = login_info["name"]
        is_auth_targeted = True

    else:
        # Fall back to a generic query field
        query_field = find_any_query_field(schema)
        if query_field is None:
            # Last resort — use __typename which always exists
            query_field = "__typename"
            query_doc = f"query {{ " + " ".join(
                [f"a{i}: __typename" for i in range(BATCH_SIZE)]
            ) + " }"
        else:
            query_doc = build_generic_alias_batch(query_field, BATCH_SIZE)
        target_operation = query_field
        is_auth_targeted = False

    logger.info(
        "[batch_abuse] Sending alias batch of %d aliases targeting '%s'",
        BATCH_SIZE, target_operation
    )

    try:
        start_time = time.time()

        response = session.post(
            target_url,
            json={"query": query_doc},
            timeout=20
        )

        elapsed = round(time.time() - start_time, 3)

        # Parse how many aliases the server actually processed.
        # If the response data has BATCH_SIZE keys, all aliases were processed.
        aliases_processed = 0
        rate_limited = False

        if response.status_code == 429:
            rate_limited = True
        elif response.status_code == 200:
            try:
                parsed = response.json()
                data = parsed.get("data") or {}
                if isinstance(data, dict):
                    aliases_processed = len(data)
            except (ValueError, TypeError):
                pass

        return {
            "query_document": query_doc,
            "target_operation": target_operation,
            "is_auth_targeted": is_auth_targeted,
            "aliases_sent": BATCH_SIZE,
            "aliases_processed": aliases_processed,
            "rate_limited": rate_limited,
            "status_code": response.status_code,
            "elapsed_seconds": elapsed,
            "raw_response": response.text[:500]
        }

    except requests.exceptions.RequestException as err:
        logger.error("[batch_abuse] Alias batch request failed: %s", err)
        return {
            "query_document": query_doc,
            "target_operation": target_operation,
            "is_auth_targeted": is_auth_targeted,
            "aliases_sent": BATCH_SIZE,
            "aliases_processed": 0,
            "rate_limited": False,
            "status_code": 0,
            "elapsed_seconds": 0.0,
            "raw_response": str(err)
        }


# ============================================================
# TEST 3: RATE LIMIT VERIFICATION
# ============================================================

def verify_single_request_rate_limit(
    target_url: str,
    session: requests.Session
) -> Dict[str, Any]:
    """
    Sends individual requests one by one (no batching) to check
    whether rate limiting exists at all on the endpoint.

    This is the baseline check: if even individual requests are
    not rate-limited, the batch abuse finding is even more severe
    because there is no rate protection at any level.

    Sends BATCH_SIZE requests sequentially and counts how many
    receive a 429 Too Many Requests response.

    Args:
        target_url: The GraphQL endpoint URL.
        session:    An authenticated requests.Session.

    Returns:
        A dict summarising the rate limit behaviour observed.
    """
    probe_query = "{ __typename }"
    responses_429 = 0
    responses_200 = 0
    total_sent = BATCH_SIZE

    logger.info(
        "[batch_abuse] Sending %d individual requests to check rate limiting",
        total_sent
    )

    for i in range(total_sent):
        try:
            response = session.post(
                target_url,
                json={"query": probe_query},
                timeout=10
            )
            if response.status_code == 429:
                responses_429 += 1
            elif response.status_code == 200:
                responses_200 += 1
        except requests.exceptions.RequestException:
            pass  # Count as neither

    rate_limit_present = responses_429 > 0

    return {
        "requests_sent": total_sent,
        "responses_200": responses_200,
        "responses_429": responses_429,
        "rate_limit_present": rate_limit_present
    }


# ============================================================
# FINDING BUILDERS
# ============================================================

def build_array_batch_finding(
    array_result: Dict[str, Any],
    target_url: str
) -> Dict[str, Any]:
    """
    Converts the raw array batch test result into a structured finding.

    OWASP API4: Unrestricted Resource Consumption.
    The server processes N operations for the cost of 1 HTTP request.
    """
    return {
        "title": "GraphQL Array Batching Enabled — Unrestricted Operation Processing",
        "protocol": "GraphQL",
        "owasp": "API4:2023 - Unrestricted Resource Consumption",
        "severity": "High",
        "cvss_score": 7.5,
        "description": (
            "The GraphQL API accepts an array of operations in a single HTTP POST request "
            "(array batching). "
            f"In this test, {array_result['operations_processed']} of "
            f"{array_result['operations_sent']} batched operations were processed "
            "in a single HTTP request. "
            "This allows an attacker to amplify their request volume significantly "
            "while evading IP-based or request-count rate limiters. "
            "An attacker performing credential stuffing can test "
            f"{array_result['operations_sent']}× more passwords "
            "for every HTTP request the rate limiter counts."
        ),
        "evidence": {
            "target_url": target_url,
            "operations_sent": array_result["operations_sent"],
            "operations_processed": array_result["operations_processed"],
            "http_status": array_result["status_code"],
            "sample_payload": json.dumps(
                [{"query": "{ __typename }"}] * 2,
                indent=2
            )
        },
        "remediation": (
            "1. Disable array batching unless explicitly required. "
            "In Apollo Server: set allowBatchedHttpRequests: false. "
            "2. If batching is needed, enforce a maximum batch size (e.g., 5 operations). "
            "3. Apply rate limiting at the operation level, not just the HTTP request level. "
            "Consider using libraries like graphql-rate-limit."
        )
    }


def build_alias_batch_finding(
    alias_result: Dict[str, Any],
    target_url: str
) -> Dict[str, Any]:
    """
    Converts the raw alias batch test result into a structured finding.

    Two possible OWASP mappings depending on what was targeted:
    - API4 if a generic query was used (resource consumption)
    - API2 if a login mutation was targeted (broken authentication)
    """
    if alias_result["is_auth_targeted"]:
        owasp = "API2:2023 - Broken Authentication"
        severity = "Critical"
        cvss_score = 9.0
        title = (
            f"GraphQL Alias Batching Enables Credential Stuffing "
            f"via '{alias_result['target_operation']}' Mutation"
        )
        description = (
            f"The GraphQL API processes {alias_result['aliases_processed']} alias "
            f"calls to the '{alias_result['target_operation']}' authentication mutation "
            "within a single HTTP request, using the alias batching technique. "
            "An attacker can use GraphQL aliases to send dozens or hundreds of "
            "login attempts (each with a different username/password pair) "
            "in a single HTTP request, completely bypassing IP-based and "
            "request-count rate limiting. "
            "This is a classic GraphQL credential stuffing vector documented "
            "in multiple HackerOne bug bounty reports."
        )
        remediation = (
            "1. Apply rate limiting at the GraphQL resolver level, not just HTTP level. "
            "2. Detect and reject queries with excessive alias counts. "
            "Set a maximum alias count per query (e.g., 3). "
            "3. Add CAPTCHA or MFA to authentication flows. "
            "4. Monitor for failed login spikes from single IPs. "
            "5. Consider using a GraphQL-aware WAF or API gateway."
        )
    else:
        owasp = "API4:2023 - Unrestricted Resource Consumption"
        severity = "Medium"
        cvss_score = 6.5
        title = "GraphQL Alias Batching Enables Request Amplification"
        description = (
            f"The GraphQL API processes {alias_result['aliases_processed']} aliased "
            "fields within a single HTTP request. "
            "While no authentication endpoint was targeted in this specific test, "
            "this behaviour confirms the server applies no alias count restrictions. "
            "If an authentication mutation exists, it would be equally vulnerable "
            "to credential stuffing via this technique."
        )
        remediation = (
            "1. Enforce a maximum alias count per GraphQL document. "
            "2. Apply rate limiting at the resolver level. "
            "3. Use a query complexity analysis library to reject expensive queries."
        )

    return {
        "title": title,
        "protocol": "GraphQL",
        "owasp": owasp,
        "severity": severity,
        "cvss_score": cvss_score,
        "description": description,
        "evidence": {
            "target_url": target_url,
            "target_operation": alias_result["target_operation"],
            "aliases_sent": alias_result["aliases_sent"],
            "aliases_processed": alias_result["aliases_processed"],
            "http_status": alias_result["status_code"],
            "response_time_seconds": alias_result["elapsed_seconds"],
            "sample_query": alias_result["query_document"][:500]
        },
        "remediation": remediation
    }


# ============================================================
# MAIN ENTRY POINT
# ============================================================

def check_batch_abuse(
    target_url: str,
    session: requests.Session,
    schema: Optional[Any] = None,
    param_candidates: list = None,
) -> List[Dict[str, Any]]:
    """
    Main entry point for the GraphQL batch abuse scanner.

    Runs three sub-tests in sequence:
      1. Array batching — does the server accept a JSON array of operations?
      2. Alias batching — does the server process unlimited aliases per query?
      3. Rate limit baseline — does the server rate-limit individual requests?

    Results from tests 1 and 2 are converted to findings.
    The rate limit baseline enriches those findings with context.

    Called by main.py as part of the GraphQL scan chain.

    Args:
        target_url:  The GraphQL endpoint URL (e.g., http://target/graphql).
        session:     A requests.Session object (may carry auth headers).
        schema:      Optional parsed GraphQLSchema from the introspection module.
                     If None, schema-dependent features (login mutation detection)
                     are skipped gracefully.

    Returns:
        A list of finding dicts. Empty list = no batch abuse detected.
    """
    findings = []

    print(f"\n[*] Phase 12 — GraphQL Batch Abuse Scanner")
    print(f"[*] Target: {target_url}")
    print(f"[*] Batch size: {BATCH_SIZE} operations per test")

    # ----------------------------------------------------------
    # Test 1: Array Batching
    # ----------------------------------------------------------
    print(f"\n[*] Test 1: Checking array batch support...")
    array_result = run_array_batch_test(target_url, session)

    if array_result["supported"]:
        print(
            f"[!] VULNERABLE: Server processed {array_result['operations_processed']} "
            f"of {array_result['operations_sent']} batched operations."
        )
        findings.append(build_array_batch_finding(array_result, target_url))
    else:
        print(f"[+] Array batching not supported or blocked. Status: {array_result['status_code']}")

    # ----------------------------------------------------------
    # Test 2: Alias Batching
    # ----------------------------------------------------------
    print(f"\n[*] Test 2: Checking alias batch support...")
    alias_result = run_alias_batch_test(target_url, session, schema)

    # Flag as vulnerable if more than half the aliases were processed
    aliases_processed_ratio = (
        alias_result["aliases_processed"] / alias_result["aliases_sent"]
        if alias_result["aliases_sent"] > 0 else 0
    )

    if not alias_result["rate_limited"] and aliases_processed_ratio >= VULNERABLE_THRESHOLD:
        print(
            f"[!] VULNERABLE: Server processed {alias_result['aliases_processed']} "
            f"of {alias_result['aliases_sent']} aliases "
            f"targeting '{alias_result['target_operation']}'."
        )
        if alias_result["is_auth_targeted"]:
            print(f"[!] CRITICAL: Authentication mutation targeted — credential stuffing risk.")
        findings.append(build_alias_batch_finding(alias_result, target_url))
    elif alias_result["rate_limited"]:
        print(f"[+] Rate limiting triggered on alias batch (HTTP 429). Protected.")
    else:
        print(
            f"[+] Server processed {alias_result['aliases_processed']} of "
            f"{alias_result['aliases_sent']} aliases — below threshold."
        )

    # ----------------------------------------------------------
    # Test 3: Rate Limit Baseline
    # ----------------------------------------------------------
    print(f"\n[*] Test 3: Checking individual request rate limiting...")
    rl_result = verify_single_request_rate_limit(target_url, session)

    if not rl_result["rate_limit_present"] and findings:
        # No rate limiting at all, even for individual requests.
        # Add this as context to each finding we already have.
        for finding in findings:
            finding["evidence"]["no_individual_rate_limit"] = True
            finding["evidence"]["individual_requests_sent"] = rl_result["requests_sent"]
            finding["description"] += (
                " Additionally, no rate limiting was observed even for individual "
                "requests, meaning the endpoint has no protection at any level."
            )
        print(f"[!] No rate limiting detected even for individual requests.")
    elif rl_result["rate_limit_present"]:
        print(
            f"[+] Individual request rate limiting present "
            f"({rl_result['responses_429']} of {rl_result['requests_sent']} requests blocked). "
            f"Batch abuse bypasses this protection."
        )
    else:
        print(f"[+] Individual rate limit baseline: {rl_result['responses_200']} OK, "
              f"{rl_result['responses_429']} blocked.")

    # ----------------------------------------------------------
    # Summary
    # ----------------------------------------------------------
    if findings:
        print(f"\n[!] Batch abuse scan complete: {len(findings)} finding(s) found.")
    else:
        print(f"\n[+] Batch abuse scan complete: No vulnerabilities detected.")

    return findings
