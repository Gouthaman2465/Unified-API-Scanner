"""
scanners/graphql/field_auth.py

GraphQL Field-Level Authorization Bypass Scanner
Protocol: GraphQL
OWASP:    API1 (BOLA/IDOR) - unauthorized field access
          API2 (Broken Auth) - sensitive fields exposed without auth

What this module does:
  1. Takes a parsed GraphQL schema (from introspection module)
  2. Identifies fields with sensitive-sounding names
  3. Requests those fields without authentication
  4. Requests those fields with low-privilege auth
  5. Flags any field that returns data it should not
"""

import requests
import logging
from dataclasses import dataclass, field as dc_field
from typing import Optional

logger = logging.getLogger(__name__)

# -------------------------------------------------------
# SENSITIVE FIELD KEYWORDS
# These are names that — if returned without proper
# authorization — represent a security finding.
# All comparisons are done case-insensitively.
# -------------------------------------------------------
SENSITIVE_KEYWORDS = [
    "admin",
    "password",
    "passwd",
    "hash",
    "token",
    "secret",
    "key",
    "role",
    "permission",
    "privilege",
    "email",
    "phone",
    "ssn",
    "credit",
    "card",
    "internal",
    "private",
    "debug",
    "salary",
    "dob",
    "address",
    "api_key",
    "access_token",
    "refresh_token",
]


# -------------------------------------------------------
# FINDING DATA STRUCTURE
# One instance of this is created per vulnerable field.
# -------------------------------------------------------
@dataclass
class FieldAuthFinding:
    field_name: str           # The field that was exposed
    parent_type: str          # The GraphQL type it belongs to (e.g. "User")
    query_name: str           # The query used to fetch it (e.g. "getUser")
    query_sent: str           # Full query string sent
    auth_context: str         # "unauthenticated" or "non_admin"
    returned_value: str       # What the server returned for this field
    severity: str             # Critical / High / Medium
    owasp_category: str       # API1 or API2


def is_sensitive_field(field_name: str) -> bool:
    """
    Returns True if the field name matches any known
    sensitive keyword pattern.

    We check case-insensitively so 'isAdmin', 'IS_ADMIN',
    and 'adminFlag' all match the 'admin' keyword.
    """
    name_lower = field_name.lower()
    return any(keyword in name_lower for keyword in SENSITIVE_KEYWORDS)


def extract_sensitive_fields(schema) -> dict[str, list[str]]:
    """
    Walks the introspection schema and returns a dict of:
      { "TypeName": ["sensitiveField1", "sensitiveField2"] }

    Accepts either:
      - A raw introspection dict (with "types" key)
      - A GraphQLSchema dataclass (from discovery/graphql_schema.py)
    """
    sensitive_map = {}

    # ── Handle GraphQLSchema dataclass ───────────────────────────────────────
    if hasattr(schema, "types") and not isinstance(schema, dict):
        for gql_type in schema.types:
            if gql_type.name.startswith("__") or gql_type.kind == "SCALAR":
                continue
            sensitive_fields = [
                f.name for f in gql_type.fields
                if is_sensitive_field(f.name)
            ]
            if sensitive_fields:
                sensitive_map[gql_type.name] = sensitive_fields
                logger.debug(
                    "Type '%s' has %d sensitive fields: %s",
                    gql_type.name, len(sensitive_fields), sensitive_fields,
                )
        return sensitive_map

    # ── Handle raw introspection dict ────────────────────────────────────────
    if schema is None:
        return {}
    types = schema.get("types", [])

    for gql_type in types:
        type_name = gql_type.get("name", "")
        kind = gql_type.get("kind", "")
        fields = gql_type.get("fields") or []

        if type_name.startswith("__") or kind == "SCALAR":
            continue

        sensitive_fields = [
            f["name"] for f in fields
            if is_sensitive_field(f["name"])
        ]

        if sensitive_fields:
            sensitive_map[type_name] = sensitive_fields
            logger.debug(
                "Type '%s' has %d sensitive fields: %s",
                type_name, len(sensitive_fields), sensitive_fields,
            )

    return sensitive_map
    
    
    
    
def build_field_query(query_name: str, fields: list[str]) -> str:
    """
    Builds a valid GraphQL query string that requests
    only the sensitive fields we want to test.

    Example output:
      query {
        getUser {
          isAdmin
          passwordHash
          apiToken
        }
      }

    Note: This builds a query without arguments.
    Real APIs may require ID arguments — handled
    in the caller by trying with and without args.
    """
    field_lines = "\n    ".join(fields)
    return f"query {{\n  {query_name} {{\n    {field_lines}\n  }}\n}}"


def send_graphql_request(
    url: str,
    query: str,
    token: Optional[str] = None,
    proxies: Optional[dict] = None,
    timeout: int = 10,
) -> Optional[dict]:
    """
    Sends a single GraphQL POST request.

    Returns the parsed JSON response dict, or None on failure.

    GraphQL always uses:
      Method:       POST
      Content-Type: application/json
      Body:         {"query": "<query string>"}
    """
    headers = {"Content-Type": "application/json"}

    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        response = requests.post(
            url,
            json={"query": query},
            headers=headers,
            proxies=proxies,
            timeout=timeout,
        )
        return response.json()

    except requests.exceptions.Timeout:
        logger.warning("Request timed out for query: %s", query[:60])
        return None

    except requests.exceptions.RequestException as exc:
        logger.error("Request failed: %s", exc)
        return None

    except ValueError:
        logger.error("Response was not valid JSON")
        return None


def extract_returned_fields(response: dict) -> dict[str, any]:
    """
    Extracts the field:value pairs from a GraphQL response.

    GraphQL response structure:
      {
        "data": {
          "queryName": {
            "fieldA": value,
            "fieldB": value
          }
        },
        "errors": [...]
      }

    Returns a flat dict of {field_name: value} for the
    first query result in the data block.
    Returns empty dict if no data or only errors.
    """
    if not response:
        return {}

    data = response.get("data")
    if not data:
        return {}

    # Get the first query result object
    for query_result in data.values():
        if isinstance(query_result, dict):
            return query_result
        # Handle list responses (e.g. getUsers returns a list)
        if isinstance(query_result, list) and query_result:
            first = query_result[0]
            if isinstance(first, dict):
                return first

    return {}


def determine_severity(field_name: str, auth_context: str) -> tuple[str, str]:
    """
    Returns (severity, owasp_category) based on the field
    name and how it was accessed.

    Rules:
    - Password / token / key fields returned without auth = Critical / API2
    - Admin / role / privilege fields returned = High / API1
    - Email / phone / PII fields = High / API1
    - Other sensitive fields = Medium / API1
    """
    name_lower = field_name.lower()

    critical_keywords = ["password", "passwd", "hash", "token", "secret", "key", "api_key"]
    high_keywords = ["admin", "role", "permission", "privilege", "email", "phone", "ssn", "credit"]

    if any(kw in name_lower for kw in critical_keywords):
        return "Critical", "API2 — Broken Authentication"

    if any(kw in name_lower for kw in high_keywords):
        return "High", "API1 — BOLA / Unauthorized Field Access"

    return "Medium", "API1 — BOLA / Unauthorized Field Access"




def test_field_authorization(
    url: str,
    schema: dict,
    query_names: list[str],
    user_token: Optional[str] = None,
    proxies: Optional[dict] = None,
) -> list[FieldAuthFinding]:
    """
    Main entry point for field-level authorization testing.

    KEY FIX: Tests one field per query instead of all fields at once.

    Why: GraphQL validates the entire query before executing it.
    If ANY requested field does not exist on the return type,
    the whole query is rejected with a validation error and
    returns no data at all — causing false negatives.

    Sending one field per request means:
      - Valid fields return data (potential finding)
      - Invalid fields return a GraphQL error (silently skipped)
    """
    findings = []
    if schema is None:
        logger.info("[Field Auth] Schema is None (introspection disabled) — skipping field auth scan.")
        return []
    # Step 1: Get all sensitive fields across all types
    sensitive_map = extract_sensitive_fields(schema)

    if not sensitive_map:
        logger.info("No sensitive field names found in schema")
        return findings

    logger.info(
        "Found sensitive fields in %d types: %s",
        len(sensitive_map),
        list(sensitive_map.keys()),
    )

    # Flatten all sensitive fields into one deduplicated list
    all_sensitive_fields = list({
        field
        for fields in sensitive_map.values()
        for field in fields
    })

    # Track what we already flagged to avoid duplicate findings
    already_flagged = set()

    # Step 2: Test each query × each field individually
    # One request per (query_name, field_name) combination.
    # This avoids GraphQL validation rejecting the whole query
    # when some fields don't exist on the return type.
    for query_name in query_names:

        logger.info("Testing '%s' without authentication...", query_name)

        for field_name in all_sensitive_fields:

            # Build a minimal query with just this one field
            query_string = build_field_query(query_name, [field_name])

            # --- Test 1: Unauthenticated ---
            unauth_response = send_graphql_request(
                url=url,
                query=query_string,
                token=None,
                proxies=proxies,
            )

            returned = extract_returned_fields(unauth_response)
            value = returned.get(field_name)

            if value is not None:
                key = (query_name, field_name, "unauthenticated")
                if key not in already_flagged:
                    already_flagged.add(key)
                    severity, owasp = determine_severity(field_name, "unauthenticated")
                    findings.append(FieldAuthFinding(
                        field_name=field_name,
                        parent_type="(inferred from response)",
                        query_name=query_name,
                        query_sent=query_string,
                        auth_context="unauthenticated",
                        returned_value=str(value)[:200],
                        severity=severity,
                        owasp_category=owasp,
                    ))
                    logger.warning(
                        "[%s] '%s' via query '%s' returned value without auth: %s",
                        severity, field_name, query_name, str(value)[:60]
                    )

            # --- Test 2: Low-privilege token ---
            if user_token:
                auth_response = send_graphql_request(
                    url=url,
                    query=query_string,
                    token=user_token,
                    proxies=proxies,
                )

                returned_auth = extract_returned_fields(auth_response)
                auth_value = returned_auth.get(field_name)

                if auth_value is not None:
                    key = (query_name, field_name, "non_admin")
                    if key not in already_flagged:
                        already_flagged.add(key)
                        severity, owasp = determine_severity(field_name, "non_admin")
                        findings.append(FieldAuthFinding(
                            field_name=field_name,
                            parent_type="(inferred from response)",
                            query_name=query_name,
                            query_sent=query_string,
                            auth_context="non_admin",
                            returned_value=str(auth_value)[:200],
                            severity=severity,
                            owasp_category=owasp,
                        ))
                        logger.warning(
                            "[%s] '%s' via query '%s' returned value with non-admin token",
                            severity, field_name, query_name
                        )

    logger.info("Field authorization test complete. %d finding(s).", len(findings))
    return findings

def run_field_auth_scan(
    url: str,
    session,
    schema,
    token: str,
    param_candidates: list = None,
) -> list:
    # Extract real root query field names from the schema
    # param_candidates are parameter/field names — NOT query names
    query_names = []
    if schema and hasattr(schema, "types"):
        for gql_type in schema.types:
            if gql_type.name == schema.query_type:
                query_names = [f.name for f in gql_type.fields]
                break

    # Fall back to param_candidates only if schema gave us nothing
    if schema is None:
        logger.info("[Field Auth] No schema available — field auth scan skipped.")
        return []
    if not query_names:
        query_names = param_candidates or []

    raw_findings = test_field_authorization(
        url=url,
        schema=schema,
        query_names=query_names,
        user_token=token,
        proxies=session.proxies if session and hasattr(session, "proxies") else None,
    )

    return [
        {
            "protocol": "GraphQL",
            "finding_type": "Field-Level Authorization Bypass",
            "field_name": f.field_name,
            "parent_type": f.parent_type,
            "query_name": f.query_name,
            "query_sent": f.query_sent,
            "auth_context": f.auth_context,
            "returned_value": f.returned_value,
            "severity": f.severity,
            "owasp_category": f.owasp_category,
            "remediation": (
                f"Add field-level authorization check in the resolver for "
                f"'{f.field_name}'. Verify the caller's role before returning "
                f"this field. Do not rely on object-level auth alone."
            ),
        }
        for f in raw_findings
    ]
