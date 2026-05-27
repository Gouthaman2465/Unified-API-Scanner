# scanners/graphql/introspection.py
# Protocol: GraphQL
# Purpose: Test whether GraphQL introspection is enabled on the target.
#          Flag it as a security misconfiguration finding (OWASP API7).
#          Also attempt field suggestion probing as a fallback.

import requests
import logging
from typing import Optional, List, Dict, Any
from discovery.graphql_schema import fetch_schema, probe_field_suggestions, GraphQLSchema

logger = logging.getLogger(__name__)

# Sensitive field names that are especially concerning if exposed via introspection
SENSITIVE_FIELD_NAMES = [
    "password", "passwd", "secret", "token", "apiKey", "api_key",
    "isAdmin", "is_admin", "role", "privateKey", "private_key",
    "ssn", "creditCard", "credit_card", "internalId", "internal_id"
]


def check_introspection(
    target_url: str,
    session: requests.Session
) -> List[Dict[str, Any]]:
    """
    Main entry point for the introspection scanner.

    Tests whether introspection is enabled.
    If enabled, parses the schema and flags sensitive fields found.
    If disabled, attempts field suggestion probing as fallback.

    Returns a list of finding dictionaries for the report.
    """
    findings = []

    schema = fetch_schema(target_url, session)

    if schema is not None:
        # Introspection is enabled — this is a finding
        logger.warning("Introspection is ENABLED on target")

        sensitive_fields = find_sensitive_fields(schema)

        finding = {
            "title": "GraphQL Introspection Enabled",
            "protocol": "GraphQL",
            "owasp": "API7:2023 - Security Misconfiguration",
            "severity": "Medium",
            "cvss_score": 5.3,
            "description": (
                "The GraphQL API has introspection enabled in a production environment. "
                "Introspection allows any client to query the complete API schema, "
                "including all types, fields, queries, and mutations. "
                "This gives attackers a full roadmap of the API surface."
            ),
            "evidence": {
                "types_discovered": len(schema.types),
                "query_type": schema.query_type,
                "mutation_type": schema.mutation_type,
                "sensitive_fields_found": sensitive_fields
            },
            "remediation": (
                "Disable introspection in production. "
                "In most GraphQL servers this is a one-line config change. "
                "Apollo Server: introspection: false. "
                "Graphene (Python): GRAPHQL_DISABLE_INTROSPECTION=True."
            ),
            "schema": schema  # Pass schema to other modules for further testing
        }

        findings.append(finding)

        if sensitive_fields:
            findings.append(build_sensitive_field_finding(sensitive_fields, target_url))

    else:
        # Introspection disabled — try field suggestion probing
        logger.info("Introspection disabled. Attempting field suggestion probing.")
        suggested_fields = probe_field_suggestions(target_url, session)

        if suggested_fields:
            finding = {
                "title": "GraphQL Field Names Discoverable via Error Messages",
                "protocol": "GraphQL",
                "owasp": "API7:2023 - Security Misconfiguration",
                "severity": "Low",
                "cvss_score": 3.1,
                "description": (
                    "Although introspection is disabled, the GraphQL server reveals "
                    "valid field names in error messages via 'Did you mean X?' suggestions. "
                    f"Fields discovered: {', '.join(suggested_fields)}"
                ),
                "evidence": {"suggested_fields": suggested_fields},
                "remediation": (
                    "Disable field suggestions in production. "
                    "In Apollo Server set: "
                    "apollo: { fieldLevelSuggestions: false }"
                )
            }
            findings.append(finding)

    return findings


def find_sensitive_fields(schema: GraphQLSchema) -> List[str]:
    """
    Scan the parsed schema for field names that suggest
    sensitive data exposure if introspection is enabled.
    """
    found = []
    for gql_type in schema.types:
        for gql_field in gql_type.fields:
            for sensitive in SENSITIVE_FIELD_NAMES:
                if sensitive.lower() in gql_field.name.lower():
                    found.append(f"{gql_type.name}.{gql_field.name}")
    return found


def build_sensitive_field_finding(
    sensitive_fields: List[str],
    target_url: str
) -> Dict[str, Any]:
    """
    Build a separate finding for sensitive fields discovered in the schema.
    This is an additional finding on top of the introspection finding.
    """
    return {
        "title": "Sensitive Fields Exposed in GraphQL Schema",
        "protocol": "GraphQL",
        "owasp": "API3:2023 - Broken Object Property Level Authorization",
        "severity": "High",
        "cvss_score": 7.5,
        "description": (
            "The GraphQL schema exposes fields with names suggesting sensitive data. "
            "These fields are visible to any unauthenticated client via introspection. "
            f"Sensitive fields found: {', '.join(sensitive_fields)}"
        ),
        "evidence": {
            "target": target_url,
            "sensitive_fields": sensitive_fields
        },
        "remediation": (
            "Disable introspection in production. "
            "Additionally apply field-level authorization to ensure "
            "sensitive fields are only returned to authorized users."
        )
    }


def get_schema_for_other_modules(
    target_url: str,
    session: requests.Session
) -> Optional[GraphQLSchema]:
    """
    Convenience function used by depth_limit.py, field_auth.py,
    and batch_abuse.py to get the parsed schema without re-running
    the full introspection finding.

    Returns the schema object or None if introspection is disabled.
    """
    return fetch_schema(target_url, session)
    
    
    
    
def run_introspection_scan(session, target_url: str, audit_logger=None):
    """
    Adapter wrapping check_introspection() to return the
    (findings, type_map) tuple that main.py and depth_limit.py expect.

    Your GraphQLSchema object (discovery/graphql_schema.py) is a custom
    dataclass with a .types list of GraphQLType objects.
    Each GraphQLType has:
      - .name  : str  (e.g. "PasteObject")
      - .kind  : str  (e.g. "OBJECT", "SCALAR", "UNION")
      - .fields: list of GraphQLField objects, each with:
          - .name      : str  (e.g. "owner")
          - .type_name : str  (e.g. "OwnerObject")

    We convert this into the flat dict depth_limit.py expects:
      { "PasteObject": { "owner": "OwnerObject", ... }, ... }

    Returns:
        findings : list of finding dicts
        type_map : { TypeName: { fieldName: ReturnTypeName } }
    """
    findings = check_introspection(target_url, session)

    type_map = {}
    try:
        schema = get_schema_for_other_modules(target_url, session)

        if schema and hasattr(schema, "types"):
            for gql_type in schema.types:
                # Skip scalars, unions, enums — they have no fields
                # Skip GraphQL built-in types (start with __)
                if gql_type.kind not in ("OBJECT", "INPUT_OBJECT"):
                    continue
                if gql_type.name.startswith("__"):
                    continue
                if not gql_type.fields:
                    continue

                # Build field_name → return_type_name mapping
                type_map[gql_type.name] = {
                    field.name: field.type_name
                    for field in gql_type.fields
                    if field.type_name  # skip fields with no type_name
                }

    except Exception as e:
        logger.warning("Could not build type_map from schema: %s", e)

    return findings, type_map
