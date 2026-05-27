# discovery/graphql_schema.py
# Protocol: GraphQL
# Purpose: Send introspection query to target and parse the returned schema
#          into structured Python objects for use by scanner modules.

import requests
from dataclasses import dataclass, field
from typing import List, Optional, Dict
import logging

logger = logging.getLogger(__name__)

# --- Data structures to hold parsed schema ---

@dataclass
class GraphQLArgument:
    """Represents one argument on a GraphQL field."""
    name: str
    type_name: str

@dataclass
class GraphQLField:
    """Represents one field inside a GraphQL type."""
    name: str
    type_name: str
    args: List[GraphQLArgument] = field(default_factory=list)

@dataclass
class GraphQLType:
    """Represents one type in the GraphQL schema."""
    name: str
    kind: str  # OBJECT, INPUT_OBJECT, SCALAR, ENUM, etc.
    fields: List[GraphQLField] = field(default_factory=list)

@dataclass
class GraphQLSchema:
    """Top-level container for the full parsed schema."""
    query_type: Optional[str] = None       # Name of the root query type
    mutation_type: Optional[str] = None    # Name of the root mutation type
    subscription_type: Optional[str] = None
    types: List[GraphQLType] = field(default_factory=list)
    raw: Dict = field(default_factory=dict) # Raw response for evidence


# --- Full introspection query ---
# This is the standard query used by GraphQL IDEs and security tools
# to retrieve the complete schema from a GraphQL API.

INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      fields(includeDeprecated: true) {
        name
        args {
          name
          type {
            name
            kind
            ofType { name kind }
          }
        }
        type {
          name
          kind
          ofType { name kind }
        }
      }
      inputFields {
        name
        type {
          name
          kind
          ofType { name kind }
        }
      }
    }
  }
}
"""


def resolve_type_name(type_obj: dict) -> str:
    """
    GraphQL wraps types in layers like NON_NULL and LIST.
    This function unwraps them to get the actual base type name.

    Example: NON_NULL -> LIST -> STRING becomes "STRING"
    """
    if type_obj is None:
        return "Unknown"
    if type_obj.get("name"):
        return type_obj["name"]
    # Recurse into ofType to unwrap NON_NULL/LIST wrappers
    if type_obj.get("ofType"):
        return resolve_type_name(type_obj["ofType"])
    return "Unknown"


def fetch_schema(target_url: str, session: requests.Session) -> Optional[GraphQLSchema]:
    """
    Send the introspection query to the target GraphQL endpoint.
    Parse the response into a GraphQLSchema object.

    Returns None if introspection is disabled or request fails.
    """
    logger.info(f"Sending introspection query to {target_url}")

    try:
        response = session.post(
            target_url,
            json={"query": INTROSPECTION_QUERY},
            headers={"Content-Type": "application/json"},
            timeout=15
        )
    except requests.RequestException as e:
        logger.error(f"Introspection request failed: {e}")
        return None

    if response.status_code != 200:
        logger.warning(f"Non-200 response from introspection: {response.status_code}")
        return None

    try:
        body = response.json()
    except ValueError:
        logger.error("Response was not valid JSON")
        return None

    # Check if introspection returned errors (disabled on server)
    if "errors" in body and "data" not in body:
        logger.info("Introspection is disabled on this server")
        return None

    raw_schema = body.get("data", {}).get("__schema", {})
    if not raw_schema:
        logger.warning("Introspection response contained no schema data")
        return None

    return parse_schema(raw_schema, body)


def parse_schema(raw_schema: dict, full_response: dict) -> GraphQLSchema:
    """
    Convert the raw introspection JSON into structured GraphQLSchema objects.
    Filters out GraphQL's own internal types (those starting with __).
    """
    schema = GraphQLSchema(raw=full_response)

    # Extract root type names
    schema.query_type = (raw_schema.get("queryType") or {}).get("name")
    schema.mutation_type = (raw_schema.get("mutationType") or {}).get("name")
    schema.subscription_type = (raw_schema.get("subscriptionType") or {}).get("name")

    for raw_type in raw_schema.get("types", []):
        type_name = raw_type.get("name", "")

        # Skip GraphQL internal types like __Schema, __Type, __Field
        if type_name.startswith("__"):
            continue

        # Skip built-in scalar types
        if type_name in ("String", "Int", "Float", "Boolean", "ID"):
            continue

        kind = raw_type.get("kind", "")
        gql_type = GraphQLType(name=type_name, kind=kind)

        # Parse fields (for OBJECT types like Query, Mutation, User)
        for raw_field in raw_type.get("fields") or []:
            field_name = raw_field.get("name", "")
            field_type = resolve_type_name(raw_field.get("type", {}))

            gql_field = GraphQLField(name=field_name, type_name=field_type)

            # Parse arguments on each field
            for raw_arg in raw_field.get("args") or []:
                arg_name = raw_arg.get("name", "")
                arg_type = resolve_type_name(raw_arg.get("type", {}))
                gql_field.args.append(GraphQLArgument(name=arg_name, type_name=arg_type))

            gql_type.fields.append(gql_field)

        # Parse input fields (for INPUT_OBJECT types used in mutations)
        for raw_input in raw_type.get("inputFields") or []:
            input_name = raw_input.get("name", "")
            input_type = resolve_type_name(raw_input.get("type", {}))
            gql_type.fields.append(GraphQLField(name=input_name, type_name=input_type))

        schema.types.append(gql_type)

    logger.info(f"Schema parsed: {len(schema.types)} types found")
    return schema


def probe_field_suggestions(target_url: str, session: requests.Session) -> List[str]:
    """
    Fallback discovery when introspection is disabled.

    GraphQL still suggests correct field names when you make a typo.
    We send intentionally broken queries and extract field name hints
    from the error messages.

    Example: querying { usr { id } } returns "Did you mean 'user'?"
    """
    # Common field name guesses to probe with slight typos
    probe_guesses = [
        "usr", "passwrd", "admn", "tok", "secrt",
        "profil", "accnt", "rol", "emal", "phon"
    ]

    discovered = []

    for guess in probe_guesses:
        query = f"{{ {guess} {{ id }} }}"
        try:
            response = session.post(
                target_url,
                json={"query": query},
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            body = response.json()

            # Extract "Did you mean X?" suggestions from error messages
            for error in body.get("errors", []):
                message = error.get("message", "")
                if "Did you mean" in message:
                    # Extract the suggested name from the message
                    parts = message.split('"')
                    for i, part in enumerate(parts):
                        if part and not part.startswith(" "):
                            discovered.append(part)
                            logger.info(f"Field suggestion discovered: {part}")

        except requests.RequestException:
            continue

    return list(set(discovered))  # Remove duplicates



# ─────────────────────────────────────────────────────────────────────────────
# PHASE 15 — addition to discovery/graphql_schema.py
# Paste this function at the BOTTOM of your existing graphql_schema.py
# ─────────────────────────────────────────────────────────────────────────────


def extract_graphql_input_args(schema) -> list:
    """
    Extract field names from INPUT_OBJECT types and direct mutation arguments
    in a GraphQL introspection schema.  These are the parameter names an
    attacker would probe for mass-assignment vulnerabilities.

    Args:
        schema: dict returned by fetch_graphql_schema() — expected structure:
                {
                  "data": {
                    "__schema": {
                      "types": [
                        { "kind": "INPUT_OBJECT", "name": "...",
                          "inputFields": [ {"name": "..."}, ... ] },
                        { "kind": "OBJECT", "name": "Mutation",
                          "fields": [ { "name": "...",
                                        "args": [ {"name": "..."}, ... ] } ] }
                      ]
                    }
                  }
                }

    Returns:
        Deduplicated list of argument/field name strings.
    """
    candidates = []

    if not schema:
        return candidates

    # If a GraphQLSchema dataclass was passed, use its stored raw response
    if isinstance(schema, GraphQLSchema):
        schema = schema.raw

    types = (
        schema.get("data", {})
              .get("__schema", {})
              .get("types", [])
    ) or []

    for gql_type in types:
        kind = gql_type.get("kind", "")
        name = gql_type.get("name", "")

        # Skip GraphQL built-in internal types
        if name.startswith("__"):
            continue

        # ── INPUT_OBJECT: harvest inputFields ────────────────────────────────
        if kind == "INPUT_OBJECT":
            for field in gql_type.get("inputFields", []) or []:
                field_name = field.get("name", "")
                if field_name and not field_name.startswith("__"):
                    candidates.append(field_name)

        # ── OBJECT named "Mutation": harvest args on each mutation field ──────
        if kind == "OBJECT" and name == "Mutation":
            for field in gql_type.get("fields", []) or []:
                for arg in field.get("args", []) or []:
                    arg_name = arg.get("name", "")
                    if arg_name and not arg_name.startswith("__"):
                        candidates.append(arg_name)

    return list(set(candidates))
