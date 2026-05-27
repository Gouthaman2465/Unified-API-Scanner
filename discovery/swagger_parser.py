"""
discovery/swagger_parser.py

Fetches and parses OpenAPI/Swagger specification from a REST API target.
Discovers all endpoints, HTTP methods, and parameters automatically.
Feeds discovered endpoints into IDOR and mass assignment scanners.

Protocol: REST only
OWASP: API7 (Security Misconfiguration) — exposed Swagger is itself a finding
"""

import re
import requests
import yaml
import json


# Common paths where Swagger/OpenAPI specs are served
SWAGGER_PATHS = [
    "/identity/api/docs/openapi.json",  # <-- Add this! This is your live crAPI target path
    "/swagger.json",
    "/openapi.json",
    "/swagger.yaml",
    "/openapi.yaml",
    "/api/swagger.json",
    "/api/openapi.json",
    "/v1/swagger.json",
    "/v2/swagger.json",
    "/v3/swagger.json",
    "/api/docs/swagger.json",
    "/api-docs",
    "/api-docs.json",
]


def fetch_swagger_spec(base_url: str, session: requests.Session) -> dict | None:
    """
    Tries common Swagger/OpenAPI paths on the target.
    Returns the parsed spec as a Python dict, or None if not found.

    Args:
        base_url: Target API base URL e.g. http://localhost:8888
        session:  Shared requests session (carries auth headers, proxy config)

    Returns:
        Parsed OpenAPI spec dict, or None if no spec found
    """
    base_url = base_url.rstrip("/")

    for path in SWAGGER_PATHS:
        url = base_url + path
        try:
            response = session.get(url, timeout=5, verify=False)

            if response.status_code != 200:
                continue

            content_type = response.headers.get("Content-Type", "")

            # Parse JSON spec
            if "json" in content_type or path.endswith(".json"):
                try:
                    spec = response.json()
                    if _is_valid_openapi_spec(spec):
                        print(f"[+] Swagger spec found at: {url}")
                        return {"spec": spec, "url": url}
                except Exception:
                    continue

            # Parse YAML spec
            elif "yaml" in content_type or path.endswith(".yaml"):
                try:
                    spec = yaml.safe_load(response.text)
                    if _is_valid_openapi_spec(spec):
                        print(f"[+] Swagger spec found at: {url}")
                        return {"spec": spec, "url": url}
                except Exception:
                    continue

        except requests.exceptions.RequestException:
            # Connection refused, timeout, etc — try next path
            continue

    print("[-] No Swagger/OpenAPI spec found at common paths.")
    return None


def _is_valid_openapi_spec(spec: dict) -> bool:
    """
    Checks if a parsed document looks like a real OpenAPI spec.
    Avoids false positives from other JSON files at similar paths.

    Args:
        spec: Parsed dictionary to validate

    Returns:
        True if this looks like an OpenAPI/Swagger document
    """
    if not isinstance(spec, dict):
        return False

    # OpenAPI 3.x has "openapi" key, Swagger 2.x has "swagger" key
    # Both must have "paths" to be useful
    has_version = "openapi" in spec or "swagger" in spec
    has_paths = "paths" in spec

    return has_version and has_paths


def extract_endpoints(spec: dict) -> list[dict]:
    """
    Parses all paths and methods from an OpenAPI spec.
    Returns a list of endpoint descriptors ready for security testing.

    Each descriptor contains:
        - method: HTTP method (GET, POST, PUT, DELETE, PATCH)
        - path: URL path with {param} placeholders
        - path_params: list of path parameter names
        - query_params: list of query parameter names
        - body_fields: list of request body field names (for POST/PUT)
        - has_id_param: True if path contains an ID-style parameter
        - raw_operation: full operation dict from spec (for reference)

    Args:
        spec: Parsed OpenAPI spec dict

    Returns:
        List of endpoint descriptor dicts
    """
    endpoints = []
    paths = spec.get("paths", {})

    # HTTP methods that carry security testing interest
    testable_methods = {"get", "post", "put", "patch", "delete"}

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue

        for method, operation in path_item.items():
            method = method.lower()

            if method not in testable_methods:
                # Skip non-HTTP keys like "parameters", "summary"
                continue

            if not isinstance(operation, dict):
                continue

            # Extract path parameters like {id}, {userId}, {vehicleId}
            path_params = _extract_path_params(path)

            # Extract query and header parameters from the parameters list
            query_params, header_params = _extract_operation_params(operation)

            # Extract request body field names (for PUT/POST mass assignment)
            body_fields = _extract_body_fields(operation, spec)

            # Flag endpoints that look like object retrieval by ID
            # These are prime IDOR candidates
            has_id_param = _has_id_style_param(path_params)

            endpoint = {
                "method": method.upper(),
                "path": path,
                "path_params": path_params,
                "query_params": query_params,
                "header_params": header_params,
                "body_fields": body_fields,
                "has_id_param": has_id_param,
                "raw_operation": operation,
            }

            endpoints.append(endpoint)

    print(f"[+] Extracted {len(endpoints)} endpoints from Swagger spec.")
    return endpoints


def _extract_path_params(path: str) -> list[str]:
    """
    Pulls parameter names from a path string like /users/{id}/orders/{orderId}.

    Args:
        path: URL path string with {placeholder} style parameters

    Returns:
        List of parameter name strings e.g. ['id', 'orderId']
    """
    return re.findall(r'\{(\w+)\}', path)


def _extract_operation_params(operation: dict) -> tuple[list[str], list[str]]:
    """
    Extracts query and header parameter names from an operation's
    parameters list.

    Args:
        operation: Single operation dict from spec (e.g. the GET block)

    Returns:
        Tuple of (query_param_names, header_param_names)
    """
    query_params = []
    header_params = []

    parameters = operation.get("parameters", [])

    for param in parameters:
        if not isinstance(param, dict):
            continue

        name = param.get("name", "")
        location = param.get("in", "")

        if location == "query":
            query_params.append(name)
        elif location == "header":
            header_params.append(name)

    return query_params, header_params


def _extract_body_fields(operation: dict, spec: dict) -> list[str]:
    """
    Extracts field names from the request body schema.
    Handles both OpenAPI 3.x (requestBody) and Swagger 2.x (body parameter).
    These fields are candidates for mass assignment injection.

    Args:
        operation: Single operation dict from spec
        spec: Full spec dict (needed for $ref resolution)

    Returns:
        List of request body field name strings
    """
    fields = []

    # OpenAPI 3.x style
    request_body = operation.get("requestBody", {})
    if request_body:
        content = request_body.get("content", {})
        for media_type, media_obj in content.items():
            schema = media_obj.get("schema", {})
            fields.extend(_extract_schema_fields(schema, spec))

    # Swagger 2.x style — body parameter
    for param in operation.get("parameters", []):
        if param.get("in") == "body":
            schema = param.get("schema", {})
            fields.extend(_extract_schema_fields(schema, spec))

    return list(set(fields))  # deduplicate


def _extract_schema_fields(schema: dict, spec: dict) -> list[str]:
    """
    Recursively extracts field names from a JSON schema object.
    Resolves $ref references to definitions/components.

    Args:
        schema: JSON schema dict (may contain $ref)
        spec: Full spec for $ref resolution

    Returns:
        List of field name strings
    """
    if not isinstance(schema, dict):
        return []

    # Resolve $ref like "#/definitions/User" or "#/components/schemas/User"
    if "$ref" in schema:
        schema = _resolve_ref(schema["$ref"], spec)

    properties = schema.get("properties", {})
    return list(properties.keys())


def _resolve_ref(ref: str, spec: dict) -> dict:
    """
    Resolves a JSON $ref pointer like "#/components/schemas/User"
    to its actual schema dict within the spec.

    Args:
        ref: $ref string starting with #/
        spec: Full OpenAPI spec dict

    Returns:
        Resolved schema dict, or empty dict if resolution fails
    """
    if not ref.startswith("#/"):
        return {}

    # Split "#/components/schemas/User" → ["components", "schemas", "User"]
    parts = ref.lstrip("#/").split("/")

    node = spec
    for part in parts:
        if not isinstance(node, dict):
            return {}
        node = node.get(part, {})

    return node


def _has_id_style_param(path_params: list[str]) -> bool:
    """
    Checks if any path parameter looks like an object identifier.
    These endpoints are IDOR candidates worth testing.

    Args:
        path_params: List of path parameter names

    Returns:
        True if any parameter name suggests an ID
    """
    id_patterns = re.compile(
        r'(^id$|_id$|Id$|ID$|uuid|guid|slug)',
        re.IGNORECASE
    )
    return any(id_patterns.search(param) for param in path_params)


def filter_idor_candidates(endpoints: list[dict]) -> list[dict]:
    """
    Filters endpoint list to only those that are likely IDOR candidates.
    Used by idor.py to focus testing on relevant endpoints.

    Criteria:
        - GET method (reading a resource)
        - Has at least one ID-style path parameter

    Args:
        endpoints: Full list of extracted endpoints

    Returns:
        Filtered list of IDOR candidate endpoints
    """
    candidates = [
        ep for ep in endpoints
        if ep["method"] == "GET" and ep["has_id_param"]
    ]
    print(f"[+] {len(candidates)} IDOR candidate endpoints identified.")
    return candidates


def filter_mass_assignment_candidates(endpoints: list[dict]) -> list[dict]:
    """
    Filters endpoints that are candidates for mass assignment testing.
    Used by mass_assignment.py to focus on write operations with body fields.

    Criteria:
        - PUT or PATCH method (updating an object)
        - Has at least one body field defined

    Args:
        endpoints: Full list of extracted endpoints

    Returns:
        Filtered list of mass assignment candidate endpoints
    """
    candidates = [
        ep for ep in endpoints
        if ep["method"] in ("PUT", "PATCH") and ep["body_fields"]
    ]
    print(f"[+] {len(candidates)} mass assignment candidate endpoints identified.")
    return candidates


def build_test_url(base_url: str, path: str, param_value: str = "1") -> str:
    """
    Replaces all {param} placeholders in a path with a test value.
    Used by scanner modules to build concrete URLs for testing.

    Args:
        base_url:    Target base URL e.g. http://localhost:8888
        path:        Path with placeholders e.g. /users/{id}
        param_value: Value to substitute e.g. "1", "2", "admin"

    Returns:
        Full concrete URL e.g. http://localhost:8888/users/1
    """
    concrete_path = re.sub(r'\{\w+\}', param_value, path)
    return base_url.rstrip("/") + concrete_path



# ─────────────────────────────────────────────────────────────────────────────
# PHASE 15 — additions to discovery/swagger_parser.py
# Paste these three functions at the BOTTOM of your existing swagger_parser.py
# ─────────────────────────────────────────────────────────────────────────────




def discover_rest_params(
    base_url: str,
    mass_targets: list = None,
    session=None,
) -> list:
    """
    Phase 15 — REST parameter discovery.
    Harvests parameter names from:
      1. Body fields in the Swagger/OpenAPI spec (if found)
      2. Keys from live GET responses to known endpoints
    """
    import requests as _requests

    http = session or _requests.Session()
    discovered = []

    # ── Source 1: Swagger spec body fields ───────────────────────────────────
    spec_result = fetch_swagger_spec(base_url, http)
    if spec_result:
        endpoints = extract_endpoints(spec_result["spec"])
        for ep in endpoints:
            discovered.extend(ep.get("body_fields", []))

    # ── Source 2: Live response harvesting from known endpoints ──────────────
    targets = mass_targets or []
    for url in targets:
        try:
            resp = http.get(url, timeout=5, verify=False)
            if resp.status_code == 200:
                harvested = harvest_response_params(resp.text)
                discovered.extend(harvested)
        except Exception:
            continue

    return list(set(discovered))


def harvest_response_params(response_body: str) -> list:
    """
    Parse a raw JSON response string and return every key name found
    as a parameter candidate (response harvesting technique).

    Args:
        response_body: raw JSON string (e.g. from a GET /users/1 response)

    Returns:
        List of unique key names found in the response JSON.
    """
    try:
        data = json.loads(response_body)
    except (json.JSONDecodeError, TypeError):
        return []

    fields = _harvest_json_fields(data, depth=0)
    return list(set(fields))


def _harvest_json_fields(data, depth: int = 0) -> list:
    """
    Internal recursive helper — walks up to 2 levels deep into nested
    JSON objects/lists and collects every dict key as a candidate parameter.

    Args:
        data : parsed JSON object (dict, list, or scalar)
        depth: current recursion depth (stops at 2)

    Returns:
        List of key name strings.
    """
    fields = []
    if depth > 2:
        return fields

    if isinstance(data, dict):
        for key, value in data.items():
            # Skip GraphQL / JSON-schema internals
            if key.startswith("__"):
                continue
            fields.append(key)
            fields.extend(_harvest_json_fields(value, depth + 1))

    elif isinstance(data, list):
        for item in data:
            fields.extend(_harvest_json_fields(item, depth + 1))

    return fields
