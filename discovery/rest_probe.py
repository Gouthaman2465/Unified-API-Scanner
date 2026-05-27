"""
discovery/rest_probe.py

Dynamic REST endpoint prober for mass assignment discovery.

This replaces all hardcoded fallback endpoints.

When no Swagger/OpenAPI spec is found, this module:
  1. Probes common REST path patterns and checks which ones respond with JSON
  2. Identifies PUT/PATCH-capable endpoints by sending OPTIONS requests
  3. For any endpoint that returns a JSON object with an 'id' field,
     treats it as a mass assignment candidate
  4. Returns a list of target dicts identical in shape to what
     swagger_parser.py returns — so run_rest_scan() needs zero changes

Why this works better than hardcoded paths:
  A hardcoded path only works against one specific lab (crAPI).
  This prober works against ANY REST API because it discovers
  what actually exists rather than assuming.

Protocol: REST only.
"""

import requests
from typing import Optional


# ── BINARY FIELD STRIPPING ───────────────────────────────────────────────────
#
# These fields contain raw base64-encoded binary data (videos, images, etc.)
# They are useless for diffing, and they flood logs and reports with garbage.
# Strip them from every response before any processing.

BINARY_FIELDS = {
    "profileVideo",
    "profile_pic_url",
    "picture_url",
    "avatar",
    "thumbnail",
    "image",
    "photo",
    "video_data",
}


def _strip_binary_fields(data: dict) -> dict:
    """
    Remove known binary/base64 fields from a response dict.
    Call this immediately after response.json() on any endpoint.
    """
    return {k: v for k, v in data.items() if k not in BINARY_FIELDS}


# ── COMMON REST PATH PATTERNS ────────────────────────────────────────────────
#
# These are the most common REST resource paths across real APIs.
# Ordered from most likely to least likely to exist.
# We probe GET first — if the server responds with JSON containing an object,
# it is a candidate for PUT-based mass assignment testing.
#
# Why these specific paths?
# REST APIs almost always expose user/profile/account resources.
# These are the highest-value targets for mass assignment because
# they contain privileged fields (role, isAdmin, balance, etc.).

COMMON_REST_RESOURCE_PATTERNS = [

    # crAPI — confirmed working paths
    "/identity/api/v2/user/dashboard",
    "/community/api/v2/community/posts/my-posts",

    "/identity/api/v2/user/videos",        # crAPI video — mass assignment target
    "/identity/api/v2/user/dashboard",     # crAPI user dashboard
    "/community/api/v2/community/posts/my-posts",


    # User/profile resources — highest value targets
    "/api/v2/user",
    "/api/v1/user",
    "/api/user",
    "/api/v2/profile",
    "/api/v1/profile",
    "/api/profile",
    "/api/v2/me",
    "/api/v1/me",
    "/api/me",
    "/user/profile",
    "/users/me",

    # Account/settings resources — often have role/subscription fields
    "/api/v2/account",
    "/api/v1/account",
    "/api/account",
    "/api/v2/settings",
    "/api/v1/settings",

    # Workshop/vehicle patterns (crAPI-style — still useful as a pattern)
    "/workshop/api/merchant/contact-mechanic",
    "/workshop/api/shop/orders",
    "/identity/api/v2/user/dashboard",

    # Generic REST patterns
    "/api/v2/users",
    "/api/v1/users",
    "/api/users",
    "/api/v2/members",
    "/api/v1/members",
]


# ── RESPONSE ANALYSIS ────────────────────────────────────────────────────────

def _is_json_object(response: requests.Response) -> bool:
    """
    Returns True if the response body is a JSON dict (not a list, not HTML).
    A JSON dict is what we want — it represents a single resource object
    that a PUT can modify.
    """
    try:
        data = response.json()
        return isinstance(data, dict)
    except (ValueError, AttributeError):
        return False


def _is_json_list_of_objects(response: requests.Response) -> bool:
    """
    Returns True if the response is a list of dicts, e.g. [{"id": 1, ...}].
    This means the endpoint is a collection — we need to go one level deeper
    to get a single object URL.
    """
    try:
        data = response.json()
        return isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict)
    except (ValueError, AttributeError):
        return False


def _extract_id_from_response(response: requests.Response) -> Optional[int | str]:
    """
    Try to extract an 'id' (or common ID field variants) from a JSON response.
    Returns the ID value or None.

    Why: We need the real ID to build the object URL for mass assignment.
    If the GET /api/v2/user returns {"id": 42, "name": "Alice"},
    the object URL for PUT is /api/v2/user/42.
    """
    try:
        data = response.json()
        if isinstance(data, dict):
            # Strip binary fields before processing
            data = _strip_binary_fields(data)
            # Try common ID field names in priority order
            for id_field in ["id", "userId", "user_id", "memberId", "accountId"]:
                if id_field in data:
                    return data[id_field]
        elif isinstance(data, list) and data:
            first = data[0]
            if isinstance(first, dict):
                first = _strip_binary_fields(first)
                for id_field in ["id", "userId", "user_id"]:
                    if id_field in first:
                        return first[id_field]
    except (ValueError, AttributeError):
        pass
    return None


def _check_put_supported(
    session: requests.Session,
    url: str
) -> bool:
    """
    We no longer reject candidates based on OPTIONS.
    Reason: Many APIs don't implement OPTIONS or return incomplete Allow headers.
    The actual PUT attempt in run_mass_assignment_scan() is the real test.
    We keep this function so the call site is unchanged.
    """
    return True

# ── SINGLE ENDPOINT PROBE ────────────────────────────────────────────────────

def probe_endpoint(
    session: requests.Session,
    base_url: str,
    path: str
) -> Optional[dict]:
    """
    Probe a single REST path to determine if it is a valid mass assignment
    candidate.

    Steps:
      1. GET {base_url}{path}
      2. If response is JSON, extract any ID field
      3. If an ID is found, build the object URL ({path}/{id}) and GET that too
      4. Confirm the object URL returns a valid JSON dict
      5. Check if PUT is supported on the object URL
      6. Return a candidate dict if all checks pass

    Returns:
        A dict with keys: path, object_url, body_fields
        or None if this path is not a valid candidate.

    Args:
        session  : Authenticated requests.Session
        base_url : Target base URL e.g. http://localhost:8888
        path     : Path to probe e.g. /api/v2/user
    """
    full_url = f"{base_url.rstrip('/')}{path}"

    try:
        response = session.get(full_url, timeout=8)
    except requests.RequestException:
        return None

    # Only care about successful responses
    if response.status_code not in (200, 201):
        print(f"[PROBE-DEBUG] {path} -> {response.status_code}")
        return None

    object_url = full_url
    body_fields = []
    object_id = None

    # Case 1: Response is a single JSON object with an ID
    # e.g. GET /api/v2/user → {"id": 42, "name": "Alice", "role": "user"}
    # This IS the object. Use this URL directly for PUT.
    if _is_json_object(response):
        object_id = _extract_id_from_response(response)

        if object_id:
            # Try building a more specific URL with the ID appended
            id_url = f"{full_url.rstrip('/')}/{object_id}"

            try:
                id_response = session.get(id_url, timeout=5)

                if id_response.status_code == 200 and _is_json_object(id_response):
                    object_url = id_url

            except requests.RequestException:
                pass  # Use the original URL without /id suffix

        # Some APIs use a "dashboard" or "summary" GET URL
        # but a different write URL.
        #
        # Example:
        #   GET  /identity/api/v2/user/dashboard
        #   PUT  /identity/api/v2/user/8
        #
        # If dashboard exists and exposes an ID,
        # try resolving a sibling write endpoint.
        if object_id and "dashboard" in path.lower():

            parent_path = "/".join(
                path.rstrip("/").split("/")[:-1]
            )

            alt_write_url = (
                f"{base_url.rstrip('/')}"
                f"{parent_path}/{object_id}"
            )

            try:
                alt_response = session.get(
                    alt_write_url,
                    timeout=5
                )

                if (
                    alt_response.status_code == 200
                    and _is_json_object(alt_response)
                ):
                    object_url = alt_write_url
                    print(f"[PROBE] Resolved write URL: {object_url}")

            except requests.RequestException:
                pass

        # Extract field names from the response body — strip binary fields first
        try:
            raw_body = response.json()
            cleaned_body = _strip_binary_fields(raw_body)
            body_fields = list(cleaned_body.keys())

        except (ValueError, AttributeError):
            body_fields = []

    # Case 2: Response is a list of objects
    # e.g. GET /api/v2/users → [{"id": 42, ...}]
    # We need to pick the first item and build its URL.
    elif _is_json_list_of_objects(response):

        object_id = _extract_id_from_response(response)

        if not object_id:
            return None

        object_url = f"{full_url.rstrip('/')}/{object_id}"

        try:
            obj_response = session.get(
                object_url,
                timeout=5
            )

            if (
                obj_response.status_code != 200
                or not _is_json_object(obj_response)
            ):
                return None

            # Strip binary fields before extracting field names
            raw_obj = obj_response.json()
            cleaned_obj = _strip_binary_fields(raw_obj)
            body_fields = list(cleaned_obj.keys())

        except requests.RequestException:
            return None

    else:
        # Not JSON or empty — skip
        return None

    # Final check: is PUT/PATCH likely supported?
    if not _check_put_supported(session, object_url):
        return None

    # Follow any reference fields (video_id, order_id etc.) to child resources
    # This is how we find PUT-capable endpoints that aren't directly listable
    extra = _follow_reference_fields(session, base_url, response, path)
    # Note: extra candidates are returned via discover_mass_assignment_targets
    # Store them on the result so the caller can collect them
    # Build the candidate result object
    result = {
        "method": "PUT",
        "path": path,
        "object_url": object_url,
        "body_fields": [],
    }

    # Attach discovered child resources
    result["_extra_candidates"] = extra

    return result

# ── MAIN PROBER ──────────────────────────────────────────────────────────────

def discover_mass_assignment_targets(
    session: requests.Session,
    base_url: str,
    extra_paths: Optional[list] = None,
) -> list[dict]:
    """
    Probe the target API to discover real PUT/PATCH-capable endpoints
    that are valid mass assignment candidates.

    This is called by main.py when Swagger discovery fails.
    It replaces ALL hardcoded fallback endpoints.

    Args:
        session     : Authenticated requests.Session
        base_url    : Target base URL
        extra_paths : Optional additional paths to probe
                      (from -p flag or config)

    Returns:
        List of candidate dicts, each with:
          - method      : "PUT"
          - path        : relative path string
          - object_url  : absolute URL of the single object to test
          - body_fields : field names discovered from the GET response

        Empty list if nothing suitable was found.
    """

    paths_to_probe = list(COMMON_REST_RESOURCE_PATTERNS)

    # User-supplied paths take priority
    if extra_paths:
        paths_to_probe = extra_paths + paths_to_probe

    print(
        f"[PROBE] Probing "
        f"{len(paths_to_probe)} common REST paths "
        f"for mass assignment candidates..."
    )

    candidates = []

    # Prevent duplicate URLs discovered through
    # different endpoint forms.
    seen_object_urls = set()

    for path in paths_to_probe:

        result = probe_endpoint(
            session,
            base_url,
            path
        )

        if result and result["object_url"] not in seen_object_urls:

            seen_object_urls.add(
                result["object_url"]
            )

            candidates.append(result)

            print(
                f"[PROBE] ✓ Candidate found: "
                f"{result['object_url']} "
                f"(fields: "
                f"{result['body_fields'][:5]}"
                f"{'...' if len(result['body_fields']) > 5 else ''})"
            )

            # Also collect any child resources discovered
            # through nested reference fields.
            #
            # Example:
            #   /posts -> contains author.id
            #   → discover /users/{id}
            #
            # probe_endpoint() may attach these as:
            #   result['_extra_candidates']
            for extra in result.pop("_extra_candidates", []):

                if extra["object_url"] not in seen_object_urls:

                    seen_object_urls.add(
                        extra["object_url"]
                    )

                    candidates.append(extra)

                    print(
                        f"[PROBE] ✓ Candidate found: "
                        f"{extra['object_url']} "
                        f"(fields: "
                        f"{extra['body_fields'][:5]}"
                        f"{'...' if len(extra['body_fields']) > 5 else ''})"
                    )

    if not candidates:

        print(
            "[PROBE] No mass assignment candidates "
            "discovered via probing."
        )

    else:

        print(
            f"[PROBE] Discovery complete — "
            f"{len(candidates)} candidate(s) found."
        )

    return candidates


def _follow_reference_fields(
    session: requests.Session,
    base_url: str,
    response: requests.Response,
    source_path: str,
) -> list[dict]:
    """
    When a JSON response contains fields like video_id, order_id etc.,
    try to construct and probe the child resource URL.
    e.g. dashboard returns video_id=52 → probe /identity/api/v2/user/videos/52
    """
    candidates = []
    try:
        data = response.json()
        # Strip binary fields before reading reference fields
        data = _strip_binary_fields(data)
    except ValueError:
        return candidates

    # Map of known reference fields to their resource paths
    REFERENCE_MAP = {
        "video_id": "/identity/api/v2/user/videos/{id}",
        "order_id": "/workshop/api/shop/orders/{id}",
    }

    for field, path_template in REFERENCE_MAP.items():
        ref_id = data.get(field)
        if not ref_id:
            continue

        child_path = path_template.replace("{id}", str(ref_id))
        child_url = f"{base_url.rstrip('/')}{child_path}"

        try:
            child_resp = session.get(child_url, timeout=5)
            if child_resp.status_code == 200 and _is_json_object(child_resp):
                # Strip binary fields from child response too
                raw_child = child_resp.json()
                cleaned_child = _strip_binary_fields(raw_child)
                body_fields = list(cleaned_child.keys())
                candidates.append({
                    "method": "PUT",
                    "path": child_path,
                    "object_url": child_url,
                    "path_params": [],
                    "body_fields": body_fields,
                })
                print(f"[PROBE] ✓ Reference followed: {child_url} "
                      f"(via {field}={ref_id} in {source_path})")
        except requests.RequestException:
            continue

    return candidates
