"""
scanners/graphql/depth_limit.py

GraphQL Query Depth Limit Attack Scanner
OWASP API4 — Unrestricted Resource Consumption

Theory:
  GraphQL clients control query shape. Without a depth
  limit, a client can nest queries arbitrarily deep,
  forcing the server to resolve circular type references
  repeatedly. This exhausts CPU and memory — causing
  Denial of Service from a single HTTP request.

Attack flow:
  1. Receive the type map from introspection (Phase 5)
  2. Find a circular type chain (A → B → A → B...)
  3. Build queries at depths: 3, 5, 7, 10, 15, 20
  4. Send each query and measure response time
  5. Flag if server processes depth > 10 without error
  6. Flag critical if server crashes or times out
"""

import time
import logging
import json

logger = logging.getLogger(__name__)


# --- QUERY BUILDING ---

def find_circular_chain(type_map: dict) -> list[str]:
    """
    Scan the introspection type map to find a circular
    field chain suitable for a depth bomb.

    A circular chain is: TypeA has a field of TypeB,
    and TypeB has a field of TypeA (or back to any
    ancestor in the chain).

    Args:
        type_map: Dict from graphql_schema.py.
                  Format: { "TypeName": ["field1", "field2", ...] }
                  where field values are other type names.

    Returns:
        A list of alternating field names that form a
        circular chain, e.g. ["orders", "user", "orders", "user"]
        Returns an empty list if no circular chain found.

    Example:
        type_map = {
            "User":  {"orders": "Order"},
            "Order": {"user":   "User"},
        }
        Result: ["orders", "user"]  ← two fields to alternate
    """
    # Build a reverse lookup: TypeName → fields that return it
    # We want to find: TypeA.fieldX → TypeB, TypeB.fieldY → TypeA
    for type_name, fields in type_map.items():
        for field_name, return_type in fields.items():
            # Check if the return type has a field pointing back
            if return_type in type_map:
                back_fields = type_map[return_type]
                for back_field_name, back_return_type in back_fields.items():
                    if back_return_type == type_name:
                        # Found a circular pair
                        logger.debug(
                            "Circular chain found: %s.%s → %s.%s → %s",
                            type_name, field_name,
                            return_type, back_field_name,
                            type_name
                        )
                        return [field_name, back_field_name]

    # No circular chain found in type map
    return []






def build_depth_query(
    root_query: str,
    root_args: str,
    circular_fields: list[str],
    depth: int
) -> str:
    """
    Construct a GraphQL query nested `depth` levels deep
    using the circular field chain.

    Indexing rule:
      The root query returns TypeA. So the first nested field
      must be circular_fields[0] (the field ON TypeA that leads
      to TypeB). Then circular_fields[1] leads back to TypeA.
      We always start from index 0, not from depth % len.

    Example with circular_fields = ["owner", "paste"], depth = 3:
      pastes {        ← root (returns PasteObject)
        owner {       ← index 0: PasteObject.owner → OwnerObject
          paste {     ← index 1: OwnerObject.paste → PasteObject
            owner {   ← index 0: PasteObject.owner → OwnerObject
              id
            }
          }
        }
      }
    """
    if not circular_fields:
        circular_fields = ["items", "node"]

    # Build from inside out.
    # Innermost leaf is just a scalar.
    inner = "id"

    # Wrap depth times, starting field index from 0 at the outermost level.
    # We build inside-out, so the outermost wrap is added last.
    # At wrap i (0-indexed from outside), field index = i % len(circular_fields).
    # Building inside-out means wrap 0 is added in the last iteration.
    # So at iteration step k (from depth-1 down to 0):
    #   field_index = k % len(circular_fields)
    for k in range(depth - 1, -1, -1):
        field = circular_fields[k % len(circular_fields)]
        inner = field + " { " + inner + " }"

    return "{ " + root_query + root_args + " { " + inner + " } }"
    
    
    
    


def build_fallback_depth_query(depth: int) -> str:
    """
    Build a generic depth bomb query when no schema
    introspection data is available.

    Uses a common circular pattern seen in many GraphQL
    APIs: viewer → repositories → owner → repositories...

    This is a last-resort probe when introspection failed
    but we still want to test depth limits.

    Args:
        depth: Number of nesting levels to generate.

    Returns:
        A generic deeply nested query string.
    """
    # Build from inside out
    inner = "id"
    fields = ["repositories { nodes", "owner"]

    for i in range(depth):
        field = fields[i % len(fields)]
        indent = "  " * (depth - i + 1)
        inner = field + " {\n" + indent + "  " + inner + "\n" + indent + "}"

    return "{\n  viewer {\n    " + inner + "\n  }\n}"


# --- RESPONSE ANALYSIS ---



def detect_exponential_slowdown(
    timing_results: list[dict],
    threshold_multiplier: float = 4.0
) -> dict | None:
    """
    Check if response times are growing exponentially
    as depth increases — a sign of resource exhaustion
    even if the server never explicitly errors.

    Args:
        timing_results:       List of classify_depth_response
                              output dicts, in depth order.
        threshold_multiplier: How much slower the last result
                              must be vs the first to flag.
                              Default: 4x slowdown = suspicious.

    Returns:
        A finding dict if exponential slowdown detected,
        None otherwise.
    """
    # Need at least two successful results to compare
    successful = [r for r in timing_results if r["status"] == "ok"]
    if len(successful) < 2:
        return None

    baseline_ms = successful[0]["elapsed_ms"]
    last_ms = successful[-1]["elapsed_ms"]

    if baseline_ms <= 0:
        return None

    slowdown_ratio = last_ms / baseline_ms

    if slowdown_ratio >= threshold_multiplier:
        return {
            "type": "exponential_slowdown",
            "baseline_depth": successful[0]["depth"],
            "baseline_ms": baseline_ms,
            "peak_depth": successful[-1]["depth"],
            "peak_ms": last_ms,
            "slowdown_ratio": round(slowdown_ratio, 2),
            "note": (
                f"Response time grew {slowdown_ratio:.1f}x from "
                f"depth {successful[0]['depth']} ({baseline_ms:.0f}ms) "
                f"to depth {successful[-1]['depth']} ({last_ms:.0f}ms)"
            )
        }

    return None




def measure_response_depth(response_body: str) -> int:
    """
    Count how many levels deep the actual returned data goes.
    Handles both dict and list nodes — when a list is encountered,
    peek into the first element and keep walking.

    Returns 0 if response is empty, null, or unparseable.
    """
    try:
        data = json.loads(response_body)
        node = data.get("data", {})
        depth = 0

        while node is not None:
            if isinstance(node, dict) and node:
                depth += 1
                node = next(iter(node.values()))
            elif isinstance(node, list) and node:
                node = node[0]
            else:
                break

        return depth
    except Exception:
        return 0



def classify_depth_response(
    depth: int,
    status_code: int,
    response_body: str,
    elapsed_ms: float
) -> dict:
    """
    Analyze the server's response to a depth query and
    classify the result.

    Args:
        depth:         The nesting depth that was sent.
        status_code:   HTTP status code returned.
        response_body: Raw response text.
        elapsed_ms:    How long the request took in ms.

    Returns:
        A dict with keys:
          - depth: int
          - status: "ok" | "error" | "timeout" | "crash"
          - server_rejected: bool
          - elapsed_ms: float
          - actual_data_depth: int  (new — how deep data actually went)
          - confidence: "HIGH" | "LOW"  (new — false positive signal)
          - note: str
    """
    result = {
        "depth": depth,
        "status": "ok",
        "server_rejected": False,
        "elapsed_ms": round(elapsed_ms, 2),
        "actual_data_depth": 0,
        "confidence": "HIGH",
        "note": ""
    }

    # Check for explicit depth limit rejection
    depth_error_signals = [
        "max depth",
        "maximum depth",
        "depth limit",
        "query too deep",
        "query depth",
        "exceeds maximum",
        "complexity",
        "query validation failed",  # catches non-standard rejections
        "validation error",
    ]
    body_lower = response_body.lower()
    for signal in depth_error_signals:
        if signal in body_lower:
            result["status"] = "error"
            result["server_rejected"] = True
            result["note"] = (
                f"Server explicitly rejected depth {depth}: "
                f"contains '{signal}'"
            )
            return result

    # Check for generic GraphQL errors with null data
    if '"errors"' in response_body and '"data":null' in response_body:
        result["status"] = "error"
        result["note"] = (
            f"Server returned GraphQL error at depth {depth}"
        )
        return result

    # Check for HTTP-level errors
    if status_code == 500:
        result["status"] = "crash"
        result["note"] = (
            f"Server returned 500 at depth {depth} — possible crash"
        )
        return result

    if status_code in (503, 504):
        result["status"] = "timeout"
        result["note"] = (
            f"Server returned {status_code} at depth {depth} "
            f"— timeout/unavailable"
        )
        return result

    if status_code == 0:
        result["status"] = "timeout"
        result["note"] = f"Request timed out at depth {depth}"
        return result

    # --- False positive check ---
    # Server returned 200 — but did it actually resolve the chain,
    # or did it hit null early and stop resolving?
    actual_depth = measure_response_depth(response_body)
    result["actual_data_depth"] = actual_depth

    if actual_depth < (depth // 2):
        # Data depth is less than half the query depth —
        # chain resolved to null early, server was not truly stressed.
        result["confidence"] = "LOW"
        result["note"] = (
            f"Server processed depth {depth} in {elapsed_ms:.0f}ms "
            f"BUT data only {actual_depth} levels deep — "
            f"possible null early exit. Confidence: LOW."
        )
    else:
        result["confidence"] = "HIGH"
        result["note"] = (
            f"Server processed depth {depth} in {elapsed_ms:.0f}ms "
            f"(data depth: {actual_depth}). Confidence: HIGH."
        )

    return result
    
    
    
    
    

# --- MAIN SCANNER ENTRY POINT ---

def run_depth_limit_scan(
    session,
    target_url: str,
    type_map: dict,
    audit_logger,
    depths: list[int] | None = None,
    request_timeout: int = 15
) -> list[dict]:
    """
    Run the full depth limit attack scan against a
    GraphQL endpoint.

    This function:
    1. Finds a circular type chain in the schema
    2. Builds queries at each depth level in `depths`
    3. Sends each query and records timing + response
    4. Classifies each response (with false positive detection)
    5. Detects exponential slowdown pattern
    6. Returns a list of findings ready for reporting

    Args:
        session:         requests.Session with auth headers set
        target_url:      GraphQL endpoint URL (e.g. /graphql)
        type_map:        Dict from introspection phase.
                         Format: { "TypeName": {"fieldName": "ReturnType"} }
                         Pass empty dict to use fallback queries.
        audit_logger:    utils/logger.py AuditLogger instance
        depths:          List of depth levels to test.
                         Default: [3, 5, 7, 10, 15, 20]
        request_timeout: Per-request timeout in seconds.
                         Default: 15s (generous for deep queries)

    Returns:
        List of finding dicts. Empty list = no vulnerabilities.
        Each finding has these keys:
          - title, owasp, severity, protocol
          - evidence (query sent, response received)
          - depth_at_failure, max_depth_processed
          - confidence_note (explains HIGH/LOW confidence)
    """
    if depths is None:
        depths = [3, 5, 7, 10, 15, 20]

    findings = []
    timing_results = []

    logger.info("[Depth Scan] Starting depth limit scan on %s", target_url)
    logger.info("[Depth Scan] Testing depths: %s", depths)

    # Step 1: Find circular chain from introspection data
    circular_fields = find_circular_chain(type_map)

    if circular_fields:
        logger.info(
            "[Depth Scan] Circular chain found: %s",
            " → ".join(circular_fields)
        )
        use_fallback = False
    else:
        logger.warning(
            "[Depth Scan] No circular chain found in schema. "
            "Using generic fallback queries."
        )
        use_fallback = True

    # Step 2: Determine root query from type_map
    # Look for a top-level query type field to use as entry point
    root_query = "user"
    root_args = "(id: 1)"
    for type_name, fields in type_map.items():
        if type_name.lower() in ("query", "querytype"):
            if fields:
                root_query = list(fields.keys())[0]
                root_args = ""
            break

    # Step 3: Probe each depth level
    max_depth_processed = 0
    first_rejected_depth = None

    for depth in depths:
        # Build the query for this depth
        if use_fallback:
            query_str = build_fallback_depth_query(depth)
        else:
            query_str = build_depth_query(
                root_query, root_args, circular_fields, depth
            )

        logger.debug("[Depth Scan] Depth %d query:\n%s", depth, query_str)

        # Send the query and time it
        start = time.perf_counter()
        status_code = 0
        response_body = ""

        try:
            response = session.post(
                target_url,
                json={"query": query_str},
                timeout=request_timeout
            )
            status_code = response.status_code
            response_body = response.text

        except Exception as e:
            response_body = str(e)
            logger.warning(
                "[Depth Scan] Request failed at depth %d: %s", depth, e
            )

        elapsed_ms = (time.perf_counter() - start) * 1000

        # Classify this response (includes false positive confidence check)
        result = classify_depth_response(
            depth, status_code, response_body, elapsed_ms
        )
        timing_results.append(result)

        # Log to audit CSV
        if audit_logger:
            audit_logger.log(
                protocol="GraphQL",
                method="POST",
                url=target_url,
                status_code=status_code,
                finding=f"DepthProbe-D{depth}: {result['status']}",
                evidence=query_str[:200]
            )

        logger.info(
            "[Depth Scan] Depth %d → %s | confidence: %s | %s [%.0fms]",
            depth,
            result["status"],
            result.get("confidence", "N/A"),
            result["note"],
            elapsed_ms
        )

        # Track progress
        if result["status"] == "ok":
            max_depth_processed = depth

        # Track first explicit rejection
        if result["server_rejected"] and first_rejected_depth is None:
            first_rejected_depth = depth
            logger.info(
                "[Depth Scan] Server enforces depth limit at depth %d",
                depth
            )
            break

        # Stop probing if server crashed — don't DoS the lab further
        if result["status"] in ("crash", "timeout"):
            logger.warning(
                "[Depth Scan] Server crash/timeout at depth %d — "
                "stopping probe to avoid extended DoS",
                depth
            )
            findings.append({
                "title": "GraphQL Query Depth — Server Crash/Timeout",
                "protocol": "GraphQL",
                "owasp": "API4 — Unrestricted Resource Consumption",
                "severity": "Critical",
                "cvss_base": 7.5,
                "depth_at_failure": depth,
                "max_depth_processed": max_depth_processed,
                "confidence_note": "Critical — server failed to respond.",
                "evidence": {
                    "query_sent": query_str,
                    "response": response_body[:500],
                    "elapsed_ms": round(elapsed_ms, 2)
                },
                "description": (
                    f"The GraphQL endpoint crashed or timed out when "
                    f"processing a query nested {depth} levels deep. "
                    f"No depth limit is enforced. A single malicious "
                    f"HTTP request can cause server Denial of Service."
                ),
                "remediation": (
                    "Implement a query depth limit of 10 or fewer levels. "
                    "Use a GraphQL middleware library such as "
                    "graphql-depth-limit (Node.js) or graphene-django's "
                    "max_depth setting (Python). Also implement query "
                    "complexity analysis as a complementary control."
                )
            })
            break

    # Step 4: Check if server processed deep queries without any rejection.
    # Also check confidence — if all "ok" results had LOW confidence
    # (data resolved to null early), downgrade severity and flag for
    # manual verification instead of reporting a clean High.
    if max_depth_processed >= 10 and first_rejected_depth is None:

        high_confidence_results = [
            r for r in timing_results
            if r["status"] == "ok" and r.get("confidence") == "HIGH"
        ]
        low_confidence_results = [
            r for r in timing_results
            if r["status"] == "ok" and r.get("confidence") == "LOW"
        ]

        if low_confidence_results and not high_confidence_results:
            # Every successful probe hit null early —
            # server was never actually stressed. Weak finding.
            severity = "Medium"
            cvss_base = 4.3
            confidence_note = (
                "All depth probes returned shallow data — "
                "circular chain likely resolves to null early. "
                "Manual verification recommended before reporting."
            )
        else:
            # At least some probes confirmed deep data resolution —
            # server genuinely processed the nested queries.
            severity = "High"
            cvss_base = 6.5
            confidence_note = (
                f"{len(high_confidence_results)} of "
                f"{len(timing_results)} probes confirmed deep "
                f"data resolution (confidence: HIGH)."
            )

        findings.append({
            "title": "GraphQL Query Depth Limit Not Enforced",
            "protocol": "GraphQL",
            "owasp": "API4 — Unrestricted Resource Consumption",
            "severity": severity,
            "cvss_base": cvss_base,
            "depth_at_failure": None,
            "max_depth_processed": max_depth_processed,
            "confidence_note": confidence_note,
            "evidence": {
                "depths_tested": depths,
                "timing_results": timing_results,
                "max_depth_responded": max_depth_processed
            },
            "description": (
                f"The GraphQL endpoint processed queries nested up to "
                f"{max_depth_processed} levels deep without returning "
                f"any depth limit error. {confidence_note}"
            ),
            "remediation": (
                "Implement query depth limiting at the GraphQL server level. "
                "A maximum depth of 10 is the common industry standard. "
                "Combine with query complexity scoring for comprehensive "
                "resource consumption protection."
            )
        })

    # Step 5: Check for exponential slowdown even if no explicit crash
    slowdown = detect_exponential_slowdown(timing_results)
    if slowdown:
        findings.append({
            "title": "GraphQL Depth Query — Exponential Response Time Growth",
            "protocol": "GraphQL",
            "owasp": "API4 — Unrestricted Resource Consumption",
            "severity": "Medium",
            "cvss_base": 5.3,
            "depth_at_failure": None,
            "max_depth_processed": max_depth_processed,
            "confidence_note": (
                f"Response time grew {slowdown['slowdown_ratio']}x — "
                f"non-linear scaling confirmed."
            ),
            "evidence": slowdown,
            "description": (
                f"Response times grew {slowdown['slowdown_ratio']}x as "
                f"query depth increased from {slowdown['baseline_depth']} "
                f"to {slowdown['peak_depth']} levels. This non-linear "
                f"scaling indicates resolver-level resource exhaustion "
                f"even without an explicit server crash."
            ),
            "remediation": (
                "Implement DataLoader batching to reduce resolver-level "
                "database queries. Add query depth and complexity limits. "
                "Monitor response time distribution per query depth."
            )
        })

    if not findings:
        logger.info(
            "[Depth Scan] No depth limit vulnerabilities found. "
            "Server appears to enforce limits correctly."
        )
    else:
        logger.info(
            "[Depth Scan] %d finding(s) identified.", len(findings)
        )

    return findings
