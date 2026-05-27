"""
discovery/protocol_detector.py

Unified API protocol detection engine for Aegis-API.

Supports:
  - REST
  - SOAP
  - GraphQL

Detection strategy:
  1. Heuristic pre-classification
  2. GraphQL probe
  3. SOAP probe
  4. REST fallback
"""

import logging
import requests

from dataclasses import dataclass, field
from typing import List, Optional


logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------

PROBE_TIMEOUT = 3

GRAPHQL_INTROSPECTION_PROBE = """
{
  __schema {
    queryType {
      name
    }
  }
}
"""

SOAP_PROBE_ENVELOPE = """<?xml version="1.0" encoding="utf-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Header/>
  <soapenv:Body/>
</soapenv:Envelope>
"""


# ---------------------------------------------------------------------------
# DETECTION RESULT MODEL
# ---------------------------------------------------------------------------

@dataclass
class DetectionResult:
    protocol: str
    confidence: str
    signals: List[str] = field(default_factory=list)
    base_url: str = ""


# ---------------------------------------------------------------------------
# MAIN DETECTOR
# ---------------------------------------------------------------------------

def detect_protocol(
    base_url: str,
    proxy: Optional[str] = None
) -> DetectionResult:

    proxies = {"http": proxy, "https": proxy} if proxy else None

    logger.info(
        "Starting protocol detection for: %s",
        base_url
    )

    base_url_lower = base_url.lower()

    # -------------------------------------------------------------------
    # SOAP HEURISTIC PRE-CHECK
    # -------------------------------------------------------------------

    if (
        ".asmx" in base_url_lower or
        ".wso" in base_url_lower or
        "soap" in base_url_lower or
        "wsdl" in base_url_lower
    ):

        logger.info(
            "SOAP heuristic triggered for target"
        )

        soap_result = _probe_soap(
            base_url,
            proxies
        )

        if soap_result.confidence in ("HIGH", "MEDIUM"):

            logger.info(
                "SOAP detected with %s confidence",
                soap_result.confidence
            )

            return soap_result

    # -------------------------------------------------------------------
    # GRAPHQL
    # -------------------------------------------------------------------

    graphql_result = _probe_graphql(
        base_url,
        proxies
    )

    if graphql_result.confidence in ("HIGH", "MEDIUM"):

        logger.info(
            "GraphQL detected with %s confidence",
            graphql_result.confidence
        )

        return graphql_result

    # -------------------------------------------------------------------
    # SOAP
    # -------------------------------------------------------------------

    soap_result = _probe_soap(
        base_url,
        proxies
    )

    if soap_result.confidence in ("HIGH", "MEDIUM"):

        logger.info(
            "SOAP detected with %s confidence",
            soap_result.confidence
        )

        return soap_result

    # -------------------------------------------------------------------
    # REST
    # -------------------------------------------------------------------

    rest_result = _probe_rest(
        base_url,
        proxies
    )

    if rest_result.confidence in ("HIGH", "MEDIUM"):

        logger.info(
            "REST detected with %s confidence",
            rest_result.confidence
        )

        return rest_result

    # -------------------------------------------------------------------
    # UNKNOWN
    # -------------------------------------------------------------------

    logger.warning(
        "Protocol detection inconclusive for: %s",
        base_url
    )

    return DetectionResult(
        protocol="UNKNOWN",
        confidence="LOW",
        signals=[
            "No definitive protocol fingerprints found at any probed path"
        ],
        base_url=base_url
    )


# ---------------------------------------------------------------------------
# GRAPHQL DETECTION
# ---------------------------------------------------------------------------

def _probe_graphql(
    base_url: str,
    proxies: Optional[dict]
) -> DetectionResult:

    signals = []

    candidate_paths = [
        "",            # probe the base URL exactly as given first
        "/graphql",
        "/api/graphql",
        "/query",
        "/gql",
        "/graphql/v1",
        "/api/v1/graphql"
    ]

    for path in candidate_paths:

        probe_url = base_url.rstrip("/") + path

        logger.debug(
            "GraphQL probe: POST %s",
            probe_url
        )

        try:

            response = requests.post(
                probe_url,
                json={
                    "query": GRAPHQL_INTROSPECTION_PROBE
                },
                headers={
                    "Content-Type": "application/json"
                },
                timeout=PROBE_TIMEOUT,
                proxies=proxies,
                verify=False
            )

            content_type = response.headers.get(
                "Content-Type",
                ""
            ).lower()

            body_text = response.text.lower()

            # -----------------------------------------------------------
            # Introspection success
            # -----------------------------------------------------------

            if "__schema" in body_text:

                signals.append(
                    f"Introspection query returned __schema at {path}"
                )

                signals.append(
                    f"Content-Type: {content_type}"
                )

                signals.append(
                    "Introspection is ENABLED — schema fully exposed"
                )

                return DetectionResult(
                    protocol="GRAPHQL",
                    confidence="HIGH",
                    signals=signals,
                    base_url=probe_url
                )

            # -----------------------------------------------------------
            # GraphQL error shape
            # -----------------------------------------------------------

            if (
                "errors" in body_text and
                "application/json" in content_type
            ):

                signals.append(
                    f"GraphQL error response detected at {path}"
                )

                return DetectionResult(
                    protocol="GRAPHQL",
                    confidence="HIGH",
                    signals=signals,
                    base_url=probe_url
                )

            # -----------------------------------------------------------
            # GraphQL playground detection
            # -----------------------------------------------------------

            if (
                "graphql" in body_text or
                "graphiql" in body_text or
                "apollo" in body_text
            ):

                signals.append(
                    f"GraphQL playground interface detected at {path}"
                )

                return DetectionResult(
                    protocol="GRAPHQL",
                    confidence="MEDIUM",
                    signals=signals,
                    base_url=probe_url
                )

        except requests.exceptions.RequestException as e:

            logger.debug(
                "GraphQL probe failed at %s: %s",
                probe_url,
                str(e)
            )

            continue

    return DetectionResult(
        protocol="UNKNOWN",
        confidence="LOW",
        signals=["No GraphQL fingerprints found"],
        base_url=base_url
    )


# ---------------------------------------------------------------------------
# SOAP DETECTION
# ---------------------------------------------------------------------------

def _probe_soap(
    base_url: str,
    proxies: Optional[dict]
) -> DetectionResult:

    signals = []

    base_url_lower = base_url.lower()

    # -------------------------------------------------------------------
    # Smart SOAP path selection
    # -------------------------------------------------------------------

    if (
        ".asmx" in base_url_lower or
        ".wso" in base_url_lower
    ):

        soap_sub_paths = [""]

    else:

        soap_sub_paths = [
            "",
            "/services",
            "/ws",
            "/soap",
            "/api/soap",
            "/service",
            "/webservice",
            "/WebService.asmx",
            "/Service.asmx"
        ]

    for sub_path in soap_sub_paths:

        probe_url = base_url.rstrip("/") + sub_path

        # ---------------------------------------------------------------
        # WSDL PROBE
        # ---------------------------------------------------------------

        wsdl_signal = _check_wsdl_at_url(
            probe_url,
            proxies
        )

        if wsdl_signal:

            signals.append(wsdl_signal)

            return DetectionResult(
                protocol="SOAP",
                confidence="HIGH",
                signals=signals,
                base_url=probe_url
            )

        # ---------------------------------------------------------------
        # SOAP ENVELOPE PROBE
        # ---------------------------------------------------------------

        logger.debug(
            "SOAP probe: POST %s",
            probe_url
        )

        try:

            response = requests.post(
                probe_url,
                data=SOAP_PROBE_ENVELOPE,
                headers={
                    "Content-Type": "text/xml; charset=utf-8",
                    "SOAPAction": '""'
                },
                timeout=PROBE_TIMEOUT,
                proxies=proxies,
                verify=False
            )

            content_type = response.headers.get(
                "Content-Type",
                ""
            ).lower()

            body_text = response.text.lower()

            # -----------------------------------------------------------
            # SOAP Envelope
            # -----------------------------------------------------------

            if (
                "<soap" in body_text or
                "soapenv:envelope" in body_text or
                "soap:envelope" in body_text or
                "soap-env:envelope" in body_text
            ):

                signals.append(
                    f"SOAP envelope detected at {sub_path or '/'}"
                )

                return DetectionResult(
                    protocol="SOAP",
                    confidence="HIGH",
                    signals=signals,
                    base_url=probe_url
                )

            # -----------------------------------------------------------
            # SOAP Fault
            # -----------------------------------------------------------

            if (
                "fault" in body_text and
                "xml" in content_type
            ):

                signals.append(
                    f"SOAP fault detected at {sub_path or '/'}"
                )

                return DetectionResult(
                    protocol="SOAP",
                    confidence="HIGH",
                    signals=signals,
                    base_url=probe_url
                )

            # -----------------------------------------------------------
            # Weak XML signal
            # -----------------------------------------------------------

            if (
                "xml" in content_type and
                response.status_code != 404
            ):

                signals.append(
                    f"XML response detected at {sub_path or '/'}"
                )

        except requests.exceptions.RequestException as e:

            logger.debug(
                "SOAP probe failed at %s: %s",
                probe_url,
                str(e)
            )

            continue

    # -------------------------------------------------------------------
    # MEDIUM SOAP
    # -------------------------------------------------------------------

    if signals:

        return DetectionResult(
            protocol="SOAP",
            confidence="MEDIUM",
            signals=signals,
            base_url=base_url
        )

    return DetectionResult(
        protocol="UNKNOWN",
        confidence="LOW",
        signals=["No SOAP fingerprints found"],
        base_url=base_url
    )


def _check_wsdl_at_url(
    url: str,
    proxies: Optional[dict]
) -> Optional[str]:

    wsdl_suffixes = [
        "?wsdl",
        "?WSDL",
        "?wsdl=1"
    ]

    for suffix in wsdl_suffixes:

        wsdl_url = f"{url.rstrip('/')}{suffix}"

        logger.debug(
            "WSDL probe: GET %s",
            wsdl_url
        )

        try:

            response = requests.get(
                wsdl_url,
                timeout=PROBE_TIMEOUT,
                proxies=proxies,
                verify=False,
                allow_redirects=True
            )

            content_type = response.headers.get(
                "Content-Type",
                ""
            ).lower()

            body_text = response.text.lower()

            wsdl_detected = (
                "<wsdl:definitions" in body_text or
                (
                    "<definitions" in body_text and
                    "schemas.xmlsoap.org/wsdl" in body_text
                )
            )

            if (
                response.status_code == 200 and
                wsdl_detected
            ):

                logger.info(
                    "WSDL detected at %s",
                    wsdl_url
                )

                return (
                    f"WSDL exposed at {wsdl_url} "
                    f"(Content-Type: {content_type})"
                )

        except requests.exceptions.RequestException as e:

            logger.debug(
                "WSDL probe failed at %s: %s",
                wsdl_url,
                str(e)
            )

            continue

    return None


# ---------------------------------------------------------------------------
# REST DETECTION
# ---------------------------------------------------------------------------

def _probe_rest(
    base_url: str,
    proxies: Optional[dict]
) -> DetectionResult:

    signals = []

    rest_paths = [
        "",
        "/api",
        "/api/v1",
        "/identity/api/v2",
        "/workshop/api"
    ]

    for path in rest_paths:

        probe_url = base_url.rstrip("/") + path

        logger.debug(
            "REST probe: GET %s",
            probe_url
        )

        try:

            response = requests.get(
                probe_url,
                timeout=PROBE_TIMEOUT,
                proxies=proxies,
                verify=False
            )

            content_type = response.headers.get(
                "Content-Type",
                ""
            ).lower()

            body_preview = response.text[:200]

            # -----------------------------------------------------------
            # JSON Detection
            # -----------------------------------------------------------

            if "application/json" in content_type:

                signals.append(
                    f"JSON Content-Type confirmed: {content_type}"
                )

                try:

                    response.json()

                    signals.append(
                        "Response body is valid parseable JSON"
                    )

                    return DetectionResult(
                        protocol="REST",
                        confidence="HIGH",
                        signals=signals,
                        base_url=probe_url
                    )

                except ValueError:

                    logger.debug(
                        "JSON parsing failed. Body preview: %s",
                        body_preview
                    )

                    signals.append(
                        "Content-Type claims JSON but body invalid"
                    )

                    return DetectionResult(
                        protocol="REST",
                        confidence="MEDIUM",
                        signals=signals,
                        base_url=probe_url
                    )

            # -----------------------------------------------------------
            # Generic API behavior
            # -----------------------------------------------------------

            if response.status_code in (200, 401, 403):

                if "html" not in content_type:

                    signals.append(
                        f"API-like HTTP behavior detected at {path}"
                    )

                    return DetectionResult(
                        protocol="REST",
                        confidence="MEDIUM",
                        signals=signals,
                        base_url=probe_url
                    )

        except requests.exceptions.RequestException as e:

            logger.debug(
                "REST probe failed at %s: %s",
                probe_url,
                str(e)
            )

            continue

    return DetectionResult(
        protocol="UNKNOWN",
        confidence="LOW",
        signals=["No REST fingerprints found"],
        base_url=base_url
    )
