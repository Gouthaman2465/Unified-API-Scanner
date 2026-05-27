"""
tests/rest/test_rate_limit.py — Unit tests for the Rate Limit Detection Module

Tests are fully offline — no real HTTP requests are made.
The requests.Session.get / post methods are monkey-patched with mock objects
so these tests run in any environment without a target API.

Run with:
    cd api2.00
    python -m pytest tests/rest/test_rate_limit.py -v
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from unittest.mock import MagicMock, patch
import pytest

from scanners.rest.rate_limit import (
    analyse_burst_results,
    build_finding,
    run_rate_limit_scan,
    RATE_LIMIT_STATUS_CODE,
    SUCCESS_STATUS_CODES,
)


# ---------------------------------------------------------------------------
# Helpers — build fake burst result lists
# ---------------------------------------------------------------------------

def _make_results(codes: list[int]) -> list[dict]:
    """Build a fake burst result list from a list of status codes."""
    results = []
    for i, code in enumerate(codes, 1):
        results.append({
            "request_number":   i,
            "status_code":      code,
            "response_time_ms": 40 + i,
            "is_success":       code in SUCCESS_STATUS_CODES,
            "is_rate_limited":  code == RATE_LIMIT_STATUS_CODE,
        })
    return results


# ---------------------------------------------------------------------------
# analyse_burst_results — pattern detection
# ---------------------------------------------------------------------------

class TestAnalyseBurstResults:

    def test_no_rate_limit_detected(self):
        """50 x 200 → pattern should be 'none'."""
        results = _make_results([200] * 50)
        analysis = analyse_burst_results(results)
        assert analysis["pattern"] == "none"
        assert analysis["rate_limited"] is False
        assert analysis["threshold"] is None
        assert analysis["success_count"] == 50

    def test_hard_rate_limit_detected(self):
        """200 x 10 then 429 x 40 → pattern should be 'hard'."""
        codes = [200] * 10 + [429] * 40
        results = _make_results(codes)
        analysis = analyse_burst_results(results)
        assert analysis["pattern"] == "hard"
        assert analysis["rate_limited"] is True
        assert analysis["threshold"] == 11        # first 429 at request 11
        assert analysis["soft_limit"] is False

    def test_soft_rate_limit_detected(self):
        """200 x 5, 429 x 3, 200 x 2 → pattern should be 'soft'."""
        codes = [200] * 5 + [429] * 3 + [200] * 2
        results = _make_results(codes)
        analysis = analyse_burst_results(results)
        assert analysis["pattern"] == "soft"
        assert analysis["rate_limited"] is True
        assert analysis["soft_limit"] is True
        assert analysis["threshold"] == 6

    def test_threshold_is_first_429(self):
        """Threshold should be the very first 429 in the sequence."""
        codes = [200, 200, 429, 429, 200]
        results = _make_results(codes)
        analysis = analyse_burst_results(results)
        assert analysis["threshold"] == 3    # index 3 (1-based) is the first 429

    def test_avg_response_time_calculated(self):
        """Average response time should be computed from non-zero values."""
        results = _make_results([200] * 10)
        # Override times manually
        for i, r in enumerate(results):
            r["response_time_ms"] = (i + 1) * 10   # 10, 20, ... 100
        analysis = analyse_burst_results(results)
        assert analysis["avg_response_ms"] == 55   # mean of 10..100


# ---------------------------------------------------------------------------
# build_finding — output format
# ---------------------------------------------------------------------------

class TestBuildFinding:

    def test_no_finding_for_hard_limit(self):
        """Hard rate limit = correct behaviour = no finding generated."""
        analysis = {
            "pattern": "hard", "rate_limited": True, "threshold": 10,
            "soft_limit": False, "success_count": 9, "rate_limit_count": 41,
            "avg_response_ms": 45,
        }
        finding = build_finding("http://target/login", analysis, 50)
        assert finding is None

    def test_finding_for_no_rate_limit(self):
        """Pattern 'none' should produce a High severity finding."""
        analysis = {
            "pattern": "none", "rate_limited": False, "threshold": None,
            "soft_limit": False, "success_count": 50, "rate_limit_count": 0,
            "avg_response_ms": 42,
        }
        finding = build_finding("http://target/login", analysis, 50)
        assert finding is not None
        assert finding["owasp"] == "API4:2023"
        assert finding["protocol"] == "REST"
        assert finding["evidence"]["severity"] == "High"
        assert finding["evidence"]["pattern"] == "none"

    def test_finding_for_soft_rate_limit(self):
        """Pattern 'soft' should produce a Medium severity finding."""
        analysis = {
            "pattern": "soft", "rate_limited": True, "threshold": 20,
            "soft_limit": True, "success_count": 25, "rate_limit_count": 25,
            "avg_response_ms": 50,
        }
        finding = build_finding("http://target/login", analysis, 50)
        assert finding is not None
        assert finding["evidence"]["severity"] == "Medium"
        assert finding["evidence"]["threshold"] == 20

    def test_finding_url_is_set(self):
        """The URL in the finding must match what was passed in."""
        analysis = {
            "pattern": "none", "rate_limited": False, "threshold": None,
            "soft_limit": False, "success_count": 50, "rate_limit_count": 0,
            "avg_response_ms": 40,
        }
        url = "http://127.0.0.1:8888/api/auth/login"
        finding = build_finding(url, analysis, 50)
        assert finding["url"] == url


# ---------------------------------------------------------------------------
# run_rate_limit_scan — integration with mocked session
# ---------------------------------------------------------------------------

class TestRunRateLimitScan:

    def _mock_session(self, status_codes: list[int]) -> MagicMock:
        """
        Creates a mock requests.Session where .get() cycles through
        the provided status codes in order.
        """
        session = MagicMock()
        responses = []
        for code in status_codes:
            resp = MagicMock()
            resp.status_code = code
            responses.append(resp)
        session.get.side_effect = responses
        return session

    def test_returns_empty_list_when_hard_limit(self):
        """Hard limit → no findings → empty list returned."""
        codes = [200] * 10 + [429] * 40
        session = self._mock_session(codes)
        findings = run_rate_limit_scan(
            session, "http://127.0.0.1:8888",
            endpoint_path="/identity/api/auth/login",
            burst_count=50,
        )
        assert findings == []

    def test_returns_finding_when_no_limit(self):
        """No 429 at all → High finding returned."""
        codes = [200] * 50
        session = self._mock_session(codes)
        findings = run_rate_limit_scan(
            session, "http://127.0.0.1:8888",
            endpoint_path="/identity/api/auth/login",
            burst_count=50,
        )
        assert len(findings) == 1
        assert findings[0]["owasp"] == "API4:2023"
        assert findings[0]["evidence"]["severity"] == "High"

    def test_url_constructed_correctly(self):
        """URL must be base_url + endpoint_path without double slashes."""
        codes = [200] * 50
        session = self._mock_session(codes)
        run_rate_limit_scan(
            session, "http://127.0.0.1:8888/",
            endpoint_path="/identity/api/auth/login",
            burst_count=50,
        )
        # All calls should go to the correctly joined URL
        called_url = session.get.call_args_list[0][0][0]
        assert "//identity" not in called_url
        assert called_url.startswith("http://127.0.0.1:8888")
