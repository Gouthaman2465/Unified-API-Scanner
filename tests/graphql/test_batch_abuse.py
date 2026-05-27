# tests/graphql/test_batch_abuse.py
# Phase 12: Unit tests for the GraphQL batch abuse scanner
#
# These tests run without a live server by using mock objects.
# Run from the project root:
#   cd api2.00
#   python -m pytest tests/graphql/test_batch_abuse.py -v

import json
import unittest
from unittest.mock import MagicMock, patch, call

# Add project root to path so imports work
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from scanners.graphql.batch_abuse import (
    build_array_batch_payload,
    build_alias_batch_mutation,
    build_generic_alias_batch,
    find_login_mutation,
    find_any_query_field,
    run_array_batch_test,
    run_alias_batch_test,
    check_batch_abuse,
    BATCH_SIZE,
    VULNERABLE_THRESHOLD,
)


# ============================================================
# HELPER: Mock Schema Builder
# ============================================================

def make_mock_schema(mutation_type="Mutation", has_login=True):
    """
    Builds a minimal mock schema object that mimics
    the GraphQLSchema structure from discovery/graphql_schema.py.
    """
    schema = MagicMock()
    schema.query_type = "Query"
    schema.mutation_type = mutation_type

    # Build a mock login field
    login_field = MagicMock()
    login_field.name = "login"

    email_arg = MagicMock()
    email_arg.name = "email"

    password_arg = MagicMock()
    password_arg.name = "password"

    login_field.args = [email_arg, password_arg]

    # Build a mock query field
    query_field = MagicMock()
    query_field.name = "pastes"
    query_field.args = []
    query_field.fields = []

    # Build mock types
    mutation_type_obj = MagicMock()
    mutation_type_obj.name = mutation_type
    mutation_type_obj.fields = [login_field] if has_login else []

    query_type_obj = MagicMock()
    query_type_obj.name = "Query"
    query_type_obj.fields = [query_field]

    schema.types = [mutation_type_obj, query_type_obj]

    return schema


# ============================================================
# TESTS: Payload Builders
# ============================================================

class TestPayloadBuilders(unittest.TestCase):

    def test_array_batch_produces_list(self):
        """build_array_batch_payload should return a list of dicts."""
        result = build_array_batch_payload("{ __typename }", 5)
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 5)
        for item in result:
            self.assertIn("query", item)

    def test_array_batch_count_respected(self):
        """The count argument must control how many operations are produced."""
        result = build_array_batch_payload("{ __typename }", BATCH_SIZE)
        self.assertEqual(len(result), BATCH_SIZE)

    def test_alias_mutation_contains_mutation_keyword(self):
        """build_alias_batch_mutation must produce a document starting with 'mutation'."""
        doc = build_alias_batch_mutation("login", "email", "password", 3)
        self.assertTrue(doc.strip().startswith("mutation"))

    def test_alias_mutation_contains_correct_alias_count(self):
        """Each alias should appear exactly once in the mutation document."""
        count = 5
        doc = build_alias_batch_mutation("login", "email", "password", count)
        for i in range(count):
            self.assertIn(f"attempt{i}:", doc)

    def test_alias_mutation_uses_correct_field_names(self):
        """The email and password field names must appear in the generated document."""
        doc = build_alias_batch_mutation("login", "userEmail", "userPass", 2)
        self.assertIn("userEmail:", doc)
        self.assertIn("userPass:", doc)

    def test_generic_alias_batch_structure(self):
        """build_generic_alias_batch should produce a query with 'alias' prefixed keys."""
        doc = build_generic_alias_batch("pastes", 4)
        self.assertIn("query", doc)
        for i in range(4):
            self.assertIn(f"alias{i}:", doc)


# ============================================================
# TESTS: Schema Analysis
# ============================================================

class TestSchemaAnalysis(unittest.TestCase):

    def test_find_login_mutation_with_login_in_schema(self):
        """find_login_mutation should return login info when schema has a login mutation."""
        schema = make_mock_schema(has_login=True)
        result = find_login_mutation(schema)
        self.assertIsNotNone(result)
        self.assertEqual(result["name"], "login")
        self.assertEqual(result["email_field"], "email")
        self.assertEqual(result["password_field"], "password")

    def test_find_login_mutation_with_no_login(self):
        """find_login_mutation should return None when no auth mutation exists."""
        schema = make_mock_schema(has_login=False)
        result = find_login_mutation(schema)
        self.assertIsNone(result)

    def test_find_login_mutation_with_none_schema(self):
        """find_login_mutation should return None gracefully when schema is None."""
        result = find_login_mutation(None)
        self.assertIsNone(result)

    def test_find_any_query_field_returns_string(self):
        """find_any_query_field should return a field name string."""
        schema = make_mock_schema()
        result = find_any_query_field(schema)
        self.assertIsNotNone(result)
        self.assertIsInstance(result, str)

    def test_find_any_query_field_with_none_schema(self):
        """find_any_query_field should return None when schema is None."""
        result = find_any_query_field(None)
        self.assertIsNone(result)


# ============================================================
# TESTS: Array Batch Test
# ============================================================

class TestArrayBatching(unittest.TestCase):

    def _make_session(self, status_code, json_body):
        """Helper to build a mock session with a controlled response."""
        session = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = status_code
        mock_response.json.return_value = json_body
        mock_response.text = json.dumps(json_body)
        session.post.return_value = mock_response
        return session

    def test_array_batching_detected_when_server_returns_list(self):
        """
        A server that returns a JSON list of responses with 'data' keys
        should be flagged as supporting array batching.
        """
        body = [{"data": {"__typename": "Query"}} for _ in range(BATCH_SIZE)]
        session = self._make_session(200, body)

        result = run_array_batch_test("http://test/graphql", session)

        self.assertTrue(result["supported"])
        self.assertEqual(result["operations_processed"], BATCH_SIZE)

    def test_array_batching_not_detected_when_server_returns_single_object(self):
        """
        A server that returns a single JSON object (not a list)
        should NOT be flagged as supporting array batching.
        """
        body = {"data": {"__typename": "Query"}}
        session = self._make_session(200, body)

        result = run_array_batch_test("http://test/graphql", session)

        self.assertFalse(result["supported"])

    def test_array_batching_not_detected_on_error_status(self):
        """
        A server returning a non-200 status should not be flagged.
        """
        body = {"errors": [{"message": "Batch not supported"}]}
        session = self._make_session(400, body)

        result = run_array_batch_test("http://test/graphql", session)

        self.assertFalse(result["supported"])

    def test_array_batching_handles_network_error(self):
        """
        A network error should return a result with supported=False
        rather than raising an exception.
        """
        import requests
        session = MagicMock()
        session.post.side_effect = requests.exceptions.ConnectionError("refused")

        result = run_array_batch_test("http://test/graphql", session)

        self.assertFalse(result["supported"])
        self.assertEqual(result["operations_processed"], 0)


# ============================================================
# TESTS: Alias Batch Test
# ============================================================

class TestAliasBatching(unittest.TestCase):

    def _make_session(self, status_code, json_body, elapsed=0.5):
        """Helper to build a mock session with a controlled response."""
        session = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = status_code
        mock_response.json.return_value = json_body
        mock_response.text = json.dumps(json_body)
        session.post.return_value = mock_response
        return session

    def test_alias_batching_detected_with_full_data_response(self):
        """
        A server that returns BATCH_SIZE keys in the response data
        should be flagged as processing all aliases.
        """
        data = {f"attempt{i}": {"token": None} for i in range(BATCH_SIZE)}
        body = {"data": data}
        session = self._make_session(200, body)
        schema = make_mock_schema(has_login=True)

        result = run_alias_batch_test("http://test/graphql", session, schema)

        self.assertEqual(result["aliases_processed"], BATCH_SIZE)
        self.assertFalse(result["rate_limited"])

    def test_alias_batching_rate_limited_on_429(self):
        """
        An HTTP 429 response should set rate_limited=True.
        """
        body = {}
        session = self._make_session(429, body)
        schema = make_mock_schema(has_login=True)

        result = run_alias_batch_test("http://test/graphql", session, schema)

        self.assertTrue(result["rate_limited"])

    def test_alias_batching_targets_login_when_schema_available(self):
        """
        When a schema is provided with a login mutation, the alias batch
        should target that mutation (is_auth_targeted should be True).
        """
        data = {f"attempt{i}": {"token": None} for i in range(BATCH_SIZE)}
        body = {"data": data}
        session = self._make_session(200, body)
        schema = make_mock_schema(has_login=True)

        result = run_alias_batch_test("http://test/graphql", session, schema)

        self.assertTrue(result["is_auth_targeted"])
        self.assertEqual(result["target_operation"], "login")

    def test_alias_batching_falls_back_without_schema(self):
        """
        When schema is None, the test should still run using __typename fallback.
        """
        body = {"data": {"a0": "Query", "a1": "Query"}}
        session = self._make_session(200, body)

        # Should not raise
        result = run_alias_batch_test("http://test/graphql", session, None)
        self.assertIsNotNone(result)


# ============================================================
# TESTS: Full check_batch_abuse Integration
# ============================================================

class TestCheckBatchAbuseIntegration(unittest.TestCase):

    def test_returns_two_findings_when_both_vulnerabilities_present(self):
        """
        When both array batching and alias batching are vulnerable,
        check_batch_abuse should return two findings.
        """
        session = MagicMock()

        # Response for array batch: a JSON list
        array_response = MagicMock()
        array_response.status_code = 200
        array_response.json.return_value = [
            {"data": {"__typename": "Query"}} for _ in range(BATCH_SIZE)
        ]
        array_response.text = "[]"

        # Response for alias batch: all aliases processed
        alias_data = {f"attempt{i}": {"token": None} for i in range(BATCH_SIZE)}
        alias_response = MagicMock()
        alias_response.status_code = 200
        alias_response.json.return_value = {"data": alias_data}
        alias_response.text = "{}"

        # Response for rate limit check: all 200, no 429
        rl_response = MagicMock()
        rl_response.status_code = 200
        rl_response.json.return_value = {"data": {"__typename": "Query"}}
        rl_response.text = "{}"

        # Return array_response first, then alias_response, then rl_response for each check
        session.post.side_effect = (
            [array_response]           # array batch test
            + [alias_response]         # alias batch test
            + [rl_response] * BATCH_SIZE  # rate limit test
        )

        schema = make_mock_schema(has_login=True)
        findings = check_batch_abuse("http://test/graphql", session, schema)

        self.assertEqual(len(findings), 2)

    def test_returns_empty_list_when_server_is_protected(self):
        """
        When the server rejects batching and returns 429 on aliases,
        check_batch_abuse should return an empty findings list.
        """
        session = MagicMock()

        # Array batch: server returns a single object (not a list)
        safe_response = MagicMock()
        safe_response.status_code = 400
        safe_response.json.return_value = {"errors": [{"message": "not supported"}]}
        safe_response.text = '{"errors":[]}'

        # Alias batch: 429
        rate_limit_response = MagicMock()
        rate_limit_response.status_code = 429
        rate_limit_response.json.return_value = {}
        rate_limit_response.text = ""

        # Rate limit check
        rl_response = MagicMock()
        rl_response.status_code = 200
        rl_response.json.return_value = {}
        rl_response.text = ""

        session.post.side_effect = (
            [safe_response]
            + [rate_limit_response]
            + [rl_response] * BATCH_SIZE
        )

        schema = make_mock_schema(has_login=True)
        findings = check_batch_abuse("http://test/graphql", session, schema)

        self.assertEqual(len(findings), 0)

    def test_finding_owasp_mapping_is_correct_for_auth_targeted(self):
        """
        When an auth mutation is targeted via alias batching,
        the finding should map to OWASP API2 (Broken Authentication)
        and have Critical severity.
        """
        session = MagicMock()

        # Array batch: not supported
        not_supported = MagicMock()
        not_supported.status_code = 400
        not_supported.json.return_value = {}
        not_supported.text = ""

        # Alias batch: vulnerable with login mutation targeted
        alias_data = {f"attempt{i}": {"token": None} for i in range(BATCH_SIZE)}
        alias_ok = MagicMock()
        alias_ok.status_code = 200
        alias_ok.json.return_value = {"data": alias_data}
        alias_ok.text = "{}"

        # Rate limit: none
        rl_ok = MagicMock()
        rl_ok.status_code = 200
        rl_ok.json.return_value = {}
        rl_ok.text = ""

        session.post.side_effect = (
            [not_supported]
            + [alias_ok]
            + [rl_ok] * BATCH_SIZE
        )

        schema = make_mock_schema(has_login=True)
        findings = check_batch_abuse("http://test/graphql", session, schema)

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertIn("API2", finding["owasp"])
        self.assertEqual(finding["severity"], "Critical")
        self.assertEqual(finding["cvss_score"], 9.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
