"""Tests for MCP assertion library."""

from __future__ import annotations

import pytest

from agent_lint.protocols.mcp.client import MCPResponse
from agent_lint.protocols.mcp.assertions import (
    assert_content_matches,
    assert_content_text,
    assert_error,
    assert_no_secrets,
    assert_response_time,
    assert_result_contains,
    assert_tool_exists,
    assert_valid_response,
)


def _ok(result=None):
    return MCPResponse(result=result if result is not None else {"status": "ok"})


def _err(code=-32600, message="error"):
    return MCPResponse(result=None, error={"code": code, "message": message})


def _content(text):
    return MCPResponse(result={"content": [{"type": "text", "text": text}]})


class TestAssertValidResponse:
    def test_passes_with_result(self):
        assert_valid_response(_ok())

    def test_fails_with_error(self):
        with pytest.raises(AssertionError, match="error"):
            assert_valid_response(_err())

    def test_fails_with_none_result(self):
        with pytest.raises(AssertionError, match="None"):
            assert_valid_response(MCPResponse(result=None))


class TestAssertError:
    def test_passes_with_error(self):
        assert_error(_err())

    def test_passes_with_specific_code(self):
        assert_error(_err(code=-32601), code=-32601)

    def test_fails_with_result(self):
        with pytest.raises(AssertionError, match="Expected an error"):
            assert_error(_ok())

    def test_fails_with_wrong_code(self):
        with pytest.raises(AssertionError, match="Expected error code"):
            assert_error(_err(code=-32600), code=-32601)


class TestAssertResultContains:
    def test_passes_with_key(self):
        assert_result_contains(_ok({"name": "test"}), "name")

    def test_passes_with_key_and_value(self):
        assert_result_contains(_ok({"count": 5}), "count", 5)

    def test_fails_missing_key(self):
        with pytest.raises(AssertionError, match="not found"):
            assert_result_contains(_ok({"a": 1}), "b")

    def test_fails_wrong_value(self):
        with pytest.raises(AssertionError, match="Expected"):
            assert_result_contains(_ok({"a": 1}), "a", 2)


class TestAssertContentText:
    def test_passes(self):
        assert_content_text(_content("hello"), "hello")

    def test_fails(self):
        with pytest.raises(AssertionError, match="Expected text content"):
            assert_content_text(_content("hello"), "world")


class TestAssertContentMatches:
    def test_passes(self):
        assert_content_matches(_content("temperature: 72F"), r"\d+F")

    def test_fails(self):
        with pytest.raises(AssertionError, match="No text content matched"):
            assert_content_matches(_content("hello"), r"\d+")


class TestAssertToolExists:
    def test_passes(self):
        resp = _ok({"tools": [{"name": "get_weather"}, {"name": "list_users"}]})
        assert_tool_exists(resp, "get_weather")

    def test_fails(self):
        resp = _ok({"tools": [{"name": "get_weather"}]})
        with pytest.raises(AssertionError, match="not found"):
            assert_tool_exists(resp, "delete_all")


class TestAssertNoSecrets:
    def test_passes_clean(self):
        assert_no_secrets(_ok({"data": "normal text"}))

    def test_fails_with_api_key(self):
        with pytest.raises(AssertionError, match="API key"):
            assert_no_secrets(_ok({"key": 'api_key: "sk-abc123456789012345678901"'}))


class TestAssertResponseTime:
    def test_passes(self):
        resp = MCPResponse(result={}, elapsed_ms=100)
        assert_response_time(resp, 500)

    def test_fails(self):
        resp = MCPResponse(result={}, elapsed_ms=1000)
        with pytest.raises(AssertionError, match="exceeds limit"):
            assert_response_time(resp, 500)
