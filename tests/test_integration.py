"""Integration tests: full validator pipeline against a mock MCP server."""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from agent_lint.protocols.mcp.validator import MCPValidator

MOCK_URL = "http://mock-mcp-server:8080"


def _jsonrpc_response(result: dict | list) -> httpx.Response:
    """Build a JSON-RPC 2.0 response."""
    return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": result})


def _jsonrpc_error(code: int, message: str) -> httpx.Response:
    return httpx.Response(200, json={
        "jsonrpc": "2.0", "id": 1,
        "error": {"code": code, "message": message},
    })


GOOD_TOOLS = {
    "tools": [
        {
            "name": "get_weather",
            "description": "Get current weather for a specific city by name",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "city": {
                        "type": "string",
                        "description": "City name to look up",
                        "maxLength": 100,
                    },
                },
                "required": ["city"],
            },
        },
        {
            "name": "list_users",
            "description": "List all users in the current organization",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "page": {
                        "type": "integer",
                        "description": "Page number",
                    },
                },
            },
        },
    ]
}

DANGEROUS_TOOLS = {
    "tools": [
        {
            "name": "execute_command",
            "description": "Execute any command on the server",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "cmd": {},  # no type
                },
            },
        },
        {
            "name": "read_file",
            "description": "Read any file from the filesystem",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                },
            },
        },
    ]
}

SERVER_CAPABILITIES = {
    "protocolVersion": "2025-03-26",
    "capabilities": {"tools": {}},
    "serverInfo": {"name": "mock-server", "version": "1.0.0"},
}


def _route_handler(tools_response: dict, headers: dict | None = None):
    """Create a respx side effect that routes JSON-RPC methods."""
    resp_headers = headers or {"content-type": "application/json"}

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        method = body.get("method", "")

        if method == "initialize":
            result = SERVER_CAPABILITIES
        elif method == "tools/list":
            result = tools_response
        elif method == "resources/list":
            result = {"resources": []}
        else:
            return _jsonrpc_error(-32601, f"Method not found: {method}")

        return httpx.Response(
            200,
            json={"jsonrpc": "2.0", "id": body.get("id", 1), "result": result},
            headers=resp_headers,
        )

    return handler


class TestFullPipelineGoodServer:
    """Integration test: a well-behaved MCP server should score high."""

    async def test_good_server_passes(self):
        with respx.mock:
            respx.post(MOCK_URL).mock(side_effect=_route_handler(
                GOOD_TOOLS,
                headers={
                    "content-type": "application/json",
                    "x-ratelimit-limit": "100",
                    "x-ratelimit-remaining": "99",
                },
            ))

            validator = MCPValidator(security_level="standard")
            report = await validator.validate(MOCK_URL)

        assert report.security_score >= 75
        assert report.quality_score >= 75
        assert report.score >= 70
        # No critical/high security issues
        high_issues = [
            r for r in report.failed
            if r.category == "security" and r.severity.value in ("critical", "high")
        ]
        assert len(high_issues) == 0

    async def test_all_categories_present(self):
        with respx.mock:
            respx.post(MOCK_URL).mock(side_effect=_route_handler(GOOD_TOOLS))

            validator = MCPValidator()
            report = await validator.validate(MOCK_URL)

        categories = {r.category for r in report.results}
        assert "schema" in categories
        assert "security" in categories
        assert "quality" in categories
        assert "performance" in categories


class TestFullPipelineDangerousServer:
    """Integration test: a dangerous MCP server should score low."""

    async def test_dangerous_server_has_security_issues(self):
        with respx.mock:
            respx.post(MOCK_URL).mock(side_effect=_route_handler(DANGEROUS_TOOLS))

            validator = MCPValidator(security_level="strict")
            report = await validator.validate(MOCK_URL)

        assert report.has_security_issues
        assert report.security_score < 75

        # Should detect: dangerous name, risky param, overly permissive, no rate limit
        failed_names = {r.name for r in report.failed}
        assert "dangerous_tool_name" in failed_names
        assert "risky_param_no_validation" in failed_names
        assert "overly_permissive" in failed_names

    async def test_permissive_level_raises_score(self):
        with respx.mock:
            respx.post(MOCK_URL).mock(side_effect=_route_handler(DANGEROUS_TOOLS))

            strict = MCPValidator(security_level="strict")
            permissive = MCPValidator(security_level="permissive")

            strict_report = await strict.validate(MOCK_URL)
            permissive_report = await permissive.validate(MOCK_URL)

        # Permissive should have fewer failures (higher score)
        assert permissive_report.security_score >= strict_report.security_score


class TestFullPipelineUnreachableServer:
    """Integration test: unreachable server should fail gracefully."""

    async def test_connection_error(self):
        with respx.mock:
            respx.post(MOCK_URL).mock(side_effect=httpx.ConnectError("Connection refused"))

            validator = MCPValidator()
            report = await validator.validate(MOCK_URL)

        # Should have a critical schema failure and stop early
        assert len(report.results) > 0
        init_result = next(r for r in report.results if r.name == "jsonrpc_initialize")
        assert not init_result.passed
        assert init_result.severity.value == "critical"
        # Should NOT have quality/security checks (early exit)
        categories = {r.category for r in report.results}
        assert "security" not in categories
        assert "quality" not in categories


class TestFullPipelineSecurityLevelNone:
    """Integration test: security level 'none' should pass all security."""

    async def test_none_passes_all_security(self):
        with respx.mock:
            respx.post(MOCK_URL).mock(side_effect=_route_handler(DANGEROUS_TOOLS))

            validator = MCPValidator(security_level="none")
            report = await validator.validate(MOCK_URL)

        # All security results should be passing
        security_results = [r for r in report.results if r.category == "security"]
        assert all(r.passed for r in security_results)
        assert report.security_score == 100
