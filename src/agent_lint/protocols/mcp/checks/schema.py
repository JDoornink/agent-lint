"""Schema validation checks for MCP servers."""

from __future__ import annotations

from agent_lint.core.checks import CheckResult, Severity
from agent_lint.protocols.mcp.client import MCPClient, MCPClientError, MCPResponse


async def check_schema(client: MCPClient) -> list[CheckResult]:
    """Validate that the server speaks valid JSON-RPC 2.0 and MCP."""
    results: list[CheckResult] = []

    # Check initialize
    try:
        init_resp = await client.initialize()
        if init_resp.error:
            results.append(CheckResult(
                name="jsonrpc_initialize",
                passed=False,
                message=f"Initialize returned error: {init_resp.error}",
                severity=Severity.CRITICAL,
                category="schema",
                recommendation="Ensure the server implements the MCP initialize method.",
            ))
        else:
            results.append(CheckResult(
                name="jsonrpc_initialize",
                passed=True,
                message="Valid JSON-RPC 2.0 endpoint",
                severity=Severity.INFO,
                category="schema",
            ))
    except MCPClientError as e:
        results.append(CheckResult(
            name="jsonrpc_initialize",
            passed=False,
            message=f"Failed to connect: {e}",
            severity=Severity.CRITICAL,
            category="schema",
            recommendation="Check that the server URL is correct and the server is running.",
        ))
        return results  # Can't continue if we can't connect

    # Check tools/list
    try:
        tools_resp = await client.list_tools()
        if tools_resp.error:
            results.append(CheckResult(
                name="tools_list",
                passed=False,
                message=f"tools/list returned error: {tools_resp.error}",
                severity=Severity.HIGH,
                category="schema",
                recommendation="Implement the tools/list method.",
            ))
        else:
            tools = _extract_tools(tools_resp)
            results.append(CheckResult(
                name="tools_list",
                passed=True,
                message=f"Tools list returned ({len(tools)} tools)",
                severity=Severity.INFO,
                category="schema",
            ))
    except MCPClientError as e:
        results.append(CheckResult(
            name="tools_list",
            passed=False,
            message=f"tools/list failed: {e}",
            severity=Severity.HIGH,
            category="schema",
        ))

    # Check resources/list
    try:
        resources_resp = await client.list_resources()
        if resources_resp.error:
            results.append(CheckResult(
                name="resources_list",
                passed=True,
                message="Resources endpoint not implemented (optional)",
                severity=Severity.INFO,
                category="schema",
            ))
        else:
            results.append(CheckResult(
                name="resources_list",
                passed=True,
                message="Resources endpoint responds",
                severity=Severity.INFO,
                category="schema",
            ))
    except MCPClientError:
        results.append(CheckResult(
            name="resources_list",
            passed=True,
            message="Resources endpoint not available (optional)",
            severity=Severity.INFO,
            category="schema",
        ))

    return results


def _extract_tools(resp: MCPResponse) -> list[dict]:
    """Extract tools list from a tools/list response."""
    if isinstance(resp.result, dict):
        return resp.result.get("tools", [])
    if isinstance(resp.result, list):
        return resp.result
    return []
