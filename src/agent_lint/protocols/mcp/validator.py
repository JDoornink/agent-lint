"""MCP validation orchestrator."""

from __future__ import annotations

import json

from agent_lint.core.checks import ValidationReport
from agent_lint.core.validator import BaseValidator
from agent_lint.protocols.mcp.checks.performance import check_payload_size, check_response_time
from agent_lint.protocols.mcp.checks.quality import check_quality
from agent_lint.protocols.mcp.checks.schema import check_schema
from agent_lint.protocols.mcp.checks.security.patterns import check_dangerous_patterns
from agent_lint.protocols.mcp.checks.security.permissions import check_permissions
from agent_lint.protocols.mcp.checks.security.ratelimit import check_rate_limiting
from agent_lint.protocols.mcp.checks.security.secrets import check_secrets
from agent_lint.protocols.mcp.checks.security.dynamic import check_dynamic_security
from agent_lint.protocols.mcp.checks.security.validation import check_input_validation
from agent_lint.protocols.mcp.client import MCPClient, MCPClientError


class MCPValidator(BaseValidator):
    """Orchestrates all MCP validation checks against a server."""

    def __init__(self, security_level: str = "standard", dynamic: bool = False) -> None:
        super().__init__(security_level=security_level)
        self.dynamic = dynamic

    async def validate(self, url: str) -> ValidationReport:
        """Run all validation checks against an MCP server."""
        report = ValidationReport(server_url=url)

        async with MCPClient(url) as client:
            # Schema checks (also establishes connection)
            schema_results = await check_schema(client)
            report.add_all(schema_results)

            # If we can't even connect, stop here
            if any(
                not r.passed and r.name == "jsonrpc_initialize"
                for r in schema_results
            ):
                return report

            # Get tools and response headers for remaining checks
            tools, raw_responses, headers = await self._get_tools(client)

            # Performance checks (from the tools/list call)
            try:
                tools_resp = await client.list_tools()
                report.add(check_response_time(tools_resp.elapsed_ms))
                report.add(check_payload_size(tools_resp.response_size))
            except MCPClientError:
                pass  # Already reported in schema checks

            # Quality checks
            quality_results = await check_quality(tools)
            report.add_all(quality_results)

            # Security checks
            pattern_results = await check_dangerous_patterns(tools)
            report.add_all(pattern_results)

            validation_results = await check_input_validation(tools)
            report.add_all(validation_results)

            permission_results = await check_permissions(tools)
            report.add_all(permission_results)

            secret_results = await check_secrets(tools, raw_responses)
            report.add_all(secret_results)

            report.add(check_rate_limiting(headers))

            # Dynamic security checks (opt-in)
            if self.dynamic:
                dynamic_results = await check_dynamic_security(client, tools)
                report.add_all(dynamic_results)

        # Apply security level filtering
        self._apply_security_level(report)

        return report

    async def _get_tools(
        self, client: MCPClient
    ) -> tuple[list[dict], list[str], dict[str, str]]:
        """Extract tools, raw response text, and headers from the server."""
        tools: list[dict] = []
        raw_responses: list[str] = []
        headers: dict[str, str] = {}

        try:
            resp = await client.list_tools()
            raw_responses.append(json.dumps(resp.result) if resp.result else "")
            headers = resp.headers

            if isinstance(resp.result, dict):
                tools = resp.result.get("tools", [])
            elif isinstance(resp.result, list):
                tools = resp.result
        except MCPClientError:
            pass

        return tools, raw_responses, headers
