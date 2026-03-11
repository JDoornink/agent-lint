"""Tests for dynamic security testing."""

from __future__ import annotations

import pytest

from agent_lint.protocols.mcp.mock import MockMCPServer
from agent_lint.protocols.mcp.checks.security.dynamic import check_dynamic_security


class TestDynamicSecurity:
    async def test_vulnerable_tool_detected(self):
        """A tool that accepts SQL injection payloads should be flagged."""
        server = MockMCPServer()
        server.add_tool(
            "query_db",
            input_schema={
                "type": "object",
                "properties": {"sql": {"type": "string"}},
            },
            # Default handler returns success for everything - vulnerable!
        )
        client = server.client()
        tools = (await client.list_tools()).result["tools"]
        results = await check_dynamic_security(client, tools)
        failed = [r for r in results if not r.passed]
        assert len(failed) >= 1
        assert failed[0].name == "dynamic_sql_injection"
        assert failed[0].tool_name == "query_db"

    async def test_safe_tool_passes(self):
        """A tool that rejects injection payloads should pass."""
        def handler(args):
            sql = args.get("sql", "")
            for bad in ("'", ";", "OR 1=1", "UNION", "DROP", "SELECT *"):
                if bad in sql or bad.lower() in sql:
                    raise ValueError("Invalid SQL")
            return {"content": [{"type": "text", "text": "ok"}]}

        server = MockMCPServer()
        server.add_tool(
            "query_db",
            input_schema={
                "type": "object",
                "properties": {"sql": {"type": "string"}},
            },
            handler=handler,
        )
        client = server.client()
        tools = (await client.list_tools()).result["tools"]
        results = await check_dynamic_security(client, tools)
        assert all(r.passed for r in results)

    async def test_path_traversal_detected(self):
        server = MockMCPServer()
        server.add_tool(
            "read_file",
            input_schema={
                "type": "object",
                "properties": {"path": {"type": "string"}},
            },
        )
        client = server.client()
        tools = (await client.list_tools()).result["tools"]
        results = await check_dynamic_security(client, tools)
        failed = [r for r in results if r.name == "dynamic_path_traversal"]
        assert len(failed) >= 1

    async def test_command_injection_detected(self):
        server = MockMCPServer()
        server.add_tool(
            "run_task",
            input_schema={
                "type": "object",
                "properties": {"cmd": {"type": "string"}},
            },
        )
        client = server.client()
        tools = (await client.list_tools()).result["tools"]
        results = await check_dynamic_security(client, tools)
        failed = [r for r in results if r.name == "dynamic_command_injection"]
        assert len(failed) >= 1

    async def test_no_risky_params_passes(self):
        """Tools without risky parameter names should pass."""
        server = MockMCPServer()
        server.add_tool(
            "get_weather",
            input_schema={
                "type": "object",
                "properties": {"city": {"type": "string"}},
            },
        )
        client = server.client()
        tools = (await client.list_tools()).result["tools"]
        results = await check_dynamic_security(client, tools)
        assert all(r.passed for r in results)

    async def test_empty_tools_passes(self):
        server = MockMCPServer()
        client = server.client()
        results = await check_dynamic_security(client, [])
        assert all(r.passed for r in results)
