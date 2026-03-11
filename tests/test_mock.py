"""Tests for MockMCPServer and MockMCPClient."""

from __future__ import annotations

import pytest

from agent_lint.protocols.mcp.mock import MockMCPServer


class TestMockMCPServer:
    def test_add_tool_chainable(self):
        server = MockMCPServer()
        result = server.add_tool("a").add_tool("b")
        assert result is server

    async def test_initialize(self):
        server = MockMCPServer()
        client = server.client()
        resp = await client.initialize()
        assert resp.result["protocolVersion"] == "2025-03-26"
        assert resp.error is None

    async def test_list_tools_empty(self):
        server = MockMCPServer()
        client = server.client()
        resp = await client.list_tools()
        assert resp.result["tools"] == []

    async def test_list_tools_with_tools(self):
        server = MockMCPServer()
        server.add_tool("get_weather", description="Get weather")
        server.add_tool("list_users", description="List users")
        client = server.client()
        resp = await client.list_tools()
        names = [t["name"] for t in resp.result["tools"]]
        assert names == ["get_weather", "list_users"]

    async def test_call_tool_default_handler(self):
        server = MockMCPServer()
        server.add_tool("ping")
        client = server.client()
        resp = await client.call_tool("ping", {})
        assert resp.result == {"content": [{"type": "text", "text": "ok"}]}
        assert resp.error is None

    async def test_call_tool_custom_handler(self):
        def handler(args):
            return {"content": [{"type": "text", "text": f"Hello {args['name']}"}]}

        server = MockMCPServer()
        server.add_tool("greet", handler=handler)
        client = server.client()
        resp = await client.call_tool("greet", {"name": "World"})
        assert resp.result["content"][0]["text"] == "Hello World"

    async def test_call_tool_handler_raises(self):
        def handler(args):
            raise ValueError("bad input")

        server = MockMCPServer()
        server.add_tool("fail", handler=handler)
        client = server.client()
        resp = await client.call_tool("fail", {})
        assert resp.error is not None
        assert "bad input" in resp.error["message"]

    async def test_call_unknown_tool(self):
        server = MockMCPServer()
        client = server.client()
        resp = await client.call_tool("nonexistent", {})
        assert resp.error is not None
        assert "Unknown tool" in resp.error["message"]

    async def test_call_log(self):
        server = MockMCPServer()
        server.add_tool("ping")
        client = server.client()
        await client.call_tool("ping", {"a": 1})
        await client.call_tool("ping", {"b": 2})
        assert len(server.calls) == 2
        assert server.calls[0]["tool"] == "ping"
        assert server.calls[0]["arguments"] == {"a": 1}

    async def test_list_resources(self):
        server = MockMCPServer()
        server.add_resource({"uri": "file:///test.txt", "name": "test"})
        client = server.client()
        resp = await client.list_resources()
        assert len(resp.result["resources"]) == 1

    async def test_context_manager(self):
        server = MockMCPServer()
        async with server.client() as client:
            resp = await client.initialize()
            assert resp.result is not None
