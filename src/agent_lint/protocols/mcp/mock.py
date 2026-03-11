"""In-process mock MCP server for testing."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field

from agent_lint.protocols.mcp.client import MCPResponse


@dataclass
class ToolExpectation:
    """Defines expected behavior for a single tool."""

    name: str
    description: str = ""
    input_schema: dict = field(default_factory=lambda: {"type": "object", "properties": {}})
    handler: Callable[[dict], dict] | None = None


class MockMCPServer:
    """In-process mock MCP server with expectation-based routing.

    Example::

        server = MockMCPServer()
        server.add_tool("get_weather", description="Get weather", input_schema={
            "type": "object",
            "properties": {"city": {"type": "string"}},
        })
        client = server.client()
        response = await client.call_tool("get_weather", {"city": "London"})
    """

    def __init__(self) -> None:
        self._tools: dict[str, ToolExpectation] = {}
        self._resources: list[dict] = []
        self._server_info: dict = {"name": "mock-mcp", "version": "0.0.0"}
        self._call_log: list[dict] = []

    def add_tool(
        self,
        name: str,
        description: str = "",
        input_schema: dict | None = None,
        handler: Callable[[dict], dict] | None = None,
    ) -> MockMCPServer:
        """Register a tool. Returns self for chaining."""
        self._tools[name] = ToolExpectation(
            name=name,
            description=description,
            input_schema=input_schema or {"type": "object", "properties": {}},
            handler=handler,
        )
        return self

    def add_resource(self, resource: dict) -> MockMCPServer:
        """Register a resource. Returns self for chaining."""
        self._resources.append(resource)
        return self

    def client(self) -> MockMCPClient:
        """Return a client-like object bound to this mock server."""
        return MockMCPClient(self)

    @property
    def calls(self) -> list[dict]:
        """All tool calls made against this server."""
        return list(self._call_log)

    def _handle_initialize(self) -> dict:
        return {
            "protocolVersion": "2025-03-26",
            "capabilities": {"tools": {}},
            "serverInfo": self._server_info,
        }

    def _handle_list_tools(self) -> dict:
        tools = []
        for t in self._tools.values():
            tools.append({
                "name": t.name,
                "description": t.description,
                "inputSchema": t.input_schema,
            })
        return {"tools": tools}

    def _handle_list_resources(self) -> dict:
        return {"resources": self._resources}

    def _handle_call_tool(self, name: str, arguments: dict) -> MCPResponse:
        self._call_log.append({
            "tool": name,
            "arguments": arguments,
        })

        if name not in self._tools:
            return MCPResponse(
                result=None,
                error={"code": -32602, "message": f"Unknown tool: {name}"},
            )

        tool = self._tools[name]
        if tool.handler is not None:
            try:
                result = tool.handler(arguments)
            except Exception as e:
                return MCPResponse(
                    result=None,
                    error={"code": -32000, "message": str(e)},
                )
        else:
            result = {"content": [{"type": "text", "text": "ok"}]}

        self._call_log[-1]["response"] = result
        return MCPResponse(
            result=result,
            response_size=len(json.dumps(result)),
        )


class MockMCPClient:
    """Client interface backed by MockMCPServer, matching MCPClient API."""

    def __init__(self, server: MockMCPServer) -> None:
        self._server = server

    async def initialize(self) -> MCPResponse:
        result = self._server._handle_initialize()
        return MCPResponse(result=result, response_size=len(json.dumps(result)))

    async def list_tools(self) -> MCPResponse:
        result = self._server._handle_list_tools()
        return MCPResponse(result=result, response_size=len(json.dumps(result)))

    async def list_resources(self) -> MCPResponse:
        result = self._server._handle_list_resources()
        return MCPResponse(result=result, response_size=len(json.dumps(result)))

    async def call_tool(self, name: str, arguments: dict | None = None) -> MCPResponse:
        return self._server._handle_call_tool(name, arguments or {})

    async def close(self) -> None:
        pass

    async def __aenter__(self) -> MockMCPClient:
        return self

    async def __aexit__(self, *args: object) -> None:
        pass
