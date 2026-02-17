"""MCP client for communicating with MCP servers over JSON-RPC 2.0."""

from __future__ import annotations

import time
from dataclasses import dataclass, field

import httpx


class MCPClientError(Exception):
    """Error communicating with an MCP server."""


@dataclass
class MCPResponse:
    """Response from an MCP JSON-RPC call."""

    result: dict | list | None
    error: dict | None = None
    elapsed_ms: float = 0
    response_size: int = 0
    headers: dict[str, str] = field(default_factory=dict)


class MCPClient:
    """Client for MCP servers using JSON-RPC 2.0 over HTTP."""

    def __init__(self, url: str, timeout: float = 30.0) -> None:
        self.url = url.rstrip("/")
        self._request_id = 0
        self._client = httpx.AsyncClient(timeout=timeout)

    async def close(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> MCPClient:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.close()

    def _next_id(self) -> int:
        self._request_id += 1
        return self._request_id

    async def _rpc_call(self, method: str, params: dict | None = None) -> MCPResponse:
        """Make a JSON-RPC 2.0 call to the MCP server."""
        payload: dict = {
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": method,
        }
        if params is not None:
            payload["params"] = params

        start = time.monotonic()
        try:
            response = await self._client.post(self.url, json=payload)
            elapsed_ms = (time.monotonic() - start) * 1000
            response.raise_for_status()
        except httpx.HTTPError as e:
            raise MCPClientError(f"HTTP error calling {method}: {e}") from e

        response_size = len(response.content)

        try:
            data = response.json()
        except ValueError as e:
            raise MCPClientError(f"Invalid JSON response for {method}") from e

        return MCPResponse(
            result=data.get("result"),
            error=data.get("error"),
            elapsed_ms=elapsed_ms,
            response_size=response_size,
            headers=dict(response.headers),
        )

    async def initialize(self) -> MCPResponse:
        """Send the initialize request to the MCP server."""
        return await self._rpc_call("initialize", {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "agent-lint", "version": "0.1.0"},
        })

    async def list_tools(self) -> MCPResponse:
        """List tools available on the MCP server."""
        return await self._rpc_call("tools/list")

    async def list_resources(self) -> MCPResponse:
        """List resources available on the MCP server."""
        return await self._rpc_call("resources/list")

    async def call_tool(self, name: str, arguments: dict | None = None) -> MCPResponse:
        """Call a tool on the MCP server."""
        return await self._rpc_call("tools/call", {
            "name": name,
            "arguments": arguments or {},
        })
