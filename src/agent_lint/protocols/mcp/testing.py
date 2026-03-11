"""pytest fixtures for MCP testing."""

from __future__ import annotations

import pytest

from agent_lint.protocols.mcp.client import MCPClient
from agent_lint.protocols.mcp.mock import MockMCPServer


@pytest.fixture
def mock_mcp_server():
    """Provide a fresh MockMCPServer for each test."""
    return MockMCPServer()


@pytest.fixture
async def mcp_client(request, mock_mcp_server):
    """Provide an MCP client.

    If --mcp-url is passed on the CLI, connects to a real server.
    Otherwise, returns the mock_mcp_server's client.
    """
    url = request.config.getoption("--mcp-url", default=None)
    if url:
        client = MCPClient(url)
        yield client
        await client.close()
    else:
        yield mock_mcp_server.client()
