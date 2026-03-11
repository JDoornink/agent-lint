"""pytest plugin for agent-lint. Auto-registered via pytest11 entry point."""

from __future__ import annotations


def pytest_addoption(parser):
    group = parser.getgroup("agent-lint", "MCP/A2A testing options")
    group.addoption(
        "--mcp-url",
        action="store",
        default=None,
        help="URL of the MCP server to test against (uses mock if not set)",
    )
    group.addoption(
        "--agent-lint-policy",
        action="store",
        default=None,
        help="Path to .agent-lint.yaml policy file",
    )
    group.addoption(
        "--agent-lint-junit",
        action="store",
        default=None,
        help="Path to write JUnit XML report",
    )


# Re-export fixtures so they're auto-discovered by pytest
from agent_lint.protocols.mcp.testing import mock_mcp_server, mcp_client  # noqa: E402, F401
