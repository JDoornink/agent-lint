"""Public MCP testing API.

Usage::

    from agent_lint import mcp

    result = await client.call_tool("get_weather", {"city": "London"})
    mcp.assert_valid_response(result)
"""

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
from agent_lint.protocols.mcp.mock import MockMCPServer

__all__ = [
    "assert_content_matches",
    "assert_content_text",
    "assert_error",
    "assert_no_secrets",
    "assert_response_time",
    "assert_result_contains",
    "assert_tool_exists",
    "assert_valid_response",
    "MockMCPServer",
]
