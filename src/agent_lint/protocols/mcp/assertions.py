"""MCP-specific test assertions."""

from __future__ import annotations

import re
from typing import Any

from agent_lint.protocols.mcp.client import MCPResponse
from agent_lint.protocols.mcp.checks.security.secrets import SECRET_PATTERNS


def assert_valid_response(response: MCPResponse, *, message: str = "") -> None:
    """Assert the response has a result and no error."""
    prefix = f"{message}: " if message else ""
    if response.error is not None:
        raise AssertionError(
            f"{prefix}Expected valid response but got error: {response.error}"
        )
    if response.result is None:
        raise AssertionError(f"{prefix}Expected a result but got None")


def assert_error(response: MCPResponse, *, code: int | None = None, message: str = "") -> None:
    """Assert the response is an error (optionally with a specific code)."""
    prefix = f"{message}: " if message else ""
    if response.error is None:
        raise AssertionError(
            f"{prefix}Expected an error response but got result: {response.result}"
        )
    if code is not None and response.error.get("code") != code:
        raise AssertionError(
            f"{prefix}Expected error code {code} but got {response.error.get('code')}"
        )


def assert_result_contains(
    response: MCPResponse, key: str, value: Any = ..., *, message: str = ""
) -> None:
    """Assert the result dict contains a key (optionally with a specific value)."""
    prefix = f"{message}: " if message else ""
    assert_valid_response(response, message=message)
    if not isinstance(response.result, dict):
        raise AssertionError(f"{prefix}Expected dict result but got {type(response.result).__name__}")
    if key not in response.result:
        raise AssertionError(f"{prefix}Key '{key}' not found in result: {list(response.result.keys())}")
    if value is not ... and response.result[key] != value:
        raise AssertionError(
            f"{prefix}Expected result['{key}'] == {value!r} but got {response.result[key]!r}"
        )


def assert_content_text(response: MCPResponse, expected: str, *, message: str = "") -> None:
    """Assert the response contains a text content block matching expected."""
    prefix = f"{message}: " if message else ""
    assert_valid_response(response, message=message)
    if not isinstance(response.result, dict):
        raise AssertionError(f"{prefix}Expected dict result with 'content' key")
    content = response.result.get("content", [])
    texts = [c.get("text", "") for c in content if c.get("type") == "text"]
    if expected not in texts:
        raise AssertionError(
            f"{prefix}Expected text content '{expected}' but found: {texts}"
        )


def assert_content_matches(response: MCPResponse, pattern: str, *, message: str = "") -> None:
    """Assert any text content block matches a regex pattern."""
    prefix = f"{message}: " if message else ""
    assert_valid_response(response, message=message)
    if not isinstance(response.result, dict):
        raise AssertionError(f"{prefix}Expected dict result with 'content' key")
    content = response.result.get("content", [])
    texts = [c.get("text", "") for c in content if c.get("type") == "text"]
    if not any(re.search(pattern, t) for t in texts):
        raise AssertionError(
            f"{prefix}No text content matched pattern '{pattern}'. Found: {texts}"
        )


def assert_tool_exists(tools_response: MCPResponse, tool_name: str, *, message: str = "") -> None:
    """Assert the tools/list response contains a tool by name."""
    prefix = f"{message}: " if message else ""
    assert_valid_response(tools_response, message=message)
    if isinstance(tools_response.result, dict):
        tools = tools_response.result.get("tools", [])
    elif isinstance(tools_response.result, list):
        tools = tools_response.result
    else:
        raise AssertionError(f"{prefix}Unexpected result type: {type(tools_response.result).__name__}")
    names = [t.get("name", "") for t in tools]
    if tool_name not in names:
        raise AssertionError(f"{prefix}Tool '{tool_name}' not found. Available: {names}")


def assert_no_secrets(response: MCPResponse, *, message: str = "") -> None:
    """Assert the response does not contain credential patterns."""
    prefix = f"{message}: " if message else ""
    text = str(response.result)
    for pattern, label in SECRET_PATTERNS:
        if re.search(pattern, text):
            raise AssertionError(f"{prefix}Possible {label} detected in response")


def assert_response_time(response: MCPResponse, max_ms: float, *, message: str = "") -> None:
    """Assert the response was returned within the time limit."""
    prefix = f"{message}: " if message else ""
    if response.elapsed_ms > max_ms:
        raise AssertionError(
            f"{prefix}Response time {response.elapsed_ms:.0f}ms exceeds limit of {max_ms:.0f}ms"
        )
