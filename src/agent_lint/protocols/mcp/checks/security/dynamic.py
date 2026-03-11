"""Dynamic security testing: call tools with malicious payloads."""

from __future__ import annotations

from dataclasses import dataclass

from agent_lint.core.checks import CheckResult, Severity
from agent_lint.protocols.mcp.client import MCPResponse


SQL_INJECTION_PAYLOADS = [
    "'; DROP TABLE users; --",
    "1 OR 1=1",
    "1; SELECT * FROM information_schema.tables",
    "' UNION SELECT NULL, NULL--",
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../etc/passwd",
    "..\\..\\windows\\system32\\config\\sam",
    "/etc/shadow",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]

COMMAND_INJECTION_PAYLOADS = [
    "; cat /etc/passwd",
    "| ls -la",
    "$(whoami)",
    "`id`",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img onerror=alert(1) src=x>",
]

SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://localhost:22",
    "http://[::1]:80",
]


@dataclass
class PayloadSuite:
    """A set of payloads targeting a specific vulnerability class."""

    name: str
    param_patterns: list[str]
    payloads: list[str]
    severity: Severity


PAYLOAD_SUITES = [
    PayloadSuite("sql_injection", ["sql", "query", "where", "filter"],
                 SQL_INJECTION_PAYLOADS, Severity.HIGH),
    PayloadSuite("path_traversal", ["path", "file", "filename", "filepath"],
                 PATH_TRAVERSAL_PAYLOADS, Severity.HIGH),
    PayloadSuite("command_injection", ["cmd", "command", "exec", "script", "shell"],
                 COMMAND_INJECTION_PAYLOADS, Severity.CRITICAL),
    PayloadSuite("xss", ["html", "content", "text", "body", "message"],
                 XSS_PAYLOADS, Severity.MEDIUM),
    PayloadSuite("ssrf", ["url", "uri", "endpoint", "href", "link"],
                 SSRF_PAYLOADS, Severity.HIGH),
]


def _param_matches_suite(param_name: str, suite: PayloadSuite) -> bool:
    """Check if a parameter name is relevant for a payload suite."""
    return any(p in param_name.lower() for p in suite.param_patterns)


def _indicates_success(response: MCPResponse) -> bool:
    """Determine if a response indicates the payload was accepted (not rejected)."""
    if response.error is not None:
        return False
    return response.result is not None


async def check_dynamic_security(client: object, tools: list[dict]) -> list[CheckResult]:
    """Call tools with malicious payloads and check if the server rejects them.

    A tool SHOULD return an error response for malicious input.
    If it returns a success response, that is a finding.

    Args:
        client: MCPClient or MockMCPClient (any object with call_tool method).
        tools: List of tool definitions from tools/list.
    """
    results: list[CheckResult] = []

    for tool in tools:
        tool_name = tool.get("name", "")
        params = tool.get("inputSchema", tool.get("parameters", {}))
        properties = params.get("properties", {})

        for param_name in properties:
            for suite in PAYLOAD_SUITES:
                if not _param_matches_suite(param_name, suite):
                    continue

                # Test with up to 2 payloads per suite for speed
                for payload in suite.payloads[:2]:
                    response = await client.call_tool(
                        tool_name, {param_name: payload}
                    )
                    if _indicates_success(response):
                        results.append(CheckResult(
                            name=f"dynamic_{suite.name}",
                            passed=False,
                            message=f"Tool '{tool_name}' accepted {suite.name} "
                                    f"payload in parameter '{param_name}'",
                            severity=suite.severity,
                            category="security",
                            tool_name=tool_name,
                            recommendation=f"Tool should reject or sanitize "
                                           f"{suite.name} payloads in '{param_name}'.",
                        ))
                        break  # One finding per suite per param is enough

    if not results:
        results.append(CheckResult(
            name="dynamic_security",
            passed=True,
            message="No dynamic security vulnerabilities detected",
            severity=Severity.INFO,
            category="security",
        ))

    return results
