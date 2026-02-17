"""Credential and secret exposure detection in MCP responses."""

from __future__ import annotations

import re

from agent_lint.core.checks import CheckResult, Severity

SECRET_PATTERNS = [
    (r"(?:api[_-]?key|apikey)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{20,}", "API key"),
    (r"(?:secret|token|password|passwd|pwd)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{8,}", "credential"),
    (r"sk-[A-Za-z0-9]{20,}", "OpenAI API key"),
    (r"ghp_[A-Za-z0-9]{36}", "GitHub personal access token"),
    (r"AKIA[A-Z0-9]{16}", "AWS access key"),
    (r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----", "private key"),
    (r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", "bearer token"),
]


async def check_secrets(tools: list[dict], raw_responses: list[str]) -> list[CheckResult]:
    """Check for credential patterns in tool definitions and responses."""
    results: list[CheckResult] = []

    # Check tool definitions for leaked credentials
    for tool in tools:
        tool_str = str(tool)
        for pattern, label in SECRET_PATTERNS:
            if re.search(pattern, tool_str):
                results.append(CheckResult(
                    name="credential_in_definition",
                    passed=False,
                    message=f"Possible {label} found in tool '{tool.get('name', '?')}' definition",
                    severity=Severity.HIGH,
                    category="security",
                    recommendation="Remove credentials from tool definitions. "
                                   "Use environment variables or a secrets manager.",
                ))
                break

    # Check raw responses
    for response_text in raw_responses:
        for pattern, label in SECRET_PATTERNS:
            if re.search(pattern, response_text):
                results.append(CheckResult(
                    name="credential_in_response",
                    passed=False,
                    message=f"Possible {label} detected in server response",
                    severity=Severity.HIGH,
                    category="security",
                    recommendation="Ensure server responses do not leak credentials. "
                                   "Redact sensitive values before returning.",
                ))
                break

    if not results:
        results.append(CheckResult(
            name="no_credentials",
            passed=True,
            message="No credential patterns detected in responses",
            severity=Severity.INFO,
            category="security",
        ))

    return results
