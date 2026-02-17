"""Overly permissive description detection for MCP tools."""

from __future__ import annotations

import re

from agent_lint.core.checks import CheckResult, Severity

PERMISSIVE_PATTERNS = [
    (r"any\s+file", "any file"),
    (r"any\s+url", "any URL"),
    (r"any\s+command", "any command"),
    (r"any\s+path", "any path"),
    (r"any\s+query", "any query"),
    (r"all\s+files", "all files"),
    (r"full\s+access", "full access"),
    (r"unrestricted", "unrestricted"),
    (r"no\s+limit", "no limit"),
    (r"arbitrary", "arbitrary"),
]


async def check_permissions(tools: list[dict]) -> list[CheckResult]:
    """Check for overly permissive tool descriptions."""
    results: list[CheckResult] = []

    for tool in tools:
        name = tool.get("name", "<unnamed>")
        description = (tool.get("description") or "").lower()

        for pattern, label in PERMISSIVE_PATTERNS:
            if re.search(pattern, description):
                results.append(CheckResult(
                    name="overly_permissive",
                    passed=False,
                    message=f"Tool '{name}' has overly permissive description "
                            f"(mentions '{label}')",
                    severity=Severity.MEDIUM,
                    category="security",
                    recommendation="Narrow the tool's scope. Specify exactly what "
                                   "files, URLs, or commands are allowed.",
                ))
                break

    if not results:
        results.append(CheckResult(
            name="permissions",
            passed=True,
            message="No overly permissive tool descriptions",
            severity=Severity.INFO,
            category="security",
        ))

    return results
