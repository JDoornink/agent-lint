"""Dangerous pattern detection in MCP tool definitions."""

from __future__ import annotations

import re

from agent_lint.core.checks import CheckResult, Severity

DANGEROUS_TOOL_NAMES = [
    r"execute", r"exec", r"run_command", r"shell",
    r"eval", r"system", r"spawn", r"popen",
]

RISKY_PARAM_NAMES = [
    r"^cmd$", r"^command$", r"^sql$", r"^query$",
    r"^path$", r"^file$", r"^url$", r"^script$",
]


async def check_dangerous_patterns(tools: list[dict]) -> list[CheckResult]:
    """Check for dangerous naming patterns in tools."""
    results: list[CheckResult] = []

    for tool in tools:
        tool_name = tool.get("name", "")
        tool_name_lower = tool_name.lower()

        # Check tool name
        for pattern in DANGEROUS_TOOL_NAMES:
            if re.search(pattern, tool_name_lower):
                results.append(CheckResult(
                    name="dangerous_tool_name",
                    passed=False,
                    message=f"Tool '{tool_name}' has risky name pattern '{pattern}'",
                    severity=Severity.MEDIUM,
                    category="security",
                    recommendation="Review tool for command execution risks. "
                                   "Ensure proper input validation and sandboxing.",
                ))
                break

        # Check parameter names
        params = tool.get("inputSchema", tool.get("parameters", {}))
        properties = params.get("properties", {})
        for param_name, param_schema in properties.items():
            for pattern in RISKY_PARAM_NAMES:
                if re.search(pattern, param_name.lower()):
                    if "type" not in param_schema:
                        results.append(CheckResult(
                            name="risky_param_no_validation",
                            passed=False,
                            message=f"Tool '{tool_name}' has risky parameter "
                                    f"'{param_name}' without type validation",
                            severity=Severity.MEDIUM,
                            category="security",
                            recommendation="Add JSON schema type validation for this parameter.",
                        ))
                    break

    if not results:
        results.append(CheckResult(
            name="dangerous_patterns",
            passed=True,
            message="No dangerous naming patterns detected",
            severity=Severity.INFO,
            category="security",
        ))

    return results
