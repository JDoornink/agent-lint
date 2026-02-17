"""Quality checks for MCP tool definitions."""

from __future__ import annotations

from agent_lint.core.checks import CheckResult, Severity

VAGUE_DESCRIPTIONS = [
    "helper", "utility", "misc", "do stuff", "does things",
    "general purpose", "multi-purpose",
]

MIN_DESCRIPTION_LENGTH = 10


async def check_quality(tools: list[dict]) -> list[CheckResult]:
    """Check tool documentation quality."""
    results: list[CheckResult] = []

    if not tools:
        results.append(CheckResult(
            name="no_tools",
            passed=True,
            message="No tools to check",
            severity=Severity.INFO,
            category="quality",
        ))
        return results

    for tool in tools:
        name = tool.get("name", "<unnamed>")
        description = tool.get("description", "")

        # Check for missing description
        if not description:
            results.append(CheckResult(
                name="missing_description",
                passed=False,
                message=f"Tool '{name}' has no description",
                severity=Severity.MEDIUM,
                category="quality",
                recommendation="Add a clear description explaining what this tool does.",
            ))
            continue

        # Check for vague description
        desc_lower = description.lower()
        if len(description) < MIN_DESCRIPTION_LENGTH or any(
            v in desc_lower for v in VAGUE_DESCRIPTIONS
        ):
            results.append(CheckResult(
                name="vague_description",
                passed=False,
                message=f"Tool '{name}' has vague description: '{description}'",
                severity=Severity.LOW,
                category="quality",
                recommendation="Provide a specific description of what this tool does, "
                               "its inputs, and expected outputs.",
            ))
        else:
            results.append(CheckResult(
                name="good_description",
                passed=True,
                message=f"Tool '{name}' has a description",
                severity=Severity.INFO,
                category="quality",
            ))

        # Check parameter descriptions
        params = tool.get("inputSchema", tool.get("parameters", {}))
        properties = params.get("properties", {})
        for param_name, param_schema in properties.items():
            if not param_schema.get("description"):
                results.append(CheckResult(
                    name="missing_param_description",
                    passed=False,
                    message=f"Tool '{name}' parameter '{param_name}' missing description",
                    severity=Severity.LOW,
                    category="quality",
                    recommendation=f"Add a description for parameter '{param_name}'.",
                ))

    # Summary check: all tools have descriptions
    all_described = all(tool.get("description") for tool in tools)
    results.append(CheckResult(
        name="all_tools_described",
        passed=all_described,
        message="All tools have descriptions" if all_described
                else "Some tools are missing descriptions",
        severity=Severity.INFO if all_described else Severity.MEDIUM,
        category="quality",
    ))

    return results
