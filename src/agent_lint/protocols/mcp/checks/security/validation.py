"""Input validation checks for MCP tool definitions."""

from __future__ import annotations

from agent_lint.core.checks import CheckResult, Severity


async def check_input_validation(tools: list[dict]) -> list[CheckResult]:
    """Check that tool parameters have proper type validation."""
    results: list[CheckResult] = []

    for tool in tools:
        name = tool.get("name", "<unnamed>")
        params = tool.get("inputSchema", tool.get("parameters", {}))
        properties = params.get("properties", {})

        if not properties:
            continue

        for param_name, param_schema in properties.items():
            if "type" not in param_schema and "$ref" not in param_schema:
                results.append(CheckResult(
                    name="missing_type_validation",
                    passed=False,
                    message=f"Tool '{name}' parameter '{param_name}' has no type defined",
                    severity=Severity.MEDIUM,
                    category="security",
                    recommendation=f"Add a 'type' field to the schema for '{param_name}'.",
                ))

            # Check for string params without constraints
            if param_schema.get("type") == "string":
                has_constraints = any(
                    k in param_schema
                    for k in ("enum", "pattern", "maxLength", "minLength", "format")
                )
                if not has_constraints:
                    results.append(CheckResult(
                        name="unconstrained_string",
                        passed=False,
                        message=f"Tool '{name}' parameter '{param_name}' is an "
                                f"unconstrained string",
                        severity=Severity.LOW,
                        category="security",
                        recommendation="Consider adding constraints like enum, pattern, "
                                       "or maxLength to limit input.",
                    ))

    if not results:
        results.append(CheckResult(
            name="input_validation",
            passed=True,
            message="All parameters have type validation",
            severity=Severity.INFO,
            category="security",
        ))

    return results
