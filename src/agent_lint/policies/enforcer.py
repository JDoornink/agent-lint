"""Apply policy rules to check results."""

from __future__ import annotations

from agent_lint.core.checks import CheckResult, Severity, ValidationReport
from agent_lint.policies.schema import PolicyConfig

# Maps user-friendly rule names in YAML to internal CheckResult.name values
RULE_TO_CHECK_NAMES: dict[str, list[str]] = {
    "dangerous_patterns": ["dangerous_tool_name", "risky_param_no_validation"],
    "missing_validation": ["missing_type_validation", "unconstrained_string"],
    "overly_permissive": ["overly_permissive"],
    "credential_exposure": ["credential_in_response", "credential_in_definition"],
    "rate_limiting": ["rate_limiting"],
    "dynamic_security": [
        "dynamic_sql_injection",
        "dynamic_path_traversal",
        "dynamic_command_injection",
        "dynamic_xss",
        "dynamic_ssrf",
    ],
}


def _build_reverse_map(rule_map: dict[str, list[str]]) -> dict[str, str]:
    """Build check_name -> rule_name reverse mapping."""
    reverse = {}
    for rule_name, check_names in rule_map.items():
        for check_name in check_names:
            reverse[check_name] = rule_name
    return reverse


_CHECK_TO_RULE = _build_reverse_map(RULE_TO_CHECK_NAMES)


class PolicyEnforcer:
    """Apply policy overrides to validation results."""

    def __init__(self, policy: PolicyConfig) -> None:
        self.policy = policy

    def apply(self, report: ValidationReport) -> ValidationReport:
        """Mutate report by applying policy overrides."""
        for result in report.results:
            if result.category != "security":
                continue

            # Check tool-level exceptions
            if result.tool_name and self._is_excepted(result):
                result.passed = True
                continue

            # Check rule-level overrides
            rule_name = _CHECK_TO_RULE.get(result.name)
            if rule_name and rule_name in self.policy.security.rules:
                action = self.policy.security.rules[rule_name]
                if action == "off":
                    result.passed = True
                elif action == "warn":
                    result.severity = Severity.LOW
                # "error" keeps the result as-is (failed)

        return report

    def _is_excepted(self, result: CheckResult) -> bool:
        """Check if a result's tool is exempted by policy exceptions."""
        for exc in self.policy.security.exceptions:
            if exc.tool != result.tool_name:
                continue
            # If no specific rules listed, exempt from everything
            if exc.rules is None:
                return True
            # Check if this result's rule is in the exception list
            rule_name = _CHECK_TO_RULE.get(result.name)
            if rule_name and rule_name in exc.rules:
                return True
        return False
