"""Tests for policy engine."""

from __future__ import annotations

import pytest
from pathlib import Path

from agent_lint.core.checks import CheckResult, Severity, ValidationReport
from agent_lint.policies.schema import PolicyConfig, SecurityPolicy, ToolException
from agent_lint.policies.loader import load_policy, find_policy_file
from agent_lint.policies.enforcer import PolicyEnforcer


class TestPolicySchema:
    def test_defaults(self):
        config = PolicyConfig()
        assert config.security.level == "standard"
        assert config.security.rules == {}
        assert config.security.exceptions == []

    def test_full_config(self):
        config = PolicyConfig(
            security=SecurityPolicy(
                level="strict",
                rules={"dangerous_patterns": "error", "missing_validation": "warn"},
                exceptions=[ToolException(tool="admin_exec", reason="Admin only")],
            )
        )
        assert config.security.level == "strict"
        assert config.security.rules["dangerous_patterns"] == "error"
        assert config.security.exceptions[0].tool == "admin_exec"


class TestPolicyLoader:
    def test_load_missing_file(self):
        config = load_policy(Path("/nonexistent/file.yaml"))
        assert config.security.level == "standard"

    def test_load_valid_yaml(self, tmp_path):
        policy_file = tmp_path / ".agent-lint.yaml"
        policy_file.write_text(
            "security:\n  level: strict\n  rules:\n    dangerous_patterns: error\n"
        )
        config = load_policy(policy_file)
        assert config.security.level == "strict"
        assert config.security.rules["dangerous_patterns"] == "error"

    def test_load_empty_yaml(self, tmp_path):
        policy_file = tmp_path / ".agent-lint.yaml"
        policy_file.write_text("")
        config = load_policy(policy_file)
        assert config.security.level == "standard"

    def test_find_policy_file(self, tmp_path):
        policy_file = tmp_path / ".agent-lint.yaml"
        policy_file.write_text("security:\n  level: strict\n")
        found = find_policy_file(tmp_path)
        assert found == policy_file

    def test_find_policy_file_yml(self, tmp_path):
        policy_file = tmp_path / ".agent-lint.yml"
        policy_file.write_text("security:\n  level: strict\n")
        found = find_policy_file(tmp_path)
        assert found == policy_file

    def test_find_policy_file_not_found(self, tmp_path):
        sub = tmp_path / "deep" / "nested"
        sub.mkdir(parents=True)
        found = find_policy_file(sub)
        assert found is None


class TestPolicyEnforcer:
    def _make_report(self, *results):
        report = ValidationReport(server_url="http://test")
        for r in results:
            report.add(r)
        return report

    def test_off_disables_rule(self):
        policy = PolicyConfig(
            security=SecurityPolicy(rules={"dangerous_patterns": "off"})
        )
        report = self._make_report(
            CheckResult("dangerous_tool_name", False, "bad", Severity.MEDIUM, "security")
        )
        PolicyEnforcer(policy).apply(report)
        assert report.results[0].passed is True

    def test_warn_downgrades_severity(self):
        policy = PolicyConfig(
            security=SecurityPolicy(rules={"missing_validation": "warn"})
        )
        report = self._make_report(
            CheckResult("missing_type_validation", False, "bad", Severity.MEDIUM, "security")
        )
        PolicyEnforcer(policy).apply(report)
        assert report.results[0].severity == Severity.LOW

    def test_error_keeps_failure(self):
        policy = PolicyConfig(
            security=SecurityPolicy(rules={"dangerous_patterns": "error"})
        )
        report = self._make_report(
            CheckResult("dangerous_tool_name", False, "bad", Severity.MEDIUM, "security")
        )
        PolicyEnforcer(policy).apply(report)
        assert report.results[0].passed is False

    def test_tool_exception_all_rules(self):
        policy = PolicyConfig(
            security=SecurityPolicy(
                exceptions=[ToolException(tool="admin_exec", reason="Admin only")]
            )
        )
        report = self._make_report(
            CheckResult(
                "dangerous_tool_name", False, "bad", Severity.MEDIUM, "security",
                tool_name="admin_exec",
            )
        )
        PolicyEnforcer(policy).apply(report)
        assert report.results[0].passed is True

    def test_tool_exception_specific_rules(self):
        policy = PolicyConfig(
            security=SecurityPolicy(
                exceptions=[
                    ToolException(
                        tool="admin_exec",
                        reason="Admin only",
                        rules=["dangerous_patterns"],
                    )
                ]
            )
        )
        report = self._make_report(
            CheckResult(
                "dangerous_tool_name", False, "bad", Severity.MEDIUM, "security",
                tool_name="admin_exec",
            ),
            CheckResult(
                "overly_permissive", False, "bad", Severity.MEDIUM, "security",
                tool_name="admin_exec",
            ),
        )
        PolicyEnforcer(policy).apply(report)
        # dangerous_patterns is excepted, overly_permissive is not
        assert report.results[0].passed is True
        assert report.results[1].passed is False

    def test_does_not_affect_quality(self):
        policy = PolicyConfig(
            security=SecurityPolicy(rules={"dangerous_patterns": "off"})
        )
        report = self._make_report(
            CheckResult("missing_description", False, "bad", Severity.MEDIUM, "quality")
        )
        PolicyEnforcer(policy).apply(report)
        assert report.results[0].passed is False

    def test_no_tool_name_skips_exception(self):
        policy = PolicyConfig(
            security=SecurityPolicy(
                exceptions=[ToolException(tool="admin_exec", reason="Admin only")]
            )
        )
        report = self._make_report(
            CheckResult("dangerous_tool_name", False, "bad", Severity.MEDIUM, "security")
        )
        PolicyEnforcer(policy).apply(report)
        assert report.results[0].passed is False
