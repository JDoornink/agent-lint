"""Reporter output tests."""

from __future__ import annotations

import json

from agent_lint.core.checks import CheckResult, Severity, ValidationReport
from agent_lint.core.reporter import ConsoleReporter, JsonReporter, SarifReporter


def _make_report() -> ValidationReport:
    report = ValidationReport(server_url="http://test-server:8080")
    report.add(CheckResult(
        "jsonrpc_initialize", True, "Valid JSON-RPC 2.0 endpoint",
        Severity.INFO, "schema",
    ))
    report.add(CheckResult(
        "dangerous_tool_name", False,
        "Tool 'execute_cmd' has risky name pattern",
        Severity.MEDIUM, "security",
        recommendation="Review for command execution risks.",
    ))
    report.add(CheckResult(
        "good_description", True, "All tools have descriptions",
        Severity.INFO, "quality",
    ))
    report.add(CheckResult(
        "response_time", True, "Response time: 120ms (good)",
        Severity.INFO, "performance",
    ))
    return report


class TestJsonReporter:
    def test_output_is_valid_json(self, capsys):
        reporter = JsonReporter()
        reporter.output(_make_report())
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["server_url"] == "http://test-server:8080"
        assert isinstance(data["results"], list)
        assert len(data["results"]) == 4
        assert "security_score" in data
        assert "quality_score" in data

    def test_failed_results_included(self, capsys):
        reporter = JsonReporter()
        reporter.output(_make_report())
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        failed = [r for r in data["results"] if not r["passed"]]
        assert len(failed) == 1
        assert failed[0]["name"] == "dangerous_tool_name"


class TestSarifReporter:
    def test_output_is_valid_sarif(self, capsys):
        reporter = SarifReporter()
        reporter.output(_make_report())
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["version"] == "2.1.0"
        assert len(data["runs"]) == 1
        run = data["runs"][0]
        assert run["tool"]["driver"]["name"] == "agent-lint"

    def test_only_failures_in_results(self, capsys):
        reporter = SarifReporter()
        reporter.output(_make_report())
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        sarif_results = data["runs"][0]["results"]
        # Only failed checks should appear in SARIF results
        assert len(sarif_results) == 1
        assert sarif_results[0]["ruleId"] == "dangerous_tool_name"


class TestConsoleReporter:
    def test_does_not_crash(self):
        reporter = ConsoleReporter()
        reporter.output(_make_report())
