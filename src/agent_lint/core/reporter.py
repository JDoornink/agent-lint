"""Report output formatters for validation results."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from agent_lint.core.checks import CheckResult, Severity, ValidationReport


class Reporter(ABC):
    @abstractmethod
    def output(self, report: ValidationReport) -> str:
        """Format and output the report. Returns the formatted string."""


class ConsoleReporter(Reporter):
    """Rich-formatted console output."""

    SEVERITY_COLORS = {
        Severity.CRITICAL: "red bold",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "blue",
        Severity.INFO: "green",
    }

    SEVERITY_ICONS = {
        Severity.CRITICAL: "\u2717",  # ✗
        Severity.HIGH: "\u2717",
        Severity.MEDIUM: "\u26a0",   # ⚠
        Severity.LOW: "\u26a0",
        Severity.INFO: "\u2713",     # ✓
    }

    def output(self, report: ValidationReport) -> str:
        console = Console()
        lines: list[str] = []

        console.print()
        console.print(
            Panel(
                f"[bold]Validating MCP Server:[/bold] {report.server_url}",
                title="agent-lint",
                border_style="blue",
            )
        )

        # Group results by category
        categories = {}
        for result in report.results:
            categories.setdefault(result.category, []).append(result)

        category_titles = {
            "schema": "Schema Validation",
            "security": "Security Analysis",
            "quality": "Tool Quality",
            "performance": "Performance",
        }

        for category in ["schema", "security", "quality", "performance"]:
            results = categories.get(category, [])
            if not results:
                continue

            console.print()
            console.print(f"[bold]{category_titles.get(category, category)}[/bold]")

            for result in results:
                icon = self.SEVERITY_ICONS.get(result.severity, " ")
                color = self.SEVERITY_COLORS.get(result.severity, "white")

                if result.passed:
                    console.print(f"  [green]{icon}[/green] {result.message}")
                else:
                    severity_label = result.severity.value.upper()
                    console.print(
                        f"  [{color}]{icon} [{severity_label}][/{color}] "
                        f"{result.message}"
                    )
                    if result.recommendation:
                        console.print(
                            f"      [dim]Recommendation: {result.recommendation}[/dim]"
                        )

        # Summary
        console.print()
        console.print("\u2501" * 50)

        sec_score = report.security_score
        qual_score = report.quality_score
        sec_label = _score_label(sec_score)
        qual_label = _score_label(qual_score)

        sec_color = _score_color(sec_score)
        qual_color = _score_color(qual_score)

        console.print(f"[{sec_color}]Security Score: {sec_score}/100 - {sec_label}[/{sec_color}]")
        console.print(f"[{qual_color}]Quality Score: {qual_score}/100 - {qual_label}[/{qual_color}]")
        console.print()

        return ""


class JsonReporter(Reporter):
    """JSON output format."""

    def output(self, report: ValidationReport) -> str:
        data = {
            "server_url": report.server_url,
            "score": report.score,
            "security_score": report.security_score,
            "quality_score": report.quality_score,
            "has_security_issues": report.has_security_issues,
            "results": [
                {
                    "name": r.name,
                    "passed": r.passed,
                    "message": r.message,
                    "severity": r.severity.value,
                    "category": r.category,
                    "recommendation": r.recommendation,
                }
                for r in report.results
            ],
        }
        output = json.dumps(data, indent=2)
        print(output)
        return output


class SarifReporter(Reporter):
    """SARIF output format for GitHub Security integration."""

    def output(self, report: ValidationReport) -> str:
        sarif = {
            "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "agent-lint",
                            "version": "0.1.0",
                            "informationUri": "https://github.com/agent-lint/agent-lint",
                            "rules": self._build_rules(report),
                        }
                    },
                    "results": self._build_results(report),
                }
            ],
        }
        output = json.dumps(sarif, indent=2)
        print(output)
        return output

    def _build_rules(self, report: ValidationReport) -> list[dict]:
        seen = set()
        rules = []
        for r in report.results:
            if r.name not in seen:
                seen.add(r.name)
                rules.append({
                    "id": r.name,
                    "shortDescription": {"text": r.message},
                })
        return rules

    def _build_results(self, report: ValidationReport) -> list[dict]:
        severity_map = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "note",
        }
        return [
            {
                "ruleId": r.name,
                "level": severity_map.get(r.severity, "note"),
                "message": {"text": r.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": report.server_url,
                            }
                        }
                    }
                ],
            }
            for r in report.results
            if not r.passed
        ]


def _score_label(score: int) -> str:
    if score >= 90:
        return "Excellent"
    elif score >= 75:
        return "Minor Issues"
    elif score >= 50:
        return "Needs Improvement"
    else:
        return "Poor"


def _score_color(score: int) -> str:
    if score >= 90:
        return "green"
    elif score >= 75:
        return "yellow"
    elif score >= 50:
        return "red"
    else:
        return "red bold"
