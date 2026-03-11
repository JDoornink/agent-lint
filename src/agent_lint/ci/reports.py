"""CI/CD report formats."""

from __future__ import annotations

import xml.etree.ElementTree as ET

from agent_lint.core.checks import ValidationReport


class JUnitReporter:
    """Write validation results as JUnit XML."""

    def output(self, report: ValidationReport, path: str | None = None) -> str:
        """Generate JUnit XML. If path is given, write to file."""
        testsuite = ET.Element("testsuite", {
            "name": f"agent-lint: {report.server_url}",
            "tests": str(len(report.results)),
            "failures": str(len(report.failed)),
        })

        for result in report.results:
            testcase = ET.SubElement(testsuite, "testcase", {
                "name": result.name,
                "classname": f"agent-lint.{result.category}",
            })
            if not result.passed:
                failure = ET.SubElement(testcase, "failure", {
                    "message": result.message,
                    "type": result.severity.value,
                })
                if result.recommendation:
                    failure.text = result.recommendation

        xml_str = ET.tostring(testsuite, encoding="unicode")
        xml_str = '<?xml version="1.0" encoding="UTF-8"?>\n' + xml_str

        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(xml_str)

        return xml_str
