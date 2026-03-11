"""Tests for JUnit XML reporter."""

from __future__ import annotations

import xml.etree.ElementTree as ET

import pytest

from agent_lint.core.checks import CheckResult, Severity, ValidationReport
from agent_lint.ci.reports import JUnitReporter


class TestJUnitReporter:
    def _make_report(self, *results):
        report = ValidationReport(server_url="http://test")
        for r in results:
            report.add(r)
        return report

    def test_valid_xml(self):
        report = self._make_report(
            CheckResult("test_a", True, "ok", Severity.INFO, "security"),
            CheckResult("test_b", False, "bad", Severity.HIGH, "security"),
        )
        xml_str = JUnitReporter().output(report)
        # Should be valid XML
        root = ET.fromstring(xml_str)
        assert root.tag == "testsuite"
        assert root.attrib["tests"] == "2"
        assert root.attrib["failures"] == "1"

    def test_testcases_present(self):
        report = self._make_report(
            CheckResult("check_a", True, "ok", Severity.INFO, "quality"),
            CheckResult("check_b", False, "bad", Severity.MEDIUM, "security"),
        )
        xml_str = JUnitReporter().output(report)
        root = ET.fromstring(xml_str)
        testcases = root.findall("testcase")
        assert len(testcases) == 2
        assert testcases[0].attrib["name"] == "check_a"
        assert testcases[0].attrib["classname"] == "agent-lint.quality"

    def test_failure_details(self):
        report = self._make_report(
            CheckResult(
                "bad_check", False, "something wrong", Severity.HIGH, "security",
                recommendation="Fix it",
            ),
        )
        xml_str = JUnitReporter().output(report)
        root = ET.fromstring(xml_str)
        failure = root.find(".//failure")
        assert failure is not None
        assert failure.attrib["message"] == "something wrong"
        assert failure.attrib["type"] == "high"
        assert failure.text == "Fix it"

    def test_passing_has_no_failure(self):
        report = self._make_report(
            CheckResult("ok_check", True, "all good", Severity.INFO, "schema"),
        )
        xml_str = JUnitReporter().output(report)
        root = ET.fromstring(xml_str)
        failure = root.find(".//failure")
        assert failure is None

    def test_write_to_file(self, tmp_path):
        report = self._make_report(
            CheckResult("a", True, "ok", Severity.INFO, "security"),
        )
        path = tmp_path / "results.xml"
        JUnitReporter().output(report, path=str(path))
        assert path.exists()
        content = path.read_text()
        assert "<?xml" in content

    def test_empty_report(self):
        report = self._make_report()
        xml_str = JUnitReporter().output(report)
        root = ET.fromstring(xml_str)
        assert root.attrib["tests"] == "0"
        assert root.attrib["failures"] == "0"
