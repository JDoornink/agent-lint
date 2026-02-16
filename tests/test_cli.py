"""CLI smoke tests."""

from __future__ import annotations

from click.testing import CliRunner

from agent_lint.cli import cli


class TestCLI:
    def test_version(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output

    def test_help(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "agent-lint" in result.output

    def test_validate_help(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["validate", "--help"])
        assert result.exit_code == 0
        assert "--format" in result.output
        assert "--fail-under" in result.output
        assert "--fail-on-security" in result.output
        assert "--security-level" in result.output
