"""CLI entry point for agent-lint."""

from __future__ import annotations

import asyncio

import click

from agent_lint import __version__
from agent_lint.core.reporter import ConsoleReporter, JsonReporter, SarifReporter
from agent_lint.protocols.mcp.validator import MCPValidator


@click.group()
@click.version_option(version=__version__)
def cli() -> None:
    """agent-lint: Quality and security tools for AI agents."""


@cli.command()
@click.argument("url")
@click.option(
    "--format", "-f",
    "output_format",
    type=click.Choice(["console", "json", "sarif"]),
    default="console",
    help="Output format",
)
@click.option(
    "--fail-under",
    type=int,
    default=0,
    help="Fail if overall score is below this threshold (0-100)",
)
@click.option(
    "--fail-on-security",
    is_flag=True,
    help="Exit with error if any security issues are found",
)
@click.option(
    "--security-level",
    type=click.Choice(["strict", "standard", "permissive", "none"]),
    default="standard",
    help="Security check strictness level",
)
def validate(
    url: str,
    output_format: str,
    fail_under: int,
    fail_on_security: bool,
    security_level: str,
) -> None:
    """Validate an MCP server for quality and security issues."""
    validator = MCPValidator(security_level=security_level)
    report = asyncio.run(validator.validate(url))

    reporters = {
        "console": ConsoleReporter(),
        "json": JsonReporter(),
        "sarif": SarifReporter(),
    }
    reporters[output_format].output(report)

    if fail_on_security and report.has_security_issues:
        raise SystemExit(1)
    if report.score < fail_under:
        raise SystemExit(1)


if __name__ == "__main__":
    cli()
