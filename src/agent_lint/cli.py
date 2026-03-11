"""CLI entry point for agent-lint."""

from __future__ import annotations

import asyncio
import subprocess
import sys

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
@click.option(
    "--policy",
    type=click.Path(exists=True),
    default=None,
    help="Path to .agent-lint.yaml policy file",
)
@click.option(
    "--dynamic",
    is_flag=True,
    help="Run dynamic security tests (calls tools with payloads)",
)
@click.option(
    "--junit-xml",
    type=click.Path(),
    default=None,
    help="Write JUnit XML report to this path",
)
def validate(
    url: str,
    output_format: str,
    fail_under: int,
    fail_on_security: bool,
    security_level: str,
    policy: str | None,
    dynamic: bool,
    junit_xml: str | None,
) -> None:
    """Validate an MCP server for quality and security issues."""
    from agent_lint.policies.loader import load_policy
    from agent_lint.policies.enforcer import PolicyEnforcer

    # Load policy (from file or defaults)
    policy_config = load_policy(policy)

    # Use policy's security level if not overridden on CLI
    if policy and security_level == "standard":
        security_level = policy_config.security.level

    validator = MCPValidator(security_level=security_level, dynamic=dynamic)
    report = asyncio.run(validator.validate(url))

    # Apply policy overrides
    PolicyEnforcer(policy_config).apply(report)

    # Output report
    reporters = {
        "console": ConsoleReporter(),
        "json": JsonReporter(),
        "sarif": SarifReporter(),
    }
    reporters[output_format].output(report)

    # Write JUnit XML if requested
    if junit_xml:
        from agent_lint.ci.reports import JUnitReporter
        JUnitReporter().output(report, path=junit_xml)

    # Exit codes
    if fail_on_security and report.has_security_issues:
        raise SystemExit(1)
    if report.score < fail_under:
        raise SystemExit(1)


@cli.command()
@click.argument("test_path", default="tests/")
@click.option("--mcp-url", default=None, help="MCP server URL for testing")
def test(test_path: str, mcp_url: str | None) -> None:
    """Run MCP tests using pytest."""
    args = [sys.executable, "-m", "pytest", test_path]
    if mcp_url:
        args.extend(["--mcp-url", mcp_url])
    raise SystemExit(subprocess.call(args))


if __name__ == "__main__":
    cli()
