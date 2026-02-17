"""Base validator interface for protocol validators."""

from __future__ import annotations

from abc import ABC, abstractmethod

from agent_lint.core.checks import Severity, ValidationReport

# Security levels define the minimum severity that counts as a failure.
# "strict" treats everything LOW and above as a real finding.
# "standard" ignores LOW findings (they become pass).
# "permissive" only flags HIGH and CRITICAL.
# "none" downgrades all security findings to pass.
SECURITY_LEVEL_THRESHOLD: dict[str, Severity | None] = {
    "strict": Severity.LOW,
    "standard": Severity.MEDIUM,
    "permissive": Severity.HIGH,
    "none": None,
}


class BaseValidator(ABC):
    """Base class for protocol validators (MCP, A2A, etc.)."""

    def __init__(self, security_level: str = "standard") -> None:
        self.security_level = security_level

    @abstractmethod
    async def validate(self, url: str) -> ValidationReport:
        """Run all validation checks against a server. Subclasses must implement."""

    def _apply_security_level(self, report: ValidationReport) -> None:
        """Downgrade security findings below the threshold to passing."""
        threshold = SECURITY_LEVEL_THRESHOLD.get(self.security_level, Severity.MEDIUM)

        # "none" disables all security checks
        if threshold is None:
            for result in report.results:
                if result.category == "security" and not result.passed:
                    result.passed = True
            return

        severity_rank = {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }
        min_rank = severity_rank[threshold]

        for result in report.results:
            if result.category == "security" and not result.passed:
                if severity_rank[result.severity] < min_rank:
                    result.passed = True
