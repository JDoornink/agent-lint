"""Performance checks for MCP servers."""

from __future__ import annotations

from agent_lint.core.checks import CheckResult, Severity

# Thresholds
RESPONSE_TIME_GOOD_MS = 500
RESPONSE_TIME_WARN_MS = 2000
PAYLOAD_SIZE_WARN_BYTES = 1 * 1024 * 1024  # 1MB
PAYLOAD_SIZE_BAD_BYTES = 5 * 1024 * 1024   # 5MB


def check_response_time(elapsed_ms: float) -> CheckResult:
    """Check if server response time is acceptable."""
    if elapsed_ms <= RESPONSE_TIME_GOOD_MS:
        return CheckResult(
            name="response_time",
            passed=True,
            message=f"Response time: {elapsed_ms:.0f}ms (good)",
            severity=Severity.INFO,
            category="performance",
        )
    elif elapsed_ms <= RESPONSE_TIME_WARN_MS:
        return CheckResult(
            name="response_time",
            passed=True,
            message=f"Response time: {elapsed_ms:.0f}ms (acceptable)",
            severity=Severity.LOW,
            category="performance",
        )
    else:
        return CheckResult(
            name="response_time",
            passed=False,
            message=f"Response time: {elapsed_ms:.0f}ms (slow)",
            severity=Severity.MEDIUM,
            category="performance",
            recommendation="Optimize server response time. Consider caching or async processing.",
        )


def check_payload_size(size_bytes: int) -> CheckResult:
    """Check if response payload size is reasonable."""
    size_display = _format_size(size_bytes)

    if size_bytes <= PAYLOAD_SIZE_WARN_BYTES:
        return CheckResult(
            name="payload_size",
            passed=True,
            message=f"Response payload: {size_display}",
            severity=Severity.INFO,
            category="performance",
        )
    elif size_bytes <= PAYLOAD_SIZE_BAD_BYTES:
        return CheckResult(
            name="payload_size",
            passed=False,
            message=f"Large response payload: {size_display}",
            severity=Severity.LOW,
            category="performance",
            recommendation="Consider pagination or streaming for large responses.",
        )
    else:
        return CheckResult(
            name="payload_size",
            passed=False,
            message=f"Very large response payload: {size_display}",
            severity=Severity.MEDIUM,
            category="performance",
            recommendation="Response is very large. Implement pagination or streaming.",
        )


def _format_size(size_bytes: int) -> str:
    """Format byte size to human-readable string."""
    if size_bytes < 1024:
        return f"{size_bytes}B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f}KB"
    else:
        return f"{size_bytes / (1024 * 1024):.1f}MB"
