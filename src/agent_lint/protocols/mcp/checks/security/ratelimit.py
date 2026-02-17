"""Rate limiting detection for MCP servers."""

from __future__ import annotations

from agent_lint.core.checks import CheckResult, Severity

RATE_LIMIT_HEADERS = [
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-rate-limit-limit",
    "x-rate-limit-remaining",
    "ratelimit-limit",
    "ratelimit-remaining",
    "retry-after",
]


def check_rate_limiting(headers: dict[str, str]) -> CheckResult:
    """Check if the server advertises rate limiting via response headers."""
    headers_lower = {k.lower(): v for k, v in headers.items()}

    found = [h for h in RATE_LIMIT_HEADERS if h in headers_lower]

    if found:
        return CheckResult(
            name="rate_limiting",
            passed=True,
            message=f"Rate limiting detected ({', '.join(found)})",
            severity=Severity.INFO,
            category="security",
        )
    else:
        return CheckResult(
            name="rate_limiting",
            passed=False,
            message="No rate limiting headers detected",
            severity=Severity.LOW,
            category="security",
            recommendation="Consider adding rate limiting to prevent abuse. "
                           "Use headers like X-RateLimit-Limit and X-RateLimit-Remaining.",
        )
