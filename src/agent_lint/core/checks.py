"""Core check result types and validation report."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class CheckResult:
    name: str
    passed: bool
    message: str
    severity: Severity
    category: str  # "security", "quality", "performance", "schema"
    recommendation: str | None = None


@dataclass
class ValidationReport:
    """Aggregated results from all validation checks."""

    server_url: str
    results: list[CheckResult] = field(default_factory=list)

    def add(self, result: CheckResult) -> None:
        self.results.append(result)

    def add_all(self, results: list[CheckResult]) -> None:
        self.results.extend(results)

    @property
    def passed(self) -> list[CheckResult]:
        return [r for r in self.results if r.passed]

    @property
    def failed(self) -> list[CheckResult]:
        return [r for r in self.results if not r.passed]

    @property
    def has_security_issues(self) -> bool:
        return any(r.category == "security" and not r.passed for r in self.results)

    def _category_score(self, category: str) -> int:
        """Score for a category as percentage of passed checks (0-100)."""
        cat_results = [r for r in self.results if r.category == category]
        if not cat_results:
            return 100
        passed = sum(1 for r in cat_results if r.passed)
        return int(passed / len(cat_results) * 100)

    @property
    def security_score(self) -> int:
        return self._category_score("security")

    @property
    def quality_score(self) -> int:
        return self._category_score("quality")

    @property
    def score(self) -> int:
        """Overall score: weighted average of all categories."""
        categories = {r.category for r in self.results}
        if not categories:
            return 100
        scores = [self._category_score(c) for c in categories]
        return int(sum(scores) / len(scores))
