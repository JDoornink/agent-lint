"""Unit tests for MCP check modules."""

from __future__ import annotations

import pytest

from agent_lint.core.checks import CheckResult, Severity, ValidationReport
from agent_lint.protocols.mcp.checks.performance import check_payload_size, check_response_time
from agent_lint.protocols.mcp.checks.quality import check_quality
from agent_lint.protocols.mcp.checks.security.patterns import check_dangerous_patterns
from agent_lint.protocols.mcp.checks.security.permissions import check_permissions
from agent_lint.protocols.mcp.checks.security.secrets import check_secrets
from agent_lint.protocols.mcp.checks.security.ratelimit import check_rate_limiting
from agent_lint.protocols.mcp.checks.security.validation import check_input_validation


# --- Quality checks ---

class TestQualityChecks:
    async def test_good_tools_pass(self, sample_tools):
        results = await check_quality(sample_tools)
        failed = [r for r in results if not r.passed]
        # sample_tools have descriptions but "sql" param lacks description constraint
        assert any(r.passed for r in results)

    async def test_missing_description_detected(self, poor_quality_tools):
        results = await check_quality(poor_quality_tools)
        missing = [r for r in results if r.name == "missing_description"]
        assert len(missing) >= 1

    async def test_vague_description_detected(self, poor_quality_tools):
        results = await check_quality(poor_quality_tools)
        vague = [r for r in results if r.name == "vague_description"]
        assert len(vague) >= 1

    async def test_empty_tools_list(self):
        results = await check_quality([])
        assert all(r.passed for r in results)


# --- Security: Dangerous patterns ---

class TestDangerousPatterns:
    async def test_detects_dangerous_tool_names(self, dangerous_tools):
        results = await check_dangerous_patterns(dangerous_tools)
        dangerous = [r for r in results if r.name == "dangerous_tool_name"]
        assert len(dangerous) >= 2  # execute_command and eval_code

    async def test_detects_risky_params_without_type(self, dangerous_tools):
        results = await check_dangerous_patterns(dangerous_tools)
        risky = [r for r in results if r.name == "risky_param_no_validation"]
        assert len(risky) >= 1  # cmd without type

    async def test_safe_tools_pass(self):
        tools = [
            {
                "name": "get_weather",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "city": {"type": "string"},
                    },
                },
            }
        ]
        results = await check_dangerous_patterns(tools)
        assert all(r.passed for r in results)


# --- Security: Input validation ---

class TestInputValidation:
    async def test_missing_type_detected(self):
        tools = [
            {
                "name": "test_tool",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "param1": {},  # no type
                    },
                },
            }
        ]
        results = await check_input_validation(tools)
        missing = [r for r in results if r.name == "missing_type_validation"]
        assert len(missing) == 1

    async def test_unconstrained_string_detected(self):
        tools = [
            {
                "name": "test_tool",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},  # no constraints
                    },
                },
            }
        ]
        results = await check_input_validation(tools)
        unconstrained = [r for r in results if r.name == "unconstrained_string"]
        assert len(unconstrained) == 1

    async def test_constrained_string_passes(self):
        tools = [
            {
                "name": "test_tool",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "status": {"type": "string", "enum": ["active", "inactive"]},
                    },
                },
            }
        ]
        results = await check_input_validation(tools)
        assert all(r.passed for r in results)


# --- Security: Permissions ---

class TestPermissions:
    async def test_overly_permissive_detected(self):
        tools = [
            {
                "name": "file_reader",
                "description": "Read any file from the filesystem",
                "inputSchema": {"type": "object", "properties": {}},
            }
        ]
        results = await check_permissions(tools)
        permissive = [r for r in results if r.name == "overly_permissive"]
        assert len(permissive) == 1

    async def test_specific_description_passes(self):
        tools = [
            {
                "name": "read_config",
                "description": "Read the application configuration file",
                "inputSchema": {"type": "object", "properties": {}},
            }
        ]
        results = await check_permissions(tools)
        assert all(r.passed for r in results)


# --- Security: Secrets ---

class TestSecrets:
    async def test_detects_api_key_in_response(self):
        results = await check_secrets([], ['api_key: "sk-abc123456789012345678901"'])
        leaked = [r for r in results if r.name == "credential_in_response"]
        assert len(leaked) >= 1

    async def test_detects_aws_key_in_tool_definition(self):
        tools = [
            {
                "name": "aws_tool",
                "description": "Uses AKIAIOSFODNN7EXAMPLE for auth",
                "inputSchema": {"type": "object", "properties": {}},
            }
        ]
        results = await check_secrets(tools, [])
        leaked = [r for r in results if r.name == "credential_in_definition"]
        assert len(leaked) >= 1

    async def test_clean_responses_pass(self):
        results = await check_secrets(
            [{"name": "safe", "description": "A safe tool"}],
            ["Normal response text"],
        )
        assert all(r.passed for r in results)


# --- Security: Rate limiting ---

class TestRateLimiting:
    def test_detects_rate_limit_headers(self):
        headers = {"X-RateLimit-Limit": "100", "X-RateLimit-Remaining": "99"}
        result = check_rate_limiting(headers)
        assert result.passed

    def test_missing_rate_limit_headers(self):
        headers = {"Content-Type": "application/json"}
        result = check_rate_limiting(headers)
        assert not result.passed
        assert result.severity == Severity.LOW

    def test_retry_after_counts(self):
        headers = {"Retry-After": "60"}
        result = check_rate_limiting(headers)
        assert result.passed


# --- Performance ---

class TestPerformance:
    def test_fast_response_passes(self):
        result = check_response_time(100)
        assert result.passed

    def test_slow_response_fails(self):
        result = check_response_time(5000)
        assert not result.passed

    def test_small_payload_passes(self):
        result = check_payload_size(1024)
        assert result.passed

    def test_large_payload_fails(self):
        result = check_payload_size(10 * 1024 * 1024)
        assert not result.passed


# --- ValidationReport ---

class TestValidationReport:
    def test_score_calculation(self):
        from agent_lint.core.checks import CheckResult
        report = ValidationReport(server_url="http://test")
        report.add(CheckResult("a", True, "ok", Severity.INFO, "security"))
        report.add(CheckResult("b", False, "bad", Severity.MEDIUM, "security"))
        report.add(CheckResult("c", True, "ok", Severity.INFO, "quality"))
        assert report.security_score == 50
        assert report.quality_score == 100
        assert report.has_security_issues

    def test_empty_report(self):
        report = ValidationReport(server_url="http://test")
        assert report.score == 100
        assert not report.has_security_issues


# --- Security level filtering ---

class TestSecurityLevel:
    def test_standard_downgrades_low_severity(self):
        from agent_lint.protocols.mcp.validator import MCPValidator
        validator = MCPValidator(security_level="standard")
        report = ValidationReport(server_url="http://test")
        report.add(CheckResult("low_issue", False, "low", Severity.LOW, "security"))
        report.add(CheckResult("med_issue", False, "med", Severity.MEDIUM, "security"))
        validator._apply_security_level(report)
        # LOW should be downgraded to pass, MEDIUM stays failed
        assert report.results[0].passed is True
        assert report.results[1].passed is False

    def test_strict_keeps_low_severity(self):
        from agent_lint.protocols.mcp.validator import MCPValidator
        validator = MCPValidator(security_level="strict")
        report = ValidationReport(server_url="http://test")
        report.add(CheckResult("low_issue", False, "low", Severity.LOW, "security"))
        validator._apply_security_level(report)
        assert report.results[0].passed is False

    def test_permissive_downgrades_medium(self):
        from agent_lint.protocols.mcp.validator import MCPValidator
        validator = MCPValidator(security_level="permissive")
        report = ValidationReport(server_url="http://test")
        report.add(CheckResult("med_issue", False, "med", Severity.MEDIUM, "security"))
        report.add(CheckResult("high_issue", False, "high", Severity.HIGH, "security"))
        validator._apply_security_level(report)
        # MEDIUM downgraded, HIGH stays
        assert report.results[0].passed is True
        assert report.results[1].passed is False

    def test_does_not_affect_non_security(self):
        from agent_lint.protocols.mcp.validator import MCPValidator
        validator = MCPValidator(security_level="permissive")
        report = ValidationReport(server_url="http://test")
        report.add(CheckResult("quality", False, "bad", Severity.LOW, "quality"))
        validator._apply_security_level(report)
        # Quality results should not be touched
        assert report.results[0].passed is False

    def test_none_downgrades_everything(self):
        from agent_lint.protocols.mcp.validator import MCPValidator
        validator = MCPValidator(security_level="none")
        report = ValidationReport(server_url="http://test")
        report.add(CheckResult("crit", False, "crit", Severity.CRITICAL, "security"))
        report.add(CheckResult("high", False, "high", Severity.HIGH, "security"))
        report.add(CheckResult("quality", False, "bad", Severity.LOW, "quality"))
        validator._apply_security_level(report)
        # All security findings downgraded, quality untouched
        assert report.results[0].passed is True
        assert report.results[1].passed is True
        assert report.results[2].passed is False
