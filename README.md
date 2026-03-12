# agent-lint

> The quality and security platform for AI agents.

Validate MCP servers, scan for vulnerabilities, write integration tests, and ship reliable agents.

[![PyPI](https://img.shields.io/pypi/v/agent-lint-cli)](https://pypi.org/project/agent-lint-cli/)
[![Python](https://img.shields.io/pypi/pyversions/agent-lint-cli)](https://pypi.org/project/agent-lint-cli/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## Install

```bash
pip install agent-lint-cli
```

---

## Validate an MCP Server

```bash
agent-lint validate https://my-mcp-server.com
```

```
🔍 Validating MCP Server: https://my-mcp-server.com

Schema Validation
  ✓ Valid JSON-RPC 2.0 endpoint
  ✓ Tools list returned (5 tools)
  ✓ Resources endpoint responds

Security Analysis
  ⚠ [MEDIUM] Tool "run_query" has parameter "sql" without type validation
  ⚠ [MEDIUM] Tool "execute_task" has risky name pattern
  ✓ No credential patterns detected
  ✓ Rate limiting headers present

Tool Quality
  ✓ All tools have descriptions
  ✗ Tool "helper" missing parameter descriptions

Performance
  ✓ Response time: 245ms
  ⚠ Large response payload: 2.3MB

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Security Score: 75/100
Quality Score:  68/100
```

### Options

| Flag | Description |
|------|-------------|
| `--format console\|json\|sarif` | Output format (default: `console`) |
| `--fail-under N` | Exit 1 if overall score is below N (0–100) |
| `--fail-on-security` | Exit 1 if any security issues are found |
| `--security-level strict\|standard\|permissive\|none` | Check strictness (default: `standard`) |
| `--dynamic` | Run dynamic security tests (calls tools with payloads) |
| `--policy PATH` | Path to `.agent-lint.yaml` policy file |
| `--junit-xml PATH` | Write JUnit XML results to file |

---

## CI/CD Integration

### GitHub Actions

```yaml
# .github/workflows/mcp-security.yml
name: MCP Security

on: [push, pull_request]

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ./.github/actions/agent-lint
        with:
          url: https://my-mcp-server.com
          fail-on-security: "true"
          security-level: strict
```

The action automatically uploads SARIF results to the GitHub Security tab.

### Inline with CLI

```bash
# Fail on any security issue
agent-lint validate https://my-server.com --fail-on-security

# Require minimum score
agent-lint validate https://my-server.com --fail-under 80

# SARIF output for GitHub Security tab
agent-lint validate https://my-server.com -f sarif > results.sarif

# JUnit XML for test reporting
agent-lint validate https://my-server.com --junit-xml results.xml

# Dynamic security testing (calls tools with injection payloads)
agent-lint validate https://my-server.com --dynamic
```

---

## Security Policies

Create an `.agent-lint.yaml` file to enforce rules across your team:

```yaml
# .agent-lint.yaml
security:
  level: strict

  rules:
    dangerous_patterns: error
    missing_validation: error
    overly_permissive: warn
    credential_exposure: error

  exceptions:
    - tool: admin_execute
      reason: "Admin-only endpoint with auth middleware"
      rules:
        - dangerous_patterns
```

Then run with:

```bash
agent-lint validate https://my-server.com --policy .agent-lint.yaml
```

Policy security level overrides `--security-level` unless you pass `--security-level` explicitly.

---

## MCP Testing (pytest)

agent-lint ships a pytest plugin and fixtures for writing integration tests against MCP servers.

### Install testing extras

```bash
pip install "agent-lint-cli[testing]"
```

### Write tests

```python
# tests/test_my_server.py
from agent_lint import mcp


class TestQueryTool:

    async def test_basic_query(self, mcp_client):
        response = await mcp_client.call_tool("query_database", {"sql": "SELECT 1"})
        mcp.assert_valid_response(response)

    async def test_rejects_sql_injection(self, mcp_client):
        response = await mcp_client.call_tool(
            "query_database",
            {"sql": "'; DROP TABLE users; --"},
        )
        mcp.assert_error(response)

    async def test_response_time(self, mcp_client):
        response = await mcp_client.call_tool("query_database", {"sql": "SELECT 1"})
        mcp.assert_response_time(response, max_ms=500)

    async def test_no_secrets_in_response(self, mcp_client):
        response = await mcp_client.call_tool("get_config", {})
        mcp.assert_no_secrets(response)
```

### Run against a real server

```bash
# Against a live server
agent-lint test tests/ --mcp-url https://my-mcp-server.com

# Or with pytest directly
pytest tests/ --mcp-url https://my-mcp-server.com
```

### Run with the mock server (no real server needed)

```python
# tests/test_mock.py
async def test_with_mock(mock_mcp_server, mcp_client):
    mock_mcp_server.add_tool(
        "get_weather",
        description="Get weather for a city",
        input_schema={
            "type": "object",
            "properties": {"city": {"type": "string"}},
            "required": ["city"],
        },
        handler=lambda args: {"content": [{"type": "text", "text": f"Sunny in {args['city']}"}]},
    )

    response = await mcp_client.call_tool("get_weather", {"city": "London"})
    mcp.assert_valid_response(response)
    mcp.assert_content_matches(response, r"Sunny")
```

When `--mcp-url` is not passed, `mcp_client` automatically uses the mock server.

---

## Assertion Reference

| Assertion | Description |
|-----------|-------------|
| `mcp.assert_valid_response(r)` | Response has a result and no error |
| `mcp.assert_error(r, code=None)` | Response is an error (optionally assert error code) |
| `mcp.assert_result_contains(r, key, value)` | Result dict contains key (optionally assert value) |
| `mcp.assert_content_text(r, expected)` | Response has a text content block matching string |
| `mcp.assert_content_matches(r, pattern)` | Any text content block matches regex |
| `mcp.assert_tool_exists(r, name)` | `tools/list` response contains a named tool |
| `mcp.assert_no_secrets(r)` | Response does not contain credential patterns |
| `mcp.assert_response_time(r, max_ms)` | Response was returned within the time limit |

---

## Security Checks

agent-lint runs these checks by default (static analysis on tool definitions):

| Check | Severity | Description |
|-------|----------|-------------|
| Dangerous tool names | Medium | Names like `execute`, `shell`, `eval`, `run_command` |
| Risky parameters without validation | Medium | `sql`, `cmd`, `path`, `url` without JSON schema type |
| Overly permissive descriptions | Medium | Descriptions claiming "any file", "any command" |
| Credential exposure | High | API keys, tokens, secrets in responses |
| Missing rate limiting | Low | No rate-limit headers on responses |

With `--dynamic`, agent-lint also calls tools with injection payloads to detect runtime vulnerabilities:

| Payload Class | Example Parameters Targeted |
|---------------|-----------------------------|
| SQL injection | `sql`, `query`, `filter` |
| Path traversal | `path`, `file`, `filename` |
| Command injection | `cmd`, `command`, `exec`, `shell` |
| XSS | `html`, `content`, `body` |
| SSRF | `url`, `uri`, `endpoint` |

> **Note:** Static analysis is a first line of defense on tool definitions only. It cannot analyze handler code or detect all runtime vulnerabilities. Use `--dynamic` for deeper testing.

---

## Roadmap

| Version | Status | Features |
|---------|--------|----------|
| v0.1 | Released | MCP validation + basic security |
| **v0.2** | **Current** | MCP testing, pytest plugin, policy engine, CI/CD |
| v0.3 | Planned | A2A validation and testing |
| v1.0 | Planned | Observability, trace capture and replay |
