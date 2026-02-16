# agent-lint

Quality and security platform for AI agents. Validate MCP servers, scan for vulnerabilities, ship reliable agents.

## Install

```bash
pip install agent-lint
```

## Usage

```bash
agent-lint validate https://my-mcp-server.com
```

### Options

```
--format, -f     Output format: console, json, sarif (default: console)
--fail-under     Fail if score below threshold (0-100)
--fail-on-security  Fail if any security issues found
--security-level    strict, standard, or permissive (default: standard)
```

### CI/CD Integration

```bash
# Exit non-zero on security issues
agent-lint validate https://my-server.com --fail-on-security

# Require minimum score
agent-lint validate https://my-server.com --fail-under 80

# SARIF output for GitHub Security tab
agent-lint validate https://my-server.com -f sarif > results.sarif
```
