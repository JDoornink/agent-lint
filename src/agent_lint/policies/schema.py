"""Pydantic models for .agent-lint.yaml policy files."""

from __future__ import annotations

from pydantic import BaseModel


class ToolException(BaseModel):
    """Exception for a specific tool from specific rules."""

    tool: str
    reason: str
    rules: list[str] | None = None  # If None, exempts from all rules


class SecurityPolicy(BaseModel):
    """Security section of the policy configuration."""

    level: str = "standard"  # strict | standard | permissive | none
    rules: dict[str, str] = {}  # rule_name -> "error" | "warn" | "off"
    exceptions: list[ToolException] = []


class PolicyConfig(BaseModel):
    """Top-level policy configuration from .agent-lint.yaml."""

    security: SecurityPolicy = SecurityPolicy()
