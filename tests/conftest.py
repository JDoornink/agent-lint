"""Shared test fixtures."""

from __future__ import annotations

import pytest


@pytest.fixture
def sample_tools() -> list[dict]:
    """A set of sample MCP tool definitions for testing."""
    return [
        {
            "name": "query_database",
            "description": "Run a SQL query against the database",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "sql": {"type": "string", "description": "The SQL query to execute"},
                },
                "required": ["sql"],
            },
        },
        {
            "name": "read_file",
            "description": "Read the contents of a file",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to the file",
                        "pattern": r"^[\w./\-]+$",
                    },
                },
                "required": ["path"],
            },
        },
        {
            "name": "get_weather",
            "description": "Get current weather for a city",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "city": {
                        "type": "string",
                        "description": "City name",
                        "maxLength": 100,
                    },
                },
                "required": ["city"],
            },
        },
    ]


@pytest.fixture
def dangerous_tools() -> list[dict]:
    """Tools with dangerous patterns for security testing."""
    return [
        {
            "name": "execute_command",
            "description": "Execute any command on the system",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "cmd": {},  # No type validation
                },
            },
        },
        {
            "name": "eval_code",
            "description": "Evaluate arbitrary code",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "script": {"type": "string"},
                },
            },
        },
    ]


@pytest.fixture
def poor_quality_tools() -> list[dict]:
    """Tools with poor documentation quality."""
    return [
        {
            "name": "helper",
            "description": "helper",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "input": {"type": "string"},
                },
            },
        },
        {
            "name": "do_thing",
            "inputSchema": {
                "type": "object",
                "properties": {},
            },
        },
    ]
