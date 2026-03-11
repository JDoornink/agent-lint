"""Find and parse policy configuration files."""

from __future__ import annotations

from pathlib import Path

import yaml

from agent_lint.policies.schema import PolicyConfig

POLICY_FILENAMES = [".agent-lint.yaml", ".agent-lint.yml"]


def find_policy_file(start_dir: Path | None = None) -> Path | None:
    """Walk up from start_dir looking for a policy file."""
    directory = start_dir or Path.cwd()
    directory = directory.resolve()

    for _ in range(50):  # safety limit
        for filename in POLICY_FILENAMES:
            candidate = directory / filename
            if candidate.is_file():
                return candidate
        parent = directory.parent
        if parent == directory:
            break
        directory = parent

    return None


def load_policy(path: Path | str | None = None) -> PolicyConfig:
    """Load policy from file path, or return defaults if no file found."""
    if path is not None:
        path = Path(path)
    else:
        path = find_policy_file()

    if path is None or not path.is_file():
        return PolicyConfig()

    with open(path) as f:
        data = yaml.safe_load(f)

    if not data or not isinstance(data, dict):
        return PolicyConfig()

    return PolicyConfig(**data)
