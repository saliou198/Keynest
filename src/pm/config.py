"""Simple config persistence for pwvault (token, preferences).

Stores data as JSON in ~/.pwvault/config.json.
"""

import json
import os
from pathlib import Path

CONFIG_DIR = Path.home() / ".pwvault"
CONFIG_FILE = CONFIG_DIR / "config.json"


def _ensure_dir() -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)


def _read_config() -> dict:
    if not CONFIG_FILE.exists():
        return {}
    return json.loads(CONFIG_FILE.read_text())


def _write_config(data: dict) -> None:
    _ensure_dir()
    CONFIG_FILE.write_text(json.dumps(data, indent=2))


def save_github_token(access_token: str) -> None:
    """Persist the GitHub access token."""
    cfg = _read_config()
    cfg["github_token"] = access_token
    _write_config(cfg)


def get_github_token() -> str | None:
    """Return the stored GitHub token, or None."""
    return _read_config().get("github_token")


def save_github_repo(owner: str, repo: str) -> None:
    """Persist the GitHub repository target."""
    cfg = _read_config()
    cfg["github_owner"] = owner
    cfg["github_repo"] = repo
    _write_config(cfg)


def get_github_repo() -> tuple[str, str] | None:
    """Return (owner, repo) or None if not configured."""
    cfg = _read_config()
    owner = cfg.get("github_owner")
    repo = cfg.get("github_repo")
    if owner and repo:
        return owner, repo
    return None
