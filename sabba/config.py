"""User config for the interactive app: the chosen model and the OpenRouter key.

Stored at ~/.sabba/config.json with owner-only permissions, well outside any repo. The
key lives here and is pushed into the environment for get_provider() at runtime, so it is
never written into the source tree.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

HOME = Path(os.environ.get("SABBA_HOME", Path.home() / ".sabba"))
PATH = HOME / "config.json"


def load() -> dict:
    try:
        return json.loads(PATH.read_text())
    except (OSError, ValueError):
        return {}


def save(cfg: dict) -> None:
    HOME.mkdir(parents=True, exist_ok=True)
    PATH.write_text(json.dumps(cfg, indent=2))
    try:
        PATH.chmod(0o600)
    except OSError:
        pass


def apply_env(cfg: dict) -> None:
    """Put the saved backend, model, and key into the environment for get_provider()."""
    cfg = cfg or load()
    os.environ["SABBA_LLM_BACKEND"] = cfg.get("backend", "openrouter")
    if cfg.get("model"):
        os.environ["OPENROUTER_MODEL"] = cfg["model"]
        os.environ["SABBA_MODEL"] = cfg["model"]
    if cfg.get("local_model"):
        os.environ["SABBA_LOCAL_MODEL"] = cfg["local_model"]
    if cfg.get("local_base_url"):
        os.environ["SABBA_LOCAL_BASE_URL"] = cfg["local_base_url"]
    if cfg.get("api_key"):
        os.environ["OPENROUTER_API_KEY"] = cfg["api_key"]
    if cfg.get("voyage_key"):
        os.environ["VOYAGE_API_KEY"] = cfg["voyage_key"]
    if cfg.get("eth_rpc"):
        os.environ["SABBA_ETH_RPC"] = cfg["eth_rpc"]
    if cfg.get("jazzer_home"):
        os.environ["SABBA_JAZZER_HOME"] = cfg["jazzer_home"]
    if cfg.get("jazzerjs_home"):
        os.environ["SABBA_JAZZERJS_HOME"] = cfg["jazzerjs_home"]


def masked(key: str) -> str:
    if not key:
        return "not set"
    return key[:7] + "..." + key[-4:] if len(key) > 14 else "set"
