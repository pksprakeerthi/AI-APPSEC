"""Configuration loaded from environment variables. No secrets live in source code."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent
SAMPLE_DATA_PATH = PROJECT_ROOT / "data" / "sample_findings.json"

load_dotenv(PROJECT_ROOT / ".env")

APP_TITLE = "AI Application Security Risk Investigator"
APP_TAGLINE = "Connect the risks. Trace the evidence. Prioritize what matters."
DEFAULT_LLM_MODEL = "claude-sonnet-5-5"

_GRAPH_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")
_TRUE_VALUES = {"1", "true", "yes", "on"}
_FALSE_VALUES = {"0", "false", "no", "off", ""}


class ConfigError(ValueError):
    """Raised when an environment variable has an invalid value."""


@dataclass(frozen=True)
class FalkorSettings:
    host: str
    port: int
    username: Optional[str]
    password: Optional[str]
    ssl: bool
    graph_name: str


@dataclass(frozen=True)
class LLMSettings:
    api_key: Optional[str]
    model: str

    @property
    def enabled(self) -> bool:
        return bool(self.api_key)


def _env_optional(name: str) -> Optional[str]:
    value = os.getenv(name)
    if value is None:
        return None
    value = value.strip()
    return value or None


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    value = raw.strip().lower()
    if value in _TRUE_VALUES:
        return True
    if value in _FALSE_VALUES:
        return False
    raise ConfigError(f"{name} must be true or false, got {raw!r}.")


def load_falkor_settings() -> FalkorSettings:
    """Read and validate FalkorDB settings from the environment."""
    host = _env_optional("FALKORDB_HOST") or "localhost"
    port_raw = _env_optional("FALKORDB_PORT") or "6379"
    try:
        port = int(port_raw)
    except ValueError as exc:
        raise ConfigError(f"FALKORDB_PORT must be an integer, got {port_raw!r}.") from exc
    if not 1 <= port <= 65535:
        raise ConfigError(f"FALKORDB_PORT must be between 1 and 65535, got {port}.")

    graph_name = _env_optional("FALKORDB_GRAPH") or "appsec_investigator"
    if not _GRAPH_NAME_PATTERN.match(graph_name):
        raise ConfigError(
            "FALKORDB_GRAPH may only contain letters, digits, '_' and '-' (max 64 characters)."
        )

    return FalkorSettings(
        host=host,
        port=port,
        username=_env_optional("FALKORDB_USERNAME"),
        password=_env_optional("FALKORDB_PASSWORD"),
        ssl=_env_bool("FALKORDB_SSL", False),
        graph_name=graph_name,
    )


def load_llm_settings() -> LLMSettings:
    """Read optional LLM settings. The app works without them."""
    return LLMSettings(
        api_key=_env_optional("ANTHROPIC_API_KEY"),
        model=_env_optional("LLM_MODEL") or DEFAULT_LLM_MODEL,
    )
