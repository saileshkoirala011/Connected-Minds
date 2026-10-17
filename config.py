"""
config.py — Application settings loaded from environment / .env file.

All env variables are read once at import time. Import `settings` everywhere:

    from config import settings
    print(settings.falkordb_host)

Never call os.getenv() directly outside this module.
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

# Load .env from the project root (no-op if not present; env vars override)
load_dotenv(Path(__file__).parent / ".env")


class _Settings:
    """
    Typed container for all environment-driven settings.

    Reads from environment variables with documented defaults.
    """

    # ── FalkorDB ──────────────────────────────────────────────────────────
    @property
    def falkordb_host(self) -> str:
        return os.getenv("FALKORDB_HOST", "localhost")

    @property
    def falkordb_port(self) -> int:
        return int(os.getenv("FALKORDB_PORT", "6379"))

    @property
    def falkordb_username(self) -> str:
        return os.getenv("FALKORDB_USERNAME", "")

    @property
    def falkordb_password(self) -> str:
        return os.getenv("FALKORDB_PASSWORD", "")

    @property
    def falkordb_ssl(self) -> bool:
        return os.getenv("FALKORDB_SSL", "false").lower() == "true"

    @property
    def falkordb_graph(self) -> str:
        return os.getenv("FALKORDB_GRAPH", "graphsentinel")

    # ── LLM (Anthropic) ───────────────────────────────────────────────────
    @property
    def anthropic_api_key(self) -> str:
        return os.getenv("ANTHROPIC_API_KEY", "")

    @property
    def anthropic_model(self) -> str:
        return os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-5")

    # ── Agent behaviour ───────────────────────────────────────────────────
    @property
    def agent_max_tool_calls(self) -> int:
        """Maximum tool calls per question (rules.md §5)."""
        return int(os.getenv("AGENT_MAX_TOOL_CALLS", "8"))

    @property
    def agent_tool_max_rows(self) -> int:
        """Maximum rows any single tool may return."""
        return int(os.getenv("AGENT_TOOL_MAX_ROWS", "100"))

    # ── Ingest ────────────────────────────────────────────────────────────
    @property
    def ingest_repo_size_mb(self) -> int:
        """Max repo size in MB before rejecting the clone."""
        return int(os.getenv("INGEST_REPO_SIZE_MB", "50"))

    @property
    def ingest_file_cap(self) -> int:
        """Max number of .py files to parse per repo."""
        return int(os.getenv("INGEST_FILE_CAP", "3000"))

    @property
    def ingest_timeout_seconds(self) -> int:
        """Total ingest time limit in seconds."""
        return int(os.getenv("INGEST_TIMEOUT_SECONDS", "120"))

    @property
    def data_dir(self) -> str:
        """Directory for temporary repo clones (gitignored)."""
        return os.getenv("DATA_DIR", "data")

    # ── OSV API ───────────────────────────────────────────────────────────
    @property
    def osv_timeout_seconds(self) -> int:
        return int(os.getenv("OSV_TIMEOUT_SECONDS", "15"))

    @property
    def osv_max_retries(self) -> int:
        return int(os.getenv("OSV_MAX_RETRIES", "3"))

    # ── App / UI ──────────────────────────────────────────────────────────
    @property
    def app_password(self) -> str:
        """Optional demo gate password; no gate if empty."""
        return os.getenv("APP_PASSWORD", "")

    @property
    def app_env(self) -> str:
        return os.getenv("APP_ENV", "development")

    # ── Convenience ───────────────────────────────────────────────────────
    def is_production(self) -> bool:
        return self.app_env == "production"

    def llm_configured(self) -> bool:
        """True if an Anthropic API key is available."""
        return bool(self.anthropic_api_key)

    def falkordb_url(self) -> str:
        """Human-readable connection string for logging (no password)."""
        return f"falkordb://{self.falkordb_host}:{self.falkordb_port}/{self.falkordb_graph}"


settings = _Settings()
