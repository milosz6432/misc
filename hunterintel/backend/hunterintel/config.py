"""Typed application settings, loaded from environment variables / ``.env``.

Design notes
------------
* Every secret is a ``SecretStr`` so it can never leak through ``repr()``,
  logging of the settings object, or accidental serialisation.
* Provider API keys use their conventional names (``VIRUSTOTAL_API_KEY`` …) and
  also accept the ``HUNTERINTEL_`` prefixed spelling.
* Everything has a safe default so the application starts with **no** configuration.
"""

from __future__ import annotations

import json
from functools import lru_cache
from typing import Annotated, Literal

from pydantic import AliasChoices, Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

SharingTier = Literal["local", "public", "third_party"]


def _csv(value: object) -> object:
    """Accept either a JSON list or a comma-separated string from the environment."""
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.startswith("["):
            return json.loads(stripped)
        return [item.strip() for item in stripped.split(",") if item.strip()]
    return value


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="HUNTERINTEL_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    # ── application ────────────────────────────────────────────────────────
    app_name: str = "HunterIntel"
    environment: Literal["development", "production", "test"] = "development"
    database_url: str = "sqlite+aiosqlite:///./hunterintel.db"
    auto_create_schema: bool = Field(
        default=True,
        description="Create tables on start-up (SQLite dev convenience). "
        "Production should run `alembic upgrade head` and set this to false.",
    )
    redis_url: str | None = None
    api_token: SecretStr | None = Field(
        default=None,
        description="If set, every /api/v1 request must send 'Authorization: Bearer <token>'.",
    )
    cors_origins: Annotated[list[str], NoDecode] = ["http://localhost:5173"]
    inbound_rate_limit_per_minute: int = Field(default=240, ge=1)
    max_upload_bytes: int = Field(default=25 * 1024 * 1024, ge=1024)

    # ── outbound HTTP ──────────────────────────────────────────────────────
    http_timeout_seconds: float = Field(default=12.0, gt=0, le=120)
    http_connect_timeout_seconds: float = Field(default=5.0, gt=0, le=60)
    max_response_bytes: int = Field(default=2 * 1024 * 1024, ge=1024)
    user_agent: str = "HunterIntel/0.1 (+https://github.com/; OSINT research tool)"
    global_outbound_per_second: int = Field(default=20, ge=1)
    provider_rate_limits: Annotated[dict[str, str], NoDecode] = Field(
        default_factory=dict,
        description='Override per-provider limits, e.g. "virustotal=4/60,crtsh=1/3" '
        "(requests/seconds).",
    )
    cache_ttl_seconds: int = Field(default=900, ge=0)

    # ── DNS ────────────────────────────────────────────────────────────────
    dns_resolvers: Annotated[list[str], NoDecode] = ["1.1.1.1", "9.9.9.9"]
    dns_timeout_seconds: float = Field(default=4.0, gt=0, le=30)

    # ── privacy / active behaviour ─────────────────────────────────────────
    default_sharing: SharingTier = Field(
        default="public",
        description="Highest provider tier pre-selected in a query plan. "
        "'public' = keyless public sources; 'third_party' = also keyed vendors.",
    )
    allow_active_probes: bool = Field(
        default=False,
        description="Enable the opt-in redirect-chain probe (one bounded request per hop).",
    )
    probe_max_hops: int = Field(default=8, ge=1, le=20)
    probe_allowed_ports: Annotated[list[int], NoDecode] = [80, 443, 8080, 8443]
    geoip_db_path: str | None = None

    # ── bounded fan-out ────────────────────────────────────────────────────
    max_discovered_domains: int = Field(default=40, ge=1, le=500)
    max_certificates: int = Field(default=100, ge=1, le=1000)
    max_graph_nodes: int = Field(default=250, ge=10, le=2000)

    # ── provider credentials ───────────────────────────────────────────────
    virustotal_api_key: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("VIRUSTOTAL_API_KEY", "HUNTERINTEL_VIRUSTOTAL_API_KEY"),
    )
    abuseipdb_api_key: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("ABUSEIPDB_API_KEY", "HUNTERINTEL_ABUSEIPDB_API_KEY"),
    )
    otx_api_key: SecretStr | None = Field(
        default=None, validation_alias=AliasChoices("OTX_API_KEY", "HUNTERINTEL_OTX_API_KEY")
    )
    abusech_auth_key: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("ABUSECH_AUTH_KEY", "HUNTERINTEL_ABUSECH_AUTH_KEY"),
    )

    # ── validators ─────────────────────────────────────────────────────────
    @field_validator("cors_origins", "dns_resolvers", mode="before")
    @classmethod
    def _split_csv(cls, value: object) -> object:
        return _csv(value)

    @field_validator("probe_allowed_ports", mode="before")
    @classmethod
    def _split_ports(cls, value: object) -> object:
        value = _csv(value)
        if isinstance(value, list):
            return [int(v) for v in value]
        return value

    @field_validator("provider_rate_limits", mode="before")
    @classmethod
    def _parse_limits(cls, value: object) -> object:
        if isinstance(value, str):
            out: dict[str, str] = {}
            for part in value.split(","):
                if "=" in part:
                    name, spec = part.split("=", 1)
                    out[name.strip().lower()] = spec.strip()
            return out
        return value

    @field_validator(
        "api_token",
        "virustotal_api_key",
        "abuseipdb_api_key",
        "otx_api_key",
        "abusech_auth_key",
        mode="after",
    )
    @classmethod
    def _blank_secret_is_none(cls, value: SecretStr | None) -> SecretStr | None:
        if value is not None and not value.get_secret_value().strip():
            return None
        return value

    # ── helpers ────────────────────────────────────────────────────────────
    def secret_values(self) -> list[str]:
        """All configured secret strings (used for redaction, never logged)."""
        secrets = [
            self.api_token,
            self.virustotal_api_key,
            self.abuseipdb_api_key,
            self.otx_api_key,
            self.abusech_auth_key,
        ]
        return [s.get_secret_value() for s in secrets if s is not None]


@lru_cache
def get_settings() -> Settings:
    return Settings()
