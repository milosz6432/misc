from __future__ import annotations

import pytest

from hunterintel.config import Settings


def test_defaults_need_no_configuration() -> None:
    s = Settings(_env_file=None)
    assert s.virustotal_api_key is None and s.api_token is None
    assert s.default_sharing == "public"
    assert s.allow_active_probes is False  # active behaviour is opt-in
    assert s.secret_values() == []


def test_provider_keys_use_conventional_env_names_and_never_appear_in_repr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-secret-value-0001")
    monkeypatch.setenv("ABUSECH_AUTH_KEY", "ab-secret-value-0002")
    monkeypatch.setenv("HUNTERINTEL_API_TOKEN", "tok-secret-value-0003")
    s = Settings(_env_file=None)
    assert s.virustotal_api_key is not None
    assert s.virustotal_api_key.get_secret_value() == "vt-secret-value-0001"
    assert sorted(s.secret_values()) == sorted(
        ["vt-secret-value-0001", "ab-secret-value-0002", "tok-secret-value-0003"]
    )
    rendered = repr(s) + str(s) + s.model_dump_json()
    for secret in s.secret_values():
        assert secret not in rendered


def test_blank_keys_are_treated_as_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OTX_API_KEY", "   ")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "")
    s = Settings(_env_file=None)
    assert s.otx_api_key is None and s.abuseipdb_api_key is None


def test_list_and_mapping_env_parsing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HUNTERINTEL_DNS_RESOLVERS", "9.9.9.9, 8.8.8.8")
    monkeypatch.setenv("HUNTERINTEL_CORS_ORIGINS", '["https://a.example","https://b.example"]')
    monkeypatch.setenv("HUNTERINTEL_PROBE_ALLOWED_PORTS", "80,443")
    monkeypatch.setenv("HUNTERINTEL_PROVIDER_RATE_LIMITS", "virustotal=4/60, CrtSh=1/3")
    s = Settings(_env_file=None)
    assert s.dns_resolvers == ["9.9.9.9", "8.8.8.8"]
    assert s.cors_origins == ["https://a.example", "https://b.example"]
    assert s.probe_allowed_ports == [80, 443]
    assert s.provider_rate_limits == {"virustotal": "4/60", "crtsh": "1/3"}
