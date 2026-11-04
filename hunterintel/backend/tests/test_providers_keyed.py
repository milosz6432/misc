"""Keyed providers.

The payloads below are *test fixtures shaped like each vendor's documented response*. They
exist to prove parsing, scoring inputs and safety properties; they are not intelligence data
and no live vendor call was made (see README → Verification status).
"""

from __future__ import annotations

import base64
from collections.abc import Callable
from urllib.parse import parse_qs

import httpx
import pytest

from hunterintel.config import Settings
from hunterintel.domain.evidence import Assurance, RunStatus
from hunterintel.domain.indicators import parse_indicator
from hunterintel.providers.abusech import MalwareBazaarProvider, URLhausProvider
from hunterintel.providers.abuseipdb import AbuseIPDBProvider
from hunterintel.providers.otx import OTXProvider
from hunterintel.providers.registry import build_registry
from hunterintel.providers.virustotal import VirusTotalProvider, signal_from_stats, vt_url_id
from tests.helpers import json_response, make_ctx

KEY = "k3y-0123456789abcdef"
SHA256 = "a" * 64
MD5 = "b" * 32
SHA1 = "c" * 40


@pytest.fixture
def keyed(make_settings: Callable[..., Settings]) -> Settings:
    return make_settings(
        virustotal_api_key=KEY,
        abuseipdb_api_key=KEY,
        otx_api_key=KEY,
        abusech_auth_key=KEY,
    )


class Recorder:
    """Captures every request so safety properties can be asserted across providers."""

    def __init__(self, responder: Callable[[httpx.Request], httpx.Response]) -> None:
        self.requests: list[httpx.Request] = []
        self.responder = responder

    def __call__(self, req: httpx.Request) -> httpx.Response:
        self.requests.append(req)
        return self.responder(req)


def lookup(provider, raw, ctx, forced=None):  # noqa: ANN001, ANN201
    return provider.lookup(parse_indicator(raw, forced), ctx)


# ── configuration & secrecy ──────────────────────────────────────────────────


def test_providers_unconfigured_without_keys(settings: Settings) -> None:
    for p in build_registry(settings).all():
        if p.key_env and p.name != "geoip_local":
            assert not p.is_configured(), p.name
            assert (
                p.key_env in p.not_configured_reason() or "key" in p.not_configured_reason().lower()
            )


def test_provider_info_never_leaks_key_material(keyed: Settings) -> None:
    blob = repr([p.info() for p in build_registry(keyed).all()])
    assert KEY not in blob
    assert all(
        p.info()["configured"]
        for p in build_registry(keyed).all()
        if p.key_env and p.name != "geoip_local"
    )


# ── VirusTotal ───────────────────────────────────────────────────────────────

VT_FILE = {
    "data": {
        "id": SHA256,
        "type": "file",
        "attributes": {
            "last_analysis_stats": {
                "malicious": 14,
                "suspicious": 2,
                "harmless": 0,
                "undetected": 55,
                "timeout": 1,
            },
            "last_analysis_date": 1730000000,
            "reputation": -20,
            "tags": ["peexe", "Trojan"],
            "type_description": "Win32 EXE",
            "type_tag": "peexe",
            "size": 40960,
            "meaningful_name": "setup.exe",
            "names": ["setup.exe"],
            "md5": MD5,
            "sha1": SHA1,
            "sha256": SHA256,
            "popular_threat_classification": {
                "suggested_threat_label": "trojan.example/family",
                "popular_threat_name": [{"value": "example", "count": 9}],
                "popular_threat_category": [{"value": "trojan", "count": 12}],
            },
        },
    }
}


def test_vt_signal_scaling_and_verdicts() -> None:
    clean = signal_from_stats(
        {"harmless": 60, "undetected": 10, "malicious": 0, "suspicious": 0}, 0.85
    )
    assert (clean.verdict, clean.strength, clean.definitive) == ("harmless", 0.0, True)
    few = signal_from_stats({"malicious": 1, "undetected": 70}, 0.85)
    assert few.verdict == "suspicious" and 0.2 < few.strength < 0.3
    many = signal_from_stats({"malicious": 12, "suspicious": 0, "undetected": 60}, 0.85)
    assert many.verdict == "malicious" and many.strength > 0.9
    empty = signal_from_stats({}, 0.85)
    assert (empty.verdict, empty.definitive) == (
        "unknown",
        False,
    )  # absence of analysis is not "clean"
    thin = signal_from_stats({"undetected": 3}, 0.85)
    assert thin.verdict == "unknown" and not thin.definitive  # too few engines to call it harmless


def test_vt_url_id_is_unpadded_urlsafe_base64() -> None:
    url = "https://example.com/a?b=c"
    ident = vt_url_id(url)
    assert (
        "=" not in ident
        and base64.urlsafe_b64decode(ident + "=" * (-len(ident) % 4)).decode() == url
    )


async def test_vt_hash_lookup_is_a_read_only_get_with_key_in_header_only(keyed: Settings) -> None:
    rec = Recorder(lambda r: json_response(VT_FILE))
    res = await lookup(VirusTotalProvider(keyed), SHA256, make_ctx(keyed, rec))
    req = rec.requests[0]
    assert req.method == "GET" and not req.content  # nothing is ever uploaded
    assert req.url.host == "www.virustotal.com" and req.url.path == f"/api/v3/files/{SHA256}"
    assert req.headers["x-apikey"] == KEY and KEY not in str(req.url)
    kinds = {o.kind: o for o in res.observations}
    assert kinds["reputation"].assurance is Assurance.PROVIDER_CLAIM
    assert kinds["reputation"].data["signal"]["verdict"] == "malicious"
    assert kinds["file.info"].data["file_type"] == "Win32 EXE"
    assert {r.dst_value for r in res.relationships} == {MD5, SHA1}  # same_file_as aliases
    assert {"trojan", "peexe", "example"} <= set(res.tags)


async def test_vt_url_lookup_uses_identifier_not_submission(keyed: Settings) -> None:
    rec = Recorder(lambda r: httpx.Response(404, json={"error": {"code": "NotFoundError"}}))
    res = await lookup(VirusTotalProvider(keyed), "https://example.com/x", make_ctx(keyed, rec))
    req = rec.requests[0]
    assert (
        req.method == "GET" and req.url.path == f"/api/v3/urls/{vt_url_id('https://example.com/x')}"
    )
    assert res.status is RunStatus.NO_DATA and "not a clean verdict" in (res.message or "")


async def test_vt_domain_and_ip_shapes(keyed: Settings) -> None:
    dom = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 70,
                    "undetected": 5,
                },
                "categories": {"VendorA": "business"},
                "registrar": "Example Registrar",
                "last_dns_records": [
                    {"type": "A", "value": "198.51.100.7", "ttl": 60},
                    {"type": "NS", "value": "ns.example.net"},
                ],
            }
        }
    }
    res = await lookup(
        VirusTotalProvider(keyed), "example.com", make_ctx(keyed, lambda r: json_response(dom))
    )
    rep = next(o for o in res.observations if o.kind == "reputation")
    assert rep.data["signal"]["verdict"] == "harmless"
    assert [(r.rel_type, r.dst_value, r.assurance) for r in res.relationships] == [
        ("resolves_to", "198.51.100.7", Assurance.PROVIDER_CLAIM)
    ]
    ip = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 0, "harmless": 80},
                "asn": 64500,
                "as_owner": "EXAMPLE-AS",
                "country": "US",
                "network": "198.51.100.0/24",
            }
        }
    }
    res = await lookup(
        VirusTotalProvider(keyed), "8.8.8.8", make_ctx(keyed, lambda r: json_response(ip))
    )
    assert any(r.dst_value == "AS64500" for r in res.relationships)
    asn_obs = next(o for o in res.observations if o.kind == "network.asn")
    assert "not a physical location" in asn_obs.data["caveat"]


@pytest.mark.parametrize(
    ("code", "status"),
    [(429, RunStatus.RATE_LIMITED), (401, RunStatus.ERROR), (503, RunStatus.ERROR)],
)
async def test_vt_http_failures_map_to_honest_statuses(
    keyed: Settings, code: int, status: RunStatus
) -> None:
    res = await lookup(
        VirusTotalProvider(keyed), "example.com", make_ctx(keyed, lambda r: httpx.Response(code))
    )
    assert res.status is status and not res.observations


async def test_vt_garbage_response_is_error_not_clean(keyed: Settings) -> None:
    res = await lookup(
        VirusTotalProvider(keyed),
        "example.com",
        make_ctx(keyed, lambda r: httpx.Response(200, text="<html>")),
    )
    assert res.status is RunStatus.ERROR


# ── AbuseIPDB ────────────────────────────────────────────────────────────────


def abuse(score: int, reports: int = 5, whitelisted: bool = False, tor: bool = False) -> dict:
    return {
        "data": {
            "ipAddress": "203.0.113.9",
            "isPublic": True,
            "ipVersion": 4,
            "isWhitelisted": whitelisted,
            "abuseConfidenceScore": score,
            "countryCode": "NL",
            "usageType": "Data Center/Web Hosting/Transit",
            "isp": "Example Hosting",
            "domain": "example-host.net",
            "hostnames": [],
            "isTor": tor,
            "totalReports": reports,
            "numDistinctUsers": 3,
            "lastReportedAt": "2026-10-30T12:00:00+00:00",
        }
    }


@pytest.mark.parametrize(
    ("score", "reports", "whitelisted", "verdict", "definitive"),
    [
        (97, 120, False, "malicious", True),
        (40, 3, False, "suspicious", True),
        (0, 0, False, "unknown", False),
        (5, 2, False, "unknown", False),
        (0, 4, True, "harmless", True),
    ],
)
async def test_abuseipdb_verdict_mapping(
    keyed: Settings, score: int, reports: int, whitelisted: bool, verdict: str, definitive: bool
) -> None:
    rec = Recorder(lambda r: json_response(abuse(score, reports, whitelisted)))
    res = await lookup(AbuseIPDBProvider(keyed), "1.2.3.4", make_ctx(keyed, rec))
    sig = res.observations[0].data["signal"]
    assert (sig["verdict"], sig["definitive"]) == (verdict, definitive)
    req = rec.requests[0]
    assert req.url.path == "/api/v2/check" and dict(req.url.params) == {
        "ipAddress": "1.2.3.4",
        "maxAgeInDays": "90",
    }
    assert req.headers["key"] == KEY and KEY not in str(req.url)
    assert "not a proven-benign" in res.observations[1].data["caveat"]


async def test_abuseipdb_tor_tag_and_rate_limit(keyed: Settings) -> None:
    res = await lookup(
        AbuseIPDBProvider(keyed),
        "1.2.3.4",
        make_ctx(keyed, lambda r: json_response(abuse(80, tor=True))),
    )
    assert "tor-exit" in res.tags
    res = await lookup(
        AbuseIPDBProvider(keyed),
        "1.2.3.4",
        make_ctx(keyed, lambda r: httpx.Response(429, headers={"retry-after": "3600"})),
    )
    assert res.status is RunStatus.RATE_LIMITED and "3600" in (res.message or "")


# ── OTX ──────────────────────────────────────────────────────────────────────


def otx_doc(n: int) -> dict:
    return {
        "indicator": "example.net",
        "pulse_info": {
            "count": n,
            "pulses": [
                {
                    "id": f"p{i}",
                    "name": f"Pulse {i}",
                    "created": "2026-01-01T00:00:00",
                    "modified": f"2026-02-{i + 1:02d}T00:00:00",
                    "author_name": "analyst1",
                    "TLP": "white",
                    "tags": ["phishing", "kit"],
                    "adversary": "ExampleGroup",
                    "malware_families": [{"display_name": "ExampleLoader"}],
                    "attack_ids": [{"id": "T1566", "name": "Phishing"}],
                }
                for i in range(min(n, 20))
            ],
        },
    }


async def test_otx_never_calls_anything_malicious_on_pulses_alone(keyed: Settings) -> None:
    rec = Recorder(lambda r: json_response(otx_doc(60)))
    res = await lookup(OTXProvider(keyed), "www.example.net", make_ctx(keyed, rec))
    sig = res.observations[0].data["signal"]
    assert sig["verdict"] == "suspicious" and sig["strength"] > 0.9 and sig["reliability"] < 0.5
    assert "context, not proof" in sig["label"]
    req = rec.requests[0]
    assert (
        req.url.path == "/api/v1/indicators/hostname/www.example.net/general"
        and req.headers["x-otx-api-key"] == KEY
    )
    pulses = next(o for o in res.observations if o.kind == "otx.pulses")
    assert pulses.data["attack_ids"] == {"T1566": "Phishing"} and pulses.data[
        "malware_families"
    ] == ["ExampleLoader"]
    assert {"phishing", "examplegroup", "exampleloader"} <= set(res.tags) and res.truncated


async def test_otx_section_names_and_no_pulses(keyed: Settings) -> None:
    rec = Recorder(lambda r: json_response(otx_doc(0)))
    for raw, section in [
        ("example.net", "domain"),
        ("203.0.113.9", "IPv4"),
        ("2001:4860:4860::8888", "IPv6"),
        (SHA256, "file"),
    ]:
        res = await lookup(OTXProvider(keyed), raw, make_ctx(keyed, rec))
        assert f"/indicators/{section}/" in rec.requests[-1].url.path
        assert res.status is RunStatus.NO_DATA and "not evidence of safety" in (res.message or "")
    await lookup(OTXProvider(keyed), "https://example.net/a?b=1", make_ctx(keyed, rec))
    assert (
        "/indicators/url/https%3A%2F%2Fexample.net%2Fa%3Fb%3D1/general"
        in rec.requests[-1].url.raw_path.decode()
    )


# ── abuse.ch ─────────────────────────────────────────────────────────────────

URLHAUS_URL = {
    "query_status": "ok",
    "id": "1",
    "url": "http://203.0.113.50/bin/a.exe",
    "url_status": "online",
    "host": "203.0.113.50",
    "date_added": "2026-10-01 10:00:00 UTC",
    "threat": "malware_download",
    "tags": ["elf", "Mozi"],
    "blacklists": {"spamhaus_dbl": "not listed"},
    "urlhaus_reference": "https://urlhaus.abuse.ch/url/1/",
    "payloads": [
        {
            "firstseen": "2026-10-01",
            "filename": "a.exe",
            "file_type": "exe",
            "response_sha256": SHA256,
            "response_md5": MD5,
            "signature": "ExampleLoader",
        }
    ],
}


async def test_urlhaus_url_listing(keyed: Settings) -> None:
    rec = Recorder(lambda r: json_response(URLHAUS_URL))
    res = await lookup(
        URLhausProvider(keyed), "http://203.0.113.50/bin/a.exe", make_ctx(keyed, rec), None
    )
    req = rec.requests[0]
    assert req.method == "POST" and req.url.path == "/v1/url/" and req.headers["auth-key"] == KEY
    assert req.headers["content-type"].startswith("application/x-www-form-urlencoded")
    assert parse_qs(req.content.decode()) == {"url": ["http://203.0.113.50/bin/a.exe"]}
    sig = res.observations[0].data["signal"]
    assert sig["verdict"] == "malicious" and sig["strength"] == 0.95 and sig["reliability"] == 0.9
    assert [(r.rel_type, r.dst_value) for r in res.relationships] == [("distributes", SHA256)]
    assert {"malware_download", "mozi", "exampleloader"} <= set(res.tags)


async def test_urlhaus_not_listed_is_no_data_never_clean(keyed: Settings) -> None:
    res = await lookup(
        URLhausProvider(keyed),
        "example.com",
        make_ctx(keyed, lambda r: json_response({"query_status": "no_results"})),
    )
    assert res.status is RunStatus.NO_DATA and "not a clean verdict" in (res.message or "")


async def test_urlhaus_host_and_payload_requests(keyed: Settings) -> None:
    rec = Recorder(
        lambda r: json_response(
            {
                "query_status": "ok",
                "url_count": "2",
                "firstseen": "2026-01-01",
                "urls": [
                    {
                        "url": "http://bad.example.net/x.sh",
                        "url_status": "online",
                        "threat": "malware_download",
                        "tags": ["sh"],
                    },
                    {"url": "http://bad.example.net/y.sh", "url_status": "offline"},
                ],
            }
        )
    )
    res = await lookup(URLhausProvider(keyed), "bad.example.net", make_ctx(keyed, rec))
    assert rec.requests[0].url.path == "/v1/host/" and parse_qs(
        rec.requests[0].content.decode()
    ) == {"host": ["bad.example.net"]}
    assert res.observations[0].data["signal"]["strength"] == 0.9 and len(res.relationships) == 2

    rec2 = Recorder(
        lambda r: json_response(
            {
                "query_status": "ok",
                "sha256_hash": SHA256,
                "md5_hash": MD5,
                "file_type": "elf",
                "signature": "Mozi",
                "url_count": "1",
                "urls": [{"url": "http://bad.example.net/x.sh", "url_status": "online"}],
            }
        )
    )
    res = await lookup(URLhausProvider(keyed), SHA256, make_ctx(keyed, rec2))
    assert rec2.requests[0].url.path == "/v1/payload/" and "sha256_hash" in parse_qs(
        rec2.requests[0].content.decode()
    )
    assert res.relationships[0].rel_type == "downloaded_from"


def test_urlhaus_does_not_claim_sha1_support(keyed: Settings) -> None:
    p = URLhausProvider(keyed)
    assert p.can_handle(parse_indicator(MD5)) and p.can_handle(parse_indicator(SHA256))
    assert not p.can_handle(parse_indicator(SHA1))


MB_OK = {
    "query_status": "ok",
    "data": [
        {
            "sha256_hash": SHA256,
            "sha1_hash": SHA1,
            "md5_hash": MD5,
            "first_seen": "2026-09-01 08:00:00",
            "last_seen": None,
            "file_name": "invoice.exe",
            "file_size": 123456,
            "file_type": "exe",
            "file_type_mime": "application/x-dosexec",
            "signature": "ExampleLoader",
            "tags": ["exe", "loader"],
            "delivery_method": "email_attachment",
            "origin_country": "DE",
            "intelligence": {"clamav": ["Win.Trojan.Example-1"], "downloads": "50", "uploads": "3"},
            "imphash": "d" * 32,
        }
    ],
}


async def test_malwarebazaar_hit(keyed: Settings) -> None:
    rec = Recorder(lambda r: json_response(MB_OK))
    res = await lookup(MalwareBazaarProvider(keyed), MD5, make_ctx(keyed, rec))
    req = rec.requests[0]
    assert (
        req.method == "POST"
        and req.url.host == "mb-api.abuse.ch"
        and req.headers["auth-key"] == KEY
    )
    assert parse_qs(req.content.decode()) == {
        "query": ["get_info"],
        "hash": [MD5],
    }  # a hash string only — no file bytes
    info = next(o for o in res.observations if o.kind == "file.info")
    assert info.data["file_type"] == "exe" and info.data["mime_type"] == "application/x-dosexec"
    assert info.data["signature"] == "ExampleLoader"
    assert {r.dst_value for r in res.relationships} == {SHA1, SHA256}
    assert "exampleloader" in res.tags and "email_attachment" in res.tags


async def test_malwarebazaar_not_found_and_errors(keyed: Settings) -> None:
    res = await lookup(
        MalwareBazaarProvider(keyed),
        MD5,
        make_ctx(keyed, lambda r: json_response({"query_status": "hash_not_found"})),
    )
    assert res.status is RunStatus.NO_DATA
    res = await lookup(
        MalwareBazaarProvider(keyed),
        MD5,
        make_ctx(keyed, lambda r: json_response({"query_status": "illegal_hash"})),
    )
    assert res.status is RunStatus.ERROR
    res = await lookup(
        MalwareBazaarProvider(keyed), MD5, make_ctx(keyed, lambda r: httpx.Response(401))
    )
    assert res.status is RunStatus.ERROR and "credentials" in (res.message or "")


# ── cross-provider safety property ───────────────────────────────────────────


async def test_no_provider_ever_sends_file_content_or_multipart(keyed: Settings) -> None:
    """Every outbound body is empty or a tiny urlencoded identifier form; never multipart/binary."""
    rec = Recorder(
        lambda r: json_response(
            {"query_status": "no_results", "data": {"attributes": {}}, "pulse_info": {"count": 0}}
        )
    )
    ctx = make_ctx(keyed, rec)
    cases = [
        (VirusTotalProvider, SHA256),
        (VirusTotalProvider, "https://example.com/x"),
        (AbuseIPDBProvider, "1.2.3.4"),
        (OTXProvider, SHA256),
        (URLhausProvider, "http://example.com/x"),
        (MalwareBazaarProvider, SHA256),
    ]
    for cls, raw in cases:
        await lookup(cls(keyed), raw, ctx)
    assert len(rec.requests) == len(cases)
    for req in rec.requests:
        ctype = req.headers.get("content-type", "")
        assert "multipart" not in ctype and "octet-stream" not in ctype
        assert len(req.content) < 512
        if req.url.host == "www.virustotal.com":
            assert req.method == "GET"  # the only VT verbs used are read-only lookups
