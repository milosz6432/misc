"""Gateway behaviour: allow-lists, limits, caching, redirects, rate limiting, secret hygiene."""

from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest

from hunterintel.core.http import (
    BlockedDestinationError,
    FetchTimeoutError,
    HttpGateway,
    ResponseTooLargeError,
    UpstreamError,
)
from hunterintel.core.ratelimit import RateLimitedError, RateSpec

HOST = "www.virustotal.com"
URL = f"https://{HOST}/api/v3/domains/example.com"


async def test_happy_path_returns_body_and_headers(
    gateway_factory: Callable[..., HttpGateway],
) -> None:
    gw = gateway_factory(
        lambda req: httpx.Response(200, json={"ok": True}, headers={"X-Thing": "1"})
    )
    r = await gw.request("GET", URL, provider="virustotal", allowed_hosts=[HOST])
    assert r.status_code == 200 and r.json() == {"ok": True} and r.headers["x-thing"] == "1"


async def test_user_agent_is_set_and_identity_encoding_requested(
    gateway_factory: Callable[..., HttpGateway],
) -> None:
    seen: dict[str, str] = {}

    def handler(req: httpx.Request) -> httpx.Response:
        seen.update(req.headers)
        return httpx.Response(200, json={})

    gw = gateway_factory(handler)
    await gw.request("GET", URL, provider="virustotal", allowed_hosts=[HOST])
    assert seen["user-agent"].startswith("HunterIntel/")
    assert seen["accept-encoding"] == "identity"  # no decompression bombs


async def test_rejects_plain_http_and_foreign_hosts(
    gateway_factory: Callable[..., HttpGateway],
) -> None:
    called = False

    def handler(req: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200)

    gw = gateway_factory(handler)
    with pytest.raises(BlockedDestinationError):
        await gw.request("GET", f"http://{HOST}/x", provider="virustotal", allowed_hosts=[HOST])
    with pytest.raises(BlockedDestinationError):
        await gw.request(
            "GET", "https://attacker.example.net/x", provider="virustotal", allowed_hosts=[HOST]
        )
    with pytest.raises(BlockedDestinationError):
        await gw.request("GET", "https://127.0.0.1/x", provider="virustotal")
    assert not called


async def test_response_size_cap_enforced_while_streaming(
    gateway_factory: Callable[..., HttpGateway],
) -> None:
    gw = gateway_factory(lambda req: httpx.Response(200, content=b"x" * 5000))
    with pytest.raises(ResponseTooLargeError):
        await gw.request("GET", URL, provider="p", allowed_hosts=[HOST], max_bytes=1000)
    ok = await gw.request("GET", URL, provider="p", allowed_hosts=[HOST], max_bytes=10_000)
    assert len(ok.body) == 5000


async def test_declared_content_length_rejected_before_download(
    gateway_factory: Callable[..., HttpGateway],
) -> None:
    gw = gateway_factory(
        lambda req: httpx.Response(200, content=b"x", headers={"content-length": "99999999"})
    )
    with pytest.raises((ResponseTooLargeError, UpstreamError)):
        await gw.request("GET", URL, provider="p", allowed_hosts=[HOST], max_bytes=1000)


async def test_timeouts_are_mapped(gateway_factory: Callable[..., HttpGateway]) -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=req)

    gw = gateway_factory(handler)
    with pytest.raises(FetchTimeoutError):
        await gw.request("GET", URL, provider="p", allowed_hosts=[HOST])


async def test_upstream_errors_never_echo_secrets(
    make_settings: Callable[..., object], gateway_factory: Callable[..., HttpGateway]
) -> None:
    s = make_settings(virustotal_api_key="SUPER-SECRET-KEY-123456")

    def handler(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom key=SUPER-SECRET-KEY-123456", request=req)

    gw = gateway_factory(handler, s)  # type: ignore[arg-type]
    with pytest.raises(UpstreamError) as err:
        await gw.request(
            "GET",
            URL,
            provider="p",
            allowed_hosts=[HOST],
            headers={"x-apikey": "SUPER-SECRET-KEY-123456"},
        )
    assert "SUPER-SECRET" not in str(err.value)


async def test_cache_prevents_duplicate_upstream_calls_and_refresh_bypasses(
    gateway_factory: Callable[..., HttpGateway],
) -> None:
    hits = 0

    def handler(req: httpx.Request) -> httpx.Response:
        nonlocal hits
        hits += 1
        return httpx.Response(200, json={"n": hits})

    gw = gateway_factory(handler)
    a = await gw.request("GET", URL, provider="p", allowed_hosts=[HOST], cache_ttl=60)
    b = await gw.request("GET", URL, provider="p", allowed_hosts=[HOST], cache_ttl=60)
    assert hits == 1 and b.from_cache and a.json() == b.json()
    c = await gw.request("GET", URL, provider="p", allowed_hosts=[HOST], cache_ttl=60, refresh=True)
    assert hits == 2 and not c.from_cache and c.json() == {"n": 2}


async def test_errors_are_not_cached(gateway_factory: Callable[..., HttpGateway]) -> None:
    hits = 0

    def handler(req: httpx.Request) -> httpx.Response:
        nonlocal hits
        hits += 1
        return httpx.Response(500)

    gw = gateway_factory(handler)
    await gw.request("GET", URL, provider="p", allowed_hosts=[HOST], cache_ttl=60)
    await gw.request("GET", URL, provider="p", allowed_hosts=[HOST], cache_ttl=60)
    assert hits == 2


async def test_redirects_not_followed_by_default(
    gateway_factory: Callable[..., HttpGateway],
) -> None:
    gw = gateway_factory(
        lambda req: httpx.Response(302, headers={"location": "https://other.example.net/"})
    )
    r = await gw.request("GET", URL, provider="p", allowed_hosts=[HOST])
    assert r.status_code == 302


async def test_redirects_revalidated_and_secrets_stripped_cross_host(
    gateway_factory: Callable[..., HttpGateway],
) -> None:
    seen: list[tuple[str, str | None]] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append((req.url.host, req.headers.get("x-apikey")))
        if req.url.host == "rdap.example.net":
            return httpx.Response(302, headers={"location": "https://rdap2.example.org/domain/x"})
        return httpx.Response(200, json={"done": True})

    gw = gateway_factory(handler)
    r = await gw.request(
        "GET",
        "https://rdap.example.net/domain/x",
        provider="rdap",
        headers={"x-apikey": "k"},
        max_redirects=3,
    )
    assert r.json() == {"done": True}
    assert seen == [("rdap.example.net", "k"), ("rdap2.example.org", None)]


async def test_redirect_to_private_target_is_blocked(
    gateway_factory: Callable[..., HttpGateway],
) -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(
            302, headers={"location": "https://169.254.169.254/latest/meta-data/"}
        )

    gw = gateway_factory(handler)
    with pytest.raises(BlockedDestinationError):
        await gw.request("GET", "https://rdap.example.net/x", provider="rdap", max_redirects=3)


async def test_provider_rate_limit_surfaces_as_error(
    gateway_factory: Callable[..., HttpGateway],
) -> None:
    gw = gateway_factory(lambda req: httpx.Response(200, json={}))
    spec = RateSpec(1, 3600)
    await gw.request("GET", URL, provider="slowvendor", allowed_hosts=[HOST], rate=spec)
    with pytest.raises(RateLimitedError):
        await gw.request("GET", URL, provider="slowvendor", allowed_hosts=[HOST], rate=spec)
