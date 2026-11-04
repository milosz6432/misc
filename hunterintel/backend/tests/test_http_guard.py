"""SSRF guard tests — exercised against real sockets on 127.0.0.1 where it matters."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Callable

import httpx
import pytest

from hunterintel.core.cache import MemoryCache
from hunterintel.core.http import (
    BlockedDestinationError,
    GuardedBackend,
    GuardedTransport,
    HttpGateway,
    validate_url_for_fetch,
)
from hunterintel.core.ratelimit import MemoryRateLimiter


def fixed_resolver(mapping: dict[str, list[str]]) -> Callable[[str, int], object]:
    async def resolve(host: str, port: int) -> list[str]:
        return mapping.get(host, [])

    return resolve  # type: ignore[return-value]


# ── static URL validation ────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "url",
    [
        "ftp://example.com/",
        "file:///etc/passwd",
        "gopher://example.com/",
        "http://user:pass@example.com/",
        "http://localhost/",
        "http://127.0.0.1/",
        "http://127.1/",
        "http://2130706433/",
        "http://0x7f000001/",
        "http://0177.0.0.1/",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/",
        "http://[::ffff:127.0.0.1]/",
        "http://10.0.0.5:80/",
        "http://metadata.google.internal/",
        "http://printer.local/",
        "http://example.com:22/",
        "http://example.com:6379/",
        "http:///nohost",
    ],
)
def test_static_validation_blocks_dangerous_urls(url: str) -> None:
    with pytest.raises(BlockedDestinationError):
        validate_url_for_fetch(url)


@pytest.mark.parametrize(
    "url", ["http://example.com/", "https://example.com/a?b=c", "https://1.1.1.1/"]
)
def test_static_validation_allows_public_urls(url: str) -> None:
    assert validate_url_for_fetch(url).host


def test_allow_list_and_https_requirements() -> None:
    with pytest.raises(BlockedDestinationError, match="allow-list"):
        validate_url_for_fetch("https://evil.example.org/", allowed_hosts=["www.virustotal.com"])
    with pytest.raises(BlockedDestinationError, match="https"):
        validate_url_for_fetch("http://www.virustotal.com/", require_https=True)
    validate_url_for_fetch(
        "https://www.virustotal.com/", require_https=True, allowed_hosts=["www.virustotal.com"]
    )


# ── connect-time guard ───────────────────────────────────────────────────────


async def test_guard_blocks_host_resolving_to_private_address() -> None:
    backend = GuardedBackend(resolver=fixed_resolver({"evil.example.net": ["10.0.0.5"]}))
    async with httpx.AsyncClient(transport=GuardedTransport(backend)) as client:
        with pytest.raises(BlockedDestinationError, match="non-public"):
            await client.get("http://evil.example.net/")


async def test_guard_blocks_when_any_answer_is_private() -> None:
    """Round-robin answers mixing a public and an internal address must still be refused."""
    backend = GuardedBackend(
        resolver=fixed_resolver({"mixed.example.net": ["93.184.216.34", "127.0.0.1"]})
    )
    with pytest.raises(BlockedDestinationError):
        await backend.validated_addresses("mixed.example.net", 80)


@pytest.mark.parametrize(
    "literal", ["127.0.0.1", "169.254.169.254", "2130706433", "[::1]", "::ffff:10.0.0.1"]
)
async def test_guard_blocks_ip_literals_without_resolving(literal: str) -> None:
    called = False

    async def resolver(host: str, port: int) -> list[str]:
        nonlocal called
        called = True
        return []

    backend = GuardedBackend(resolver=resolver)
    with pytest.raises(BlockedDestinationError):
        await backend.validated_addresses(literal, 80)
    assert not called


async def test_guard_rejects_unix_sockets() -> None:
    with pytest.raises(BlockedDestinationError):
        await GuardedBackend().connect_unix_socket("/var/run/docker.sock")


@pytest.fixture
async def local_server() -> AsyncIterator[tuple[int, list[bytes]]]:
    """A tiny HTTP server on 127.0.0.1 that records the requests it receives."""
    received: list[bytes] = []

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        data = await reader.readuntil(b"\r\n\r\n")
        received.append(data)
        first = data.split(b"\r\n", 1)[0]
        if b"/redirect-private" in first:
            writer.write(
                b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/x\r\nContent-Length: 0\r\n\r\n"
            )
        elif b"/redirect-next" in first:
            writer.write(b"HTTP/1.1 301 Moved\r\nLocation: /final\r\nContent-Length: 0\r\n\r\n")
        else:
            body = b"hello"
            writer.write(
                b"HTTP/1.1 200 OK\r\nServer: test\r\nContent-Type: text/plain\r\n"
                b"Content-Length: 5\r\nConnection: close\r\n\r\n" + body
            )
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        yield port, received
    finally:
        server.close()
        await server.wait_closed()


async def test_connection_is_pinned_to_the_validated_address(
    local_server: tuple[int, list[bytes]],
) -> None:
    """DNS rebinding: first answer is 'safe', every later answer would be 10.0.0.1.

    The resolver must be consulted exactly once per connection and the socket must go to
    the address that was validated, never to a second resolution.
    """
    port, received = local_server
    answers = [["127.0.0.1"], ["10.0.0.1"], ["10.0.0.1"]]
    calls = 0

    async def rebinding_resolver(host: str, p: int) -> list[str]:
        nonlocal calls
        calls += 1
        return answers.pop(0)

    # Policy is relaxed ONLY so the test can reach its own loopback server.
    backend = GuardedBackend(resolver=rebinding_resolver, policy=lambda ip: True)
    async with httpx.AsyncClient(transport=GuardedTransport(backend)) as client:
        r = await client.get(f"http://rebind.example.net:{port}/", headers={"Connection": "close"})
    assert r.status_code == 200
    assert r.text == "hello"
    assert calls == 1
    assert b"Host: rebind.example.net" in received[0]  # virtual-host header keeps the name


# ── redirect probe ───────────────────────────────────────────────────────────


def probe_gateway(
    make_settings: Callable[..., object], port: int, resolver: object, policy: object
) -> HttpGateway:
    s = make_settings(allow_active_probes=True, probe_allowed_ports=[port], probe_max_hops=4)
    backend = GuardedBackend(resolver=resolver, policy=policy)  # type: ignore[arg-type]
    return HttpGateway(s, MemoryRateLimiter(), MemoryCache(), transport=GuardedTransport(backend))  # type: ignore[arg-type]


async def test_probe_follows_public_chain_and_never_reads_body(
    make_settings: Callable[..., object], local_server: tuple[int, list[bytes]]
) -> None:
    port, received = local_server
    gw = probe_gateway(
        make_settings, port, fixed_resolver({"chain.example.net": ["127.0.0.1"]}), lambda ip: True
    )
    try:
        result = await gw.probe_redirects(f"http://chain.example.net:{port}/redirect-next")
    finally:
        await gw.aclose()
    assert result.completed
    assert [h.status_code for h in result.hops] == [301, 200]
    assert result.hops[0].method == "HEAD"
    assert result.final_url == f"http://chain.example.net:{port}/final"
    assert result.hops[-1].remote_ip == "127.0.0.1"
    assert all(b"Cookie" not in r and b"Authorization" not in r for r in received)


async def test_probe_refuses_redirect_into_private_space(
    make_settings: Callable[..., object], local_server: tuple[int, list[bytes]]
) -> None:
    port, _ = local_server
    gw = probe_gateway(
        make_settings, port, fixed_resolver({"start.example.net": ["127.0.0.1"]}), lambda ip: True
    )
    try:
        result = await gw.probe_redirects(f"http://start.example.net:{port}/redirect-private")
    finally:
        await gw.aclose()
    assert not result.completed
    assert result.stopped_reason is not None and "refused" in result.stopped_reason
    assert len(result.hops) == 1  # the private target was never contacted


async def test_probe_blocks_hostname_that_resolves_internal_with_default_policy(
    make_settings: Callable[..., object],
) -> None:
    gw = probe_gateway(
        make_settings,
        80,
        fixed_resolver({"sneaky.example.net": ["192.168.0.10"]}),
        None
        or (lambda ip: __import__("hunterintel.core.netpolicy", fromlist=["x"]).is_public_ip(ip)),
    )
    try:
        result = await gw.probe_redirects("http://sneaky.example.net/")
    finally:
        await gw.aclose()
    assert not result.completed
    assert result.stopped_reason and result.stopped_reason.startswith("blocked")
    assert result.hops == []


async def test_probe_rejects_bad_start_url_immediately(
    make_settings: Callable[..., object],
) -> None:
    gw = probe_gateway(make_settings, 80, fixed_resolver({}), lambda ip: False)
    try:
        with pytest.raises(BlockedDestinationError):
            await gw.probe_redirects("http://169.254.169.254/latest/meta-data/")
    finally:
        await gw.aclose()


async def test_resolver_failure_is_a_clean_upstream_error_not_an_internal_one(
    make_settings: Callable[..., object],
) -> None:
    """Regression: found by running the real server where DNS was unavailable."""
    import socket

    from hunterintel.core.http import UpstreamError

    async def failing(host: str, port: int) -> list[str]:
        raise socket.gaierror(-2, "Name or service not known")

    s = make_settings()
    gw = HttpGateway(
        s,
        MemoryRateLimiter(),
        MemoryCache(),
        transport=GuardedTransport(GuardedBackend(resolver=failing)),
    )
    try:
        with pytest.raises(UpstreamError, match="cannot resolve"):
            await gw.request("GET", "https://crt.sh/", provider="crtsh", allowed_hosts=["crt.sh"])
    finally:
        await gw.aclose()
