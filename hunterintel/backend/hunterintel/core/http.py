"""The single egress point for every outbound HTTP request made by HunterIntel.

Layers of defence (outermost first)
-----------------------------------
1. **URL policy** — https only for providers, host allow-list per provider, no
   credentials in URLs, bounded redirects with per-hop re-validation, secret-bearing
   headers stripped on any cross-host redirect.
2. **Connect-time SSRF guard** (:class:`GuardedBackend`) — the hostname is resolved
   *once*, *every* returned address must be public, and the TCP connection is made
   to that validated literal IP. Because we never re-resolve, DNS-rebinding cannot swap
   a public answer for ``127.0.0.1`` between "check" and "use". TLS SNI and
   certificate verification still use the original hostname.
3. **Resource limits** — connect/read timeouts, a total deadline, and a streamed read
   that aborts as soon as the byte budget is exceeded.
4. **Rate limiting** — global and per-provider sliding windows before any packet is sent.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import time
from collections.abc import Awaitable, Callable, Collection, Iterable, Mapping
from dataclasses import dataclass, field
from http.cookiejar import DefaultCookiePolicy
from typing import Any
from urllib.parse import urljoin

import httpcore
import httpx

from hunterintel.config import Settings
from hunterintel.core.cache import Cache
from hunterintel.core.netpolicy import (
    IPAddress,
    classify_ip,
    hostname_scope,
    is_public_ip,
    parse_ip,
)
from hunterintel.core.ratelimit import RateLimiter, RateSpec, wait_for_slot
from hunterintel.core.redact import redact

log = logging.getLogger(__name__)

# ── errors ───────────────────────────────────────────────────────────────────


class GatewayError(Exception):
    """Base class. ``code`` is a stable machine-readable reason."""

    code = "gateway_error"


class BlockedDestinationError(GatewayError):
    code = "blocked_destination"


class ResponseTooLargeError(GatewayError):
    code = "response_too_large"


class FetchTimeoutError(GatewayError):
    code = "timeout"


class UpstreamError(GatewayError):
    code = "upstream_error"


# ── connect-time SSRF guard ──────────────────────────────────────────────────

Resolver = Callable[[str, int], Awaitable[list[str]]]
IPPolicy = Callable[[IPAddress], bool]


async def system_resolver(host: str, port: int) -> list[str]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=1)  # SOCK_STREAM
    seen: list[str] = []
    for info in infos:
        ip = info[4][0]
        if ip not in seen:
            seen.append(ip)
    return seen


class GuardedBackend(httpcore.AsyncNetworkBackend):
    """httpcore network backend that only ever connects to validated public IPs."""

    def __init__(
        self,
        *,
        resolver: Resolver = system_resolver,
        policy: IPPolicy = is_public_ip,
        inner: httpcore.AsyncNetworkBackend | None = None,
    ) -> None:
        self._resolver = resolver
        self._policy = policy
        self._inner = inner or httpcore.AnyIOBackend()

    async def validated_addresses(self, host: str, port: int) -> list[str]:
        literal = parse_ip(host)
        if literal is not None:
            candidates = [str(literal)]
        else:
            try:
                candidates = await self._resolver(host, port)
            except OSError as exc:  # socket.gaierror & friends: an ordinary network failure
                raise httpcore.ConnectError(f"cannot resolve {host!r}: {exc}") from exc
        if not candidates:
            raise httpcore.ConnectError(f"no addresses found for {host!r}")
        for candidate in candidates:
            addr = parse_ip(candidate)
            if addr is None or not self._policy(addr):
                scope = classify_ip(addr).value if addr is not None else "unparseable"
                raise BlockedDestinationError(
                    f"{host!r} resolves to a non-public address ({candidate}, {scope}); "
                    "connection refused by SSRF policy"
                )
        return candidates

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        addresses = await self.validated_addresses(host, port)
        last_error: Exception | None = None
        for ip in addresses:  # all were validated; connect to the literal, never the name
            try:
                return await self._inner.connect_tcp(
                    ip,
                    port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                last_error = exc
        assert last_error is not None
        raise last_error

    async def connect_unix_socket(self, *args: Any, **kwargs: Any) -> httpcore.AsyncNetworkStream:
        raise BlockedDestinationError("unix sockets are not permitted")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


class GuardedTransport(httpx.AsyncHTTPTransport):
    """An httpx transport whose connection pool uses :class:`GuardedBackend`."""

    def __init__(self, backend: GuardedBackend | None = None) -> None:
        limits = httpx.Limits(max_connections=20, max_keepalive_connections=10, keepalive_expiry=15)
        super().__init__(trust_env=True, limits=limits, http2=False)
        # Replace the pool httpx built with one that dials through our guard.
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=httpx.create_ssl_context(trust_env=True),
            max_connections=limits.max_connections,
            max_keepalive_connections=limits.max_keepalive_connections,
            keepalive_expiry=limits.keepalive_expiry,
            http1=True,
            http2=False,
            retries=0,
            network_backend=backend or GuardedBackend(),
        )


# ── result types ─────────────────────────────────────────────────────────────


@dataclass
class HttpResponse:
    status_code: int
    headers: dict[str, str]
    body: bytes
    url: str
    from_cache: bool = False

    def json(self) -> Any:
        return json.loads(self.body)

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


@dataclass
class ProbeHop:
    url: str
    status_code: int
    method: str
    location: str | None = None
    remote_ip: str | None = None
    content_type: str | None = None
    server: str | None = None
    elapsed_ms: int = 0


@dataclass
class ProbeResult:
    start_url: str
    hops: list[ProbeHop] = field(default_factory=list)
    final_url: str | None = None
    completed: bool = False
    stopped_reason: str | None = None


_REDIRECT_CODES = {301, 302, 303, 307, 308}
_SENSITIVE_HEADERS = {"authorization", "key", "x-apikey", "x-otx-api-key", "auth-key", "cookie"}


def validate_url_for_fetch(
    url: str,
    *,
    allowed_ports: Collection[int] = (80, 443),
    require_https: bool = False,
    allowed_hosts: Collection[str] | None = None,
) -> httpx.URL:
    """Static (pre-connect) validation of a URL. Raises :class:`BlockedDestinationError`."""
    try:
        parsed = httpx.URL(url)
    except (httpx.InvalidURL, ValueError) as exc:
        raise BlockedDestinationError(f"invalid URL: {exc}") from exc
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise BlockedDestinationError(f"scheme {scheme!r} is not allowed (http/https only)")
    if require_https and scheme != "https":
        raise BlockedDestinationError("only https is permitted for this request")
    if parsed.userinfo:
        raise BlockedDestinationError("credentials embedded in URLs are not permitted")
    host = parsed.host
    if not host or len(host) > 253:
        raise BlockedDestinationError("missing or oversized hostname")
    port = parsed.port or (443 if scheme == "https" else 80)
    if port not in allowed_ports:
        raise BlockedDestinationError(f"port {port} is not in the allowed port list")
    if allowed_hosts is not None and host.lower() not in {h.lower() for h in allowed_hosts}:
        raise BlockedDestinationError(f"host {host!r} is not on this provider's allow-list")
    literal = parse_ip(host)
    if literal is not None:
        if not is_public_ip(literal):
            raise BlockedDestinationError(
                f"{host!r} is a {classify_ip(literal).value} address; lookups are refused"
            )
    else:
        reason = hostname_scope(host)
        if reason:
            raise BlockedDestinationError(f"{host!r} rejected: {reason}")
    return parsed


# ── gateway ──────────────────────────────────────────────────────────────────


class HttpGateway:
    def __init__(
        self,
        settings: Settings,
        limiter: RateLimiter,
        cache: Cache,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._settings = settings
        self._limiter = limiter
        self._cache = cache
        self._client = httpx.AsyncClient(
            transport=transport or GuardedTransport(),
            timeout=httpx.Timeout(
                settings.http_timeout_seconds, connect=settings.http_connect_timeout_seconds
            ),
            follow_redirects=False,
            trust_env=False,
            headers={"User-Agent": settings.user_agent, "Accept-Encoding": "identity"},
        )
        # httpx keeps a cookie jar by default. This gateway talks to untrusted destinations and
        # must be stateless: accept no cookies at all, so nothing set by one hop (or one
        # request) can ever be replayed on another.
        self._client.cookies.jar.set_policy(DefaultCookiePolicy(allowed_domains=[]))
        self._global_spec = RateSpec(settings.global_outbound_per_second, 1.0)

    async def aclose(self) -> None:
        await self._client.aclose()

    # -- provider API calls -------------------------------------------------

    async def request(
        self,
        method: str,
        url: str,
        *,
        provider: str,
        rate: RateSpec | None = None,
        allowed_hosts: Collection[str] | None = None,
        headers: Mapping[str, str] | None = None,
        params: Mapping[str, Any] | None = None,
        data: Mapping[str, Any] | None = None,
        max_bytes: int | None = None,
        max_redirects: int = 0,
        cache_ttl: int = 0,
        refresh: bool = False,
        timeout: float | None = None,
    ) -> HttpResponse:
        """Make a bounded, rate-limited, SSRF-guarded request on behalf of a provider.

        ``allowed_hosts=None`` means "any *public* https host" and is used only where the
        target is discovered from a trusted bootstrap (RDAP). Every redirect hop is
        re-validated.
        """
        method = method.upper()
        limit = max_bytes or self._settings.max_response_bytes
        secrets = self._settings.secret_values()
        cache_key = None
        if cache_ttl > 0 and not refresh:
            cache_key = self._cache_key(method, url, params, data)
            hit = await self._cache.get(cache_key)
            if hit is not None:
                cached = json.loads(hit)
                return HttpResponse(
                    cached["s"], cached["h"], base64.b64decode(cached["b"]), cached["u"], True
                )

        await wait_for_slot(self._limiter, "global", self._global_spec, max_wait=5.0)
        if rate is not None:
            await wait_for_slot(self._limiter, f"provider:{provider}", rate)

        current_url = httpx.URL(url)
        if params:
            current_url = current_url.copy_merge_params(params)
        current_method, current_data = method, dict(data) if data else None
        send_headers = dict(headers or {})
        origin_host = current_url.host
        deadline = (timeout or self._settings.http_timeout_seconds) * 1.5

        try:
            async with asyncio.timeout(deadline):
                for _hop in range(max_redirects + 1):
                    validate_url_for_fetch(
                        str(current_url),
                        require_https=True,
                        allowed_hosts=allowed_hosts,
                        allowed_ports=(443,),
                    )
                    started = time.monotonic()
                    response = await self._fetch(
                        current_method, current_url, send_headers, current_data, limit, timeout
                    )
                    log.info(
                        "outbound provider=%s host=%s status=%s ms=%d",
                        provider,
                        current_url.host,
                        response.status_code,
                        (time.monotonic() - started) * 1000,
                    )
                    location = response.headers.get("location")
                    if response.status_code in _REDIRECT_CODES and location:
                        if _hop >= max_redirects:
                            return response
                        current_url = httpx.URL(urljoin(str(current_url), location))
                        if response.status_code == 303 or (
                            response.status_code in (301, 302) and current_method == "POST"
                        ):
                            current_method, current_data = "GET", None
                        if current_url.host != origin_host:
                            send_headers = {
                                k: v
                                for k, v in send_headers.items()
                                if k.lower() not in _SENSITIVE_HEADERS
                            }
                        continue
                    if cache_key and response.status_code == 200:
                        await self._cache.set(
                            cache_key,
                            json.dumps(
                                {
                                    "s": response.status_code,
                                    "h": response.headers,
                                    "u": response.url,
                                    "b": base64.b64encode(response.body).decode(),
                                }
                            ).encode(),
                            cache_ttl,
                        )
                    return response
                raise UpstreamError("too many redirects")  # pragma: no cover
        except GatewayError:
            raise
        except TimeoutError as exc:
            raise FetchTimeoutError(
                f"{provider}: request exceeded {deadline:.0f}s deadline"
            ) from exc
        except httpx.TimeoutException as exc:
            raise FetchTimeoutError(f"{provider}: {type(exc).__name__}") from exc
        except httpx.HTTPError as exc:
            message = redact(f"{provider}: {type(exc).__name__}: {exc}", secrets)
            raise UpstreamError(message) from exc

    async def _fetch(
        self,
        method: str,
        url: httpx.URL,
        headers: Mapping[str, str],
        data: Mapping[str, Any] | None,
        limit: int,
        timeout: float | None,
    ) -> HttpResponse:
        async with self._client.stream(
            method,
            url,
            headers=headers,
            data=data,
            timeout=timeout if timeout is not None else httpx.USE_CLIENT_DEFAULT,
        ) as resp:
            # We ask for identity encoding. A server that compresses anyway could ship a
            # decompression bomb that expands inside a single chunk before we can count it.
            encoding = resp.headers.get("content-encoding", "identity").strip().lower()
            if encoding not in ("", "identity"):
                raise UpstreamError(f"unexpected content-encoding {encoding!r}; refusing to decode")
            declared = resp.headers.get("content-length")
            if declared and declared.isdigit() and int(declared) > limit:
                raise ResponseTooLargeError(f"declared size {declared} exceeds {limit} bytes")
            chunks: list[bytes] = []
            total = 0
            async for chunk in resp.aiter_bytes():
                total += len(chunk)
                if total > limit:
                    raise ResponseTooLargeError(f"response exceeded {limit} bytes")
                chunks.append(chunk)
            return HttpResponse(
                resp.status_code,
                {k.lower(): v for k, v in resp.headers.items()},
                b"".join(chunks),
                str(resp.url),
            )

    @staticmethod
    def _cache_key(method: str, url: str, params: Any, data: Any) -> str:
        blob = json.dumps([method, url, params, data], sort_keys=True, default=str)
        return "http:" + hashlib.sha256(blob.encode()).hexdigest()

    # -- active probe (user-supplied target) -------------------------------

    async def probe_redirects(self, url: str) -> ProbeResult:
        """Follow a redirect chain hop-by-hop **without ever reading a response body**.

        This is the only code path that contacts a user-supplied destination, so it is the
        most heavily restricted: static URL policy on every hop, connect-time IP guard,
        port allow-list, hop limit, total deadline, no cookies, no credentials.
        """
        s = self._settings
        result = ProbeResult(start_url=url)
        allowed_ports = tuple(s.probe_allowed_ports)
        current = validate_url_for_fetch(url, allowed_ports=allowed_ports)
        seen: set[str] = set()
        try:
            async with asyncio.timeout(s.http_timeout_seconds * (s.probe_max_hops + 1)):
                for _ in range(s.probe_max_hops + 1):
                    key = str(current)
                    if key in seen:
                        result.stopped_reason = "redirect loop detected"
                        return result
                    seen.add(key)
                    await wait_for_slot(self._limiter, "global", self._global_spec, max_wait=5.0)
                    await wait_for_slot(self._limiter, "probe", RateSpec(10, 10.0), max_wait=10.0)
                    hop = await self._probe_once(current)
                    result.hops.append(hop)
                    if hop.status_code in _REDIRECT_CODES and hop.location:
                        try:
                            current = validate_url_for_fetch(
                                urljoin(key, hop.location), allowed_ports=allowed_ports
                            )
                        except BlockedDestinationError as exc:
                            result.stopped_reason = f"redirect target refused: {exc}"
                            return result
                        continue
                    result.completed = True
                    result.final_url = key
                    return result
                result.stopped_reason = f"stopped after {s.probe_max_hops} redirects"
                return result
        except TimeoutError:
            result.stopped_reason = "total probe deadline exceeded"
            return result
        except BlockedDestinationError as exc:
            result.stopped_reason = f"blocked: {exc}"
            return result
        except httpx.TimeoutException:
            result.stopped_reason = "request timed out"
            return result
        except httpx.HTTPError as exc:
            result.stopped_reason = f"connection failed: {type(exc).__name__}"
            return result

    async def _probe_once(self, url: httpx.URL) -> ProbeHop:
        started = time.monotonic()
        method = "HEAD"
        for _attempt in range(2):
            extra = {"Accept": "*/*", "Range": "bytes=0-0"} if method == "GET" else {}
            # Leaving the block closes the socket; the response body is never consumed.
            async with self._client.stream(method, url, headers=extra) as resp:
                if method == "HEAD" and resp.status_code in (405, 501):
                    method = "GET"
                    continue
                stream = resp.extensions.get("network_stream")
                server_addr = stream.get_extra_info("server_addr") if stream else None
                return ProbeHop(
                    url=str(url),
                    status_code=resp.status_code,
                    method=method,
                    location=resp.headers.get("location"),
                    remote_ip=server_addr[0] if server_addr else None,
                    content_type=resp.headers.get("content-type"),
                    server=resp.headers.get("server"),
                    elapsed_ms=int((time.monotonic() - started) * 1000),
                )
        raise UpstreamError("probe: server rejected both HEAD and GET")  # pragma: no cover
