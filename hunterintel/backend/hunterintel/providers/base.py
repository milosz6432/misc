"""The provider adapter interface.

A provider is a small class: declare *what* it supports and *how far an indicator travels*
when it runs, then implement :meth:`Provider.lookup`. Everything else — policy checks,
persistence, scoring, rate limiting, error mapping — is handled outside, so a new source
never touches the orchestrator, the database or the UI.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, ClassVar

from hunterintel.config import Settings
from hunterintel.core.http import HttpGateway, HttpResponse
from hunterintel.core.ratelimit import RateLimiter, RateSpec
from hunterintel.domain.evidence import ProviderResult, RunStatus, Tier
from hunterintel.domain.indicators import IndicatorType, ParsedIndicator

if TYPE_CHECKING:
    from hunterintel.providers.dnsclient import DnsClient


@dataclass
class ProviderContext:
    settings: Settings
    http: HttpGateway
    dns: DnsClient
    limiter: RateLimiter
    refresh: bool = False  # bypass response caches
    #: free-form per-run scratch space (e.g. memoised RDAP bootstrap documents)
    state: dict[str, object] = field(default_factory=dict)


class Provider(ABC):
    name: ClassVar[str]
    display_name: ClassVar[str]
    description: ClassVar[str]
    tier: ClassVar[Tier]
    supported_types: ClassVar[frozenset[IndicatorType]]
    homepage: ClassVar[str] = ""
    terms_url: ClassVar[str] = ""
    #: environment variable that enables this provider (None = no credentials needed)
    key_env: ClassVar[str | None] = None
    #: static trust in this source's maliciousness signals, 0..1 (used by scoring)
    reliability: ClassVar[float] = 0.5
    default_rate: ClassVar[RateSpec | None] = None
    #: hosts this provider may contact (enforced by the HTTP gateway); None = not HTTP-based
    allowed_hosts: ClassVar[tuple[str, ...]] = ()

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    # -- capability -------------------------------------------------------

    def is_configured(self) -> bool:
        return True

    def not_configured_reason(self) -> str:
        return f"{self.display_name} is not configured."

    def can_handle(self, parsed: ParsedIndicator) -> bool:
        return parsed.type in self.supported_types

    def rate(self) -> RateSpec | None:
        override = self.settings.provider_rate_limits.get(self.name)
        return RateSpec.parse(override) if override else self.default_rate

    # -- transparency -----------------------------------------------------

    def data_shared(self, parsed: ParsedIndicator) -> str:
        """Plain-language statement of what leaves this host. Shown in the query plan."""
        if self.tier is Tier.LOCAL:
            return "Nothing — processed entirely on this host."
        hosts = ", ".join(self.allowed_hosts) or "its service"
        return f"The {parsed.type.value} '{parsed.value}' is sent to {hosts}."

    def info(self) -> dict[str, object]:
        """Public metadata. Never includes credentials — only whether one is configured."""
        return {
            "name": self.name,
            "display_name": self.display_name,
            "description": self.description,
            "tier": self.tier.value,
            "supported_types": sorted(t.value for t in self.supported_types),
            "requires_key": self.key_env is not None,
            "key_env": self.key_env,
            "configured": self.is_configured(),
            "homepage": self.homepage,
            "terms_url": self.terms_url,
            "reliability": self.reliability,
            "rate_limit": (
                None
                if self.rate() is None
                else {"requests": self.rate().requests, "per_seconds": self.rate().per_seconds}  # type: ignore[union-attr]
            ),
        }

    # -- the one method a provider author implements -----------------------

    @abstractmethod
    async def lookup(self, parsed: ParsedIndicator, ctx: ProviderContext) -> ProviderResult: ...


class ProviderRegistry:
    def __init__(self, providers: list[Provider]) -> None:
        names = [p.name for p in providers]
        if len(set(names)) != len(names):
            raise ValueError("duplicate provider names")
        self._providers = {p.name: p for p in providers}

    def get(self, name: str) -> Provider | None:
        return self._providers.get(name)

    def all(self) -> list[Provider]:
        return list(self._providers.values())

    def names(self) -> list[str]:
        return list(self._providers)

    def for_indicator(self, parsed: ParsedIndicator) -> list[Provider]:
        return [p for p in self._providers.values() if p.can_handle(parsed)]


AsyncLookup = Callable[[ProviderContext], Awaitable[ProviderResult]]


def map_http_status(
    provider: str, response: HttpResponse, *, not_found_ok: bool = True
) -> ProviderResult | None:
    """Translate a non-success HTTP status into an honest :class:`ProviderResult`.

    Returns ``None`` for 2xx so the caller can carry on parsing. A 404 means "the source has
    nothing" (``no_data``) — which is deliberately *not* the same as "clean".
    """
    code = response.status_code
    if 200 <= code < 300:
        return None
    if code == 404 and not_found_ok:
        return ProviderResult.no_data(f"{provider} has no record for this indicator.")
    if code == 429:
        retry = response.headers.get("retry-after")
        hint = f" Retry after {retry}s." if retry and retry.isdigit() else ""
        return ProviderResult.unavailable(
            RunStatus.RATE_LIMITED, f"{provider} rate limit reached.{hint}"
        )
    if code in (401, 403):
        return ProviderResult.unavailable(
            RunStatus.ERROR,
            f"{provider} rejected the credentials or the request (HTTP {code}). "
            "Check the API key and that your plan allows this endpoint.",
        )
    if 300 <= code < 400:
        return ProviderResult.unavailable(
            RunStatus.ERROR, f"{provider} returned an unexpected redirect (HTTP {code})."
        )
    return ProviderResult.unavailable(RunStatus.ERROR, f"{provider} returned HTTP {code}.")
