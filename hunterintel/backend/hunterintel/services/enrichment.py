"""Enrichment orchestrator: plan → run providers → persist → score.

The *plan* is the privacy contract. It states, per provider, whether it will run, why it
will not, and in plain words what data leaves this host. Nothing contacts a third party
unless it appears in a plan the analyst (or an explicit API call) selected.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from hunterintel.config import Settings
from hunterintel.core.http import (
    BlockedDestinationError,
    FetchTimeoutError,
    GatewayError,
    HttpGateway,
    ResponseTooLargeError,
)
from hunterintel.core.ratelimit import RateLimitedError, RateLimiter
from hunterintel.core.redact import redact
from hunterintel.domain.evidence import TIER_RANK, ProviderResult, RunStatus, Tier, utcnow
from hunterintel.domain.indicators import ParsedIndicator
from hunterintel.providers.base import Provider, ProviderContext, ProviderRegistry
from hunterintel.providers.dnsclient import DnsClient
from hunterintel.services import store

log = logging.getLogger(__name__)

PROVIDER_DEADLINE_SECONDS = 60.0


class PlanState(StrEnum):
    AVAILABLE = "available"
    BLOCKED = "blocked"  # policy forbids it for this indicator
    NOT_CONFIGURED = "not_configured"


@dataclass
class PlanEntry:
    provider: str
    display_name: str
    tier: str
    state: PlanState
    selected_by_default: bool
    reason: str | None
    data_shared: str
    description: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "display_name": self.display_name,
            "tier": self.tier,
            "state": self.state.value,
            "selected_by_default": self.selected_by_default,
            "reason": self.reason,
            "data_shared": self.data_shared,
            "description": self.description,
        }


@dataclass
class RunSummary:
    provider: str
    status: str
    message: str | None
    duration_ms: int
    observations: int
    truncated: bool = False

    def as_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


@dataclass
class EnrichmentOutcome:
    indicator_id: int
    runs: list[RunSummary] = field(default_factory=list)
    new_observations: int = 0
    edges: int = 0
    assessment: dict[str, Any] = field(default_factory=dict)


def map_exception(exc: BaseException, secrets: list[str]) -> ProviderResult:
    """Every failure mode becomes an explicit, redacted provider status — never silence."""
    if isinstance(exc, RateLimitedError):
        return ProviderResult.unavailable(RunStatus.RATE_LIMITED, redact(str(exc), secrets))
    if isinstance(exc, FetchTimeoutError | TimeoutError):
        return ProviderResult.unavailable(
            RunStatus.TIMEOUT, redact(str(exc) or "timed out", secrets)
        )
    if isinstance(exc, BlockedDestinationError):
        return ProviderResult.unavailable(RunStatus.BLOCKED, redact(str(exc), secrets))
    if isinstance(exc, ResponseTooLargeError):
        return ProviderResult.unavailable(
            RunStatus.ERROR, redact(f"{exc}. The query is too broad for this source.", secrets)
        )
    if isinstance(exc, GatewayError):
        return ProviderResult.unavailable(RunStatus.ERROR, redact(str(exc), secrets))
    return ProviderResult.unavailable(
        RunStatus.ERROR, f"Unexpected internal error ({type(exc).__name__}); see server logs."
    )


class EnrichmentService:
    def __init__(
        self,
        settings: Settings,
        registry: ProviderRegistry,
        http: HttpGateway,
        dns: DnsClient,
        limiter: RateLimiter,
    ) -> None:
        self.settings = settings
        self.registry = registry
        self._http = http
        self._dns = dns
        self._limiter = limiter

    # -- planning ---------------------------------------------------------

    def plan(self, parsed: ParsedIndicator, *, do_not_share: bool = False) -> list[PlanEntry]:
        default_rank = TIER_RANK[Tier(self.settings.default_sharing)]
        entries: list[PlanEntry] = []
        for p in self.registry.for_indicator(parsed):
            state, reason = PlanState.AVAILABLE, None
            if not p.is_configured():
                state, reason = PlanState.NOT_CONFIGURED, p.not_configured_reason()
            elif p.tier is not Tier.LOCAL and not parsed.remote_lookup_allowed:
                state, reason = PlanState.BLOCKED, parsed.blocked_reason
            elif p.tier is not Tier.LOCAL and do_not_share:
                state, reason = (
                    PlanState.BLOCKED,
                    "This indicator is marked do-not-share; only local analysis is permitted.",
                )
            default = (
                state is PlanState.AVAILABLE
                and p.tier is not Tier.ACTIVE
                and TIER_RANK[p.tier] <= default_rank
            )
            entries.append(
                PlanEntry(
                    provider=p.name,
                    display_name=p.display_name,
                    tier=p.tier.value,
                    state=state,
                    selected_by_default=default,
                    reason=reason,
                    data_shared=p.data_shared(parsed),
                    description=p.description,
                )
            )
        return entries

    # -- execution --------------------------------------------------------

    async def _run_provider(
        self, provider: Provider, parsed: ParsedIndicator, ctx: ProviderContext
    ) -> tuple[ProviderResult, int]:
        started = time.monotonic()
        try:
            async with asyncio.timeout(PROVIDER_DEADLINE_SECONDS):
                result = await provider.lookup(parsed, ctx)
        except Exception as exc:  # noqa: BLE001 - deliberately broad: one provider must not sink the rest
            if not isinstance(exc, GatewayError | RateLimitedError | TimeoutError):
                log.exception("provider %s crashed on %s", provider.name, parsed.key)
            result = map_exception(exc, self.settings.secret_values())
        # providers may echo upstream text; scrub before it is stored or shown
        if result.message:
            result.message = redact(result.message, self.settings.secret_values())
        return result, int((time.monotonic() - started) * 1000)

    async def enrich(
        self,
        session: AsyncSession,
        parsed: ParsedIndicator,
        *,
        providers: list[str] | None = None,
        refresh: bool = False,
        tracked: bool = True,
    ) -> EnrichmentOutcome:
        now = utcnow()
        indicator = await store.get_or_create_indicator(session, parsed, tracked=tracked, now=now)
        plan = {e.provider: e for e in self.plan(parsed, do_not_share=indicator.do_not_share)}

        if providers is None:
            wanted = [name for name, e in plan.items() if e.selected_by_default]
        else:
            unknown = [n for n in providers if self.registry.get(n) is None]
            if unknown:
                raise ValueError(f"unknown provider(s): {', '.join(unknown)}")
            wanted = list(dict.fromkeys(providers))
        if "local" in plan and "local" not in wanted:
            wanted.insert(0, "local")  # zero egress, always worth having

        ctx = ProviderContext(
            settings=self.settings,
            http=self._http,
            dns=self._dns,
            limiter=self._limiter,
            refresh=refresh,
        )
        to_run: list[Provider] = []
        outcome = EnrichmentOutcome(indicator_id=indicator.id)
        for name in wanted:
            provider = self.registry.get(name)
            entry = plan.get(name)
            if provider is None or entry is None:
                # requested but does not support this indicator type
                result = ProviderResult.unavailable(
                    RunStatus.BLOCKED, f"{name} does not support {parsed.type.value} indicators."
                )
            elif entry.state is PlanState.AVAILABLE:
                to_run.append(provider)
                continue
            else:
                status = (
                    RunStatus.NOT_CONFIGURED
                    if entry.state is PlanState.NOT_CONFIGURED
                    else RunStatus.BLOCKED
                )
                result = ProviderResult.unavailable(status, entry.reason or "not permitted")
            await store.persist_result(
                session, indicator, name, result, started_at=now, duration_ms=0, now=now
            )
            outcome.runs.append(RunSummary(name, result.status.value, result.message, 0, 0))

        started_at = utcnow()
        results = await asyncio.gather(*(self._run_provider(p, parsed, ctx) for p in to_run))
        for provider, (result, ms) in zip(to_run, results, strict=True):
            stats = await store.persist_result(
                session,
                indicator,
                provider.name,
                result,
                started_at=started_at,
                duration_ms=ms,
                now=utcnow(),
            )
            outcome.new_observations += stats["new_observations"]
            outcome.edges += stats["edges"]
            outcome.runs.append(
                RunSummary(
                    provider.name,
                    result.status.value,
                    result.message,
                    ms,
                    len(result.observations),
                    result.truncated,
                )
            )

        assessment = await store.refresh_cached_assessment(session, indicator, utcnow())
        outcome.assessment = assessment.as_dict()
        await session.commit()
        return outcome
