"""Opt-in redirect-chain analysis.

This is the only provider that contacts a user-supplied destination, so it is disabled
unless ``HUNTERINTEL_ALLOW_ACTIVE_PROBES=true`` *and* the analyst explicitly selects it.
All the heavy lifting (SSRF guard, hop limits, no body reads) lives in
:meth:`HttpGateway.probe_redirects`; this adapter only reports and interprets.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from hunterintel.core.http import BlockedDestinationError
from hunterintel.domain.evidence import (
    Assurance,
    ObservationDraft,
    ProviderResult,
    RelationshipDraft,
    RiskFlag,
    RunStatus,
    Severity,
    Tier,
)
from hunterintel.domain.indicators import (
    IndicatorType,
    ParsedIndicator,
    registered_domain,
    try_parse,
)
from hunterintel.providers.base import Provider, ProviderContext


class ProbeProvider(Provider):
    name = "probe"
    display_name = "Redirect-chain probe (active)"
    description = (
        "Follows redirects hop-by-hop with HEAD/GET requests and reads headers only. "
        "Contacts the target directly — disabled by default."
    )
    tier = Tier.ACTIVE
    supported_types = frozenset({IndicatorType.URL})
    reliability = 0.0

    def is_configured(self) -> bool:
        return self.settings.allow_active_probes

    def not_configured_reason(self) -> str:
        return "Active probes are disabled. Set HUNTERINTEL_ALLOW_ACTIVE_PROBES=true to enable this opt-in feature."

    def data_shared(self, parsed: ParsedIndicator) -> str:
        return (
            f"HunterIntel itself connects to '{parsed.value}' and each redirect target "
            f"(public addresses only, max {self.settings.probe_max_hops} hops, headers only). "
            "The destination will see this server's IP address."
        )

    async def lookup(self, parsed: ParsedIndicator, ctx: ProviderContext) -> ProviderResult:
        try:
            result = await ctx.http.probe_redirects(parsed.value)
        except BlockedDestinationError as exc:
            return ProviderResult.unavailable(RunStatus.BLOCKED, str(exc))

        hops = [
            {
                "url": h.url,
                "status": h.status_code,
                "method": h.method,
                "location": h.location,
                "remote_ip": h.remote_ip,
                "content_type": h.content_type,
                "server": h.server,
                "elapsed_ms": h.elapsed_ms,
            }
            for h in result.hops
        ]
        if not hops:
            return ProviderResult.unavailable(
                RunStatus.BLOCKED
                if (result.stopped_reason or "").startswith("blocked")
                else RunStatus.ERROR,
                result.stopped_reason or "No connection could be made.",
            )

        flags: list[RiskFlag] = []
        first, last = urlsplit(hops[0]["url"]), urlsplit(hops[-1]["url"])
        start_reg = registered_domain(first.hostname or "") or first.hostname
        end_reg = registered_domain(last.hostname or "") or last.hostname
        if result.completed and start_reg != end_reg:
            flags.append(
                RiskFlag(
                    id="cross_domain_redirect",
                    severity=Severity.LOW,
                    title="Redirect crosses to a different registrable domain",
                    detail=f"{start_reg} → {end_reg}. Common for ads, link shorteners and phishing hand-offs.",
                )
            )
        if len(hops) >= 4:
            flags.append(
                RiskFlag(
                    id="long_redirect_chain",
                    severity=Severity.LOW,
                    title=f"{len(hops)} hops in redirect chain",
                    detail="Long chains are used to launder traffic through intermediaries.",
                )
            )
        if first.scheme == "https" and last.scheme == "http":
            flags.append(
                RiskFlag(
                    id="https_downgrade",
                    severity=Severity.MEDIUM,
                    title="Redirect downgrades HTTPS to HTTP",
                    detail="The chain ends on an unencrypted URL.",
                )
            )

        rels: list[RelationshipDraft] = []
        for a, b in zip(result.hops, result.hops[1:], strict=False):
            src, dst = try_parse(a.url, IndicatorType.URL), try_parse(b.url, IndicatorType.URL)
            if src and dst and src.value != dst.value:
                rels.append(
                    RelationshipDraft(
                        src_type=IndicatorType.URL,
                        src_value=src.value,
                        dst_type=IndicatorType.URL,
                        dst_value=dst.value,
                        rel_type="redirects_to",
                        assurance=Assurance.VERIFIED,
                        attrs={"status": a.status_code, "basis": "observed HTTP redirect"},
                    )
                )

        observations = [
            ObservationDraft(
                kind="probe.redirect_chain",
                title="Redirect chain (live)",
                assurance=Assurance.VERIFIED,
                data={
                    "hops": hops,
                    "completed": result.completed,
                    "final_url": result.final_url,
                    "stopped_reason": result.stopped_reason,
                    "method_note": "HEAD first (GET with Range 0-0 if HEAD is refused); bodies are never read.",
                },
                summary=(
                    f"{len(hops)} hop(s) → {hops[-1]['status']}"
                    + (f" — stopped: {result.stopped_reason}" if result.stopped_reason else "")
                ),
            )
        ]
        if flags:
            observations.append(
                ObservationDraft(
                    kind="risk_flags",
                    title="Redirect heuristics",
                    assurance=Assurance.INFERRED,
                    data={
                        "flags": [f.model_dump(mode="json") for f in flags],
                        "basis": "observed redirect chain",
                    },
                    summary=flags[0].title,
                )
            )
        return ProviderResult.ok(observations=observations, relationships=rels)
