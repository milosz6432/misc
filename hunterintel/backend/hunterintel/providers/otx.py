"""AlienVault OTX — community "pulse" membership for an indicator.

Pulses are analyst-curated collections and are noisy (benign infrastructure is routinely
mentioned in blog-style pulses). OTX can therefore raise a *suspicious* signal with modest
weight, but never a *malicious* verdict on its own.
"""

from __future__ import annotations

from collections import Counter
from typing import Any
from urllib.parse import quote

from hunterintel.core.ratelimit import RateSpec
from hunterintel.domain.evidence import (
    Assurance,
    ObservationDraft,
    ProviderResult,
    ReputationSignal,
    RunStatus,
    Tier,
)
from hunterintel.domain.indicators import IndicatorType, ParsedIndicator, registered_domain
from hunterintel.providers.base import Provider, ProviderContext, map_http_status
from hunterintel.providers.signals import clean_tags, half_life, reputation_observation

HOST = "otx.alienvault.com"


class OTXProvider(Provider):
    name = "otx"
    display_name = "AlienVault OTX"
    description = "Community threat pulses, adversaries, malware families and ATT&CK ids."
    tier = Tier.THIRD_PARTY
    supported_types = frozenset(
        {IndicatorType.DOMAIN, IndicatorType.IP, IndicatorType.URL, IndicatorType.HASH}
    )
    homepage = "https://otx.alienvault.com/"
    terms_url = "https://otx.alienvault.com/terms"
    key_env = "OTX_API_KEY"
    reliability = 0.45
    default_rate = RateSpec(10, 60.0)
    allowed_hosts = (HOST,)

    def is_configured(self) -> bool:
        return self.settings.otx_api_key is not None

    def not_configured_reason(self) -> str:
        return "No OTX API key. Set OTX_API_KEY to enable."

    @staticmethod
    def _section(parsed: ParsedIndicator) -> str:
        if parsed.type is IndicatorType.IP:
            return "IPv6" if parsed.subtype == "ipv6" else "IPv4"
        if parsed.type is IndicatorType.DOMAIN:
            return "domain" if registered_domain(parsed.value) == parsed.value else "hostname"
        if parsed.type is IndicatorType.URL:
            return "url"
        return "file"

    async def lookup(self, parsed: ParsedIndicator, ctx: ProviderContext) -> ProviderResult:
        assert self.settings.otx_api_key is not None
        path = f"/api/v1/indicators/{self._section(parsed)}/{quote(parsed.value, safe='')}/general"
        resp = await ctx.http.request(
            "GET",
            f"https://{HOST}{path}",
            provider=self.name,
            rate=self.rate(),
            allowed_hosts=self.allowed_hosts,
            headers={
                "X-OTX-API-KEY": self.settings.otx_api_key.get_secret_value(),
                "Accept": "application/json",
            },
            cache_ttl=ctx.settings.cache_ttl_seconds,
            refresh=ctx.refresh,
        )
        failure = map_http_status("AlienVault OTX", resp)
        if failure is not None:
            return failure
        try:
            doc = resp.json()
            info = doc.get("pulse_info") or {}
            count = int(info.get("count", 0))
        except (ValueError, TypeError, AttributeError):
            return ProviderResult.unavailable(
                RunStatus.ERROR, "OTX returned an unexpected response shape."
            )
        if count == 0:
            return ProviderResult.no_data(
                "No OTX pulse references this indicator (absence from OTX is not evidence of safety)."
            )

        pulses: list[dict[str, Any]] = sorted(
            info.get("pulses", []), key=lambda p: str(p.get("modified", "")), reverse=True
        )
        signal = ReputationSignal(
            source=self.name,
            verdict="suspicious",
            strength=round(half_life(count, 4.0), 3),
            reliability=self.reliability,
            label=f"Referenced in {count} community pulse(s) — context, not proof",
        )
        tag_counter: Counter[str] = Counter()
        adversaries: set[str] = set()
        families: set[str] = set()
        attack: dict[str, str] = {}
        slim: list[dict[str, Any]] = []
        for p in pulses[:25]:
            tag_counter.update(str(t).lower() for t in p.get("tags", []))
            if p.get("adversary"):
                adversaries.add(str(p["adversary"]))
            for fam in p.get("malware_families", []):
                name = fam.get("display_name") if isinstance(fam, dict) else fam
                if name:
                    families.add(str(name))
            for tech in p.get("attack_ids", []):
                if isinstance(tech, dict) and tech.get("id"):
                    attack[str(tech["id"])] = str(
                        tech.get("name") or tech.get("display_name") or ""
                    )
            slim.append(
                {
                    "id": p.get("id"),
                    "name": p.get("name"),
                    "created": p.get("created"),
                    "modified": p.get("modified"),
                    "author": p.get("author_name"),
                    "tlp": p.get("TLP"),
                    "tags": (p.get("tags") or [])[:8],
                    "adversary": p.get("adversary") or None,
                    "malware_families": [
                        f.get("display_name") if isinstance(f, dict) else f
                        for f in p.get("malware_families", [])
                    ][:5],
                    "link": f"https://otx.alienvault.com/pulse/{p.get('id')}"
                    if p.get("id")
                    else None,
                }
            )
        tags = clean_tags(
            [*(t for t, _ in tag_counter.most_common(12)), *adversaries, *families], limit=25
        )
        return ProviderResult.ok(
            observations=[
                reputation_observation(self.display_name, signal, pulse_count=count),
                ObservationDraft(
                    kind="otx.pulses",
                    title="Community pulses (AlienVault OTX)",
                    assurance=Assurance.PROVIDER_CLAIM,
                    data={
                        "pulse_count": count,
                        "pulses": slim,
                        "adversaries": sorted(adversaries),
                        "malware_families": sorted(families),
                        "attack_ids": attack,
                        "validation": doc.get("validation"),
                        "false_positive": doc.get("false_positive"),
                        "caveat": "Pulses are community-contributed and may mention benign infrastructure.",
                    },
                    summary=f"{count} pulse(s)"
                    + (f"; families: {', '.join(sorted(families)[:3])}" if families else ""),
                ),
            ],
            tags=tags,
            truncated=count > len(slim),
        )
