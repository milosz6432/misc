"""AbuseIPDB v2 ``/check`` — community abuse reports for an IP address."""

from __future__ import annotations

from hunterintel.core.ratelimit import RateSpec
from hunterintel.domain.evidence import (
    Assurance,
    ObservationDraft,
    ProviderResult,
    ReputationSignal,
    RunStatus,
    Tier,
)
from hunterintel.domain.indicators import IndicatorType, ParsedIndicator
from hunterintel.providers.base import Provider, ProviderContext, map_http_status
from hunterintel.providers.signals import clean_tags, reputation_observation

HOST = "api.abuseipdb.com"
WINDOW_DAYS = 90


class AbuseIPDBProvider(Provider):
    name = "abuseipdb"
    display_name = "AbuseIPDB"
    description = "Crowd-sourced abuse confidence score and report counts for an IP."
    tier = Tier.THIRD_PARTY
    supported_types = frozenset({IndicatorType.IP})
    homepage = "https://www.abuseipdb.com/"
    terms_url = "https://www.abuseipdb.com/terms"
    key_env = "ABUSEIPDB_API_KEY"
    reliability = 0.7
    default_rate = RateSpec(1000, 86400.0)  # free tier: 1,000 checks / day
    allowed_hosts = (HOST,)

    def is_configured(self) -> bool:
        return self.settings.abuseipdb_api_key is not None

    def not_configured_reason(self) -> str:
        return "No AbuseIPDB API key. Set ABUSEIPDB_API_KEY to enable."

    async def lookup(self, parsed: ParsedIndicator, ctx: ProviderContext) -> ProviderResult:
        assert self.settings.abuseipdb_api_key is not None
        resp = await ctx.http.request(
            "GET",
            f"https://{HOST}/api/v2/check",
            params={"ipAddress": parsed.value, "maxAgeInDays": WINDOW_DAYS},
            provider=self.name,
            rate=self.rate(),
            allowed_hosts=self.allowed_hosts,
            headers={
                "Key": self.settings.abuseipdb_api_key.get_secret_value(),
                "Accept": "application/json",
            },
            cache_ttl=ctx.settings.cache_ttl_seconds,
            refresh=ctx.refresh,
        )
        failure = map_http_status("AbuseIPDB", resp, not_found_ok=False)
        if failure is not None:
            return failure
        try:
            d = resp.json()["data"]
            score = int(d["abuseConfidenceScore"])
        except (ValueError, KeyError, TypeError):
            return ProviderResult.unavailable(
                RunStatus.ERROR, "AbuseIPDB returned an unexpected response shape."
            )

        reports = int(d.get("totalReports") or 0)
        whitelisted = bool(d.get("isWhitelisted"))
        if score >= 75:
            verdict = "malicious"
        elif score >= 25:
            verdict = "suspicious"
        elif whitelisted:
            verdict = "harmless"
        else:
            verdict = "unknown"
        definitive = verdict != "unknown"
        label = (
            f"Abuse confidence {score}% from {reports} report(s) by "
            f"{d.get('numDistinctUsers') or 0} user(s) in {WINDOW_DAYS} days"
        )
        if whitelisted:
            label += " — on AbuseIPDB's allow-list"
        signal = ReputationSignal(
            source=self.name,
            verdict=verdict,
            strength=score / 100 if not whitelisted else 0.0,
            reliability=self.reliability,
            label=label,
            definitive=definitive,
        )
        tags = ["tor-exit"] if d.get("isTor") else []
        if d.get("usageType"):
            tags.append(str(d["usageType"]))
        return ProviderResult.ok(
            observations=[
                reputation_observation(self.display_name, signal, window_days=WINDOW_DAYS),
                ObservationDraft(
                    kind="abuse.reports",
                    title="Abuse reports (AbuseIPDB)",
                    assurance=Assurance.PROVIDER_CLAIM,
                    data={
                        "abuse_confidence_score": score,
                        "total_reports": reports,
                        "distinct_reporters": d.get("numDistinctUsers"),
                        "last_reported_at": d.get("lastReportedAt"),
                        "window_days": WINDOW_DAYS,
                        "is_whitelisted": whitelisted,
                        "is_tor": d.get("isTor"),
                        "usage_type": d.get("usageType"),
                        "isp": d.get("isp"),
                        "domain": d.get("domain"),
                        "hostnames": (d.get("hostnames") or [])[:10],
                        "country_code": d.get("countryCode"),
                        "caveat": "A score of 0 means no reports, not a proven-benign address. "
                        "Country is a provider estimate.",
                        "link": f"https://www.abuseipdb.com/check/{parsed.value}",
                    },
                    summary=label,
                ),
            ],
            tags=clean_tags(tags),
        )
