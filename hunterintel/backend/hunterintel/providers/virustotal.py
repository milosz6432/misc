"""VirusTotal API v3 — *lookup only*.

We read existing analyses by identifier (domain / IP / URL id / file hash). We never call
the upload or URL-submission endpoints, so no file or URL is ever submitted for scanning.
"""

from __future__ import annotations

import base64
from typing import Any

from hunterintel.core.ratelimit import RateSpec
from hunterintel.domain.evidence import (
    Assurance,
    ObservationDraft,
    ProviderResult,
    RelationshipDraft,
    ReputationSignal,
    RunStatus,
    Tier,
)
from hunterintel.domain.indicators import IndicatorType, ParsedIndicator, try_parse
from hunterintel.providers.base import Provider, ProviderContext, map_http_status
from hunterintel.providers.signals import (
    clean_tags,
    epoch_iso,
    half_life,
    reputation_observation,
)

HOST = "www.virustotal.com"


def vt_url_id(url: str) -> str:
    """VirusTotal's URL identifier: unpadded URL-safe base64 of the URL."""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def signal_from_stats(stats: dict[str, Any] | None, reliability: float) -> ReputationSignal:
    stats = stats or {}
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    harmless = int(stats.get("harmless", 0) or 0)
    undetected = int(stats.get("undetected", 0) or 0)
    total = malicious + suspicious + harmless + undetected
    if total == 0:
        return ReputationSignal(
            source="virustotal",
            verdict="unknown",
            strength=0.0,
            reliability=reliability,
            label="VirusTotal has no completed analysis for this indicator",
            definitive=False,
        )
    detections = malicious + 0.5 * suspicious
    strength = half_life(detections, 3.0)
    if malicious >= 5:
        verdict = "malicious"
    elif malicious + suspicious >= 1:
        verdict = "suspicious"
    elif total >= 10:
        verdict = "harmless"
    else:
        verdict = "unknown"
    return ReputationSignal(
        source="virustotal",
        verdict=verdict,
        strength=round(strength, 3),
        reliability=reliability,
        label=f"{malicious} malicious / {suspicious} suspicious of {total} engines",
        definitive=verdict != "unknown",
    )


class VirusTotalProvider(Provider):
    name = "virustotal"
    display_name = "VirusTotal"
    description = "Multi-engine verdicts, categories and file metadata (read-only lookups)."
    tier = Tier.THIRD_PARTY
    supported_types = frozenset(
        {IndicatorType.DOMAIN, IndicatorType.IP, IndicatorType.URL, IndicatorType.HASH}
    )
    homepage = "https://www.virustotal.com/"
    terms_url = "https://docs.virustotal.com/docs/terms-of-service"
    key_env = "VIRUSTOTAL_API_KEY"
    reliability = 0.85
    default_rate = RateSpec(4, 60.0)  # public API quota
    allowed_hosts = (HOST,)

    def is_configured(self) -> bool:
        return self.settings.virustotal_api_key is not None

    def not_configured_reason(self) -> str:
        return "No VirusTotal API key. Set VIRUSTOTAL_API_KEY to enable."

    def data_shared(self, parsed: ParsedIndicator) -> str:
        what = "hash" if parsed.type is IndicatorType.HASH else parsed.type.value
        return (
            f"The {what} '{parsed.value}' is sent to {HOST} as a lookup. "
            "No file or URL is submitted for scanning."
        )

    def _path(self, parsed: ParsedIndicator) -> str:
        return {
            IndicatorType.DOMAIN: f"domains/{parsed.value}",
            IndicatorType.IP: f"ip_addresses/{parsed.value}",
            IndicatorType.URL: f"urls/{vt_url_id(parsed.value)}",
            IndicatorType.HASH: f"files/{parsed.value}",
        }[parsed.type]

    async def lookup(self, parsed: ParsedIndicator, ctx: ProviderContext) -> ProviderResult:
        assert self.settings.virustotal_api_key is not None
        resp = await ctx.http.request(
            "GET",
            f"https://{HOST}/api/v3/{self._path(parsed)}",
            provider=self.name,
            rate=self.rate(),
            allowed_hosts=self.allowed_hosts,
            headers={
                "x-apikey": self.settings.virustotal_api_key.get_secret_value(),
                "Accept": "application/json",
            },
            cache_ttl=ctx.settings.cache_ttl_seconds,
            refresh=ctx.refresh,
        )
        failure = map_http_status("VirusTotal", resp)
        if failure is not None:
            if failure.status is RunStatus.NO_DATA:
                failure.message = (
                    "VirusTotal has not seen this indicator (this is not a clean verdict)."
                )
            return failure
        try:
            attrs = resp.json()["data"]["attributes"]
        except (ValueError, KeyError, TypeError):
            return ProviderResult.unavailable(
                RunStatus.ERROR, "VirusTotal returned an unexpected response shape."
            )

        signal = signal_from_stats(attrs.get("last_analysis_stats"), self.reliability)
        observations = [
            reputation_observation(
                self.display_name,
                signal,
                stats=attrs.get("last_analysis_stats"),
                community_reputation=attrs.get("reputation"),
                votes=attrs.get("total_votes"),
                last_analysis=epoch_iso(attrs.get("last_analysis_date")),
                link=f"https://www.virustotal.com/gui/{self._gui_path(parsed)}",
            )
        ]
        tags = clean_tags(list(attrs.get("tags", [])))
        rels: list[RelationshipDraft] = []

        if parsed.type is IndicatorType.HASH:
            threat = attrs.get("popular_threat_classification") or {}
            names = [
                n.get("value") for n in threat.get("popular_threat_name", []) if n.get("value")
            ]
            tags = clean_tags(
                [
                    *tags,
                    *names[:3],
                    *(c.get("value") for c in threat.get("popular_threat_category", [])[:2]),
                ]
            )
            observations.append(self._file_info(attrs, threat))
            rels.extend(self._hash_aliases(parsed, attrs))
        elif parsed.type is IndicatorType.IP:
            observations.append(
                ObservationDraft(
                    kind="network.asn",
                    title="Network (VirusTotal)",
                    assurance=Assurance.PROVIDER_CLAIM,
                    data={
                        "asn": attrs.get("asn"),
                        "as_owner": attrs.get("as_owner"),
                        "network": attrs.get("network"),
                        "country": attrs.get("country"),
                        "registry": attrs.get("regional_internet_registry"),
                        "caveat": "Country is a provider estimate, not a physical location.",
                    },
                    summary=f"AS{attrs.get('asn')} {attrs.get('as_owner') or ''}".strip(),
                )
            )
            if attrs.get("asn"):
                rels.append(
                    RelationshipDraft(
                        src_type=IndicatorType.IP,
                        src_value=parsed.value,
                        dst_type=IndicatorType.ASN,
                        dst_value=f"AS{int(attrs['asn'])}",
                        rel_type="belongs_to_asn",
                        assurance=Assurance.PROVIDER_CLAIM,
                        attrs={"basis": "VirusTotal"},
                    )
                )
        elif parsed.type is IndicatorType.DOMAIN:
            observations.append(self._domain_info(attrs))
            for rec in (attrs.get("last_dns_records") or [])[: ctx.settings.max_discovered_domains]:
                if rec.get("type") in ("A", "AAAA") and rec.get("value"):
                    cand = try_parse(str(rec["value"]), IndicatorType.IP)
                    if cand is not None:
                        rels.append(
                            RelationshipDraft(
                                src_type=IndicatorType.DOMAIN,
                                src_value=parsed.value,
                                dst_type=IndicatorType.IP,
                                dst_value=cand.value,
                                rel_type="resolves_to",
                                assurance=Assurance.PROVIDER_CLAIM,
                                attrs={
                                    "basis": "VirusTotal last_dns_records",
                                    "as_of": epoch_iso(attrs.get("last_dns_records_date")),
                                },
                            )
                        )
        else:  # URL
            observations.append(
                ObservationDraft(
                    kind="url.info",
                    title="URL details (VirusTotal)",
                    assurance=Assurance.PROVIDER_CLAIM,
                    data={
                        "final_url": attrs.get("last_final_url"),
                        "title": attrs.get("title"),
                        "http_status": attrs.get("last_http_response_code"),
                        "threat_names": attrs.get("threat_names"),
                        "categories": attrs.get("categories"),
                        "times_submitted": attrs.get("times_submitted"),
                    },
                    summary=attrs.get("title") or "URL details",
                )
            )
        return ProviderResult.ok(observations=observations, relationships=rels, tags=tags)

    @staticmethod
    def _gui_path(parsed: ParsedIndicator) -> str:
        return {
            IndicatorType.DOMAIN: f"domain/{parsed.value}",
            IndicatorType.IP: f"ip-address/{parsed.value}",
            IndicatorType.URL: f"url/{vt_url_id(parsed.value)}",
            IndicatorType.HASH: f"file/{parsed.value}",
        }[parsed.type]

    @staticmethod
    def _file_info(attrs: dict[str, Any], threat: dict[str, Any]) -> ObservationDraft:
        data = {
            "file_type": attrs.get("type_description"),
            "type_tag": attrs.get("type_tag"),
            "magic": attrs.get("magic"),
            "size": attrs.get("size"),
            "meaningful_name": attrs.get("meaningful_name"),
            "names": (attrs.get("names") or [])[:10],
            "first_submission": epoch_iso(attrs.get("first_submission_date")),
            "last_submission": epoch_iso(attrs.get("last_submission_date")),
            "times_submitted": attrs.get("times_submitted"),
            "suggested_threat_label": threat.get("suggested_threat_label"),
            "hashes": {
                k: attrs.get(k)
                for k in ("md5", "sha1", "sha256", "ssdeep", "tlsh", "vhash")
                if attrs.get(k)
            },
        }
        return ObservationDraft(
            kind="file.info",
            title="File details (VirusTotal)",
            assurance=Assurance.PROVIDER_CLAIM,
            data=data,
            summary=f"{data['file_type'] or 'unknown type'}"
            + (f", {data['size']} bytes" if data["size"] else ""),
        )

    @staticmethod
    def _domain_info(attrs: dict[str, Any]) -> ObservationDraft:
        return ObservationDraft(
            kind="domain.info",
            title="Domain details (VirusTotal)",
            assurance=Assurance.PROVIDER_CLAIM,
            data={
                "registrar": attrs.get("registrar"),
                "created": epoch_iso(attrs.get("creation_date")),
                "categories": attrs.get("categories"),
                "popularity_ranks": attrs.get("popularity_ranks"),
                "last_dns_records": (attrs.get("last_dns_records") or [])[:30],
            },
            summary=", ".join(sorted(set((attrs.get("categories") or {}).values()))[:4])
            or "domain details",
        )

    @staticmethod
    def _hash_aliases(parsed: ParsedIndicator, attrs: dict[str, Any]) -> list[RelationshipDraft]:
        out: list[RelationshipDraft] = []
        for key in ("md5", "sha1", "sha256"):
            value = attrs.get(key)
            if value and value != parsed.value:
                cand = try_parse(str(value), IndicatorType.HASH)
                if cand is not None:
                    out.append(
                        RelationshipDraft(
                            src_type=IndicatorType.HASH,
                            src_value=parsed.value,
                            dst_type=IndicatorType.HASH,
                            dst_value=cand.value,
                            rel_type="same_file_as",
                            assurance=Assurance.PROVIDER_CLAIM,
                            attrs={"basis": "VirusTotal file report"},
                        )
                    )
        return out
