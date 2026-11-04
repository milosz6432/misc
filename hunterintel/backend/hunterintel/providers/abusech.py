"""abuse.ch providers: URLhaus (malware URLs) and MalwareBazaar (malware samples).

Both APIs require a free ``Auth-Key`` (``ABUSECH_AUTH_KEY``). A listing here is a strong,
curated signal, so reliability is high — but a *miss* only means "not listed".
"""

from __future__ import annotations

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
from hunterintel.providers.signals import clean_tags, reputation_observation

URLHAUS_HOST = "urlhaus-api.abuse.ch"
BAZAAR_HOST = "mb-api.abuse.ch"
MAX_EDGES = 25


class _AbuseChBase(Provider):
    key_env = "ABUSECH_AUTH_KEY"

    def is_configured(self) -> bool:
        return self.settings.abusech_auth_key is not None

    def not_configured_reason(self) -> str:
        return "No abuse.ch Auth-Key. Get a free key at https://auth.abuse.ch/ and set ABUSECH_AUTH_KEY."

    def _headers(self) -> dict[str, str]:
        assert self.settings.abusech_auth_key is not None
        return {
            "Auth-Key": self.settings.abusech_auth_key.get_secret_value(),
            "Accept": "application/json",
        }


class URLhausProvider(_AbuseChBase):
    name = "urlhaus"
    display_name = "URLhaus (abuse.ch)"
    description = "Curated list of URLs and hosts distributing malware, with payload links."
    tier = Tier.THIRD_PARTY
    supported_types = frozenset(
        {IndicatorType.URL, IndicatorType.DOMAIN, IndicatorType.IP, IndicatorType.HASH}
    )
    homepage = "https://urlhaus.abuse.ch/"
    terms_url = "https://urlhaus.abuse.ch/api/"
    reliability = 0.9
    default_rate = RateSpec(30, 60.0)
    allowed_hosts = (URLHAUS_HOST,)

    def can_handle(self, parsed: ParsedIndicator) -> bool:
        # URLhaus payload lookups accept MD5 and SHA-256 only
        if parsed.type is IndicatorType.HASH:
            return parsed.subtype in ("md5", "sha256")
        return super().can_handle(parsed)

    def _request(self, parsed: ParsedIndicator) -> tuple[str, dict[str, str]]:
        if parsed.type is IndicatorType.URL:
            return "url", {"url": parsed.value}
        if parsed.type is IndicatorType.HASH:
            return "payload", {
                "md5_hash" if parsed.subtype == "md5" else "sha256_hash": parsed.value
            }
        return "host", {"host": parsed.value}  # URLhaus accepts a hostname or an IP here

    async def lookup(self, parsed: ParsedIndicator, ctx: ProviderContext) -> ProviderResult:
        endpoint, form = self._request(parsed)
        resp = await ctx.http.request(
            "POST",
            f"https://{URLHAUS_HOST}/v1/{endpoint}/",
            data=form,
            provider=self.name,
            rate=self.rate(),
            allowed_hosts=self.allowed_hosts,
            headers=self._headers(),
            cache_ttl=ctx.settings.cache_ttl_seconds,
            refresh=ctx.refresh,
        )
        failure = map_http_status("URLhaus", resp, not_found_ok=False)
        if failure is not None:
            return failure
        try:
            doc = resp.json()
            status = doc["query_status"]
        except (ValueError, KeyError, TypeError):
            return ProviderResult.unavailable(
                RunStatus.ERROR, "URLhaus returned an unexpected response shape."
            )
        if status == "no_results":
            return ProviderResult.no_data("Not listed in URLhaus (this is not a clean verdict).")
        if status != "ok":
            return ProviderResult.unavailable(RunStatus.ERROR, f"URLhaus query_status: {status}")
        return getattr(self, f"_{endpoint}")(parsed, doc)

    # -- shaping -----------------------------------------------------------

    def _url(self, parsed: ParsedIndicator, doc: dict[str, Any]) -> ProviderResult:
        online = str(doc.get("url_status")).lower() == "online"
        signal = ReputationSignal(
            source=self.name,
            verdict="malicious",
            strength=0.95 if online else 0.8,
            reliability=self.reliability,
            label=f"Listed in URLhaus ({doc.get('threat') or 'malware'}), status: {doc.get('url_status')}",
        )
        payloads = doc.get("payloads") or []
        rels = [
            RelationshipDraft(
                src_type=IndicatorType.URL,
                src_value=parsed.value,
                dst_type=IndicatorType.HASH,
                dst_value=cand.value,
                rel_type="distributes",
                assurance=Assurance.PROVIDER_CLAIM,
                attrs={
                    "file_type": p.get("file_type"),
                    "signature": p.get("signature"),
                    "first_seen": p.get("firstseen"),
                    "basis": "URLhaus payload",
                },
            )
            for p in payloads[:MAX_EDGES]
            if (cand := try_parse(str(p.get("response_sha256") or ""), IndicatorType.HASH))
            is not None
        ]
        tags = clean_tags(
            [
                doc.get("threat"),
                *(doc.get("tags") or []),
                *(p.get("signature") for p in payloads[:5] if p.get("signature")),
            ]
        )
        return ProviderResult.ok(
            observations=[
                reputation_observation(self.display_name, signal),
                ObservationDraft(
                    kind="urlhaus.listing",
                    title="URLhaus listing",
                    assurance=Assurance.PROVIDER_CLAIM,
                    data={
                        "url_status": doc.get("url_status"),
                        "threat": doc.get("threat"),
                        "date_added": doc.get("date_added"),
                        "last_online": doc.get("last_online"),
                        "host": doc.get("host"),
                        "reporter": doc.get("reporter"),
                        "tags": doc.get("tags"),
                        "blacklists": doc.get("blacklists"),
                        "payloads": [
                            {
                                k: p.get(k)
                                for k in (
                                    "filename",
                                    "file_type",
                                    "response_sha256",
                                    "response_md5",
                                    "signature",
                                    "firstseen",
                                    "virustotal",
                                )
                            }
                            for p in payloads[:10]
                        ],
                        "reference": doc.get("urlhaus_reference"),
                    },
                    summary=signal.label,
                ),
            ],
            relationships=rels,
            tags=tags,
        )

    def _host(self, parsed: ParsedIndicator, doc: dict[str, Any]) -> ProviderResult:
        urls = doc.get("urls") or []
        count = int(doc.get("url_count") or len(urls) or 0)
        if count == 0:
            return ProviderResult.no_data("URLhaus knows this host but lists no URLs for it.")
        online = [u for u in urls if str(u.get("url_status")).lower() == "online"]
        signal = ReputationSignal(
            source=self.name,
            verdict="malicious",
            strength=0.9 if online else 0.7,
            reliability=self.reliability,
            label=f"Host serves {count} listed URL(s) in URLhaus ({len(online)} online)",
        )
        rels = [
            RelationshipDraft(
                src_type=parsed.type,
                src_value=parsed.value,
                dst_type=IndicatorType.URL,
                dst_value=cand.value,
                rel_type="hosts_url",
                assurance=Assurance.PROVIDER_CLAIM,
                attrs={
                    "status": u.get("url_status"),
                    "threat": u.get("threat"),
                    "basis": "URLhaus",
                },
            )
            for u in urls[:MAX_EDGES]
            if (cand := try_parse(str(u.get("url") or ""), IndicatorType.URL)) is not None
            and cand.remote_lookup_allowed
        ]
        return ProviderResult.ok(
            observations=[
                reputation_observation(self.display_name, signal),
                ObservationDraft(
                    kind="urlhaus.host",
                    title="URLhaus host listing",
                    assurance=Assurance.PROVIDER_CLAIM,
                    data={
                        "url_count": count,
                        "first_seen": doc.get("firstseen"),
                        "blacklists": doc.get("blacklists"),
                        "reference": doc.get("urlhaus_reference"),
                        "urls": [
                            {
                                k: u.get(k)
                                for k in ("url", "url_status", "threat", "date_added", "tags")
                            }
                            for u in urls[:15]
                        ],
                    },
                    summary=signal.label,
                ),
            ],
            relationships=rels,
            tags=clean_tags(
                [t for u in urls[:20] for t in (u.get("tags") or [])]
                + [u.get("threat") for u in urls[:20] if u.get("threat")]
            ),
            truncated=count > len(urls),
        )

    def _payload(self, parsed: ParsedIndicator, doc: dict[str, Any]) -> ProviderResult:
        signal = ReputationSignal(
            source=self.name,
            verdict="malicious",
            strength=0.9,
            reliability=self.reliability,
            label=f"Payload served from {doc.get('url_count') or 'listed'} URLhaus URL(s)"
            + (f" — {doc['signature']}" if doc.get("signature") else ""),
        )
        urls = doc.get("urls") or []
        rels = [
            RelationshipDraft(
                src_type=IndicatorType.HASH,
                src_value=parsed.value,
                dst_type=IndicatorType.URL,
                dst_value=cand.value,
                rel_type="downloaded_from",
                assurance=Assurance.PROVIDER_CLAIM,
                attrs={
                    "status": u.get("url_status"),
                    "first_seen": u.get("firstseen"),
                    "basis": "URLhaus",
                },
            )
            for u in urls[:MAX_EDGES]
            if (cand := try_parse(str(u.get("url") or ""), IndicatorType.URL)) is not None
            and cand.remote_lookup_allowed
        ]
        return ProviderResult.ok(
            observations=[
                reputation_observation(self.display_name, signal),
                ObservationDraft(
                    kind="file.info",
                    title="Payload details (URLhaus)",
                    assurance=Assurance.PROVIDER_CLAIM,
                    data={
                        "file_type": doc.get("file_type"),
                        "size": doc.get("file_size"),
                        "signature": doc.get("signature"),
                        "first_seen": doc.get("firstseen"),
                        "last_seen": doc.get("lastseen"),
                        "url_count": doc.get("url_count"),
                        "hashes": {
                            k: doc.get(k)
                            for k in ("md5_hash", "sha256_hash", "imphash", "ssdeep", "tlsh")
                            if doc.get(k)
                        },
                        "virustotal": doc.get("virustotal"),
                    },
                    summary=f"{doc.get('file_type') or 'unknown type'} — {doc.get('signature') or 'no family'}",
                ),
            ],
            relationships=rels,
            tags=clean_tags([doc.get("signature")] if doc.get("signature") else []),
        )


class MalwareBazaarProvider(_AbuseChBase):
    name = "malwarebazaar"
    display_name = "MalwareBazaar (abuse.ch)"
    description = "Malware sample metadata by hash: family, file type, delivery method."
    tier = Tier.THIRD_PARTY
    supported_types = frozenset({IndicatorType.HASH})
    homepage = "https://bazaar.abuse.ch/"
    terms_url = "https://bazaar.abuse.ch/api/"
    reliability = 0.9
    default_rate = RateSpec(20, 60.0)
    allowed_hosts = (BAZAAR_HOST,)

    def data_shared(self, parsed: ParsedIndicator) -> str:
        return (
            f"The hash '{parsed.value}' is sent to {BAZAAR_HOST} as a metadata query. "
            "The sample itself is neither uploaded nor downloaded."
        )

    async def lookup(self, parsed: ParsedIndicator, ctx: ProviderContext) -> ProviderResult:
        resp = await ctx.http.request(
            "POST",
            f"https://{BAZAAR_HOST}/api/v1/",
            data={"query": "get_info", "hash": parsed.value},
            provider=self.name,
            rate=self.rate(),
            allowed_hosts=self.allowed_hosts,
            headers=self._headers(),
            cache_ttl=ctx.settings.cache_ttl_seconds,
            refresh=ctx.refresh,
        )
        failure = map_http_status("MalwareBazaar", resp, not_found_ok=False)
        if failure is not None:
            return failure
        try:
            doc = resp.json()
            status = doc["query_status"]
        except (ValueError, KeyError, TypeError):
            return ProviderResult.unavailable(
                RunStatus.ERROR, "MalwareBazaar returned an unexpected response shape."
            )
        if status == "hash_not_found":
            return ProviderResult.no_data(
                "Hash not in MalwareBazaar (this is not a clean verdict)."
            )
        if status != "ok" or not doc.get("data"):
            return ProviderResult.unavailable(
                RunStatus.ERROR, f"MalwareBazaar query_status: {status}"
            )

        s = doc["data"][0]
        family = s.get("signature")
        signal = ReputationSignal(
            source=self.name,
            verdict="malicious",
            strength=0.95,
            reliability=self.reliability,
            label="Known malware sample in MalwareBazaar" + (f" — {family}" if family else ""),
        )
        hashes = {k: s.get(f"{k}_hash") or s.get(k) for k in ("md5", "sha1", "sha256")}
        hashes.update({k: s.get(k) for k in ("imphash", "ssdeep", "tlsh") if s.get(k)})
        intel = s.get("intelligence") or {}
        rels = [
            RelationshipDraft(
                src_type=IndicatorType.HASH,
                src_value=parsed.value,
                dst_type=IndicatorType.HASH,
                dst_value=cand.value,
                rel_type="same_file_as",
                assurance=Assurance.PROVIDER_CLAIM,
                attrs={"basis": "MalwareBazaar sample record"},
            )
            for algo in ("md5", "sha1", "sha256")
            if hashes.get(algo)
            and hashes[algo] != parsed.value
            and (cand := try_parse(str(hashes[algo]), IndicatorType.HASH)) is not None
        ]
        return ProviderResult.ok(
            observations=[
                reputation_observation(self.display_name, signal),
                ObservationDraft(
                    kind="file.info",
                    title="Sample details (MalwareBazaar)",
                    assurance=Assurance.PROVIDER_CLAIM,
                    data={
                        "file_name": s.get("file_name"),
                        "file_type": s.get("file_type"),
                        "mime_type": s.get("file_type_mime"),
                        "size": s.get("file_size"),
                        "signature": family,
                        "first_seen": s.get("first_seen"),
                        "last_seen": s.get("last_seen"),
                        "delivery_method": s.get("delivery_method"),
                        "origin_country": s.get("origin_country"),
                        "tags": s.get("tags"),
                        "clamav": intel.get("clamav"),
                        "downloads": intel.get("downloads"),
                        "uploads": intel.get("uploads"),
                        "hashes": {k: v for k, v in hashes.items() if v},
                        "link": f"https://bazaar.abuse.ch/sample/{s.get('sha256_hash')}/",
                    },
                    summary=f"{s.get('file_type') or 'unknown type'}"
                    + (f" — {family}" if family else "")
                    + (f" — {s.get('file_name')}" if s.get("file_name") else ""),
                ),
            ],
            relationships=rels,
            tags=clean_tags([family, *(s.get("tags") or []), s.get("delivery_method")]),
        )
