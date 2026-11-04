"""Certificate Transparency via crt.sh.

crt.sh is a best-effort public aggregator; it frequently times out for large domains.
Those outcomes are reported as such (``timeout`` / ``error``) — never as an empty result.
Everything it returns is a ``provider_claim``.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from hunterintel.core.ratelimit import RateSpec
from hunterintel.domain.evidence import (
    Assurance,
    ObservationDraft,
    ProviderResult,
    RelationshipDraft,
    RunStatus,
    Tier,
)
from hunterintel.domain.indicators import IndicatorType, ParsedIndicator, try_parse
from hunterintel.providers.base import Provider, ProviderContext, map_http_status

HOST = "crt.sh"
MAX_BYTES = 8 * 1024 * 1024
MAX_CERT_EDGES = 15


def _names(entry: dict[str, Any]) -> list[str]:
    raw = entry.get("name_value") or entry.get("common_name") or ""
    return sorted({n.strip().lower() for n in str(raw).splitlines() if n.strip()})


def summarise(rows: list[dict[str, Any]], cap: int) -> dict[str, Any]:
    """Deduplicate pre-cert/final-cert pairs and condense the listing."""
    unique: dict[tuple[Any, Any], dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict) or "id" not in row:
            continue
        key = (row.get("issuer_ca_id"), row.get("serial_number") or row.get("id"))
        current = unique.get(key)
        if current is None or int(row["id"]) < int(current["id"]):
            row = {
                **row,
                "_entries": sorted({int(row["id"]), *(current or {}).get("_entries", [])}),
            }
            unique[key] = row
        else:
            current["_entries"] = sorted(
                {*current.get("_entries", [int(current["id"])]), int(row["id"])}
            )
    ordered = sorted(unique.values(), key=lambda r: int(r["id"]), reverse=True)
    considered = ordered[:cap]
    issuers = Counter(str(r.get("issuer_name", "unknown")) for r in considered)
    names: set[str] = set()
    for r in considered:
        names.update(_names(r))
    not_befores = sorted(str(r["not_before"]) for r in considered if r.get("not_before"))
    return {
        "total_rows": len(rows),
        "unique_certificates": len(unique),
        "considered": len(considered),
        "truncated": len(unique) > cap,
        "issuers": dict(issuers.most_common(10)),
        "first_not_before": not_befores[0] if not_befores else None,
        "last_not_before": not_befores[-1] if not_befores else None,
        "names": sorted(names),
        "certificates": [
            {
                "crtsh_id": int(r["id"]),
                "ct_entry_ids": r.get("_entries", [int(r["id"])]),
                "serial": r.get("serial_number"),
                "common_name": r.get("common_name"),
                "issuer": r.get("issuer_name"),
                "not_before": r.get("not_before"),
                "not_after": r.get("not_after"),
                "logged_at": r.get("entry_timestamp"),
                "names": _names(r)[:25],
                "name_count": len(_names(r)),
            }
            for r in considered
        ],
        "_considered_rows": considered,
    }


class CrtShProvider(Provider):
    name = "crtsh"
    display_name = "crt.sh (Certificate Transparency)"
    description = "Certificates logged to public CT logs for a domain, with the names they cover."
    tier = Tier.PUBLIC
    supported_types = frozenset({IndicatorType.DOMAIN, IndicatorType.CERTIFICATE})
    homepage = "https://crt.sh/"
    terms_url = "https://crt.sh/"
    reliability = 0.0
    default_rate = RateSpec(1, 3.0)  # crt.sh is a volunteer-run service: be gentle
    allowed_hosts = (HOST,)

    async def lookup(self, parsed: ParsedIndicator, ctx: ProviderContext) -> ProviderResult:
        if parsed.type is IndicatorType.CERTIFICATE:
            query = (
                parsed.value.split(":", 1)[1] if parsed.value.startswith("crtsh:") else parsed.value
            )
        else:
            query = f"%.{parsed.value}"
        resp = await ctx.http.request(
            "GET",
            f"https://{HOST}/",
            params={"q": query, "output": "json"},
            provider=self.name,
            rate=self.rate(),
            allowed_hosts=self.allowed_hosts,
            max_bytes=MAX_BYTES,
            cache_ttl=ctx.settings.cache_ttl_seconds,
            refresh=ctx.refresh,
            timeout=max(ctx.settings.http_timeout_seconds, 25.0),
        )
        if resp.status_code in (502, 503, 504):
            return ProviderResult.unavailable(
                RunStatus.ERROR, f"crt.sh is overloaded (HTTP {resp.status_code}); try again later."
            )
        failure = map_http_status(self.name, resp)
        if failure is not None:
            return failure
        try:
            rows = resp.json()
        except ValueError:
            return ProviderResult.unavailable(
                RunStatus.ERROR,
                "crt.sh returned a non-JSON response (usually an overload page). Nothing was concluded.",
            )
        if not isinstance(rows, list) or not rows:
            return ProviderResult.no_data("crt.sh lists no certificates for this query.")
        if parsed.type is IndicatorType.CERTIFICATE:
            return self._certificate(parsed, rows, ctx)
        return self._domain(parsed, rows, ctx)

    def _domain(
        self, parsed: ParsedIndicator, rows: list[dict[str, Any]], ctx: ProviderContext
    ) -> ProviderResult:
        s = summarise(rows, ctx.settings.max_certificates)
        considered = s.pop("_considered_rows")
        cap = ctx.settings.max_discovered_domains
        data = {k: v for k, v in s.items() if k != "names"}
        data["subdomains"] = [n for n in s["names"] if not n.startswith("*") and n != parsed.value][
            :200
        ]
        data["wildcards"] = [n for n in s["names"] if n.startswith("*")][:50]
        data["caveat"] = (
            "Certificates prove a name was *requested and issued*, not that a host currently serves it."
        )
        rels: list[RelationshipDraft] = []
        discovered: set[str] = set()
        for row in considered[:MAX_CERT_EDGES]:
            cert = f"crtsh:{int(row['id'])}"
            rels.append(
                RelationshipDraft(
                    src_type=IndicatorType.DOMAIN,
                    src_value=parsed.value,
                    dst_type=IndicatorType.CERTIFICATE,
                    dst_value=cert,
                    rel_type="has_certificate",
                    assurance=Assurance.PROVIDER_CLAIM,
                    attrs={
                        "issuer": row.get("issuer_name"),
                        "not_before": row.get("not_before"),
                        "not_after": row.get("not_after"),
                    },
                )
            )
            for name in _names(row):
                bare = name[2:] if name.startswith("*.") else name
                cand = try_parse(bare, IndicatorType.DOMAIN)
                if cand is None or cand.value == parsed.value or not cand.remote_lookup_allowed:
                    continue
                if cand.value not in discovered and len(discovered) >= cap:
                    continue
                discovered.add(cand.value)
                rels.append(
                    RelationshipDraft(
                        src_type=IndicatorType.CERTIFICATE,
                        src_value=cert,
                        dst_type=IndicatorType.DOMAIN,
                        dst_value=cand.value,
                        rel_type="covers",
                        assurance=Assurance.PROVIDER_CLAIM,
                        attrs={"wildcard": name.startswith("*.")},
                    )
                )
        truncated = bool(s["truncated"]) or len(data["subdomains"]) > cap
        return ProviderResult.ok(
            observations=[
                ObservationDraft(
                    kind="ct.certificates",
                    title="Certificate Transparency (crt.sh)",
                    assurance=Assurance.PROVIDER_CLAIM,
                    data=data,
                    summary=(
                        f"{s['unique_certificates']} certificate(s), {len(data['subdomains'])} distinct name(s)"
                        + (" — truncated" if truncated else "")
                    ),
                )
            ],
            relationships=rels,
            truncated=truncated,
        )

    def _certificate(
        self, parsed: ParsedIndicator, rows: list[dict[str, Any]], ctx: ProviderContext
    ) -> ProviderResult:
        s = summarise(rows, 5)
        s.pop("_considered_rows")
        cert = s["certificates"][0]
        rels = []
        for name in cert["names"][: ctx.settings.max_discovered_domains]:
            bare = name[2:] if name.startswith("*.") else name
            cand = try_parse(bare, IndicatorType.DOMAIN)
            if cand is not None and cand.remote_lookup_allowed:
                rels.append(
                    RelationshipDraft(
                        src_type=IndicatorType.CERTIFICATE,
                        src_value=parsed.value,
                        dst_type=IndicatorType.DOMAIN,
                        dst_value=cand.value,
                        rel_type="covers",
                        assurance=Assurance.PROVIDER_CLAIM,
                        attrs={"wildcard": name.startswith("*.")},
                    )
                )
        return ProviderResult.ok(
            observations=[
                ObservationDraft(
                    kind="ct.certificate",
                    title="Certificate (crt.sh)",
                    assurance=Assurance.PROVIDER_CLAIM,
                    data=cert,
                    summary=f"{cert['common_name']} · issued by {cert['issuer']} · "
                    f"valid {str(cert['not_before'])[:10]} → {str(cert['not_after'])[:10]}",
                )
            ],
            relationships=rels,
        )
