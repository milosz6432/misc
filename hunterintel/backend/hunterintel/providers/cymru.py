"""IP → ASN / prefix / AS name through Team Cymru's public DNS mapping service.

It is a keyless, DNS-only lookup. Team Cymru is a third party, so results are
``provider_claim`` and the country field is the *RIR registration country*, not a physical
location (stated in every observation).
"""

from __future__ import annotations

import ipaddress

from hunterintel.domain.evidence import (
    Assurance,
    ObservationDraft,
    ProviderResult,
    RelationshipDraft,
    RunStatus,
    Tier,
)
from hunterintel.domain.indicators import IndicatorType, ParsedIndicator
from hunterintel.providers.base import Provider, ProviderContext

ORIGIN_V4 = "origin.asn.cymru.com"
ORIGIN_V6 = "origin6.asn.cymru.com"
ASN_ZONE = "asn.cymru.com"


def origin_query_name(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    if addr.version == 4:
        return ".".join(reversed(str(addr).split("."))) + "." + ORIGIN_V4
    nibbles = addr.exploded.replace(":", "")
    return ".".join(reversed(nibbles)) + "." + ORIGIN_V6


def _fields(txt: str) -> list[str]:
    return [part.strip() for part in txt.strip().strip('"').split("|")]


def parse_origin(txt: str) -> dict[str, object] | None:
    """``15169 | 8.8.8.0/24 | US | arin | 2023-12-28`` → dict (ASN field may list several)."""
    f = _fields(txt)
    if len(f) < 5 or not f[0]:
        return None
    asns = [int(a) for a in f[0].split() if a.isdigit()]
    if not asns:
        return None
    return {
        "asns": asns,
        "prefix": f[1],
        "registry_country": f[2] or None,
        "registry": f[3] or None,
        "allocated": f[4] or None,
    }


def parse_asname(txt: str) -> dict[str, object] | None:
    """``15169 | US | arin | 2000-03-30 | GOOGLE, US`` → dict."""
    f = _fields(txt)
    if len(f) < 5:
        return None
    return {
        "country": f[1] or None,
        "registry": f[2] or None,
        "allocated": f[3] or None,
        "name": f[4] or None,
    }


class CymruProvider(Provider):
    name = "cymru"
    display_name = "Team Cymru IP→ASN"
    description = "Origin ASN, announced prefix and AS name via a public DNS mapping service."
    tier = Tier.PUBLIC
    supported_types = frozenset({IndicatorType.IP, IndicatorType.ASN})
    homepage = "https://www.team-cymru.com/ip-asn-mapping"
    terms_url = "https://www.team-cymru.com/ip-asn-mapping"
    reliability = 0.0

    def data_shared(self, parsed: ParsedIndicator) -> str:
        zone = ASN_ZONE if parsed.type is IndicatorType.ASN else ORIGIN_V4 + " / " + ORIGIN_V6
        resolvers = ", ".join(self.settings.dns_resolvers) or "the system resolver"
        return f"A DNS query under {zone} containing '{parsed.value}' is sent to {resolvers}."

    async def lookup(self, parsed: ParsedIndicator, ctx: ProviderContext) -> ProviderResult:
        if parsed.type is IndicatorType.ASN:
            return await self._asn_only(parsed, ctx)
        addr = ipaddress.ip_address(parsed.value)
        answer = await ctx.dns.query(origin_query_name(addr), "TXT")
        if answer.rcode in ("TIMEOUT", "SERVFAIL", "ERROR"):
            status = RunStatus.TIMEOUT if answer.rcode == "TIMEOUT" else RunStatus.ERROR
            return ProviderResult.unavailable(status, f"Team Cymru lookup failed ({answer.rcode}).")
        origin = next((o for o in (parse_origin(str(r)) for r in answer.records) if o), None)
        if origin is None:
            return ProviderResult.no_data(
                "Team Cymru has no origin AS for this address (not announced)."
            )
        asns: list[int] = origin["asns"]  # type: ignore[assignment]
        names = {}
        for asn in asns[:3]:
            info = await ctx.dns.query(f"AS{asn}.{ASN_ZONE}", "TXT")
            parsed_name = next((n for n in (parse_asname(str(r)) for r in info.records) if n), None)
            if parsed_name:
                names[asn] = parsed_name
        first = names.get(asns[0], {})
        data = {
            **origin,
            "as_names": {f"AS{k}": v["name"] for k, v in names.items()},
            "as_name": first.get("name"),
            "caveat": "Country is the RIR allocation country of the prefix/AS, not a physical location.",
        }
        rels = [
            RelationshipDraft(
                src_type=IndicatorType.IP,
                src_value=parsed.value,
                dst_type=IndicatorType.ASN,
                dst_value=f"AS{asn}",
                rel_type="belongs_to_asn",
                assurance=Assurance.PROVIDER_CLAIM,
                attrs={"prefix": origin["prefix"], "basis": "BGP origin per Team Cymru"},
            )
            for asn in asns[:3]
        ]
        return ProviderResult.ok(
            observations=[
                ObservationDraft(
                    kind="network.asn",
                    title="Origin AS (Team Cymru)",
                    assurance=Assurance.PROVIDER_CLAIM,
                    data=data,
                    summary=f"AS{asns[0]} {first.get('name') or ''} · {origin['prefix']}".strip(),
                )
            ],
            relationships=rels,
        )

    async def _asn_only(self, parsed: ParsedIndicator, ctx: ProviderContext) -> ProviderResult:
        number = int(parsed.value[2:])
        answer = await ctx.dns.query(f"AS{number}.{ASN_ZONE}", "TXT")
        if answer.rcode in ("TIMEOUT", "SERVFAIL", "ERROR"):
            status = RunStatus.TIMEOUT if answer.rcode == "TIMEOUT" else RunStatus.ERROR
            return ProviderResult.unavailable(status, f"Team Cymru lookup failed ({answer.rcode}).")
        info = next((n for n in (parse_asname(str(r)) for r in answer.records) if n), None)
        if info is None:
            return ProviderResult.no_data("Team Cymru has no record for this AS number.")
        return ProviderResult.ok(
            observations=[
                ObservationDraft(
                    kind="network.asn_name",
                    title="AS name (Team Cymru)",
                    assurance=Assurance.PROVIDER_CLAIM,
                    data={
                        **info,
                        "caveat": "Country is the RIR allocation country, not a physical location.",
                    },
                    summary=f"{info['name']}",
                )
            ]
        )
