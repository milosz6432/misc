"""Public DNS: records, e-mail authentication posture, and reverse DNS.

Everything here is observed first-hand from the configured resolvers, so observations are
``verified`` — verified meaning "this is what DNS answered when we asked", not that the
content is benign.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
from typing import Any

import dns.reversename

from hunterintel.domain.evidence import (
    Assurance,
    ObservationDraft,
    ProviderResult,
    RelationshipDraft,
    RunStatus,
    Tier,
)
from hunterintel.domain.indicators import (
    IndicatorType,
    ParsedIndicator,
    email_domain,
    try_parse,
)
from hunterintel.providers.base import Provider, ProviderContext

DOMAIN_RTYPES = ("A", "AAAA", "NS", "MX", "TXT", "CNAME", "SOA", "CAA")


def parse_spf(txt_records: list[str]) -> dict[str, Any] | None:
    spf = [t for t in txt_records if t.lower().startswith("v=spf1")]
    if not spf:
        return None
    record = spf[0]
    all_match = re.search(r"([+\-~?]?)all\b", record)
    qualifier = all_match.group(1) if all_match else None
    policy = (
        {
            "-": "fail (reject)",
            "~": "softfail",
            "?": "neutral",
            "+": "pass (allows anyone)",
            "": "pass (allows anyone)",
        }.get(qualifier)
        if all_match
        else "no 'all' mechanism"
    )
    return {
        "record": record,
        "policy": policy,
        "includes": re.findall(r"include:([^\s]+)", record),
        "multiple_records": len(spf) > 1,
    }


def parse_dmarc(txt_records: list[str]) -> dict[str, Any] | None:
    for record in txt_records:
        if record.lower().startswith("v=dmarc1"):
            tags = dict(
                (k.strip().lower(), v.strip())
                for k, _, v in (part.partition("=") for part in record.split(";") if "=" in part)
            )
            return {
                "record": record,
                "policy": tags.get("p"),
                "subdomain_policy": tags.get("sp"),
                "pct": tags.get("pct"),
                "rua": tags.get("rua"),
            }
    return None


class DnsProvider(Provider):
    name = "dns"
    display_name = "Public DNS"
    description = (
        "A/AAAA/MX/NS/TXT/CNAME/SOA/CAA, SPF & DMARC, reverse DNS with forward confirmation."
    )
    tier = Tier.PUBLIC
    supported_types = frozenset({IndicatorType.DOMAIN, IndicatorType.IP, IndicatorType.EMAIL})
    reliability = 0.0

    def data_shared(self, parsed: ParsedIndicator) -> str:
        resolvers = ", ".join(self.settings.dns_resolvers) or "the system resolver"
        if parsed.type is IndicatorType.EMAIL:
            return (
                f"Only the domain part '{email_domain(parsed.value)}' is queried via {resolvers}. "
                "The mailbox name is never sent."
            )
        return f"DNS queries for '{parsed.value}' go to {resolvers}."

    async def lookup(self, parsed: ParsedIndicator, ctx: ProviderContext) -> ProviderResult:
        if parsed.type is IndicatorType.IP:
            return await self._reverse(parsed, ctx)
        domain = email_domain(parsed.value) if parsed.type is IndicatorType.EMAIL else parsed.value
        return await self._forward(parsed, domain, ctx)

    # -- forward -----------------------------------------------------------

    async def _forward(
        self, parsed: ParsedIndicator, domain: str, ctx: ProviderContext
    ) -> ProviderResult:
        email_mode = parsed.type is IndicatorType.EMAIL
        rtypes = ("MX", "TXT") if email_mode else DOMAIN_RTYPES
        answers = dict(
            zip(
                rtypes,
                await asyncio.gather(*(ctx.dns.query(domain, t) for t in rtypes)),
                strict=True,
            )
        )
        dmarc = await ctx.dns.query(f"_dmarc.{domain}", "TXT")

        if all(a.rcode in ("TIMEOUT", "SERVFAIL", "ERROR") for a in answers.values()):
            status = (
                RunStatus.TIMEOUT
                if any(a.rcode == "TIMEOUT" for a in answers.values())
                else RunStatus.ERROR
            )
            first = next(iter(answers.values()))
            return ProviderResult.unavailable(
                status, f"DNS resolution failed ({first.rcode}: {first.error or 'no detail'})"
            )

        nxdomain = any(a.rcode == "NXDOMAIN" for a in answers.values())
        records: dict[str, Any] = {t: a.records for t, a in answers.items() if a.records}
        failed = sorted(t for t, a in answers.items() if not a.ok)
        txt = [str(t) for t in records.get("TXT", [])]
        spf = parse_spf(txt)
        dmarc_info = parse_dmarc([str(t) for t in dmarc.records]) if dmarc.ok else None

        observations: list[ObservationDraft] = []
        resolvers = list(self.settings.dns_resolvers) or ["system"]
        if email_mode:
            observations.append(
                ObservationDraft(
                    kind="dns.email_security",
                    title=f"E-mail routing & authentication for {domain}",
                    assurance=Assurance.VERIFIED,
                    data={
                        "domain": domain,
                        "mx": records.get("MX", []),
                        "spf": spf,
                        "dmarc": dmarc_info,
                        "nxdomain": nxdomain,
                        "resolvers": resolvers,
                        "failed_queries": failed,
                    },
                    summary=(
                        "domain does not exist"
                        if nxdomain
                        else f"{len(records.get('MX', []))} MX, SPF {'present' if spf else 'absent'}, "
                        f"DMARC {'present' if dmarc_info else 'absent'}"
                    ),
                )
            )
        else:
            observations.append(
                ObservationDraft(
                    kind="dns.records",
                    title="DNS records",
                    assurance=Assurance.VERIFIED,
                    data={
                        "records": records,
                        "nxdomain": nxdomain,
                        "resolvers": resolvers,
                        "failed_queries": failed,
                        "ttl": {t: a.ttl for t, a in answers.items() if a.ttl is not None},
                    },
                    summary=(
                        "NXDOMAIN — the name does not exist"
                        if nxdomain
                        else ", ".join(f"{len(v)} {t}" for t, v in records.items()) or "no records"
                    ),
                )
            )
            if records.get("MX") or spf or dmarc_info:
                observations.append(
                    ObservationDraft(
                        kind="dns.email_security",
                        title="E-mail authentication posture",
                        assurance=Assurance.VERIFIED,
                        data={"domain": domain, "spf": spf, "dmarc": dmarc_info},
                        summary=f"SPF {'present' if spf else 'absent'}, DMARC {'present' if dmarc_info else 'absent'}",
                    )
                )

        rels = self._relationships(parsed, domain, records, ctx.settings.max_discovered_domains)
        truncated = any(
            len(records.get(t, [])) > ctx.settings.max_discovered_domains
            for t in ("A", "AAAA", "NS", "MX")
        )
        if email_mode:
            # the e-mail → domain edge is created by the local provider; keep only DNS-derived edges
            rels = [r for r in rels if r.src_type is not IndicatorType.EMAIL]
        return ProviderResult.ok(observations=observations, relationships=rels, truncated=truncated)

    def _relationships(
        self, parsed: ParsedIndicator, domain: str, records: dict[str, Any], cap: int
    ) -> list[RelationshipDraft]:
        rels: list[RelationshipDraft] = []

        def edge(dst_type: IndicatorType, dst: str, rel: str, **attrs: Any) -> None:
            cand = try_parse(dst, dst_type)
            if cand is None or cand.type is not dst_type or cand.value == domain:
                return
            rels.append(
                RelationshipDraft(
                    src_type=IndicatorType.DOMAIN,
                    src_value=domain,
                    dst_type=dst_type,
                    dst_value=cand.value,
                    rel_type=rel,
                    assurance=Assurance.VERIFIED,
                    attrs={"basis": "DNS answer", **attrs},
                )
            )

        for rtype in ("A", "AAAA"):
            for ip in records.get(rtype, [])[:cap]:
                edge(IndicatorType.IP, ip, "resolves_to", record=rtype)
        for ns in records.get("NS", [])[:cap]:
            edge(IndicatorType.DOMAIN, ns, "has_nameserver")
        for mx in records.get("MX", [])[:cap]:
            edge(IndicatorType.DOMAIN, mx["exchange"], "has_mx", preference=mx["preference"])
        for target in records.get("CNAME", [])[:cap]:
            edge(IndicatorType.DOMAIN, target, "cname_to")
        return rels

    # -- reverse -----------------------------------------------------------

    async def _reverse(self, parsed: ParsedIndicator, ctx: ProviderContext) -> ProviderResult:
        ptr_name = dns.reversename.from_address(parsed.value).to_text().rstrip(".")
        answer = await ctx.dns.query(ptr_name, "PTR")
        if answer.rcode in ("TIMEOUT", "SERVFAIL", "ERROR"):
            status = RunStatus.TIMEOUT if answer.rcode == "TIMEOUT" else RunStatus.ERROR
            return ProviderResult.unavailable(status, f"reverse lookup failed ({answer.rcode})")
        names = [str(n) for n in answer.records][: ctx.settings.max_discovered_domains]
        if not names:
            return ProviderResult.ok(
                observations=[
                    ObservationDraft(
                        kind="dns.ptr",
                        title="Reverse DNS",
                        assurance=Assurance.VERIFIED,
                        data={"ptr": [], "reverse_name": ptr_name},
                        summary="No PTR record published",
                    )
                ]
            )
        target = ipaddress.ip_address(parsed.value)
        confirmations: list[dict[str, Any]] = []
        rels: list[RelationshipDraft] = []
        for name in names[:5]:
            forward = await asyncio.gather(ctx.dns.query(name, "A"), ctx.dns.query(name, "AAAA"))
            ips = [str(ip) for a in forward for ip in a.records]
            confirmed = any(ipaddress.ip_address(ip) == target for ip in ips if _is_ip(ip))
            confirmations.append(
                {"name": name, "forward_ips": ips[:10], "forward_confirmed": confirmed}
            )
            cand = try_parse(name, IndicatorType.DOMAIN)
            if cand is not None:
                rels.append(
                    RelationshipDraft(
                        src_type=IndicatorType.IP,
                        src_value=parsed.value,
                        dst_type=IndicatorType.DOMAIN,
                        dst_value=cand.value,
                        rel_type="reverse_dns",
                        assurance=Assurance.VERIFIED,
                        attrs={"basis": "PTR record", "forward_confirmed": confirmed},
                    )
                )
        any_confirmed = any(c["forward_confirmed"] for c in confirmations)
        return ProviderResult.ok(
            observations=[
                ObservationDraft(
                    kind="dns.ptr",
                    title="Reverse DNS",
                    assurance=Assurance.VERIFIED,
                    data={
                        "ptr": names,
                        "reverse_name": ptr_name,
                        "forward_confirmation": confirmations,
                        "fcrdns": any_confirmed,
                    },
                    summary=(
                        f"{names[0]} (forward-confirmed)"
                        if any_confirmed
                        else f"{names[0]} — NOT forward-confirmed; a PTR is set by the address owner and can claim any name"
                    ),
                )
            ],
            relationships=rels,
        )


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True
