"""RDAP (RFC 7480-7484) via the IANA bootstrap registry.

We resolve the authoritative RDAP server ourselves from IANA's bootstrap files rather than
relying on a third-party redirector, then ask the registry/RIR directly. Because the answer
comes from the registry of record, observations are ``verified``.

Privacy: personal contact data is never stored. Only organisational entities are read
(registrar, network owner); entities flagged ``individual`` are skipped entirely.
"""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime
from typing import Any

from hunterintel.core.ratelimit import RateSpec
from hunterintel.domain.evidence import (
    Assurance,
    ObservationDraft,
    ProviderResult,
    RelationshipDraft,
    RiskFlag,
    RunStatus,
    Severity,
    Tier,
    utcnow,
)
from hunterintel.domain.indicators import (
    IndicatorType,
    ParsedIndicator,
    registered_domain,
    try_parse,
)
from hunterintel.providers.base import Provider, ProviderContext, map_http_status

IANA_HOST = "data.iana.org"
BOOTSTRAP = {
    "dns": f"https://{IANA_HOST}/rdap/dns.json",
    "ipv4": f"https://{IANA_HOST}/rdap/ipv4.json",
    "ipv6": f"https://{IANA_HOST}/rdap/ipv6.json",
    "asn": f"https://{IANA_HOST}/rdap/asn.json",
}
_HOLD_STATUSES = {"client hold", "server hold", "pending delete", "redemption period"}


def _pick_url(urls: list[str]) -> str | None:
    https = [u for u in urls if u.lower().startswith("https://")]
    if not https:
        return None
    base = https[0]
    return base if base.endswith("/") else base + "/"


def find_dns_service(doc: dict[str, Any], tld: str) -> str | None:
    for tlds, urls in doc.get("services", []):
        if tld.lower() in {t.lower() for t in tlds}:
            return _pick_url(urls)
    return None


def find_ip_service(
    doc: dict[str, Any], addr: ipaddress.IPv4Address | ipaddress.IPv6Address
) -> str | None:
    best: tuple[int, str] | None = None
    for cidrs, urls in doc.get("services", []):
        for cidr in cidrs:
            net = ipaddress.ip_network(cidr, strict=False)
            if net.version == addr.version and addr in net:
                url = _pick_url(urls)
                if url and (best is None or net.prefixlen > best[0]):
                    best = (net.prefixlen, url)
    return best[1] if best else None


def find_asn_service(doc: dict[str, Any], number: int) -> str | None:
    for ranges, urls in doc.get("services", []):
        for rng in ranges:
            lo, _, hi = rng.partition("-")
            if int(lo) <= number <= int(hi or lo):
                return _pick_url(urls)
    return None


# ── response parsing ─────────────────────────────────────────────────────────


def _vcard(entity: dict[str, Any], field: str) -> str | None:
    card = entity.get("vcardArray")
    if not (isinstance(card, list) and len(card) == 2):
        return None
    for item in card[1]:
        if isinstance(item, list) and len(item) >= 4 and item[0] == field:
            value = item[3]
            return value if isinstance(value, str) else None
    return None


def _is_individual(entity: dict[str, Any]) -> bool:
    return (_vcard(entity, "kind") or "").lower() == "individual"


def _org_name(entity: dict[str, Any]) -> str | None:
    return None if _is_individual(entity) else _vcard(entity, "fn")


def _events(doc: dict[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for ev in doc.get("events", []):
        action, date = ev.get("eventAction"), ev.get("eventDate")
        if isinstance(action, str) and isinstance(date, str):
            out.setdefault(action.lower(), date)
    return out


def _parse_dt(text: str | None) -> datetime | None:
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _entities_by_role(doc: dict[str, Any], role: str) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []

    def walk(entities: list[dict[str, Any]]) -> None:
        for ent in entities:
            if role in [r.lower() for r in ent.get("roles", [])]:
                found.append(ent)
            walk(ent.get("entities", []))

    walk(doc.get("entities", []))
    return found


def parse_domain(
    doc: dict[str, Any], now: datetime | None = None
) -> tuple[dict[str, Any], list[RiskFlag], list[str]]:
    now = now or utcnow()
    events = _events(doc)
    registered = _parse_dt(events.get("registration"))
    expires = _parse_dt(events.get("expiration"))
    registrars = _entities_by_role(doc, "registrar")
    registrar: dict[str, Any] = {}
    if registrars:
        ent = registrars[0]
        registrar["name"] = _org_name(ent)
        for pid in ent.get("publicIds", []):
            if str(pid.get("type", "")).lower() == "iana registrar id":
                registrar["iana_id"] = pid.get("identifier")
        abuse = _entities_by_role(ent, "abuse")
        if abuse:
            registrar["abuse_email"] = _vcard(abuse[0], "email")
    nameservers = sorted(
        {
            str(ns["ldhName"]).lower().rstrip(".")
            for ns in doc.get("nameservers", [])
            if ns.get("ldhName")
        }
    )
    statuses = [str(s) for s in doc.get("status", [])]
    data = {
        "domain": str(doc.get("ldhName", "")).lower() or None,
        "registered": registered.isoformat() if registered else None,
        "expires": expires.isoformat() if expires else None,
        "last_changed": events.get("last changed"),
        "registry_updated": events.get("last update of rdap database"),
        "age_days": (now - registered).days if registered else None,
        "status": statuses,
        "registrar": registrar or None,
        "nameservers": nameservers,
        "dnssec_signed": (doc.get("secureDNS") or {}).get("delegationSigned"),
        "privacy_note": "Registrant contact details are intentionally not collected.",
    }
    flags: list[RiskFlag] = []
    age = data["age_days"]
    if isinstance(age, int) and age < 30:
        flags.append(
            RiskFlag(
                id="newly_registered_domain",
                severity=Severity.HIGH if age < 7 else Severity.MEDIUM,
                title=f"Domain registered {age} day(s) ago",
                detail="Newly registered domains are over-represented in phishing and malware "
                "delivery. Age alone is not proof of malice.",
            )
        )
    held = [s for s in statuses if s.lower() in _HOLD_STATUSES]
    if held:
        flags.append(
            RiskFlag(
                id="registry_hold_status",
                severity=Severity.INFO,
                title="Hold / pending-delete status present",
                detail=f"Registry status {held}. The domain may be suspended or about to be released.",
            )
        )
    return data, flags, nameservers


def parse_network(doc: dict[str, Any]) -> dict[str, Any]:
    events = _events(doc)
    cidrs: list[str] = []
    for entry in doc.get("cidr0_cidrs", []):
        prefix = entry.get("v4prefix") or entry.get("v6prefix")
        if prefix and "length" in entry:
            cidrs.append(f"{prefix}/{entry['length']}")
    owners = [n for n in (_org_name(e) for e in _entities_by_role(doc, "registrant")) if n]
    abuse = [e for e in _entities_by_role(doc, "abuse") if not _is_individual(e)]
    return {
        "name": doc.get("name"),
        "handle": doc.get("handle"),
        "type": doc.get("type"),
        "start_address": doc.get("startAddress"),
        "end_address": doc.get("endAddress"),
        "cidrs": cidrs,
        "registration_country": doc.get("country"),
        "owner_organisations": owners[:3],
        "abuse_email": _vcard(abuse[0], "email") if abuse else None,
        "parent_handle": doc.get("parentHandle"),
        "allocated": events.get("registration"),
        "last_changed": events.get("last changed"),
        "status": doc.get("status", []),
        "accuracy_note": (
            "Registration country is where the block was allocated to its holder, "
            "not where the hosts physically are."
        ),
    }


def parse_autnum(doc: dict[str, Any]) -> dict[str, Any]:
    events = _events(doc)
    owners = [n for n in (_org_name(e) for e in _entities_by_role(doc, "registrant")) if n]
    return {
        "name": doc.get("name"),
        "handle": doc.get("handle"),
        "range": [doc.get("startAutnum"), doc.get("endAutnum")],
        "registration_country": doc.get("country"),
        "type": doc.get("type"),
        "owner_organisations": owners[:3],
        "allocated": events.get("registration"),
        "last_changed": events.get("last changed"),
        "status": doc.get("status", []),
    }


# ── provider ─────────────────────────────────────────────────────────────────


class RdapProvider(Provider):
    name = "rdap"
    display_name = "RDAP (registries)"
    description = (
        "Registration, registrar, nameservers and network ownership from the registry of record."
    )
    tier = Tier.PUBLIC
    supported_types = frozenset({IndicatorType.DOMAIN, IndicatorType.IP, IndicatorType.ASN})
    homepage = "https://about.rdap.org/"
    terms_url = "https://www.iana.org/help/rdap-terms-of-service"
    reliability = 0.0
    default_rate = RateSpec(10, 10.0)
    allowed_hosts = (IANA_HOST, "the authoritative registry RDAP server")

    def data_shared(self, parsed: ParsedIndicator) -> str:
        value = parsed.value
        if parsed.type is IndicatorType.DOMAIN:
            value = registered_domain(parsed.value) or parsed.value
        return (
            f"'{value}' is sent to the authoritative RDAP server for its registry "
            "(discovered via IANA's public bootstrap files)."
        )

    async def _get_json(
        self,
        ctx: ProviderContext,
        url: str,
        *,
        redirects: int = 0,
        host_any: bool = False,
        ttl: int = 0,
    ) -> tuple[Any | None, ProviderResult | None]:
        resp = await ctx.http.request(
            "GET",
            url,
            provider=self.name,
            rate=self.rate(),
            allowed_hosts=None if host_any else (IANA_HOST,),
            headers={"Accept": "application/rdap+json, application/json"},
            max_bytes=1_500_000,
            max_redirects=redirects,
            cache_ttl=ttl,
            refresh=ctx.refresh,
        )
        failure = map_http_status(self.name, resp)
        if failure is not None:
            return None, failure
        try:
            return resp.json(), None
        except ValueError:
            return None, ProviderResult.unavailable(
                RunStatus.ERROR, "RDAP server returned a response that is not valid JSON."
            )

    async def lookup(self, parsed: ParsedIndicator, ctx: ProviderContext) -> ProviderResult:
        if parsed.type is IndicatorType.DOMAIN:
            return await self._domain(parsed, ctx)
        if parsed.type is IndicatorType.IP:
            return await self._ip(parsed, ctx)
        return await self._asn(parsed, ctx)

    async def _domain(self, parsed: ParsedIndicator, ctx: ProviderContext) -> ProviderResult:
        target = registered_domain(parsed.value)
        if target is None:
            return ProviderResult.no_data(
                f"'{parsed.value}' has no recognised public suffix, so there is no registry to ask."
            )
        boot, failure = await self._get_json(ctx, BOOTSTRAP["dns"], ttl=86400)
        if failure:
            return failure
        tld = target.rsplit(".", 1)[-1]
        base = find_dns_service(boot, tld)
        if base is None:
            return ProviderResult.no_data(
                f"No RDAP service is published for '.{tld}' in the IANA bootstrap registry "
                "(many country-code TLDs do not offer RDAP)."
            )
        doc, failure = await self._get_json(
            ctx, f"{base}domain/{target}", redirects=3, host_any=True
        )
        if failure:
            return failure
        data, flags, nameservers = parse_domain(doc)
        data["queried_domain"] = target
        data["rdap_server"] = base
        if target != parsed.value:
            data["note"] = (
                f"RDAP covers registrable domains; '{target}' was queried for '{parsed.value}'."
            )
        observations = [
            ObservationDraft(
                kind="rdap.domain",
                title="Registration (RDAP)",
                assurance=Assurance.VERIFIED,
                data=data,
                summary=(
                    f"Registered {data['registered'][:10] if data['registered'] else 'date unknown'}"
                    f" via {(data.get('registrar') or {}).get('name') or 'unknown registrar'}"
                ),
            )
        ]
        if flags:
            observations.append(
                ObservationDraft(
                    kind="risk_flags",
                    title="Registration heuristics",
                    assurance=Assurance.INFERRED,
                    data={
                        "flags": [f.model_dump(mode="json") for f in flags],
                        "basis": "registration age / status from RDAP",
                    },
                    summary=flags[0].title,
                )
            )
        rels = []
        if target == parsed.value:
            for ns in nameservers[: ctx.settings.max_discovered_domains]:
                cand = try_parse(ns, IndicatorType.DOMAIN)
                if cand is not None:
                    rels.append(
                        RelationshipDraft(
                            src_type=IndicatorType.DOMAIN,
                            src_value=parsed.value,
                            dst_type=IndicatorType.DOMAIN,
                            dst_value=cand.value,
                            rel_type="has_nameserver",
                            assurance=Assurance.VERIFIED,
                            attrs={"basis": "registry delegation"},
                        )
                    )
        return ProviderResult.ok(observations=observations, relationships=rels)

    async def _ip(self, parsed: ParsedIndicator, ctx: ProviderContext) -> ProviderResult:
        addr = ipaddress.ip_address(parsed.value)
        boot, failure = await self._get_json(ctx, BOOTSTRAP[f"ipv{addr.version}"], ttl=86400)
        if failure:
            return failure
        base = find_ip_service(boot, addr)
        if base is None:
            return ProviderResult.no_data(
                "No RDAP service covers this address range in the IANA bootstrap registry."
            )
        doc, failure = await self._get_json(
            ctx, f"{base}ip/{addr.compressed}", redirects=3, host_any=True
        )
        if failure:
            return failure
        data = parse_network(doc)
        data["rdap_server"] = base
        owner = (data["owner_organisations"] or [None])[0]
        return ProviderResult.ok(
            observations=[
                ObservationDraft(
                    kind="rdap.network",
                    title="Network ownership (RDAP)",
                    assurance=Assurance.VERIFIED,
                    data=data,
                    summary=f"{data['name'] or data['handle']}"
                    f"{' — ' + owner if owner else ''}"
                    f"{' — registered in ' + data['registration_country'] if data['registration_country'] else ''}",
                )
            ]
        )

    async def _asn(self, parsed: ParsedIndicator, ctx: ProviderContext) -> ProviderResult:
        number = int(parsed.value[2:])
        boot, failure = await self._get_json(ctx, BOOTSTRAP["asn"], ttl=86400)
        if failure:
            return failure
        base = find_asn_service(boot, number)
        if base is None:
            return ProviderResult.no_data(
                "No RDAP service covers this AS number in the IANA bootstrap registry."
            )
        doc, failure = await self._get_json(
            ctx, f"{base}autnum/{number}", redirects=3, host_any=True
        )
        if failure:
            return failure
        data = parse_autnum(doc)
        data["rdap_server"] = base
        return ProviderResult.ok(
            observations=[
                ObservationDraft(
                    kind="rdap.autnum",
                    title="AS registration (RDAP)",
                    assurance=Assurance.VERIFIED,
                    data=data,
                    summary=f"{data['name'] or data['handle']}"
                    f"{' — registered in ' + data['registration_country'] if data['registration_country'] else ''}",
                )
            ]
        )
