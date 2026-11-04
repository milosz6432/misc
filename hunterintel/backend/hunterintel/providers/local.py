"""Offline analysis: parsing, structure and heuristics. Never touches the network."""

from __future__ import annotations

import ipaddress

import dns.reversename

from hunterintel.domain.evidence import (
    Assurance,
    ObservationDraft,
    ProviderResult,
    RelationshipDraft,
    Tier,
)
from hunterintel.domain.indicators import (
    IndicatorType,
    ParsedIndicator,
    decode_idn,
    email_domain,
    parse_indicator,
    registered_domain,
    split_domain,
)
from hunterintel.domain.urlanalysis import analyze_url
from hunterintel.providers.base import Provider, ProviderContext

#: Facts about well-known, *publicly documented* test artefacts. This is a lookup of a
#: fixed standard, not threat data.
KNOWN_TEST_FILES = {
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "EICAR",
    "3395856ce81f2b7382dee72602f798b642f14140": "EICAR",
    "44d88612fea8a8f36de82e1278abb02f": "EICAR",
}

_HASH_NOTE = (
    "A hash identifies content but carries no file-type information by itself. "
    "File type comes from a provider that has seen the file, or from hashing the file "
    "locally with the file tool (the file never leaves this host)."
)


class LocalProvider(Provider):
    name = "local"
    display_name = "Local analysis"
    description = "Parsing, normalisation, structure and heuristics. Runs offline."
    tier = Tier.LOCAL
    supported_types = frozenset(IndicatorType)
    reliability = 0.0  # produces facts and heuristics, never reputation

    async def lookup(self, parsed: ParsedIndicator, ctx: ProviderContext) -> ProviderResult:
        handler = getattr(self, f"_{parsed.type.value}", None)
        if handler is None:  # pragma: no cover - every type has a handler
            return ProviderResult.no_data()
        return handler(parsed)

    # -- per type ---------------------------------------------------------

    def _domain(self, p: ParsedIndicator) -> ProviderResult:
        parts = split_domain(p.value)
        unicode_form = decode_idn(p.value)
        data = {
            **parts,
            "label_count": p.value.count(".") + 1,
            "unicode_form": unicode_form if unicode_form != p.value else None,
            "scope": p.scope,
            "public_suffix_known": bool(parts["suffix"]),
        }
        rels = []
        reg = parts["registered_domain"]
        if reg and reg != p.value:
            rels.append(
                RelationshipDraft(
                    src_type=IndicatorType.DOMAIN,
                    src_value=p.value,
                    dst_type=IndicatorType.DOMAIN,
                    dst_value=reg,
                    rel_type="subdomain_of",
                    assurance=Assurance.VERIFIED,
                    attrs={"basis": "public suffix list"},
                )
            )
        return ProviderResult.ok(
            observations=[
                ObservationDraft(
                    kind="local.domain_structure",
                    title="Domain structure",
                    assurance=Assurance.VERIFIED,
                    data=data,
                    summary=f"Registrable domain: {reg or 'unknown (suffix not in list)'}",
                )
            ],
            relationships=rels,
        )

    def _ip(self, p: ParsedIndicator) -> ProviderResult:
        addr = ipaddress.ip_address(p.value)
        data = {
            "version": addr.version,
            "scope": p.scope,
            "reverse_pointer": dns.reversename.from_address(p.value).to_text().rstrip("."),
            "ipv4_mapped": str(addr.ipv4_mapped)
            if addr.version == 6 and addr.ipv4_mapped
            else None,
            "globally_routable": p.scope == "public",
        }
        return ProviderResult.ok(
            observations=[
                ObservationDraft(
                    kind="local.ip_info",
                    title="Address classification",
                    assurance=Assurance.VERIFIED,
                    data=data,
                    summary=f"IPv{addr.version}, scope: {p.scope.replace('_', '-')}",
                )
            ]
        )

    def _url(self, p: ParsedIndicator) -> ProviderResult:
        analysis = analyze_url(p.value)
        comps = analysis["components"]
        observations = [
            ObservationDraft(
                kind="local.url_components",
                title="URL components",
                assurance=Assurance.VERIFIED,
                data=comps,
                summary=f"{comps['scheme']}://{comps['host']} ({comps['host_kind']})",
            )
        ]
        flags = analysis["flags"]
        if flags:
            observations.append(
                ObservationDraft(
                    kind="risk_flags",
                    title="URL structure heuristics",
                    assurance=Assurance.INFERRED,
                    data={
                        "flags": [f.model_dump(mode="json") for f in flags],
                        "basis": "structural heuristics on the URL string",
                    },
                    summary=f"{len(flags)} structural indicator(s)",
                )
            )
        host_type = IndicatorType.DOMAIN if comps["host_kind"] == "domain" else IndicatorType.IP
        host = comps["host"].strip("[]")
        host_ind = parse_indicator(host, host_type)
        rels = [
            RelationshipDraft(
                src_type=IndicatorType.URL,
                src_value=p.value,
                dst_type=host_ind.type,
                dst_value=host_ind.value,
                rel_type="hosted_on",
                assurance=Assurance.VERIFIED,
                attrs={"basis": "URL host component"},
            )
        ]
        return ProviderResult.ok(observations=observations, relationships=rels)

    def _hash(self, p: ParsedIndicator) -> ProviderResult:
        data: dict[str, object] = {
            "algorithm": p.subtype,
            "bits": {"md5": 128, "sha1": 160, "sha256": 256}[p.subtype or "sha256"],
            "note": _HASH_NOTE,
        }
        known = KNOWN_TEST_FILES.get(p.value)
        if known:
            data["known_test_file"] = known
        obs = [
            ObservationDraft(
                kind="local.hash_info",
                title="Hash recognition",
                assurance=Assurance.VERIFIED,
                data=data,
                summary=(
                    f"{(p.subtype or '').upper()} — matches the {known} standard anti-malware test file"
                    if known
                    else f"{(p.subtype or '').upper()} digest"
                ),
            )
        ]
        return ProviderResult.ok(
            observations=obs, tags=[f"test-file:{known.lower()}"] if known else []
        )

    def _certificate(self, p: ParsedIndicator) -> ProviderResult:
        return ProviderResult.ok(
            observations=[
                ObservationDraft(
                    kind="local.certificate_id",
                    title="Certificate identifier",
                    assurance=Assurance.VERIFIED,
                    data={"form": p.subtype, "value": p.value},
                    summary="SHA-256 fingerprint" if p.subtype == "sha256" else "crt.sh record id",
                )
            ]
        )

    def _asn(self, p: ParsedIndicator) -> ProviderResult:
        return ProviderResult.ok(
            observations=[
                ObservationDraft(
                    kind="local.asn_info",
                    title="AS number",
                    assurance=Assurance.VERIFIED,
                    data={"asn": int(p.value[2:]), "scope": p.scope},
                    summary=f"{p.value} ({p.scope})",
                )
            ]
        )

    def _email(self, p: ParsedIndicator) -> ProviderResult:
        domain = email_domain(p.value)
        local_part = p.value.split("@", 1)[0]
        return ProviderResult.ok(
            observations=[
                ObservationDraft(
                    kind="local.email_info",
                    title="Address structure",
                    assurance=Assurance.VERIFIED,
                    data={
                        "domain": domain,
                        "registered_domain": registered_domain(domain),
                        "local_part_length": len(local_part),
                        "plus_addressing": "+" in local_part,
                    },
                    summary=f"Mailbox at {domain}",
                )
            ],
            relationships=[
                RelationshipDraft(
                    src_type=IndicatorType.EMAIL,
                    src_value=p.value,
                    dst_type=IndicatorType.DOMAIN,
                    dst_value=domain,
                    rel_type="mailbox_at",
                    assurance=Assurance.VERIFIED,
                    attrs={"basis": "address syntax"},
                )
            ],
        )
