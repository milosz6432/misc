"""Keyless providers: local, dns, rdap, cymru, crtsh, geoip, probe."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from hunterintel.config import Settings
from hunterintel.domain.evidence import Assurance, RunStatus
from hunterintel.domain.indicators import IndicatorType, parse_indicator
from hunterintel.providers.crtsh import CrtShProvider, summarise
from hunterintel.providers.cymru import CymruProvider, origin_query_name, parse_asname, parse_origin
from hunterintel.providers.dns_records import DnsProvider, parse_dmarc, parse_spf
from hunterintel.providers.dnsclient import DnsAnswer
from hunterintel.providers.geoip import GeoIPProvider
from hunterintel.providers.local import LocalProvider
from hunterintel.providers.probe import ProbeProvider
from hunterintel.providers.rdap import (
    BOOTSTRAP,
    RdapProvider,
    find_asn_service,
    find_dns_service,
    find_ip_service,
    parse_domain,
)
from tests.helpers import FakeDns, json_response, make_ctx

# ── local ────────────────────────────────────────────────────────────────────


async def run(provider, raw: str, ctx, forced=None):  # noqa: ANN001, ANN201
    return await provider.lookup(parse_indicator(raw, forced), ctx)


async def test_local_domain_structure_and_subdomain_edge(settings: Settings) -> None:
    res = await run(LocalProvider(settings), "a.b.example.co.uk", make_ctx(settings))
    obs = res.observations[0]
    assert obs.assurance is Assurance.VERIFIED and obs.data["registered_domain"] == "example.co.uk"
    assert [(r.rel_type, r.dst_value) for r in res.relationships] == [
        ("subdomain_of", "example.co.uk")
    ]


async def test_local_url_has_components_flags_and_host_edge(settings: Settings) -> None:
    res = await run(LocalProvider(settings), "http://8.8.8.8:8080/update.exe", make_ctx(settings))
    kinds = {o.kind: o for o in res.observations}
    assert kinds["local.url_components"].assurance is Assurance.VERIFIED
    assert kinds["risk_flags"].assurance is Assurance.INFERRED  # heuristics are never "verified"
    ids = {f["id"] for f in kinds["risk_flags"].data["flags"]}
    assert {"ip_literal_host", "non_standard_port", "executable_payload_extension"} <= ids
    assert (res.relationships[0].dst_type, res.relationships[0].dst_value) == (
        IndicatorType.IP,
        "8.8.8.8",
    )


async def test_local_hash_explains_it_cannot_know_file_type_and_recognises_eicar(
    settings: Settings,
) -> None:
    eicar = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    res = await run(LocalProvider(settings), eicar, make_ctx(settings))
    data = res.observations[0].data
    assert data["algorithm"] == "sha256" and data["known_test_file"] == "EICAR"
    assert "no file-type information" in data["note"]
    other = await run(LocalProvider(settings), "a" * 32, make_ctx(settings))
    assert "known_test_file" not in other.observations[0].data


async def test_local_email_and_ip_and_asn(settings: Settings) -> None:
    ctx = make_ctx(settings)
    email = await run(LocalProvider(settings), "ops+tag@mail.example.com", ctx)
    assert (
        email.relationships[0].rel_type == "mailbox_at"
        and email.observations[0].data["plus_addressing"]
    )
    ip = await run(LocalProvider(settings), "2001:4860:4860::8888", ctx)
    assert ip.observations[0].data["globally_routable"] and ip.observations[0].data["version"] == 6
    asn = await run(LocalProvider(settings), "AS13335", ctx)
    assert asn.observations[0].data["asn"] == 13335


# ── dns ──────────────────────────────────────────────────────────────────────


def test_spf_and_dmarc_parsing() -> None:
    spf = parse_spf(
        ["google-site-verification=x", "v=spf1 include:_spf.example.net ip4:192.0.2.0/24 -all"]
    )
    assert spf and spf["policy"] == "fail (reject)" and spf["includes"] == ["_spf.example.net"]
    assert parse_spf(["v=spf1 +all"])["policy"].startswith("pass")  # type: ignore[index]
    assert parse_spf(["unrelated"]) is None
    d = parse_dmarc(["v=DMARC1; p=reject; rua=mailto:r@example.com; pct=100"])
    assert d and d["policy"] == "reject" and d["rua"] == "mailto:r@example.com"


async def test_dns_domain_records_edges_and_assurance(settings: Settings) -> None:
    dns = FakeDns(
        {
            ("example.com", "A"): ["198.51.100.10", "198.51.100.11"],
            ("example.com", "AAAA"): ["2001:db8::10"],
            ("example.com", "NS"): ["ns1.dns-host.net", "ns2.dns-host.net"],
            ("example.com", "MX"): [{"preference": 10, "exchange": "mail.example.com"}],
            ("example.com", "TXT"): ["v=spf1 -all"],
            ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=none"],
        }
    )
    res = await run(DnsProvider(settings), "example.com", make_ctx(settings, dns=dns))
    assert res.status is RunStatus.OK
    kinds = {o.kind: o for o in res.observations}
    assert kinds["dns.records"].assurance is Assurance.VERIFIED
    assert kinds["dns.records"].data["records"]["A"] == ["198.51.100.10", "198.51.100.11"]
    assert kinds["dns.email_security"].data["dmarc"]["policy"] == "none"
    edges = {(r.rel_type, r.dst_value) for r in res.relationships}
    assert {
        ("resolves_to", "198.51.100.10"),
        ("resolves_to", "2001:db8::10"),
        ("has_nameserver", "ns1.dns-host.net"),
        ("has_mx", "mail.example.com"),
    } <= edges
    assert all(r.assurance is Assurance.VERIFIED for r in res.relationships)


async def test_dns_nxdomain_is_a_verified_negative_not_an_error(settings: Settings) -> None:
    dns = FakeDns(
        {
            ("gone.example.com", t): DnsAnswer("NXDOMAIN")
            for t in ("A", "AAAA", "NS", "MX", "TXT", "CNAME", "SOA", "CAA")
        }
    )
    res = await run(DnsProvider(settings), "gone.example.com", make_ctx(settings, dns=dns))
    assert res.status is RunStatus.OK
    assert res.observations[0].data["nxdomain"] is True and "NXDOMAIN" in (
        res.observations[0].summary or ""
    )


async def test_dns_total_failure_is_reported_not_hidden(settings: Settings) -> None:
    dns = FakeDns(
        {
            ("slow.example.com", t): DnsAnswer("TIMEOUT", error="resolver timed out")
            for t in ("A", "AAAA", "NS", "MX", "TXT", "CNAME", "SOA", "CAA")
        }
    )
    res = await run(DnsProvider(settings), "slow.example.com", make_ctx(settings, dns=dns))
    assert res.status is RunStatus.TIMEOUT and not res.observations


async def test_dns_email_only_queries_the_domain_part(settings: Settings) -> None:
    dns = FakeDns({("example.com", "MX"): [{"preference": 5, "exchange": "mx.example.com"}]})
    provider = DnsProvider(settings)
    res = await run(provider, "secret.mailbox@example.com", make_ctx(settings, dns=dns))
    assert res.status is RunStatus.OK
    assert all("secret" not in name for name, _ in dns.calls)  # mailbox name never queried
    assert "never sent" in provider.data_shared(parse_indicator("secret.mailbox@example.com"))
    assert {r.src_type for r in res.relationships} <= {IndicatorType.DOMAIN}


async def test_dns_reverse_with_forward_confirmation(settings: Settings) -> None:
    dns = FakeDns(
        {
            ("10.113.0.203.in-addr.arpa", "PTR"): ["host.example.net", "liar.example.org"],
            ("host.example.net", "A"): ["203.0.113.10"],
            ("liar.example.org", "A"): ["198.51.100.1"],
        }
    )
    res = await run(DnsProvider(settings), "203.0.113.10", make_ctx(settings, dns=dns))
    data = res.observations[0].data
    assert data["fcrdns"] is True
    conf = {c["name"]: c["forward_confirmed"] for c in data["forward_confirmation"]}
    assert conf == {"host.example.net": True, "liar.example.org": False}
    assert {r.dst_value: r.attrs["forward_confirmed"] for r in res.relationships} == {
        "host.example.net": True,
        "liar.example.org": False,
    }


async def test_dns_reverse_without_ptr(settings: Settings) -> None:
    res = await run(DnsProvider(settings), "203.0.113.77", make_ctx(settings))
    assert res.observations[0].data["ptr"] == [] and "No PTR" in (res.observations[0].summary or "")


# ── rdap ─────────────────────────────────────────────────────────────────────

DNS_BOOT = {
    "services": [
        [["com", "net"], ["https://rdap.registry-a.net/"]],
        [["org"], ["http://insecure.net/", "https://rdap.registry-b.net/"]],
    ]
}
IPV4_BOOT = {
    "services": [
        [["8.0.0.0/8"], ["https://rdap.rir-a.net/"]],
        [["8.8.0.0/16"], ["https://rdap.rir-b.net/"]],
    ]
}
ASN_BOOT = {"services": [[["1-1876", "1902-2042", "15169"], ["https://rdap.rir-a.net/"]]]}

NOW = datetime(2026, 11, 4, tzinfo=UTC)


def vcard(fn: str, *extra: list, kind: str | None = None) -> list:
    items = [["version", {}, "text", "4.0"], ["fn", {}, "text", fn], *extra]
    if kind:
        items.append(["kind", {}, "text", kind])
    return ["vcard", items]


def domain_doc(registered: datetime) -> dict:
    return {
        "objectClassName": "domain",
        "ldhName": "EXAMPLE.COM",
        "status": ["client transfer prohibited", "server hold"],
        "events": [
            {
                "eventAction": "registration",
                "eventDate": registered.isoformat().replace("+00:00", "Z"),
            },
            {"eventAction": "expiration", "eventDate": "2027-01-01T00:00:00Z"},
            {"eventAction": "last changed", "eventDate": "2026-01-01T00:00:00Z"},
        ],
        "nameservers": [{"ldhName": "NS1.DNS-HOST.NET"}, {"ldhName": "NS2.DNS-HOST.NET"}],
        "secureDNS": {"delegationSigned": True},
        "entities": [
            {
                "roles": ["registrar"],
                "publicIds": [{"type": "IANA Registrar ID", "identifier": "9999"}],
                "vcardArray": vcard("Example Registrar, Inc."),
                "entities": [
                    {
                        "roles": ["abuse"],
                        "vcardArray": vcard("", ["email", {}, "text", "abuse@registrar.example"]),
                    }
                ],
            },
            {
                "roles": ["registrant"],
                "vcardArray": vcard(
                    "Private Person Name",
                    ["email", {}, "text", "person@example.org"],
                    kind="individual",
                ),
            },
        ],
    }


def rdap_handler(
    domain_payload: dict | None = None, status: int = 200
) -> Callable[[httpx.Request], httpx.Response]:
    def handler(req: httpx.Request) -> httpx.Response:
        url = str(req.url)
        if url == BOOTSTRAP["dns"]:
            return json_response(DNS_BOOT)
        if url == BOOTSTRAP["ipv4"]:
            return json_response(IPV4_BOOT)
        if url == BOOTSTRAP["asn"]:
            return json_response(ASN_BOOT)
        if req.url.host == "rdap.registry-a.net":
            return (
                json_response(domain_payload, status)
                if domain_payload is not None
                else httpx.Response(status)
            )
        if req.url.host == "rdap.rir-b.net" and "/ip/" in url:
            return json_response(
                {
                    "name": "EXAMPLE-NET",
                    "handle": "NET-8-8-8-0-1",
                    "type": "ALLOCATION",
                    "country": "US",
                    "startAddress": "8.8.8.0",
                    "endAddress": "8.8.8.255",
                    "cidr0_cidrs": [{"v4prefix": "8.8.8.0", "length": 24}],
                    "events": [
                        {"eventAction": "registration", "eventDate": "2014-03-14T00:00:00Z"}
                    ],
                    "entities": [
                        {
                            "roles": ["registrant"],
                            "vcardArray": vcard("Example Networks LLC", kind="org"),
                        },
                        {
                            "roles": ["abuse"],
                            "vcardArray": vcard(
                                "Abuse Desk", ["email", {}, "text", "abuse@net.example"]
                            ),
                        },
                    ],
                }
            )
        if req.url.host == "rdap.rir-a.net" and "/autnum/" in url:
            return json_response(
                {
                    "name": "EXAMPLE-AS",
                    "handle": "AS15169",
                    "country": "US",
                    "startAutnum": 15169,
                    "endAutnum": 15169,
                    "entities": [
                        {"roles": ["registrant"], "vcardArray": vcard("Example Networks LLC")}
                    ],
                }
            )
        return httpx.Response(404)

    return handler


def test_bootstrap_selection_rules() -> None:
    assert find_dns_service(DNS_BOOT, "COM") == "https://rdap.registry-a.net/"
    assert find_dns_service(DNS_BOOT, "org") == "https://rdap.registry-b.net/"  # https preferred
    assert find_dns_service(DNS_BOOT, "xyz") is None
    import ipaddress

    assert (
        find_ip_service(IPV4_BOOT, ipaddress.ip_address("8.8.8.8")) == "https://rdap.rir-b.net/"
    )  # most specific
    assert find_ip_service(IPV4_BOOT, ipaddress.ip_address("8.9.9.9")) == "https://rdap.rir-a.net/"
    assert find_ip_service(IPV4_BOOT, ipaddress.ip_address("9.9.9.9")) is None
    assert (
        find_asn_service(ASN_BOOT, 1500)
        and find_asn_service(ASN_BOOT, 15169)
        and not find_asn_service(ASN_BOOT, 99999)
    )


def test_rdap_domain_parsing_drops_personal_data_and_flags_new_domains() -> None:
    data, flags, ns = parse_domain(domain_doc(NOW - timedelta(days=3)), now=NOW)
    assert data["age_days"] == 3 and data["registrar"] == {
        "name": "Example Registrar, Inc.",
        "iana_id": "9999",
        "abuse_email": "abuse@registrar.example",
    }
    assert ns == ["ns1.dns-host.net", "ns2.dns-host.net"]
    blob = str(data)
    assert "Private Person" not in blob and "person@example.org" not in blob
    ids = {f.id: f.severity.value for f in flags}
    assert ids["newly_registered_domain"] == "high" and "registry_hold_status" in ids
    _, old_flags, _ = parse_domain(domain_doc(NOW - timedelta(days=4000)), now=NOW)
    assert "newly_registered_domain" not in {f.id for f in old_flags}


async def test_rdap_domain_end_to_end(settings: Settings) -> None:
    res = await run(
        RdapProvider(settings),
        "www.example.com",
        make_ctx(settings, rdap_handler(domain_doc(datetime(2001, 1, 1, tzinfo=UTC)))),
    )
    assert res.status is RunStatus.OK
    obs = res.observations[0]
    assert obs.kind == "rdap.domain" and obs.assurance is Assurance.VERIFIED
    assert obs.data["queried_domain"] == "example.com" and "www.example.com" in obs.data["note"]
    assert res.relationships == []  # NS edges only for the registrable domain itself


async def test_rdap_apex_domain_adds_nameserver_edges(settings: Settings) -> None:
    res = await run(
        RdapProvider(settings),
        "example.com",
        make_ctx(settings, rdap_handler(domain_doc(datetime(2001, 1, 1, tzinfo=UTC)))),
    )
    assert {r.dst_value for r in res.relationships} == {"ns1.dns-host.net", "ns2.dns-host.net"}


async def test_rdap_not_found_is_no_data_and_unknown_tld_is_explained(settings: Settings) -> None:
    res = await run(
        RdapProvider(settings), "unregistered.com", make_ctx(settings, rdap_handler(None, 404))
    )
    assert res.status is RunStatus.NO_DATA
    res = await run(RdapProvider(settings), "something.xyz", make_ctx(settings, rdap_handler()))
    assert res.status is RunStatus.NO_DATA and ".xyz" in (res.message or "")


async def test_rdap_rate_limit_and_server_error_surface(settings: Settings) -> None:
    res = await run(
        RdapProvider(settings), "example.com", make_ctx(settings, rdap_handler(None, 429))
    )
    assert res.status is RunStatus.RATE_LIMITED
    res = await run(
        RdapProvider(settings), "example.com", make_ctx(settings, rdap_handler(None, 503))
    )
    assert res.status is RunStatus.ERROR and "503" in (res.message or "")


async def test_rdap_ip_network_ownership_excludes_individuals(settings: Settings) -> None:
    res = await run(RdapProvider(settings), "8.8.8.8", make_ctx(settings, rdap_handler()))
    d = res.observations[0].data
    assert (
        d["name"] == "EXAMPLE-NET"
        and d["cidrs"] == ["8.8.8.0/24"]
        and d["owner_organisations"] == ["Example Networks LLC"]
    )
    assert (
        d["registration_country"] == "US"
        and "not where the hosts physically are" in d["accuracy_note"]
    )


async def test_rdap_asn(settings: Settings) -> None:
    res = await run(RdapProvider(settings), "AS15169", make_ctx(settings, rdap_handler()))
    assert (
        res.observations[0].kind == "rdap.autnum"
        and res.observations[0].data["name"] == "EXAMPLE-AS"
    )


# ── cymru ────────────────────────────────────────────────────────────────────


def test_cymru_query_names_and_parsing() -> None:
    import ipaddress

    assert (
        origin_query_name(ipaddress.ip_address("203.0.113.10"))
        == "10.113.0.203.origin.asn.cymru.com"
    )
    v6 = origin_query_name(ipaddress.ip_address("2001:db8::1"))
    assert v6.startswith("1.0.0.0.") and v6.endswith(".8.b.d.0.1.0.0.2.origin6.asn.cymru.com")
    assert len(v6.split(".")) == 32 + 4
    assert parse_origin('"64500 64501 | 203.0.113.0/24 | US | arin | 2010-01-01"') == {
        "asns": [64500, 64501],
        "prefix": "203.0.113.0/24",
        "registry_country": "US",
        "registry": "arin",
        "allocated": "2010-01-01",
    }
    assert parse_origin("garbage") is None
    assert (
        parse_asname('"64500 | US | arin | 2001-02-03 | EXAMPLE-AS, US"')["name"]
        == "EXAMPLE-AS, US"
    )  # type: ignore[index]


async def test_cymru_lookup_is_a_provider_claim(settings: Settings) -> None:
    dns = FakeDns(
        {
            ("10.113.0.203.origin.asn.cymru.com", "TXT"): [
                "64500 | 203.0.113.0/24 | US | arin | 2010-01-01"
            ],
            ("AS64500.asn.cymru.com", "TXT"): ["64500 | US | arin | 2001-02-03 | EXAMPLE-AS, US"],
        }
    )
    res = await run(CymruProvider(settings), "203.0.113.10", make_ctx(settings, dns=dns))
    obs = res.observations[0]
    assert obs.assurance is Assurance.PROVIDER_CLAIM and obs.data["as_name"] == "EXAMPLE-AS, US"
    assert "not a physical location" in obs.data["caveat"]
    rel = res.relationships[0]
    assert (rel.rel_type, rel.dst_value, rel.assurance) == (
        "belongs_to_asn",
        "AS64500",
        Assurance.PROVIDER_CLAIM,
    )


async def test_cymru_unannounced_space_is_no_data(settings: Settings) -> None:
    res = await run(CymruProvider(settings), "203.0.113.10", make_ctx(settings))
    assert res.status is RunStatus.NO_DATA


# ── crt.sh ───────────────────────────────────────────────────────────────────

CT_ROWS = [
    {
        "id": 1002,
        "issuer_ca_id": 7,
        "issuer_name": "C=US, O=Example CA, CN=Example CA R1",
        "common_name": "example.com",
        "name_value": "example.com\nwww.example.com\n*.example.com",
        "serial_number": "AA11",
        "not_before": "2025-01-01T00:00:00",
        "not_after": "2025-04-01T00:00:00",
        "entry_timestamp": "2025-01-01T01:00:00.123",
    },
    {
        "id": 1001,
        "issuer_ca_id": 7,
        "issuer_name": "C=US, O=Example CA, CN=Example CA R1",
        "common_name": "example.com",
        "name_value": "example.com\nwww.example.com\n*.example.com",
        "serial_number": "AA11",
        "not_before": "2025-01-01T00:00:00",
        "not_after": "2025-04-01T00:00:00",
        "entry_timestamp": "2025-01-01T00:59:00.000",
    },  # pre-cert twin
    {
        "id": 900,
        "issuer_ca_id": 8,
        "issuer_name": "C=US, O=Other CA, CN=Other CA",
        "common_name": "dev.example.com",
        "name_value": "dev.example.com\ninternal.corp.local",
        "serial_number": "BB22",
        "not_before": "2024-06-01T00:00:00",
        "not_after": "2024-09-01T00:00:00",
        "entry_timestamp": "2024-06-01T00:00:00.000",
    },
]


def test_crtsh_summary_dedupes_precert_twins_and_caps() -> None:
    s = summarise(CT_ROWS, cap=10)
    assert s["total_rows"] == 3 and s["unique_certificates"] == 2
    top = s["certificates"][0]
    assert top["crtsh_id"] == 1001 and top["ct_entry_ids"] == [
        1001,
        1002,
    ]  # lowest id kept, twins recorded
    assert summarise(CT_ROWS, cap=1)["truncated"] is True


async def test_crtsh_domain_lookup(settings: Settings) -> None:
    seen: dict[str, str] = {}

    def handler(req: httpx.Request) -> httpx.Response:
        seen.update(dict(req.url.params))
        return json_response(CT_ROWS)

    res = await run(CrtShProvider(settings), "example.com", make_ctx(settings, handler))
    assert seen == {"q": "%.example.com", "output": "json"}
    obs = res.observations[0]
    assert obs.assurance is Assurance.PROVIDER_CLAIM and "dev.example.com" in obs.data["subdomains"]
    assert "*.example.com" in obs.data["wildcards"] and "requested and issued" in obs.data["caveat"]
    covered = {r.dst_value for r in res.relationships if r.rel_type == "covers"}
    assert "dev.example.com" in covered and "www.example.com" in covered
    assert (
        "internal.corp.local" not in covered
    )  # internal names are never turned into lookup targets
    assert {r.dst_value for r in res.relationships if r.rel_type == "has_certificate"} == {
        "crtsh:1001",
        "crtsh:900",
    }


async def test_crtsh_overload_html_is_an_error_not_empty(settings: Settings) -> None:
    html = lambda req: httpx.Response(200, text="<html>Sorry, the service is busy</html>")  # noqa: E731
    res = await run(CrtShProvider(settings), "example.com", make_ctx(settings, html))
    assert res.status is RunStatus.ERROR and "non-JSON" in (res.message or "")
    res = await run(
        CrtShProvider(settings), "example.com", make_ctx(settings, lambda r: httpx.Response(504))
    )
    assert res.status is RunStatus.ERROR and "overloaded" in (res.message or "")


async def test_crtsh_empty_listing_is_no_data(settings: Settings) -> None:
    res = await run(
        CrtShProvider(settings), "example.com", make_ctx(settings, lambda r: json_response([]))
    )
    assert res.status is RunStatus.NO_DATA


async def test_crtsh_certificate_lookup_by_id(settings: Settings) -> None:
    seen: dict[str, str] = {}

    def handler(req: httpx.Request) -> httpx.Response:
        seen.update(dict(req.url.params))
        return json_response([CT_ROWS[0]])

    res = await run(CrtShProvider(settings), "crtsh:1002", make_ctx(settings, handler))
    assert seen["q"] == "1002"
    assert res.observations[0].kind == "ct.certificate"
    assert {r.dst_value for r in res.relationships} == {"example.com", "www.example.com"}


# ── geoip ────────────────────────────────────────────────────────────────────


def test_geoip_not_configured_without_a_file(
    settings: Settings, make_settings: Callable[..., Settings]
) -> None:
    assert not GeoIPProvider(settings).is_configured()
    assert not GeoIPProvider(make_settings(geoip_db_path="/nonexistent.mmdb")).is_configured()


async def test_geoip_reports_accuracy_caveat(
    tmp_path, make_settings: Callable[..., Settings]
) -> None:  # noqa: ANN001
    db = tmp_path / "fake.mmdb"
    db.write_bytes(b"x")
    provider = GeoIPProvider(make_settings(geoip_db_path=str(db)))
    assert provider.is_configured()

    class Meta:
        database_type, build_epoch = "Test-City", 1700000000

    class Reader:
        def get(self, ip: str) -> dict:
            return {
                "country": {"iso_code": "DE", "names": {"en": "Germany"}},
                "city": {"names": {"en": "Berlin"}},
                "location": {"latitude": 52.5, "longitude": 13.4, "accuracy_radius": 100},
            }

        def metadata(self) -> Meta:
            return Meta()

    provider._reader = Reader()  # type: ignore[assignment]
    res = await run(provider, "1.1.1.1", make_ctx(provider.settings))
    obs = res.observations[0]
    assert obs.assurance is Assurance.PROVIDER_CLAIM and obs.data["city"] == "Berlin"
    assert "statistical" in obs.data["accuracy_note"] and obs.summary.endswith("(approximate)")  # type: ignore[union-attr]


# ── probe ────────────────────────────────────────────────────────────────────


async def test_probe_disabled_by_default(settings: Settings) -> None:
    p = ProbeProvider(settings)
    assert not p.is_configured() and "ALLOW_ACTIVE_PROBES" in p.not_configured_reason()
    assert "destination will see this server's IP" in p.data_shared(
        parse_indicator("http://example.com/")
    )


async def test_probe_interprets_chain(make_settings: Callable[..., Settings]) -> None:
    from hunterintel.core.http import ProbeHop, ProbeResult

    s = make_settings(allow_active_probes=True)
    ctx = make_ctx(s)

    async def fake_probe(url: str) -> ProbeResult:
        return ProbeResult(
            start_url=url,
            completed=True,
            final_url="http://landing.other-example.net/p",
            hops=[
                ProbeHop(
                    "https://short.example.com/x",
                    301,
                    "HEAD",
                    "http://mid.example.org/a",
                    "203.0.113.5",
                ),
                ProbeHop("http://mid.example.org/a", 302, "HEAD", "http://x.example.org/b"),
                ProbeHop(
                    "http://x.example.org/b", 302, "HEAD", "http://landing.other-example.net/p"
                ),
                ProbeHop("http://landing.other-example.net/p", 200, "GET"),
            ],
        )

    ctx.http.probe_redirects = fake_probe  # type: ignore[method-assign]
    res = await ProbeProvider(s).lookup(parse_indicator("https://short.example.com/x"), ctx)
    kinds = {o.kind: o for o in res.observations}
    assert kinds["probe.redirect_chain"].assurance is Assurance.VERIFIED
    flag_ids = {f["id"] for f in kinds["risk_flags"].data["flags"]}
    assert flag_ids == {"cross_domain_redirect", "long_redirect_chain", "https_downgrade"}
    assert kinds["risk_flags"].assurance is Assurance.INFERRED
    assert len(res.relationships) == 3 and all(
        r.rel_type == "redirects_to" for r in res.relationships
    )


async def test_probe_reports_policy_block(make_settings: Callable[..., Settings]) -> None:
    from hunterintel.core.http import ProbeResult

    s = make_settings(allow_active_probes=True)
    ctx = make_ctx(s)

    async def blocked(url: str) -> ProbeResult:
        return ProbeResult(
            start_url=url, stopped_reason="blocked: 'x' resolves to a non-public address"
        )

    ctx.http.probe_redirects = blocked  # type: ignore[method-assign]
    res = await ProbeProvider(s).lookup(parse_indicator("http://example.com/"), ctx)
    assert res.status is RunStatus.BLOCKED and "non-public" in (res.message or "")


@pytest.mark.parametrize(
    "raw", ["http://example.com", "example.com", "8.8.8.8", "AS15169", "a@example.com"]
)
def test_provider_support_matrix(settings: Settings, raw: str) -> None:
    p = parse_indicator(raw)
    assert LocalProvider(settings).can_handle(p)
    assert DnsProvider(settings).can_handle(p) == (
        p.type in (IndicatorType.DOMAIN, IndicatorType.IP, IndicatorType.EMAIL)
    )
    assert CrtShProvider(settings).can_handle(p) == (p.type is IndicatorType.DOMAIN)
