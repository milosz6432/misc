from __future__ import annotations

import pytest

from hunterintel.domain.indicators import (
    IndicatorParseError,
    IndicatorType,
    normalize_domain,
    parse_indicator,
    refang,
    registered_domain,
    try_parse,
)
from hunterintel.domain.urlanalysis import analyze_url

EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
EICAR_SHA1 = "3395856ce81f2b7382dee72602f798b642f14140"
EICAR_MD5 = "44d88612fea8a8f36de82e1278abb02f"


@pytest.mark.parametrize(
    ("raw", "type_", "value"),
    [
        ("Example.COM", IndicatorType.DOMAIN, "example.com"),
        ("example.com.", IndicatorType.DOMAIN, "example.com"),
        ("*.example.com", IndicatorType.DOMAIN, "example.com"),
        ("bücher.de", IndicatorType.DOMAIN, "xn--bcher-kva.de"),
        ("_dmarc.example.com", IndicatorType.DOMAIN, "_dmarc.example.com"),
        ("8.8.8.8", IndicatorType.IP, "8.8.8.8"),
        ("2606:4700:4700:0:0:0:0:1111", IndicatorType.IP, "2606:4700:4700::1111"),
        ("[2001:4860:4860::8888]", IndicatorType.IP, "2001:4860:4860::8888"),
        (EICAR_SHA256.upper(), IndicatorType.HASH, EICAR_SHA256),
        (EICAR_SHA1, IndicatorType.HASH, EICAR_SHA1),
        (EICAR_MD5, IndicatorType.HASH, EICAR_MD5),
        ("AS15169", IndicatorType.ASN, "AS15169"),
        ("ASN13335", IndicatorType.ASN, "AS13335"),
        ("Analyst@Example.COM", IndicatorType.EMAIL, "analyst@example.com"),
        ("<a@example.com>", IndicatorType.EMAIL, "a@example.com"),
    ],
)
def test_detects_and_normalises(raw: str, type_: IndicatorType, value: str) -> None:
    parsed = parse_indicator(raw)
    assert (parsed.type, parsed.value) == (type_, value)


def test_hash_subtypes() -> None:
    assert parse_indicator(EICAR_MD5).subtype == "md5"
    assert parse_indicator(EICAR_SHA1).subtype == "sha1"
    assert parse_indicator(EICAR_SHA256).subtype == "sha256"


def test_certificate_requires_explicit_intent() -> None:
    """A 64-hex string is a file hash unless the analyst says certificate."""
    assert parse_indicator(EICAR_SHA256).type is IndicatorType.HASH
    cert = parse_indicator(f"cert:{EICAR_SHA256.upper()}")
    assert (cert.type, cert.value, cert.subtype) == (
        IndicatorType.CERTIFICATE,
        EICAR_SHA256,
        "sha256",
    )
    assert parse_indicator(EICAR_SHA256, "certificate").type is IndicatorType.CERTIFICATE
    colon = ":".join(EICAR_SHA256[i : i + 2] for i in range(0, 64, 2))
    assert parse_indicator(f"cert:{colon}").value == EICAR_SHA256
    crt = parse_indicator("crtsh:6543210")
    assert (crt.value, crt.subtype) == ("crtsh:6543210", "crtsh_id")


def test_defanged_input_is_restored() -> None:
    p = parse_indicator("hxxps://evil[.]example[.]com/login")
    assert p.type is IndicatorType.URL and p.value == "https://evil.example.com/login"
    assert any("defanged" in n for n in p.notes)
    assert parse_indicator("evil[.]example[.]com").value == "evil.example.com"
    assert parse_indicator("user[@]example[.]com").value == "user@example.com"
    assert refang("nothing") == ("nothing", False)


@pytest.mark.parametrize(
    ("raw", "canonical"),
    [
        ("HTTP://Example.COM:80/a/./b/../c?x=1#frag", "http://example.com/a/c?x=1"),
        ("https://example.com:443", "https://example.com/"),
        ("https://example.com:8443/x", "https://example.com:8443/x"),
        ("example.com/path", "http://example.com/path"),
        ("http://bücher.de/ü", "http://xn--bcher-kva.de/%C3%BC"),
        ("http://example.com/%7euser/%2fx", "http://example.com/~user/%2Fx"),
        ("http://2130706433/x", "http://127.0.0.1/x"),
        ("http://0x7f.1/", "http://127.0.0.1/"),
        ("http://[::1]:8080/", "http://[::1]:8080/"),
    ],
)
def test_url_canonicalisation(raw: str, canonical: str) -> None:
    assert parse_indicator(raw).value == canonical


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "not an indicator",
        "localhost-only",
        "a" * 2100,
        "javascript:alert(1)",
        "file:///etc/passwd",
        "ftp2://x.com",
        "http://",
        "999.999.999.999",
        "1.2.3.4.5",
        "AS99999999999",
        "cert:abc",
        "a@",
        "@example.com",
        "a b@example.com",
        "example..com",
        "-bad.example.com",
        "ex ample.com",
        "dead" * 25,
    ],
)
def test_rejects_garbage(raw: str) -> None:
    with pytest.raises(IndicatorParseError):
        parse_indicator(raw)


def test_control_characters_and_whitespace_rejected() -> None:
    for raw in ["example.com\nHost: evil", "exa\x00mple.com", "http://example.com/a b"]:
        with pytest.raises(IndicatorParseError):
            parse_indicator(raw)


def test_bare_numbers_are_never_silently_ips() -> None:
    for raw in ["2130706433", "12345", "127.1"]:
        assert try_parse(raw) is None or try_parse(raw).type is not IndicatorType.IP  # type: ignore[union-attr]
    forced = parse_indicator("127.1", "ip")
    assert forced.value == "127.0.0.1" and not forced.remote_lookup_allowed


@pytest.mark.parametrize(
    ("raw", "scope"),
    [
        ("10.1.2.3", "private"),
        ("127.0.0.1", "loopback"),
        ("169.254.169.254", "link_local"),
        ("100.64.1.1", "cgnat"),
        ("192.0.2.1", "documentation"),
        ("::1", "loopback"),
        ("fd12:3456::1", "private"),
        ("::ffff:192.168.1.1", "private"),
    ],
)
def test_non_public_ips_block_remote_lookups(raw: str, scope: str) -> None:
    p = parse_indicator(raw)
    assert p.scope == scope and not p.remote_lookup_allowed and p.blocked_reason


@pytest.mark.parametrize(
    "raw",
    [
        "fileserver.corp.internal",
        "printer.local",
        "nas.home.arpa",
        "site.test",
        "http://10.0.0.5/admin",
        "http://intranet.lan/x",
        "http://127.0.0.1:8080/",
        "http://2130706433/",
        "bob@mail.corp.local",
    ],
)
def test_internal_names_and_urls_block_remote_lookups(raw: str) -> None:
    p = parse_indicator(raw)
    assert not p.remote_lookup_allowed and p.blocked_reason and "disabled" in p.blocked_reason


def test_public_indicators_allow_lookups() -> None:
    for raw in ["example.com", "1.1.1.1", "https://example.com/a", EICAR_SHA256, "AS13335"]:
        assert parse_indicator(raw).remote_lookup_allowed


def test_email_is_marked_sensitive() -> None:
    assert parse_indicator("alice@example.com").sensitive
    assert not parse_indicator("example.com").sensitive


def test_registered_domain_uses_public_suffix_list() -> None:
    assert registered_domain("a.b.example.co.uk") == "example.co.uk"
    assert registered_domain("www.example.com") == "example.com"
    assert registered_domain("localhost.corp") is None


def test_normalize_domain_validation() -> None:
    assert normalize_domain("XN--BCHER-KVA.de") == "xn--bcher-kva.de"
    for bad in ["x", "a.b.123", "a.-b.com", "a" * 64 + ".com", ("a" * 60 + ".") * 5 + "com"]:
        with pytest.raises(IndicatorParseError):
            normalize_domain(bad)


def flag_ids(url: str) -> set[str]:
    return {f.id for f in analyze_url(parse_indicator(url).value)["flags"]}


def test_url_analysis_components() -> None:
    a = analyze_url(
        parse_indicator("https://login.secure.example.co.uk:8443/a/b/setup.exe?id=1&t=x").value
    )
    c = a["components"]
    assert (c["scheme"], c["host"], c["port"], c["path_depth"], c["file_extension"]) == (
        "https",
        "login.secure.example.co.uk",
        8443,
        3,
        "exe",
    )
    assert c["registered_domain"] == "example.co.uk" and c["subdomain"] == "login.secure"
    assert c["query_parameters"] == ["id", "t"]


def test_url_heuristics_fire_only_when_warranted() -> None:
    assert flag_ids("https://www.example.com/index.html") == set()
    assert "ip_literal_host" in flag_ids("http://8.8.8.8/x")
    assert "userinfo_in_url" in flag_ids("http://www.paypal.com@evil.example.net/")
    assert "executable_payload_extension" in flag_ids("http://example.com/dl/update.exe")
    assert "double_extension" in flag_ids("http://example.com/invoice.pdf.exe")
    assert "non_standard_port" in flag_ids("http://example.com:8081/")
    assert "deep_subdomain" in flag_ids("http://a.b.c.d.example.com/")
    assert "embedded_domain_in_subdomain" in flag_ids("http://paypal.com.verify.evil-example.net/")
    # Cyrillic 'а' mixed with Latin letters: homograph
    assert "idn_mixed_script" in flag_ids("http://pаypal.com/")
    assert "idn_punycode" in flag_ids("http://bücher.de/")
    assert "ip_literal_host" in flag_ids("http://2130706433/")
