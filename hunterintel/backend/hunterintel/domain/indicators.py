"""Indicator parsing, normalisation and classification (pure, no I/O).

Everything the platform stores or sends to a provider first passes through
:func:`parse_indicator`, which yields a canonical value and — just as important — a
*lookup policy*: may this indicator be sent to remote services at all, and if not, why?
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from enum import StrEnum
from urllib.parse import quote, unquote, urlsplit, urlunsplit

import idna
import tldextract

from hunterintel.core.netpolicy import (
    IPScope,
    classify_ip,
    hostname_scope,
    parse_ip,
    parse_ipv4_loose,
)


class IndicatorType(StrEnum):
    DOMAIN = "domain"
    IP = "ip"
    URL = "url"
    HASH = "hash"
    CERTIFICATE = "certificate"
    ASN = "asn"
    EMAIL = "email"


class IndicatorParseError(ValueError):
    """The input is not a recognisable, safely representable indicator."""


@dataclass(frozen=True)
class ParsedIndicator:
    type: IndicatorType
    value: str  # canonical form — this is what is stored and what providers receive
    raw: str
    subtype: str | None = None  # ipv4 | ipv6 | md5 | sha1 | sha256
    scope: str = "public"  # IPScope value, or "public" / "internal" for names
    remote_lookup_allowed: bool = True
    blocked_reason: str | None = None
    sensitive: bool = False  # never forwarded as-is to third parties (e-mail addresses)
    notes: list[str] = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{self.type.value}:{self.value}"


MAX_LENGTH = 2048
_HEX = re.compile(r"^[0-9a-f]+$")
_LABEL = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")
_TLD = re.compile(r"^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$")
_ASN = re.compile(r"^(?:as|asn)\s*([0-9]{1,10})$", re.IGNORECASE)
_HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}
_CONTROL = re.compile(r"[\x00-\x1f\x7f\s]")
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

_REFANG = [
    (re.compile(r"^hxxp(s?)://", re.IGNORECASE), r"http\1://"),
    (re.compile(r"^fxp://", re.IGNORECASE), "ftp://"),
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", re.IGNORECASE), "."),
    (re.compile(r"\[@\]|\(@\)|\[at\]|\(at\)", re.IGNORECASE), "@"),
    (re.compile(r"\[:\]|\[://\]"), "://"),
]


def refang(text: str) -> tuple[str, bool]:
    """Undo common analyst/vendor 'defanging' (``hxxp://evil[.]com``)."""
    original = text
    for pattern, repl in _REFANG:
        text = pattern.sub(repl, text)
    return text, text != original


# ── domains ──────────────────────────────────────────────────────────────────


def normalize_domain(name: str) -> str:
    """Lower-case, IDNA (punycode) encode and structurally validate a DNS name."""
    name = name.strip().rstrip(".")
    if not name or len(name) > 253 * 2:
        raise IndicatorParseError("domain name is empty or too long")
    labels: list[str] = []
    for label in name.split("."):
        if not label:
            raise IndicatorParseError("domain contains an empty label")
        if label.isascii():
            labels.append(label.lower())
        else:
            try:
                labels.append(idna.encode(label, uts46=True).decode("ascii"))
            except idna.IDNAError as exc:
                raise IndicatorParseError(
                    f"invalid internationalised label {label!r}: {exc}"
                ) from exc
    ascii_name = ".".join(labels)
    if len(ascii_name) > 253:
        raise IndicatorParseError("domain exceeds 253 characters")
    if len(labels) < 2:
        raise IndicatorParseError("a domain needs at least two labels (e.g. example.com)")
    for label in labels:
        if not _LABEL.match(label):
            raise IndicatorParseError(f"invalid label {label!r}")
    if not _TLD.match(labels[-1]):
        raise IndicatorParseError(f"invalid top-level label {labels[-1]!r}")
    return ascii_name


def registered_domain(domain: str) -> str | None:
    """Registrable domain (eTLD+1) using the bundled public-suffix snapshot (no network)."""
    ext = _EXTRACT(domain)
    return ext.top_domain_under_public_suffix or None


def split_domain(domain: str) -> dict[str, str | None]:
    ext = _EXTRACT(domain)
    return {
        "subdomain": ext.subdomain or None,
        "domain": ext.domain or None,
        "suffix": ext.suffix or None,
        "registered_domain": ext.top_domain_under_public_suffix or None,
    }


def decode_idn(domain: str) -> str:
    """Best-effort Unicode rendering of a punycode name (for display / homograph checks)."""
    try:
        return ".".join(
            idna.decode(label) if label.startswith("xn--") else label for label in domain.split(".")
        )
    except idna.IDNAError:
        return domain


# ── URLs ─────────────────────────────────────────────────────────────────────

_UNRESERVED = re.compile(r"%([0-9a-fA-F]{2})")
_ALLOWED_URL_SCHEMES = {"http", "https", "ftp"}


def _normalize_percent(segment: str) -> str:
    """Upper-case percent escapes and decode escapes of unreserved characters."""

    def fix(m: re.Match[str]) -> str:
        ch = chr(int(m.group(1), 16))
        return ch if ch.isalnum() and ch.isascii() or ch in "-._~" else f"%{m.group(1).upper()}"

    return _UNRESERVED.sub(fix, segment)


_URL_SAFE = "%/:@!$&'()*+,;=-._~?[]"


def _encode_unsafe(segment: str) -> str:
    """UTF-8 percent-encode anything outside the URL-safe set, keeping existing escapes."""
    return quote(segment, safe=_URL_SAFE)


def _remove_dot_segments(path: str) -> str:
    out: list[str] = []
    for part in path.split("/"):
        if part == "..":
            if len(out) > 1:
                out.pop()
        elif part != ".":
            out.append(part)
    result = "/".join(out)
    return result if result.startswith("/") or not path.startswith("/") else "/" + result


def canonical_host(host: str) -> tuple[str, str, list[str]]:
    """Normalise a URL host. Returns (host, kind, notes); kind is domain|ipv4|ipv6."""
    notes: list[str] = []
    bare = host.strip("[]")
    if ":" in bare:
        try:
            return f"[{ipaddress.IPv6Address(bare.split('%', 1)[0]).compressed}]", "ipv6", notes
        except ValueError as exc:
            raise IndicatorParseError(f"invalid IPv6 literal: {host!r}") from exc
    try:
        return str(ipaddress.IPv4Address(bare)), "ipv4", notes
    except ValueError:
        pass
    loose = parse_ipv4_loose(bare)
    if loose is not None:
        notes.append(f"obfuscated IPv4 host '{bare}' normalised to {loose}")
        return str(loose), "ipv4", notes
    return normalize_domain(bare.lower()), "domain", notes


def canonicalize_url(raw: str) -> tuple[str, str, list[str]]:
    """Return (canonical_url, host, notes)."""
    notes: list[str] = []
    text = raw.strip()
    if "://" not in text:
        text = "http://" + text.lstrip("/")
        notes.append("no scheme supplied; assumed http://")
    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError as exc:
        raise IndicatorParseError(f"unparseable URL: {exc}") from exc
    scheme = parts.scheme.lower()
    if scheme not in _ALLOWED_URL_SCHEMES:
        raise IndicatorParseError(f"unsupported URL scheme {scheme!r} (http, https, ftp only)")
    if not parts.hostname:
        raise IndicatorParseError("URL has no host")
    host, _kind, host_notes = canonical_host(parts.hostname)
    notes.extend(host_notes)

    default_port = {"http": 80, "https": 443, "ftp": 21}[scheme]
    netloc = host
    if parts.username is not None:
        user = quote(unquote(parts.username), safe="")
        if parts.password is not None:
            user += ":" + quote(unquote(parts.password), safe="")
        netloc = f"{user}@{netloc}"
    if port is not None and port != default_port:
        netloc += f":{port}"
    elif port == default_port:
        notes.append("default port removed")

    path = _encode_unsafe(_remove_dot_segments(_normalize_percent(parts.path))) or "/"
    query = _encode_unsafe(_normalize_percent(parts.query))
    if parts.fragment:
        notes.append("fragment removed (never transmitted to servers)")
    return urlunsplit((scheme, netloc, path, query, "")), host, notes


# ── main entry point ─────────────────────────────────────────────────────────


def _ip_result(
    raw: str, addr: ipaddress.IPv4Address | ipaddress.IPv6Address, notes: list[str]
) -> ParsedIndicator:
    scope = classify_ip(addr)
    allowed = scope is IPScope.PUBLIC
    return ParsedIndicator(
        type=IndicatorType.IP,
        value=addr.compressed,
        raw=raw,
        subtype="ipv4" if addr.version == 4 else "ipv6",
        scope=scope.value,
        remote_lookup_allowed=allowed,
        blocked_reason=None
        if allowed
        else (
            f"{addr.compressed} is a {scope.value.replace('_', '-')} address; remote lookups are "
            "disabled so internal addressing is never sent to external services"
        ),
        notes=notes,
    )


def _domain_result(raw: str, domain: str, notes: list[str]) -> ParsedIndicator:
    reason = hostname_scope(domain)
    return ParsedIndicator(
        type=IndicatorType.DOMAIN,
        value=domain,
        raw=raw,
        scope="internal" if reason else "public",
        remote_lookup_allowed=reason is None,
        blocked_reason=(
            f"{reason}; remote lookups are disabled to avoid leaking internal names"
            if reason
            else None
        ),
        notes=notes,
    )


def parse_indicator(raw: str, forced_type: IndicatorType | str | None = None) -> ParsedIndicator:
    """Detect, normalise and classify an indicator.

    ``forced_type`` removes ambiguity where it exists (a 64-hex string is a file hash
    unless the analyst says it is a certificate fingerprint).
    """
    if raw is None or not raw.strip():
        raise IndicatorParseError("empty indicator")
    if len(raw) > MAX_LENGTH:
        raise IndicatorParseError(f"indicator exceeds {MAX_LENGTH} characters")
    text = raw.strip()
    if _CONTROL.search(text):
        # whitespace / control characters are never valid inside an indicator; refusing them
        # here also blocks header- and log-injection through indicator values.
        raise IndicatorParseError("indicator contains whitespace or control characters")

    forced = IndicatorType(forced_type) if forced_type else None
    notes: list[str] = []
    text, was_defanged = refang(text)
    if was_defanged:
        notes.append("defanged input restored to its live form")

    # explicit prefixes: cert:, crtsh:, asn:
    lowered = text.lower()
    for prefix in ("cert:", "certificate:", "sha256-cert:"):
        if lowered.startswith(prefix):
            forced, text = IndicatorType.CERTIFICATE, text[len(prefix) :].strip()
            lowered = text.lower()
            break

    if forced is IndicatorType.CERTIFICATE or lowered.startswith("crtsh:"):
        return _parse_certificate(raw, text, notes)
    if forced is IndicatorType.ASN or (forced is None and _ASN.match(text)):
        m = _ASN.match(text) or re.match(r"^([0-9]{1,10})$", text)
        if not m:
            raise IndicatorParseError("ASN must look like AS15169")
        number = int(m.group(1))
        if not 0 < number < 2**32:
            raise IndicatorParseError("ASN out of range")
        return ParsedIndicator(IndicatorType.ASN, f"AS{number}", raw, notes=notes)

    if forced is None or forced is IndicatorType.URL:
        looks_like_url = "://" in text or (forced is IndicatorType.URL)
        if not looks_like_url and "/" in text and "@" not in text.split("/", 1)[0]:
            # "example.com/path" — a host followed by a path
            looks_like_url = bool(re.match(r"^[A-Za-z0-9.\-\[\]:]+(/|\?)", text))
        if looks_like_url:
            return _parse_url(raw, text, notes)

    if forced is None or forced is IndicatorType.EMAIL:
        if "@" in text:
            return _parse_email(raw, text, notes)
        if forced is IndicatorType.EMAIL:
            raise IndicatorParseError("e-mail address must contain '@'")

    candidate = text.lower()
    if forced in (None, IndicatorType.HASH):
        bare = candidate[len("sha256:") :] if candidate.startswith("sha256:") else candidate
        bare = (
            bare.replace(":", "")
            if re.fullmatch(r"(?:[0-9a-f]{2}:)+[0-9a-f]{2}", candidate)
            else bare
        )
        if _HEX.match(bare) and len(bare) in _HASH_LENGTHS:
            return ParsedIndicator(
                IndicatorType.HASH, bare, raw, subtype=_HASH_LENGTHS[len(bare)], notes=notes
            )
        if forced is IndicatorType.HASH or (_HEX.match(bare) and len(bare) in (96, 128)):
            raise IndicatorParseError(
                "unsupported hash length — only MD5 (32), SHA-1 (40) and SHA-256 (64) hex "
                "are supported"
            )

    if forced in (None, IndicatorType.IP):
        try:
            return _ip_result(raw, ipaddress.ip_address(text.strip("[]").split("%", 1)[0]), notes)
        except ValueError:
            pass
        if forced is IndicatorType.IP:
            # Legacy spellings (2130706433, 0x7f.1, 127.1) are only honoured when the analyst
            # says "this is an IP"; auto-detection must not turn a bare number into an address.
            loose = parse_ipv4_loose(text)
            if loose is not None:
                notes.append(f"legacy numeric IPv4 notation normalised to {loose}")
                return _ip_result(raw, loose, notes)
            raise IndicatorParseError("not a valid IPv4/IPv6 address")

    if forced in (None, IndicatorType.DOMAIN):
        name = text
        if name.startswith("*."):
            name = name[2:]
            notes.append("wildcard prefix removed")
        return _domain_result(raw, normalize_domain(name), notes)

    raise IndicatorParseError(
        f"cannot interpret {raw!r} as {forced.value if forced else 'an indicator'}"
    )


def _parse_certificate(raw: str, text: str, notes: list[str]) -> ParsedIndicator:
    lowered = text.lower()
    if lowered.startswith("crtsh:"):
        ident = lowered[len("crtsh:") :].strip()
        if not ident.isdigit() or not 0 < int(ident) < 2**63:
            raise IndicatorParseError("crt.sh certificate id must be numeric, e.g. crtsh:12345")
        return ParsedIndicator(
            IndicatorType.CERTIFICATE, f"crtsh:{int(ident)}", raw, subtype="crtsh_id", notes=notes
        )
    fingerprint = lowered.replace(":", "").replace(" ", "")
    if fingerprint.isdigit() and not (len(fingerprint) == 64):
        return _parse_certificate(raw, f"crtsh:{fingerprint}", notes)
    if not (_HEX.match(fingerprint) and len(fingerprint) == 64):
        raise IndicatorParseError(
            "certificate must be a SHA-256 fingerprint (64 hex chars) or 'crtsh:<id>'"
        )
    return ParsedIndicator(
        IndicatorType.CERTIFICATE, fingerprint, raw, subtype="sha256", notes=notes
    )


def _parse_url(raw: str, text: str, notes: list[str]) -> ParsedIndicator:
    canonical, host, url_notes = canonicalize_url(text)
    notes.extend(url_notes)
    literal = parse_ip(host)
    reason: str | None = None
    scope = "public"
    if literal is not None:
        ip_scope = classify_ip(literal)
        if ip_scope is not IPScope.PUBLIC:
            scope = ip_scope.value
            reason = f"URL host is a {ip_scope.value.replace('_', '-')} address"
    else:
        host_reason = hostname_scope(host)
        if host_reason:
            scope, reason = "internal", f"URL host: {host_reason}"
    return ParsedIndicator(
        type=IndicatorType.URL,
        value=canonical,
        raw=raw,
        scope=scope,
        remote_lookup_allowed=reason is None,
        blocked_reason=f"{reason}; remote lookups are disabled" if reason else None,
        notes=notes,
    )


def _parse_email(raw: str, text: str, notes: list[str]) -> ParsedIndicator:
    if text.count("@") != 1:
        local, _, domain_part = text.rpartition("@")
    else:
        local, _, domain_part = text.partition("@")
    local = local.strip().strip("<>")
    if not local or len(local) > 64 or re.search(r"[\s,;:\\\"()<>\[\]@]", local):
        raise IndicatorParseError("invalid e-mail local part")
    domain = normalize_domain(domain_part.strip().strip("<>").lower())
    reason = hostname_scope(domain)
    return ParsedIndicator(
        type=IndicatorType.EMAIL,
        value=f"{local.lower()}@{domain}",
        raw=raw,
        scope="internal" if reason else "public",
        remote_lookup_allowed=reason is None,
        blocked_reason=f"e-mail domain: {reason}; remote lookups are disabled" if reason else None,
        sensitive=True,
        notes=notes,
    )


def try_parse(raw: str, forced_type: IndicatorType | str | None = None) -> ParsedIndicator | None:
    try:
        return parse_indicator(raw, forced_type)
    except (IndicatorParseError, ValueError):
        return None


def email_domain(email: str) -> str:
    return email.rsplit("@", 1)[1]
