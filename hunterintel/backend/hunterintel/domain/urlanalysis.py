"""Offline URL component analysis and structural heuristics.

Components are facts derived deterministically from the string (``verified``). The
risk flags are heuristics — useful pivots, never proof — and are always labelled
``inferred`` downstream.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from typing import Any
from urllib.parse import parse_qsl, unquote, urlsplit

from hunterintel.core.netpolicy import parse_ip
from hunterintel.domain.evidence import RiskFlag, Severity
from hunterintel.domain.indicators import decode_idn, split_domain

_EXECUTABLE_EXT = {
    "exe",
    "scr",
    "dll",
    "bat",
    "cmd",
    "com",
    "msi",
    "ps1",
    "vbs",
    "vbe",
    "js",
    "jse",
    "wsf",
    "hta",
    "jar",
    "lnk",
    "iso",
    "img",
    "apk",
    "dmg",
    "pkg",
    "sh",
    "bin",
    "docm",
    "xlsm",
    "pptm",
}
_DOC_EXT = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg", "png", "gif"}
_CONFUSABLE_SCRIPTS = {"LATIN", "CYRILLIC", "GREEK"}
_AT_LOOKALIKES = re.compile(r"%40|%2[eE]", re.IGNORECASE)


def _scripts(label: str) -> set[str]:
    found: set[str] = set()
    for ch in label:
        if ch.isalpha():
            try:
                found.add(unicodedata.name(ch).split()[0])
            except ValueError:
                continue
    return found


def analyze_url(canonical_url: str) -> dict[str, Any]:
    """Return ``{"components": {...}, "flags": [RiskFlag, ...]}`` for a canonical URL."""
    parts = urlsplit(canonical_url)
    host = parts.hostname or ""
    literal = parse_ip(host)
    host_kind = "domain" if literal is None else ("ipv6" if literal.version == 6 else "ipv4")
    default_port = {"http": 80, "https": 443, "ftp": 21}.get(parts.scheme)
    port = parts.port or default_port

    domain_parts: dict[str, str | None] = {}
    unicode_host = host
    if host_kind == "domain":
        domain_parts = split_domain(host)
        unicode_host = decode_idn(host)

    path = parts.path or "/"
    last_segment = unquote(path.rsplit("/", 1)[-1])
    extension = last_segment.rsplit(".", 1)[-1].lower() if "." in last_segment else None
    query_pairs = parse_qsl(parts.query, keep_blank_values=True)

    components: dict[str, Any] = {
        "scheme": parts.scheme,
        "host": host,
        "host_unicode": unicode_host if unicode_host != host else None,
        "host_kind": host_kind,
        "port": port,
        "userinfo_present": parts.username is not None,
        "path": path,
        "path_depth": len([p for p in path.split("/") if p]),
        "file_extension": extension,
        "query": parts.query or None,
        "query_parameters": [k for k, _ in query_pairs][:50],
        "query_parameter_count": len(query_pairs),
        "length": len(canonical_url),
        **{k: v for k, v in domain_parts.items()},
    }

    flags: list[RiskFlag] = []

    def add(flag_id: str, severity: Severity, title: str, detail: str) -> None:
        flags.append(RiskFlag(id=flag_id, severity=severity, title=title, detail=detail))

    if host_kind != "domain":
        add(
            "ip_literal_host",
            Severity.LOW,
            "IP address used instead of a domain name",
            "Legitimate services rarely link users to a bare IP; commodity malware and "
            "phishing kits often do.",
        )
    if parts.username is not None:
        add(
            "userinfo_in_url",
            Severity.MEDIUM,
            "Credentials / user-info embedded in the URL",
            "The text before '@' is not the destination. This construct is commonly used to make "
            "a URL appear to belong to a trusted domain.",
        )
    if host_kind == "domain":
        labels = host.split(".")
        if any(label.startswith("xn--") for label in labels):
            mixed = [
                decode_idn(label)
                for label in labels
                if label.startswith("xn--")
                and len(_scripts(decode_idn(label)) & _CONFUSABLE_SCRIPTS) > 1
            ]
            if mixed:
                add(
                    "idn_mixed_script",
                    Severity.HIGH,
                    "Host mixes visually confusable scripts",
                    f"Label(s) {mixed} combine Latin/Cyrillic/Greek letters — a classic homograph "
                    "technique to impersonate another domain.",
                )
            else:
                add(
                    "idn_punycode",
                    Severity.LOW,
                    "Internationalised (punycode) host",
                    f"Displays as '{unicode_host}'. Verify it is not impersonating a Latin-script "
                    "brand.",
                )
        sub = domain_parts.get("subdomain")
        if sub and sub.count(".") + 1 >= 4:
            add(
                "deep_subdomain",
                Severity.LOW,
                "Unusually deep subdomain nesting",
                f"'{sub}' has {sub.count('.') + 1} labels; long subdomain chains are used to push "
                "the registrable domain out of view.",
            )
        if domain_parts.get("registered_domain") and domain_parts["registered_domain"] != host:
            for brand_dot in re.findall(r"([a-z0-9-]+\.(?:com|net|org))", sub or ""):
                add(
                    "embedded_domain_in_subdomain",
                    Severity.MEDIUM,
                    "Subdomain contains another domain name",
                    f"'{brand_dot}' appears inside the subdomain, but the real registrable domain "
                    f"is '{domain_parts['registered_domain']}'.",
                )
                break
    if port is not None and port != default_port:
        add(
            "non_standard_port",
            Severity.LOW,
            f"Non-standard port {port}",
            "Web content served on an unusual port is more common for ad-hoc infrastructure.",
        )
    if parts.scheme == "http" and (parts.username is not None or "login" in path.lower()):
        add(
            "cleartext_credentials_page",
            Severity.LOW,
            "Login-style path over plain HTTP",
            "Credential pages served without TLS are a risk indicator.",
        )
    if extension in _EXECUTABLE_EXT:
        add(
            "executable_payload_extension",
            Severity.MEDIUM,
            f"Path ends in '.{extension}'",
            "The URL appears to deliver an executable, script, archive or macro-enabled file.",
        )
    stem_parts = last_segment.lower().split(".")
    if len(stem_parts) >= 3 and stem_parts[-1] in _EXECUTABLE_EXT and stem_parts[-2] in _DOC_EXT:
        add(
            "double_extension",
            Severity.HIGH,
            "Double extension disguises an executable",
            f"'{last_segment}' pretends to be a .{stem_parts[-2]} file.",
        )
    if len(canonical_url) > 300:
        add(
            "very_long_url",
            Severity.LOW,
            "Very long URL",
            f"{len(canonical_url)} characters; long URLs are used to hide the host or carry "
            "encoded data.",
        )
    if _AT_LOOKALIKES.search(parts.netloc):
        add(
            "encoded_host_chars",
            Severity.MEDIUM,
            "Percent-encoded characters in the host",
            "Encoded '@' or '.' in the authority component is an evasion technique.",
        )
    if re.search(r"(?:[A-Za-z0-9+/]{60,}={0,2})", parts.query):
        add(
            "long_base64_like_query",
            Severity.LOW,
            "Long base64-like value in query string",
            "May carry an encoded payload, tracking token or victim identifier.",
        )

    if literal is not None and isinstance(literal, ipaddress.IPv4Address):
        components["ip"] = str(literal)
    return {"components": components, "flags": flags}
