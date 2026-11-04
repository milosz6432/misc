"""Secret redaction for strings that may reach logs, error messages or API responses."""

from __future__ import annotations

import re
from collections.abc import Iterable

_GENERIC = re.compile(
    r"(?i)\b(api[-_ ]?key|auth[-_ ]?key|x-apikey|x-otx-api-key|authorization|token|secret|password)"
    r"(\"?\s*[:=]\s*\"?)(?:bearer\s+)?[A-Za-z0-9._~+/=\-]{8,}"
)


def redact(text: str, secrets: Iterable[str] = ()) -> str:
    """Replace every known secret value, and anything shaped like ``key: value``, with ``***``."""
    for secret in secrets:
        if secret:
            text = text.replace(secret, "***")
    return _GENERIC.sub(lambda m: f"{m.group(1)}{m.group(2)}***", text)
