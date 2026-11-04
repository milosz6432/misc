"""The evidence model shared by every provider, the store, scoring and the UI.

The central idea: **never blur where a statement came from.**

``verified``        observed first-hand from the authoritative source of record (a DNS
                    answer, a registry's RDAP response, a live HTTP hop) or computed
                    locally (parsing, hashing).
``provider_claim``  asserted by a third-party service. Reported with attribution but not
                    independently confirmed (VirusTotal, crt.sh, Team Cymru, GeoIP DBs…).
``inferred``        derived by HunterIntel from other data; the ``basis`` is recorded.

Anything we could *not* obtain is not an observation at all — it is a provider run with
a :class:`RunStatus` explaining why (no key, rate limited, blocked by policy…).
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field

from hunterintel.domain.indicators import IndicatorType


class Assurance(StrEnum):
    VERIFIED = "verified"
    PROVIDER_CLAIM = "provider_claim"
    INFERRED = "inferred"


class RunStatus(StrEnum):
    OK = "ok"  # data returned
    NO_DATA = "no_data"  # asked successfully; the source has nothing (NOT the same as "clean")
    NOT_CONFIGURED = "not_configured"  # key / database missing
    BLOCKED = "blocked"  # refused by policy (private address, do-not-share, probes disabled)
    RATE_LIMITED = "rate_limited"
    TIMEOUT = "timeout"
    ERROR = "error"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Tier(StrEnum):
    """How far an indicator travels when a provider runs."""

    LOCAL = "local"  # never leaves this host
    PUBLIC = "public"  # keyless public infrastructure (DNS, RDAP, CT)
    THIRD_PARTY = "third_party"  # keyed commercial/community vendor
    ACTIVE = "active"  # touches the target itself; explicit opt-in only


TIER_RANK = {Tier.LOCAL: 0, Tier.PUBLIC: 1, Tier.THIRD_PARTY: 2, Tier.ACTIVE: 3}


def utcnow() -> datetime:
    return datetime.now(UTC)


class RiskFlag(BaseModel):
    id: str
    severity: Severity
    title: str
    detail: str


class ReputationSignal(BaseModel):
    """A normalised statement from one source about maliciousness.

    ``strength`` is how strongly the source indicates malicious activity (0 for a clean
    verdict); ``reliability`` is our static trust in that source's signals. ``definitive``
    means the source made a determination either way — a mere "not found" is *not*
    definitive and therefore never raises confidence.
    """

    source: str
    verdict: Literal["malicious", "suspicious", "harmless", "unknown"]
    strength: float = Field(ge=0.0, le=1.0)
    reliability: float = Field(ge=0.0, le=1.0)
    label: str
    definitive: bool = True


class ObservationDraft(BaseModel):
    kind: str
    title: str
    assurance: Assurance
    data: dict[str, Any] = Field(default_factory=dict)
    summary: str | None = None
    observed_at: datetime = Field(default_factory=utcnow)


class RelationshipDraft(BaseModel):
    src_type: IndicatorType
    src_value: str
    dst_type: IndicatorType
    dst_value: str
    rel_type: str
    assurance: Assurance
    attrs: dict[str, Any] = Field(default_factory=dict)


class ProviderResult(BaseModel):
    status: RunStatus
    message: str | None = None
    observations: list[ObservationDraft] = Field(default_factory=list)
    relationships: list[RelationshipDraft] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    truncated: bool = False

    @classmethod
    def ok(cls, **kw: Any) -> ProviderResult:
        return cls(status=RunStatus.OK, **kw)

    @classmethod
    def no_data(
        cls, message: str = "The source returned no information for this indicator."
    ) -> ProviderResult:
        return cls(status=RunStatus.NO_DATA, message=message)

    @classmethod
    def unavailable(cls, status: RunStatus, message: str) -> ProviderResult:
        return cls(status=status, message=message)
