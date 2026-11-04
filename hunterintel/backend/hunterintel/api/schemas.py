"""Request bodies. Responses are plain JSON-able dicts built by the services."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from hunterintel.domain.indicators import IndicatorType

Classification = Literal["unclassified", "benign", "suspicious", "malicious", "false_positive"]
TLP = Literal["clear", "green", "amber", "amber_strict", "red"]
Severity = Literal["info", "low", "medium", "high", "critical"]
Tag = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=64)]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class IndicatorIn(_Strict):
    value: str = Field(min_length=1, max_length=2048, examples=["example.com"])
    type: IndicatorType | None = Field(
        default=None,
        description="Force the type where ambiguous (e.g. 'certificate' for a SHA-256 fingerprint).",
    )


class EnrichIn(IndicatorIn):
    providers: list[str] | None = Field(
        default=None,
        max_length=20,
        description="Provider names to run. Omit to use the default plan (local + keyless public sources).",
    )
    refresh: bool = Field(default=False, description="Bypass response caches.")


class IndicatorPatch(_Strict):
    classification: Classification | None = None
    do_not_share: bool | None = None
    tracked: bool | None = None
    ttl_days: int | None = Field(default=None, ge=1, le=3650)
    add_tags: list[Tag] = Field(default_factory=list, max_length=20)
    remove_tags: list[Tag] = Field(default_factory=list, max_length=20)


class CompareIn(_Strict):
    indicator_ids: list[int] = Field(min_length=2, max_length=10)


class InvestigationIn(_Strict):
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=20_000)
    tlp: TLP = "amber"


class InvestigationPatch(_Strict):
    title: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=20_000)
    status: Literal["open", "closed"] | None = None
    tlp: TLP | None = None


class MemberIn(_Strict):
    value: str | None = Field(default=None, max_length=2048)
    type: IndicatorType | None = None
    indicator_id: int | None = None


class NoteIn(_Strict):
    body: str = Field(min_length=1, max_length=20_000)
    indicator_id: int | None = None
    author: str = Field(default="analyst", min_length=1, max_length=64)


class NotePatch(_Strict):
    body: str = Field(min_length=1, max_length=20_000)


class FindingIn(_Strict):
    title: str = Field(min_length=1, max_length=200)
    body: str = Field(default="", max_length=20_000)
    severity: Severity = "info"
    indicator_id: int | None = None
    observation_id: int | None = Field(
        default=None, description="Snapshot this observation as the finding's evidence."
    )


class FindingPatch(_Strict):
    title: str | None = Field(default=None, min_length=1, max_length=200)
    body: str | None = Field(default=None, max_length=20_000)
    severity: Severity | None = None
