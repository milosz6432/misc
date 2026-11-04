"""SQLAlchemy 2.0 ORM models.

Layout (see docs/ARCHITECTURE.md §3)::

    Indicator ──< Observation      what a provider said / we observed (history kept)
    Indicator ──< ProviderRun      what we asked and how it ended (including failures)
    Indicator ──< IndicatorTag     tag + who applied it
    Indicator ──< Relationship >── Indicator
    Investigation ──< InvestigationIndicator >── Indicator
    Investigation ──< Finding / Note
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    TypeDecorator,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class UTCDateTime(TypeDecorator[datetime]):
    """Store naive UTC, always hand back timezone-aware UTC (SQLite drops tzinfo)."""

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Any) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("naive datetime passed to a UTC column")
        return value.astimezone(UTC).replace(tzinfo=None)

    def process_result_value(self, value: datetime | None, dialect: Any) -> datetime | None:
        return None if value is None else value.replace(tzinfo=UTC)


def _now() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class Indicator(Base):
    __tablename__ = "indicators"
    __table_args__ = (
        UniqueConstraint("type", "value", name="uq_indicator_type_value"),
        Index("ix_indicators_tracked_last_seen", "tracked", "last_seen"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    type: Mapped[str] = mapped_column(String(16), index=True)
    value: Mapped[str] = mapped_column(String(2048))
    subtype: Mapped[str | None] = mapped_column(String(16))

    #: analyst-adopted (searched / enriched / added to an investigation) vs merely discovered
    tracked: Mapped[bool] = mapped_column(Boolean, default=False)
    do_not_share: Mapped[bool] = mapped_column(Boolean, default=False)
    #: analyst judgement — kept apart from the computed assessment on purpose
    classification: Mapped[str] = mapped_column(String(24), default="unclassified")
    ttl_days: Mapped[int] = mapped_column(Integer, default=90)

    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)
    last_enriched_at: Mapped[datetime | None] = mapped_column(UTCDateTime)

    # cached assessment (recomputed on every enrichment; detail views recompute freshness)
    risk_score: Mapped[int | None] = mapped_column(Integer)
    confidence: Mapped[int | None] = mapped_column(Integer)
    verdict: Mapped[str] = mapped_column(String(16), default="unknown")

    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now, onupdate=_now)

    observations: Mapped[list[Observation]] = relationship(
        back_populates="indicator", cascade="all, delete-orphan", passive_deletes=True
    )
    runs: Mapped[list[ProviderRun]] = relationship(
        back_populates="indicator", cascade="all, delete-orphan", passive_deletes=True
    )
    tags: Mapped[list[IndicatorTag]] = relationship(
        back_populates="indicator", cascade="all, delete-orphan", passive_deletes=True
    )


class Observation(Base):
    __tablename__ = "observations"
    __table_args__ = (
        UniqueConstraint("indicator_id", "provider", "kind", "fingerprint", name="uq_observation"),
        Index("ix_observations_lookup", "indicator_id", "provider", "kind"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    indicator_id: Mapped[int] = mapped_column(ForeignKey("indicators.id", ondelete="CASCADE"))
    provider: Mapped[str] = mapped_column(String(32))
    kind: Mapped[str] = mapped_column(String(48))
    assurance: Mapped[str] = mapped_column(String(16))
    title: Mapped[str] = mapped_column(String(200))
    summary: Mapped[str | None] = mapped_column(Text)
    data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    fingerprint: Mapped[str] = mapped_column(String(64))
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)
    seen_count: Mapped[int] = mapped_column(Integer, default=1)

    indicator: Mapped[Indicator] = relationship(back_populates="observations")


class ProviderRun(Base):
    __tablename__ = "provider_runs"
    __table_args__ = (Index("ix_runs_lookup", "indicator_id", "provider", "started_at"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    indicator_id: Mapped[int] = mapped_column(ForeignKey("indicators.id", ondelete="CASCADE"))
    provider: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(16))
    message: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    observation_count: Mapped[int] = mapped_column(Integer, default=0)
    truncated: Mapped[bool] = mapped_column(Boolean, default=False)

    indicator: Mapped[Indicator] = relationship(back_populates="runs")


class IndicatorTag(Base):
    __tablename__ = "indicator_tags"
    __table_args__ = (UniqueConstraint("indicator_id", "tag", "source", name="uq_tag"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    indicator_id: Mapped[int] = mapped_column(
        ForeignKey("indicators.id", ondelete="CASCADE"), index=True
    )
    tag: Mapped[str] = mapped_column(String(64), index=True)
    source: Mapped[str] = mapped_column(String(32))  # "analyst" or a provider name
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)

    indicator: Mapped[Indicator] = relationship(back_populates="tags")


class Relationship(Base):
    __tablename__ = "relationships"
    __table_args__ = (
        UniqueConstraint("src_id", "dst_id", "rel_type", "source", name="uq_relationship"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    src_id: Mapped[int] = mapped_column(ForeignKey("indicators.id", ondelete="CASCADE"), index=True)
    dst_id: Mapped[int] = mapped_column(ForeignKey("indicators.id", ondelete="CASCADE"), index=True)
    rel_type: Mapped[str] = mapped_column(String(32))
    assurance: Mapped[str] = mapped_column(String(16))
    source: Mapped[str] = mapped_column(String(32))
    attrs: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)


class Investigation(Base):
    __tablename__ = "investigations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(12), default="open")
    tlp: Mapped[str] = mapped_column(String(8), default="amber")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now, onupdate=_now)

    members: Mapped[list[InvestigationIndicator]] = relationship(
        back_populates="investigation", cascade="all, delete-orphan", passive_deletes=True
    )
    findings: Mapped[list[Finding]] = relationship(
        back_populates="investigation", cascade="all, delete-orphan", passive_deletes=True
    )
    notes: Mapped[list[Note]] = relationship(
        back_populates="investigation", cascade="all, delete-orphan", passive_deletes=True
    )


class InvestigationIndicator(Base):
    __tablename__ = "investigation_indicators"

    investigation_id: Mapped[int] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), primary_key=True
    )
    indicator_id: Mapped[int] = mapped_column(
        ForeignKey("indicators.id", ondelete="CASCADE"), primary_key=True
    )
    added_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)

    investigation: Mapped[Investigation] = relationship(back_populates="members")
    indicator: Mapped[Indicator] = relationship()


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    investigation_id: Mapped[int] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), index=True
    )
    indicator_id: Mapped[int | None] = mapped_column(
        ForeignKey("indicators.id", ondelete="SET NULL")
    )
    observation_id: Mapped[int | None] = mapped_column(
        ForeignKey("observations.id", ondelete="SET NULL")
    )
    title: Mapped[str] = mapped_column(String(200))
    body: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(12), default="info")
    #: verbatim copy of the evidence at save time, so a finding survives later re-enrichment
    snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now, onupdate=_now)

    investigation: Mapped[Investigation] = relationship(back_populates="findings")
    indicator: Mapped[Indicator | None] = relationship()


class Note(Base):
    __tablename__ = "notes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    investigation_id: Mapped[int] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), index=True
    )
    indicator_id: Mapped[int | None] = mapped_column(
        ForeignKey("indicators.id", ondelete="SET NULL")
    )
    body: Mapped[str] = mapped_column(Text)
    author: Mapped[str] = mapped_column(String(64), default="analyst")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=_now, onupdate=_now)

    investigation: Mapped[Investigation] = relationship(back_populates="notes")
    indicator: Mapped[Indicator | None] = relationship()
