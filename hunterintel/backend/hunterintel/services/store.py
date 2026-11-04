"""IOC store: persistence of indicators, observations (with history), runs, tags, edges."""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from hunterintel.db.models import (
    Indicator,
    IndicatorTag,
    Observation,
    ProviderRun,
    Relationship,
)
from hunterintel.domain.evidence import (
    Assurance,
    ObservationDraft,
    ProviderResult,
    RelationshipDraft,
    RunStatus,
    utcnow,
)
from hunterintel.domain.indicators import (
    IndicatorParseError,
    ParsedIndicator,
    parse_indicator,
)
from hunterintel.services.scoring import TTL_DAYS, Assessment, ObsView, assess

log = logging.getLogger(__name__)

#: keys that change on every run without the underlying fact changing — excluded from the
#: fingerprint so an unchanged DNS answer does not create a new "history" row each day
VOLATILE_KEYS = {"age_days", "elapsed_ms", "ttl", "last_analysis", "observed_at"}
MAX_EDGES_PER_RUN = 300
_ASSURANCE_ORDER = {
    Assurance.VERIFIED.value: 0,
    Assurance.PROVIDER_CLAIM.value: 1,
    Assurance.INFERRED.value: 2,
}


def _strip_volatile(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _strip_volatile(v) for k, v in value.items() if k not in VOLATILE_KEYS}
    if isinstance(value, list):
        return [_strip_volatile(v) for v in value]
    return value


def fingerprint(draft: ObservationDraft) -> str:
    blob = json.dumps(
        [draft.kind, draft.assurance.value, _strip_volatile(draft.data)],
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(blob.encode()).hexdigest()


def normalise_tag(tag: str) -> str | None:
    cleaned = " ".join(str(tag).strip().lower().split())[:64]
    return cleaned or None


async def get_or_create_indicator(
    session: AsyncSession,
    parsed: ParsedIndicator,
    *,
    tracked: bool,
    now: datetime | None = None,
    sighting: bool = True,
) -> Indicator:
    """Fetch or insert the indicator row; ``tracked`` only ever flips from False to True."""
    now = now or utcnow()
    stmt = select(Indicator).where(
        Indicator.type == parsed.type.value, Indicator.value == parsed.value
    )
    row = (await session.execute(stmt)).scalar_one_or_none()
    if row is None:
        row = Indicator(
            type=parsed.type.value,
            value=parsed.value,
            subtype=parsed.subtype,
            tracked=tracked,
            ttl_days=TTL_DAYS.get(parsed.type.value, 90),
            first_seen=now,
            last_seen=now,
        )
        try:
            async with session.begin_nested():
                session.add(row)
                await session.flush()
        except IntegrityError:  # lost a race with a concurrent insert — read the winner
            row = (await session.execute(stmt)).scalar_one()
    if tracked and not row.tracked:
        row.tracked = True
    if sighting and now > row.last_seen:
        row.last_seen = now
    return row


async def record_run(
    session: AsyncSession,
    indicator: Indicator,
    provider: str,
    result: ProviderResult,
    *,
    started_at: datetime,
    duration_ms: int,
) -> ProviderRun:
    run = ProviderRun(
        indicator_id=indicator.id,
        provider=provider,
        status=result.status.value,
        message=result.message,
        started_at=started_at,
        duration_ms=duration_ms,
        observation_count=len(result.observations),
        truncated=result.truncated,
    )
    session.add(run)
    return run


async def upsert_observations(
    session: AsyncSession,
    indicator: Indicator,
    provider: str,
    drafts: list[ObservationDraft],
    now: datetime,
) -> int:
    """Insert new facts; an identical fact just has its ``last_seen``/``seen_count`` bumped."""
    changed = 0
    for draft in drafts:
        fp = fingerprint(draft)
        existing = (
            await session.execute(
                select(Observation).where(
                    Observation.indicator_id == indicator.id,
                    Observation.provider == provider,
                    Observation.kind == draft.kind,
                    Observation.fingerprint == fp,
                )
            )
        ).scalar_one_or_none()
        if existing is not None:
            existing.last_seen = now
            existing.seen_count += 1
            existing.data = draft.data  # refresh volatile fields (e.g. age_days)
            existing.summary = draft.summary
        else:
            session.add(
                Observation(
                    indicator_id=indicator.id,
                    provider=provider,
                    kind=draft.kind,
                    assurance=draft.assurance.value,
                    title=draft.title[:200],
                    summary=draft.summary,
                    data=draft.data,
                    fingerprint=fp,
                    first_seen=draft.observed_at,
                    last_seen=now,
                )
            )
            changed += 1
    await session.flush()
    return changed


async def upsert_tags(
    session: AsyncSession, indicator: Indicator, source: str, tags: list[str]
) -> None:
    existing = {
        (t.tag, t.source)
        for t in (
            await session.execute(
                select(IndicatorTag).where(IndicatorTag.indicator_id == indicator.id)
            )
        ).scalars()
    }
    for raw in tags:
        tag = normalise_tag(raw)
        if tag and (tag, source) not in existing:
            session.add(IndicatorTag(indicator_id=indicator.id, tag=tag, source=source))
            existing.add((tag, source))


async def upsert_relationships(
    session: AsyncSession, source: str, drafts: list[RelationshipDraft], now: datetime
) -> tuple[int, int]:
    """Persist edges, creating *untracked* endpoint indicators. Returns (stored, skipped)."""
    stored = skipped = 0
    for draft in drafts[:MAX_EDGES_PER_RUN]:
        try:
            src = parse_indicator(draft.src_value, draft.src_type)
            dst = parse_indicator(draft.dst_value, draft.dst_type)
        except IndicatorParseError:
            skipped += 1
            continue
        if (src.type, src.value) == (dst.type, dst.value):
            skipped += 1
            continue
        src_row = await get_or_create_indicator(
            session, src, tracked=False, now=now, sighting=False
        )
        dst_row = await get_or_create_indicator(
            session, dst, tracked=False, now=now, sighting=False
        )
        edge = (
            await session.execute(
                select(Relationship).where(
                    Relationship.src_id == src_row.id,
                    Relationship.dst_id == dst_row.id,
                    Relationship.rel_type == draft.rel_type,
                    Relationship.source == source,
                )
            )
        ).scalar_one_or_none()
        if edge is None:
            session.add(
                Relationship(
                    src_id=src_row.id,
                    dst_id=dst_row.id,
                    rel_type=draft.rel_type,
                    assurance=draft.assurance.value,
                    source=source,
                    attrs=draft.attrs,
                    first_seen=now,
                    last_seen=now,
                )
            )
        else:
            edge.last_seen, edge.attrs, edge.assurance = now, draft.attrs, draft.assurance.value
        stored += 1
    skipped += max(len(drafts) - MAX_EDGES_PER_RUN, 0)
    await session.flush()
    return stored, skipped


async def persist_result(
    session: AsyncSession,
    indicator: Indicator,
    provider: str,
    result: ProviderResult,
    *,
    started_at: datetime,
    duration_ms: int,
    now: datetime,
) -> dict[str, int]:
    await record_run(
        session, indicator, provider, result, started_at=started_at, duration_ms=duration_ms
    )
    stats = {"new_observations": 0, "edges": 0, "skipped_edges": 0}
    if result.status is RunStatus.OK:
        stats["new_observations"] = await upsert_observations(
            session, indicator, provider, result.observations, now
        )
        await upsert_tags(session, indicator, provider, result.tags)
        stats["edges"], stats["skipped_edges"] = await upsert_relationships(
            session, provider, result.relationships, now
        )
        indicator.last_seen = max(indicator.last_seen, now)
    await session.flush()
    return stats


# ── reading / assessing ──────────────────────────────────────────────────────


async def load_obs_views(session: AsyncSession, indicator_id: int) -> list[ObsView]:
    rows = (
        await session.execute(select(Observation).where(Observation.indicator_id == indicator_id))
    ).scalars()
    return [
        ObsView(o.provider, o.kind, o.assurance, o.data, o.last_seen, o.first_seen) for o in rows
    ]


async def assess_indicator(
    session: AsyncSession, indicator: Indicator, now: datetime | None = None
) -> Assessment:
    return assess(
        last_seen=indicator.last_seen,
        ttl_days=indicator.ttl_days,
        observations=await load_obs_views(session, indicator.id),
        now=now or utcnow(),
    )


async def refresh_cached_assessment(
    session: AsyncSession, indicator: Indicator, now: datetime
) -> Assessment:
    a = await assess_indicator(session, indicator, now)
    indicator.risk_score, indicator.confidence, indicator.verdict = (
        a.risk_score,
        a.confidence,
        a.verdict,
    )
    indicator.last_enriched_at = now
    await session.flush()
    return a


def strongest_assurance(values: list[str]) -> str:
    return min(values, key=lambda v: _ASSURANCE_ORDER.get(v, 9))
