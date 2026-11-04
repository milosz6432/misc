"""Serialisation of stored entities into API shapes."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from hunterintel.api.deps import Container
from hunterintel.db.models import (
    Indicator,
    IndicatorTag,
    Investigation,
    InvestigationIndicator,
    Observation,
    ProviderRun,
    Relationship,
)
from hunterintel.domain.evidence import utcnow
from hunterintel.domain.indicators import parse_indicator
from hunterintel.services import store
from hunterintel.services.scoring import freshness_of


def indicator_summary(ind: Indicator, tags: list[str] | None = None) -> dict[str, Any]:
    state, ratio, _ = freshness_of(ind.last_seen, ind.ttl_days, utcnow())
    return {
        "id": ind.id,
        "type": ind.type,
        "subtype": ind.subtype,
        "value": ind.value,
        "tracked": ind.tracked,
        "verdict": ind.verdict,
        "risk_score": ind.risk_score,
        "confidence": ind.confidence,
        "classification": ind.classification,
        "do_not_share": ind.do_not_share,
        "freshness": state.value,
        "first_seen": ind.first_seen.isoformat(),
        "last_seen": ind.last_seen.isoformat(),
        "expires_at": ind.expires_at.isoformat(),
        "last_enriched_at": ind.last_enriched_at.isoformat() if ind.last_enriched_at else None,
        "tags": tags or [],
    }


async def tags_for(session: AsyncSession, ids: list[int]) -> dict[int, list[str]]:
    out: dict[int, list[str]] = defaultdict(list)
    if not ids:
        return out
    rows = await session.execute(
        select(IndicatorTag.indicator_id, IndicatorTag.tag)
        .where(IndicatorTag.indicator_id.in_(ids))
        .order_by(IndicatorTag.tag)
    )
    for iid, tag in rows:
        if tag not in out[iid]:
            out[iid].append(tag)
    return out


def observation_dict(o: Observation, history: int | None = None) -> dict[str, Any]:
    d = {
        "id": o.id,
        "indicator_id": o.indicator_id,
        "provider": o.provider,
        "kind": o.kind,
        "assurance": o.assurance,
        "title": o.title,
        "summary": o.summary,
        "data": o.data,
        "first_seen": o.first_seen.isoformat(),
        "last_seen": o.last_seen.isoformat(),
        "seen_count": o.seen_count,
    }
    if history is not None:
        d["history_count"] = history
    return d


async def indicator_detail(session: AsyncSession, c: Container, ind: Indicator) -> dict[str, Any]:
    now = utcnow()
    assessment = await store.assess_indicator(session, ind, now)

    tag_rows = (
        (
            await session.execute(
                select(IndicatorTag)
                .where(IndicatorTag.indicator_id == ind.id)
                .order_by(IndicatorTag.tag)
            )
        )
        .scalars()
        .all()
    )
    grouped: dict[str, set[str]] = defaultdict(set)
    for t in tag_rows:
        grouped[t.tag].add(t.source)

    obs_rows = (
        (
            await session.execute(
                select(Observation)
                .where(Observation.indicator_id == ind.id)
                .order_by(Observation.last_seen, Observation.id)
            )
        )
        .scalars()
        .all()
    )
    latest: dict[tuple[str, str], Observation] = {}
    counts: dict[tuple[str, str], int] = defaultdict(int)
    for o in obs_rows:
        latest[(o.provider, o.kind)] = o
        counts[(o.provider, o.kind)] += 1
    order = {name: i for i, name in enumerate(c.registry.names())}
    current = sorted(latest.items(), key=lambda kv: (order.get(kv[0][0], 99), kv[0][1]))

    run_rows = (
        (
            await session.execute(
                select(ProviderRun)
                .where(ProviderRun.indicator_id == ind.id)
                .order_by(ProviderRun.started_at, ProviderRun.id)
            )
        )
        .scalars()
        .all()
    )
    last_run: dict[str, ProviderRun] = {r.provider: r for r in run_rows}

    parsed = parse_indicator(ind.value, ind.type)
    plan = [e.as_dict() for e in c.enrichment.plan(parsed, do_not_share=ind.do_not_share)]

    memberships = (
        await session.execute(
            select(Investigation.id, Investigation.title)
            .join(
                InvestigationIndicator, InvestigationIndicator.investigation_id == Investigation.id
            )
            .where(InvestigationIndicator.indicator_id == ind.id)
        )
    ).all()
    edge_count = (
        await session.execute(
            select(func.count())
            .select_from(Relationship)
            .where((Relationship.src_id == ind.id) | (Relationship.dst_id == ind.id))
        )
    ).scalar_one()

    summary = indicator_summary(ind, sorted(grouped))
    return {
        **summary,
        "lookup_policy": {
            "remote_lookup_allowed": parsed.remote_lookup_allowed,
            "blocked_reason": parsed.blocked_reason,
            "scope": parsed.scope,
        },
        "assessment": assessment.as_dict(),
        "tag_details": [
            {"tag": t, "sources": sorted(s), "analyst": "analyst" in s}
            for t, s in sorted(grouped.items())
        ],
        "observations": [observation_dict(o, counts[k]) for k, o in current],
        "provider_runs": [
            {
                "provider": r.provider,
                "status": r.status,
                "message": r.message,
                "started_at": r.started_at.isoformat(),
                "duration_ms": r.duration_ms,
                "observation_count": r.observation_count,
                "truncated": r.truncated,
            }
            for r in sorted(last_run.values(), key=lambda r: order.get(r.provider, 99))
        ],
        "plan": plan,
        "investigations": [{"id": i, "title": t} for i, t in memberships],
        "relationship_count": edge_count,
    }
