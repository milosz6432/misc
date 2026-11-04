"""System, provider, indicator, enrichment, graph and compare endpoints."""

from __future__ import annotations

from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from hunterintel import __version__
from hunterintel.api.deps import (
    Container,
    enrich_limit,
    get_container,
    get_session,
    inbound_limit,
    require_auth,
)
from hunterintel.api.schemas import CompareIn, EnrichIn, IndicatorIn, IndicatorPatch
from hunterintel.api.views import (
    indicator_detail,
    indicator_summary,
    observation_dict,
    tags_for,
)
from hunterintel.db.models import (
    Indicator,
    IndicatorTag,
    Investigation,
    Observation,
    ProviderRun,
)
from hunterintel.domain.evidence import utcnow
from hunterintel.domain.indicators import parse_indicator
from hunterintel.services.compare import compare_indicators
from hunterintel.services.graph import build_graph
from hunterintel.services.store import normalise_tag

public = APIRouter(prefix="/api/v1", tags=["system"])
router = APIRouter(prefix="/api/v1", dependencies=[Depends(require_auth), Depends(inbound_limit)])

IndicatorSort = Literal["last_seen", "first_seen", "risk", "confidence", "value"]


@public.get("/health", summary="Liveness and non-sensitive configuration summary")
async def health(c: Container = Depends(get_container)) -> dict[str, Any]:
    return {
        "status": "ok",
        "version": __version__,
        "auth_required": c.settings.api_token is not None,
        "redis": c.redis is not None,
        "active_probes_enabled": c.settings.allow_active_probes,
        "default_sharing": c.settings.default_sharing,
    }


@router.get(
    "/providers",
    tags=["system"],
    summary="Providers, their data-sharing tier and whether each is configured",
)
async def providers(c: Container = Depends(get_container)) -> list[dict[str, Any]]:
    return [p.info() for p in c.registry.all()]


@router.get("/stats", tags=["system"], summary="Dashboard summary")
async def stats(
    s: AsyncSession = Depends(get_session), c: Container = Depends(get_container)
) -> dict[str, Any]:
    now = utcnow()
    tracked = Indicator.tracked.is_(True)
    by_type = dict(
        (
            await s.execute(
                select(Indicator.type, func.count()).where(tracked).group_by(Indicator.type)
            )
        ).all()
    )
    by_verdict = dict(
        (
            await s.execute(
                select(Indicator.verdict, func.count())
                .where(tracked, Indicator.expires_at > now)
                .group_by(Indicator.verdict)
            )
        ).all()
    )
    expired = (
        await s.execute(
            select(func.count()).select_from(Indicator).where(tracked, Indicator.expires_at <= now)
        )
    ).scalar_one()
    recent = (
        (
            await s.execute(
                select(Indicator).where(tracked).order_by(Indicator.last_seen.desc()).limit(8)
            )
        )
        .scalars()
        .all()
    )
    tags = await tags_for(s, [i.id for i in recent])
    failures = (
        await s.execute(
            select(ProviderRun, Indicator.type, Indicator.value)
            .join(Indicator, Indicator.id == ProviderRun.indicator_id)
            .where(ProviderRun.status.in_(["error", "timeout", "rate_limited"]))
            .order_by(ProviderRun.started_at.desc())
            .limit(6)
        )
    ).all()
    invs = (
        (await s.execute(select(Investigation).order_by(Investigation.updated_at.desc()).limit(5)))
        .scalars()
        .all()
    )
    return {
        "indicators": {
            "by_type": by_type,
            "by_verdict": by_verdict,
            "expired": expired,
            "total": sum(by_type.values()),
        },
        "recent_indicators": [indicator_summary(i, tags[i.id]) for i in recent],
        "recent_failures": [
            {
                "provider": r.provider,
                "status": r.status,
                "message": r.message,
                "indicator": f"{t}:{v}",
                "at": r.started_at.isoformat(),
            }
            for r, t, v in failures
        ],
        "recent_investigations": [
            {
                "id": i.id,
                "title": i.title,
                "status": i.status,
                "tlp": i.tlp,
                "updated_at": i.updated_at.isoformat(),
            }
            for i in invs
        ],
        "providers": {
            "configured": [p.name for p in c.registry.all() if p.is_configured()],
            "unconfigured": [p.name for p in c.registry.all() if not p.is_configured()],
        },
    }


@router.post(
    "/indicators/classify",
    tags=["indicators"],
    summary="Parse, normalise and plan — zero network egress",
)
async def classify(
    body: IndicatorIn, s: AsyncSession = Depends(get_session), c: Container = Depends(get_container)
) -> dict[str, Any]:
    parsed = parse_indicator(body.value, body.type)
    existing = (
        await s.execute(
            select(Indicator).where(
                Indicator.type == parsed.type.value, Indicator.value == parsed.value
            )
        )
    ).scalar_one_or_none()
    return {
        "indicator": {
            "type": parsed.type.value,
            "value": parsed.value,
            "subtype": parsed.subtype,
            "raw": parsed.raw,
            "scope": parsed.scope,
            "remote_lookup_allowed": parsed.remote_lookup_allowed,
            "blocked_reason": parsed.blocked_reason,
            "sensitive": parsed.sensitive,
            "notes": parsed.notes,
        },
        "known": indicator_summary(existing) if existing else None,
        "plan": [
            e.as_dict()
            for e in c.enrichment.plan(
                parsed, do_not_share=bool(existing and existing.do_not_share)
            )
        ],
    }


@router.post(
    "/enrich",
    tags=["indicators"],
    dependencies=[Depends(enrich_limit)],
    summary="Run the selected providers, store the evidence and score it",
)
async def enrich(
    body: EnrichIn, s: AsyncSession = Depends(get_session), c: Container = Depends(get_container)
) -> dict[str, Any]:
    parsed = parse_indicator(body.value, body.type)
    try:
        outcome = await c.enrichment.enrich(
            s, parsed, providers=body.providers, refresh=body.refresh
        )
    except ValueError as exc:
        raise HTTPException(422, {"code": "invalid_request", "message": str(exc)}) from exc
    ind = await s.get(Indicator, outcome.indicator_id)
    assert ind is not None
    return {
        "indicator": await indicator_detail(s, c, ind),
        "runs": [r.as_dict() for r in outcome.runs],
        "new_observations": outcome.new_observations,
        "relationships_stored": outcome.edges,
    }


@router.get("/indicators", tags=["indicators"], summary="Browse the IOC store")
async def list_indicators(
    s: AsyncSession = Depends(get_session),
    q: Annotated[str | None, Query(max_length=200)] = None,
    type: Annotated[str | None, Query(max_length=16)] = None,  # noqa: A002
    verdict: Annotated[str | None, Query(max_length=16)] = None,
    classification: Annotated[str | None, Query(max_length=24)] = None,
    tag: Annotated[str | None, Query(max_length=64)] = None,
    tracked: bool | None = True,
    include_expired: bool = False,
    sort: IndicatorSort = "last_seen",
    desc: bool = True,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict[str, Any]:
    stmt = select(Indicator)
    if tracked is not None:
        stmt = stmt.where(Indicator.tracked.is_(tracked))
    if q:
        like = "%" + q.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        stmt = stmt.where(func.lower(Indicator.value).like(like, escape="\\"))
    if type:
        stmt = stmt.where(Indicator.type == type)
    if verdict:
        stmt = stmt.where(Indicator.verdict == verdict)
    if classification:
        stmt = stmt.where(Indicator.classification == classification)
    if tag:
        stmt = stmt.where(
            Indicator.id.in_(
                select(IndicatorTag.indicator_id).where(
                    IndicatorTag.tag == (normalise_tag(tag) or "")
                )
            )
        )
    if not include_expired:
        stmt = stmt.where(Indicator.expires_at > utcnow())
    total = (await s.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    column = {
        "last_seen": Indicator.last_seen,
        "first_seen": Indicator.first_seen,
        "risk": Indicator.risk_score,
        "confidence": Indicator.confidence,
        "value": Indicator.value,
    }[sort]
    stmt = stmt.order_by(
        column.desc().nulls_last() if desc else column.asc().nulls_last(), Indicator.id.desc()
    )
    rows = (await s.execute(stmt.limit(limit).offset(offset))).scalars().all()
    tags = await tags_for(s, [r.id for r in rows])
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": [indicator_summary(r, tags[r.id]) for r in rows],
    }


async def _get_or_404(s: AsyncSession, indicator_id: int) -> Indicator:
    ind = await s.get(Indicator, indicator_id)
    if ind is None:
        raise HTTPException(404, {"code": "not_found", "message": "indicator not found"})
    return ind


@router.get(
    "/indicators/{indicator_id}",
    tags=["indicators"],
    summary="Everything known about one indicator",
)
async def get_indicator(
    indicator_id: int, s: AsyncSession = Depends(get_session), c: Container = Depends(get_container)
) -> dict[str, Any]:
    return await indicator_detail(s, c, await _get_or_404(s, indicator_id))


@router.get(
    "/indicators/{indicator_id}/observations",
    tags=["indicators"],
    summary="Historical observations",
)
async def observation_history(
    indicator_id: int,
    s: AsyncSession = Depends(get_session),
    provider: Annotated[str | None, Query(max_length=32)] = None,
    kind: Annotated[str | None, Query(max_length=48)] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
) -> dict[str, Any]:
    await _get_or_404(s, indicator_id)
    stmt = select(Observation).where(Observation.indicator_id == indicator_id)
    if provider:
        stmt = stmt.where(Observation.provider == provider)
    if kind:
        stmt = stmt.where(Observation.kind == kind)
    rows = (
        (
            await s.execute(
                stmt.order_by(Observation.first_seen.desc(), Observation.id.desc()).limit(limit)
            )
        )
        .scalars()
        .all()
    )
    return {"items": [observation_dict(o) for o in rows]}


@router.get(
    "/indicators/{indicator_id}/runs",
    tags=["indicators"],
    summary="Provider run history, including failures",
)
async def run_history(
    indicator_id: int,
    s: AsyncSession = Depends(get_session),
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> dict[str, Any]:
    await _get_or_404(s, indicator_id)
    rows = (
        (
            await s.execute(
                select(ProviderRun)
                .where(ProviderRun.indicator_id == indicator_id)
                .order_by(ProviderRun.started_at.desc(), ProviderRun.id.desc())
                .limit(limit)
            )
        )
        .scalars()
        .all()
    )
    return {
        "items": [
            {
                "id": r.id,
                "provider": r.provider,
                "status": r.status,
                "message": r.message,
                "started_at": r.started_at.isoformat(),
                "duration_ms": r.duration_ms,
                "observation_count": r.observation_count,
                "truncated": r.truncated,
            }
            for r in rows
        ]
    }


@router.get(
    "/indicators/{indicator_id}/graph",
    tags=["graph"],
    summary="Relationship graph around an indicator",
)
async def indicator_graph(
    indicator_id: int,
    s: AsyncSession = Depends(get_session),
    c: Container = Depends(get_container),
    depth: Annotated[int, Query(ge=1, le=4)] = 2,
    inferred: bool = True,
) -> dict[str, Any]:
    await _get_or_404(s, indicator_id)
    return await build_graph(
        s,
        [indicator_id],
        depth=depth,
        max_nodes=c.settings.max_graph_nodes,
        include_inferred=inferred,
    )


@router.patch(
    "/indicators/{indicator_id}",
    tags=["indicators"],
    summary="Analyst classification, tags, sharing flag",
)
async def patch_indicator(
    indicator_id: int,
    body: IndicatorPatch,
    s: AsyncSession = Depends(get_session),
    c: Container = Depends(get_container),
) -> dict[str, Any]:
    ind = await _get_or_404(s, indicator_id)
    if body.classification is not None:
        ind.classification = body.classification
    if body.do_not_share is not None:
        ind.do_not_share = body.do_not_share
    if body.tracked is not None:
        ind.tracked = body.tracked
    if body.ttl_days is not None:
        ind.ttl_days = body.ttl_days
    existing = {
        (t.tag, t.source)
        for t in (
            await s.execute(select(IndicatorTag).where(IndicatorTag.indicator_id == ind.id))
        ).scalars()
    }
    for raw in body.add_tags:
        tag = normalise_tag(raw)
        if tag and (tag, "analyst") not in existing:
            s.add(IndicatorTag(indicator_id=ind.id, tag=tag, source="analyst"))
    for raw in body.remove_tags:
        tag = normalise_tag(raw)
        if tag:  # analysts may remove any tag; provider re-tagging on next enrichment is expected
            await s.execute(
                delete(IndicatorTag).where(
                    IndicatorTag.indicator_id == ind.id, IndicatorTag.tag == tag
                )
            )
    await s.commit()
    return await indicator_detail(s, c, ind)


@router.delete(
    "/indicators/{indicator_id}",
    tags=["indicators"],
    status_code=204,
    summary="Delete an indicator and its evidence",
)
async def delete_indicator(indicator_id: int, s: AsyncSession = Depends(get_session)) -> None:
    ind = await _get_or_404(s, indicator_id)
    await s.delete(ind)
    await s.commit()


@router.post(
    "/compare",
    tags=["graph"],
    summary="Compare indicators: shared infrastructure, tags, attributes",
)
async def compare(body: CompareIn, s: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    ids = list(dict.fromkeys(body.indicator_ids))
    if len(ids) < 2:
        raise HTTPException(
            422, {"code": "invalid_request", "message": "need at least two distinct indicators"}
        )
    result = await compare_indicators(s, ids)
    if len(result["indicators"]) != len(ids):
        raise HTTPException(
            404, {"code": "not_found", "message": "one or more indicators not found"}
        )
    return result
