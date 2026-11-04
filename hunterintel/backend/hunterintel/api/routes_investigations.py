"""Investigation workspace endpoints: CRUD, members, notes, findings, graph, export."""

from __future__ import annotations

import json
import re
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from hunterintel.api.deps import Container, get_container, get_session, inbound_limit, require_auth
from hunterintel.api.schemas import (
    FindingIn,
    FindingPatch,
    InvestigationIn,
    InvestigationPatch,
    MemberIn,
    NoteIn,
    NotePatch,
)
from hunterintel.db.models import Finding, Indicator, Investigation, InvestigationIndicator, Note
from hunterintel.domain.evidence import utcnow
from hunterintel.domain.indicators import parse_indicator
from hunterintel.services import investigations as svc
from hunterintel.services.graph import build_graph
from hunterintel.services.reports import build_report, render_html, render_markdown

router = APIRouter(
    prefix="/api/v1/investigations",
    tags=["investigations"],
    dependencies=[Depends(require_auth), Depends(inbound_limit)],
)


async def _inv(s: AsyncSession, investigation_id: int) -> Investigation:
    inv = await svc.get_investigation(s, investigation_id)
    if inv is None:
        raise HTTPException(404, {"code": "not_found", "message": "investigation not found"})
    return inv


def _bad(exc: svc.WorkspaceError) -> HTTPException:
    return HTTPException(422, {"code": "invalid_request", "message": str(exc)})


@router.post("", status_code=201, summary="Create an investigation")
async def create_investigation(
    body: InvestigationIn, s: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    inv = Investigation(title=body.title, description=body.description, tlp=body.tlp)
    s.add(inv)
    await s.commit()
    return await svc.investigation_detail(s, inv)


@router.get("", summary="List investigations")
async def list_investigations(
    s: AsyncSession = Depends(get_session),
    status: Literal["open", "closed"] | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict[str, Any]:
    stmt = select(Investigation)
    if status:
        stmt = stmt.where(Investigation.status == status)
    total = (await s.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    rows = (
        (
            await s.execute(
                stmt.order_by(Investigation.updated_at.desc()).limit(limit).offset(offset)
            )
        )
        .scalars()
        .all()
    )
    ids = [r.id for r in rows]
    members = (
        dict(
            (
                await s.execute(
                    select(InvestigationIndicator.investigation_id, func.count())
                    .where(InvestigationIndicator.investigation_id.in_(ids))
                    .group_by(InvestigationIndicator.investigation_id)
                )
            ).all()
        )
        if ids
        else {}
    )
    findings = (
        dict(
            (
                await s.execute(
                    select(Finding.investigation_id, func.count())
                    .where(Finding.investigation_id.in_(ids))
                    .group_by(Finding.investigation_id)
                )
            ).all()
        )
        if ids
        else {}
    )
    return {
        "total": total,
        "items": [
            {
                "id": r.id,
                "title": r.title,
                "description": r.description[:300],
                "status": r.status,
                "tlp": r.tlp,
                "indicator_count": members.get(r.id, 0),
                "finding_count": findings.get(r.id, 0),
                "created_at": r.created_at.isoformat(),
                "updated_at": r.updated_at.isoformat(),
            }
            for r in rows
        ],
    }


@router.get("/{investigation_id}", summary="Investigation with indicators, findings and notes")
async def get_investigation(
    investigation_id: int, s: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    return await svc.investigation_detail(s, await _inv(s, investigation_id))


@router.patch("/{investigation_id}", summary="Update title, description, status or TLP")
async def patch_investigation(
    investigation_id: int, body: InvestigationPatch, s: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    inv = await _inv(s, investigation_id)
    for field in ("title", "description", "status", "tlp"):
        value = getattr(body, field)
        if value is not None:
            setattr(inv, field, value)
    inv.updated_at = utcnow()
    await svc.apply_tlp(s, inv)  # tightening TLP immediately protects existing members
    await s.commit()
    return await svc.investigation_detail(s, inv)


@router.delete(
    "/{investigation_id}", status_code=204, summary="Delete an investigation (indicators are kept)"
)
async def delete_investigation(
    investigation_id: int, s: AsyncSession = Depends(get_session)
) -> None:
    await s.delete(await _inv(s, investigation_id))
    await s.commit()


@router.post(
    "/{investigation_id}/indicators",
    status_code=201,
    summary="Add an indicator (no enrichment is triggered)",
)
async def add_member(
    investigation_id: int, body: MemberIn, s: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    inv = await _inv(s, investigation_id)
    if body.indicator_id is not None:
        existing = await s.get(Indicator, body.indicator_id)
        if existing is None:
            raise HTTPException(404, {"code": "not_found", "message": "indicator not found"})
        parsed = parse_indicator(existing.value, existing.type)
    elif body.value:
        parsed = parse_indicator(body.value, body.type)
    else:
        raise HTTPException(
            422, {"code": "invalid_request", "message": "provide 'value' or 'indicator_id'"}
        )
    await svc.add_indicator(s, inv, parsed)
    await s.commit()
    return await svc.investigation_detail(s, inv)


@router.delete(
    "/{investigation_id}/indicators/{indicator_id}",
    status_code=204,
    summary="Remove an indicator from the investigation",
)
async def remove_member(
    investigation_id: int, indicator_id: int, s: AsyncSession = Depends(get_session)
) -> None:
    inv = await _inv(s, investigation_id)
    if not await svc.remove_indicator(s, inv, indicator_id):
        raise HTTPException(
            404, {"code": "not_found", "message": "indicator is not in this investigation"}
        )
    await s.commit()


# ── notes ────────────────────────────────────────────────────────────────────


@router.post("/{investigation_id}/notes", status_code=201, summary="Add an analyst note")
async def add_note(
    investigation_id: int, body: NoteIn, s: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    inv = await _inv(s, investigation_id)
    try:
        note = await svc.create_note(
            s, inv, body=body.body, indicator_id=body.indicator_id, author=body.author
        )
    except svc.WorkspaceError as exc:
        raise _bad(exc) from exc
    await s.commit()
    return svc.note_dict(note)


@router.patch("/{investigation_id}/notes/{note_id}", summary="Edit a note")
async def edit_note(
    investigation_id: int, note_id: int, body: NotePatch, s: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    note = await s.get(Note, note_id)
    if note is None or note.investigation_id != investigation_id:
        raise HTTPException(404, {"code": "not_found", "message": "note not found"})
    note.body = body.body
    note.updated_at = utcnow()
    await s.commit()
    return svc.note_dict(note)


@router.delete("/{investigation_id}/notes/{note_id}", status_code=204, summary="Delete a note")
async def delete_note(
    investigation_id: int, note_id: int, s: AsyncSession = Depends(get_session)
) -> None:
    note = await s.get(Note, note_id)
    if note is None or note.investigation_id != investigation_id:
        raise HTTPException(404, {"code": "not_found", "message": "note not found"})
    await s.delete(note)
    await s.commit()


# ── findings ─────────────────────────────────────────────────────────────────


@router.post(
    "/{investigation_id}/findings",
    status_code=201,
    summary="Save a finding, optionally snapshotting an observation as evidence",
)
async def add_finding(
    investigation_id: int, body: FindingIn, s: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    inv = await _inv(s, investigation_id)
    try:
        finding = await svc.create_finding(
            s,
            inv,
            title=body.title,
            body=body.body,
            severity=body.severity,
            indicator_id=body.indicator_id,
            observation_id=body.observation_id,
        )
    except svc.WorkspaceError as exc:
        raise _bad(exc) from exc
    await s.commit()
    return svc.finding_dict(finding)


@router.patch("/{investigation_id}/findings/{finding_id}", summary="Edit a finding")
async def edit_finding(
    investigation_id: int,
    finding_id: int,
    body: FindingPatch,
    s: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    f = await s.get(Finding, finding_id)
    if f is None or f.investigation_id != investigation_id:
        raise HTTPException(404, {"code": "not_found", "message": "finding not found"})
    for field in ("title", "body", "severity"):
        value = getattr(body, field)
        if value is not None:
            setattr(f, field, value)
    f.updated_at = utcnow()
    await s.commit()
    return svc.finding_dict(f)


@router.delete(
    "/{investigation_id}/findings/{finding_id}", status_code=204, summary="Delete a finding"
)
async def delete_finding(
    investigation_id: int, finding_id: int, s: AsyncSession = Depends(get_session)
) -> None:
    f = await s.get(Finding, finding_id)
    if f is None or f.investigation_id != investigation_id:
        raise HTTPException(404, {"code": "not_found", "message": "finding not found"})
    await s.delete(f)
    await s.commit()


# ── graph & export ───────────────────────────────────────────────────────────


@router.get(
    "/{investigation_id}/graph",
    summary="Relationship graph of every indicator in the investigation",
)
async def investigation_graph(
    investigation_id: int,
    s: AsyncSession = Depends(get_session),
    c: Container = Depends(get_container),
    depth: Annotated[int, Query(ge=0, le=3)] = 1,
    inferred: bool = True,
) -> dict[str, Any]:
    inv = await _inv(s, investigation_id)
    ids = list(
        (
            await s.execute(
                select(InvestigationIndicator.indicator_id).where(
                    InvestigationIndicator.investigation_id == inv.id
                )
            )
        ).scalars()
    )
    return await build_graph(
        s, ids, depth=depth, max_nodes=c.settings.max_graph_nodes, include_inferred=inferred
    )


@router.get(
    "/{investigation_id}/export", summary="Export a report as Markdown, JSON or self-contained HTML"
)
async def export_report(
    investigation_id: int,
    s: AsyncSession = Depends(get_session),
    format: Literal["md", "json", "html"] = "md",  # noqa: A002
    defang: Annotated[
        bool, Query(description="Defang indicators in md/html (hxxps://evil[.]example)")
    ] = True,
) -> Response:
    inv = await _inv(s, investigation_id)
    report = await build_report(s, inv)
    slug = re.sub(r"[^a-z0-9]+", "-", inv.title.lower()).strip("-")[:60] or "investigation"
    # Attachment + a locked-down CSP: an exported report can never execute script in the API origin.
    headers = {
        "Content-Disposition": f'attachment; filename="hunterintel-{slug}.{format}"',
        "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox",
        "X-Content-Type-Options": "nosniff",
    }
    if format == "json":
        return Response(
            json.dumps(report, indent=2, default=str),
            media_type="application/json",
            headers=headers,
        )
    if format == "html":
        return Response(
            render_html(report, defang_values=defang),
            media_type="text/html; charset=utf-8",
            headers=headers,
        )
    return Response(
        render_markdown(report, defang_values=defang),
        media_type="text/markdown; charset=utf-8",
        headers=headers,
    )
