"""Investigation workspace: members, notes, findings (with evidence snapshots)."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from hunterintel.db.models import (
    Finding,
    Indicator,
    Investigation,
    InvestigationIndicator,
    Note,
    Observation,
)
from hunterintel.domain.evidence import utcnow
from hunterintel.domain.indicators import ParsedIndicator
from hunterintel.services import store

TLP_LEVELS = ("clear", "green", "amber", "amber_strict", "red")
#: At these levels the indicators must not be forwarded to any third party.
RESTRICTIVE_TLP = {"red", "amber_strict"}
SEVERITIES = ("info", "low", "medium", "high", "critical")


class WorkspaceError(ValueError):
    """A request that is well-formed but not allowed (e.g. evidence from a non-member)."""


async def get_investigation(session: AsyncSession, investigation_id: int) -> Investigation | None:
    return await session.get(Investigation, investigation_id)


async def _member_ids(session: AsyncSession, investigation_id: int) -> list[int]:
    rows = await session.execute(
        select(InvestigationIndicator.indicator_id).where(
            InvestigationIndicator.investigation_id == investigation_id
        )
    )
    return list(rows.scalars())


async def apply_tlp(session: AsyncSession, inv: Investigation) -> int:
    """Enforce TLP:RED / AMBER+STRICT on every member: mark them do-not-share."""
    if inv.tlp not in RESTRICTIVE_TLP:
        return 0
    changed = 0
    for iid in await _member_ids(session, inv.id):
        ind = await session.get(Indicator, iid)
        if ind is not None and not ind.do_not_share:
            ind.do_not_share = True
            changed += 1
    return changed


async def add_indicator(
    session: AsyncSession, inv: Investigation, parsed: ParsedIndicator
) -> Indicator:
    ind = await store.get_or_create_indicator(session, parsed, tracked=True)
    exists = await session.get(InvestigationIndicator, (inv.id, ind.id))
    if exists is None:
        session.add(InvestigationIndicator(investigation_id=inv.id, indicator_id=ind.id))
    if inv.tlp in RESTRICTIVE_TLP:
        ind.do_not_share = True  # sensitivity travels with the indicator and is never auto-cleared
    inv.updated_at = utcnow()
    await session.flush()
    return ind


async def remove_indicator(session: AsyncSession, inv: Investigation, indicator_id: int) -> bool:
    link = await session.get(InvestigationIndicator, (inv.id, indicator_id))
    if link is None:
        return False
    await session.delete(link)
    inv.updated_at = utcnow()
    return True


async def create_finding(
    session: AsyncSession,
    inv: Investigation,
    *,
    title: str,
    body: str,
    severity: str,
    indicator_id: int | None,
    observation_id: int | None,
) -> Finding:
    if severity not in SEVERITIES:
        raise WorkspaceError(f"severity must be one of {', '.join(SEVERITIES)}")
    snapshot: dict[str, Any] = {}
    members = set(await _member_ids(session, inv.id))
    if observation_id is not None:
        obs = await session.get(Observation, observation_id)
        if obs is None:
            raise WorkspaceError("observation not found")
        if indicator_id is not None and obs.indicator_id != indicator_id:
            raise WorkspaceError("observation does not belong to that indicator")
        indicator_id = obs.indicator_id
        ind = await session.get(Indicator, indicator_id)
        snapshot = {
            "indicator": {"type": ind.type, "value": ind.value} if ind else None,
            "provider": obs.provider,
            "kind": obs.kind,
            "assurance": obs.assurance,
            "title": obs.title,
            "summary": obs.summary,
            "data": obs.data,
            "first_seen": obs.first_seen.isoformat(),
            "last_seen": obs.last_seen.isoformat(),
            "captured_at": utcnow().isoformat(),
        }
    if indicator_id is not None and indicator_id not in members:
        raise WorkspaceError(
            "add the indicator to the investigation before attaching a finding to it"
        )
    finding = Finding(
        investigation_id=inv.id,
        indicator_id=indicator_id,
        observation_id=observation_id,
        title=title,
        body=body,
        severity=severity,
        snapshot=snapshot,
    )
    session.add(finding)
    inv.updated_at = utcnow()
    await session.flush()
    return finding


async def create_note(
    session: AsyncSession, inv: Investigation, *, body: str, indicator_id: int | None, author: str
) -> Note:
    if indicator_id is not None and indicator_id not in await _member_ids(session, inv.id):
        raise WorkspaceError("indicator is not part of this investigation")
    note = Note(investigation_id=inv.id, indicator_id=indicator_id, body=body, author=author)
    session.add(note)
    inv.updated_at = utcnow()
    await session.flush()
    return note


def finding_dict(f: Finding) -> dict[str, Any]:
    return {
        "id": f.id,
        "investigation_id": f.investigation_id,
        "indicator_id": f.indicator_id,
        "observation_id": f.observation_id,
        "title": f.title,
        "body": f.body,
        "severity": f.severity,
        "snapshot": f.snapshot,
        "created_at": f.created_at.isoformat(),
        "updated_at": f.updated_at.isoformat(),
    }


def note_dict(n: Note) -> dict[str, Any]:
    return {
        "id": n.id,
        "investigation_id": n.investigation_id,
        "indicator_id": n.indicator_id,
        "body": n.body,
        "author": n.author,
        "created_at": n.created_at.isoformat(),
        "updated_at": n.updated_at.isoformat(),
    }


async def investigation_detail(session: AsyncSession, inv: Investigation) -> dict[str, Any]:
    member_rows = (
        await session.execute(
            select(Indicator, InvestigationIndicator.added_at)
            .join(InvestigationIndicator, InvestigationIndicator.indicator_id == Indicator.id)
            .where(InvestigationIndicator.investigation_id == inv.id)
            .order_by(InvestigationIndicator.added_at)
        )
    ).all()
    findings = (
        (
            await session.execute(
                select(Finding)
                .where(Finding.investigation_id == inv.id)
                .order_by(Finding.created_at.desc())
            )
        )
        .scalars()
        .all()
    )
    notes = (
        (
            await session.execute(
                select(Note).where(Note.investigation_id == inv.id).order_by(Note.created_at.desc())
            )
        )
        .scalars()
        .all()
    )
    return {
        "id": inv.id,
        "title": inv.title,
        "description": inv.description,
        "status": inv.status,
        "tlp": inv.tlp,
        "created_at": inv.created_at.isoformat(),
        "updated_at": inv.updated_at.isoformat(),
        "indicators": [
            {
                "id": i.id,
                "type": i.type,
                "value": i.value,
                "verdict": i.verdict,
                "risk_score": i.risk_score,
                "confidence": i.confidence,
                "classification": i.classification,
                "do_not_share": i.do_not_share,
                "added_at": added.isoformat(),
            }
            for i, added in member_rows
        ],
        "findings": [finding_dict(f) for f in findings],
        "notes": [note_dict(n) for n in notes],
    }
