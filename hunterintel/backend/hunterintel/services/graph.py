"""Relationship graph over stored edges.

Stored edges carry the assurance of whoever asserted them. On top of those, ``inferred``
edges are derived *at read time* between domains that share infrastructure; they are
never persisted, always labelled ``inferred`` with their basis, and graded by how weak
the signal is (a shared IP often just means shared hosting or a CDN).
"""

from __future__ import annotations

from collections import defaultdict
from itertools import combinations
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from hunterintel.db.models import Indicator, Relationship
from hunterintel.domain.evidence import Assurance
from hunterintel.services.store import strongest_assurance

#: relationship types through which two *domains* can share something, and how strong
#: that sharing is as evidence of common operation
_SHARING = {
    "resolves_to": (
        "shares_ip",
        "weak",
        "Shared hosting, CDNs and parking pages make shared IPs weak evidence.",
    ),
    "has_nameserver": (
        "shares_nameserver",
        "weak",
        "Many unrelated domains use the same DNS provider.",
    ),
    "has_certificate": (
        "shares_certificate",
        "medium",
        "One certificate listing both names suggests a common operator.",
    ),
    "covers": (
        "shares_certificate",
        "medium",
        "One certificate listing both names suggests a common operator.",
    ),
}
MAX_PAIRS_PER_HUB = 6
MAX_HUB_DEGREE = 8  # a hub with more domains than this is a provider, not a clue


async def build_graph(
    session: AsyncSession,
    root_ids: list[int],
    *,
    depth: int = 2,
    max_nodes: int = 250,
    include_inferred: bool = True,
) -> dict[str, Any]:
    visited: set[int] = set(root_ids)
    frontier: set[int] = set(root_ids)
    truncated = False
    for _ in range(max(depth, 0)):
        if not frontier:
            break
        rows = (
            await session.execute(
                select(Relationship).where(
                    or_(Relationship.src_id.in_(frontier), Relationship.dst_id.in_(frontier))
                )
            )
        ).scalars()
        nxt: set[int] = set()
        for r in rows:
            for nid in (r.src_id, r.dst_id):
                if nid in visited:
                    continue
                if len(visited) >= max_nodes:
                    truncated = True
                    continue
                visited.add(nid)
                nxt.add(nid)
        frontier = nxt

    indicators = {
        i.id: i
        for i in (
            await session.execute(select(Indicator).where(Indicator.id.in_(visited)))
        ).scalars()
    }
    edge_rows = (
        (
            await session.execute(
                select(Relationship).where(
                    Relationship.src_id.in_(visited), Relationship.dst_id.in_(visited)
                )
            )
        )
        .scalars()
        .all()
        if visited
        else []
    )

    merged: dict[tuple[int, int, str], dict[str, Any]] = {}
    for r in edge_rows:
        key = (r.src_id, r.dst_id, r.rel_type)
        entry = merged.setdefault(
            key,
            {
                "source": r.src_id,
                "target": r.dst_id,
                "rel_type": r.rel_type,
                "evidence": [],
                "attrs": {},
            },
        )
        entry["evidence"].append(
            {"source": r.source, "assurance": r.assurance, "last_seen": r.last_seen.isoformat()}
        )
        entry["attrs"].update(r.attrs or {})
    edges = []
    for e in merged.values():
        e["assurance"] = strongest_assurance([x["assurance"] for x in e["evidence"]])
        edges.append(e)

    if include_inferred:
        edges.extend(_inferred_edges(indicators, edge_rows, set(root_ids)))

    degree: dict[int, int] = defaultdict(int)
    for e in edges:
        degree[e["source"]] += 1
        degree[e["target"]] += 1
    nodes = [
        {
            "id": i.id,
            "type": i.type,
            "value": i.value,
            "label": _label(i),
            "tracked": i.tracked,
            "is_root": i.id in root_ids,
            "verdict": i.verdict,
            "risk_score": i.risk_score,
            "classification": i.classification,
            "degree": degree.get(i.id, 0),
        }
        for i in indicators.values()
    ]
    return {
        "nodes": nodes,
        "edges": edges,
        "root_ids": list(root_ids),
        "truncated": truncated,
        "stats": {
            "nodes": len(nodes),
            "edges": len(edges),
            "inferred_edges": sum(1 for e in edges if e["assurance"] == Assurance.INFERRED.value),
            "max_nodes": max_nodes,
        },
    }


def _label(i: Indicator) -> str:
    value = i.value
    if i.type == "url":
        value = value.split("://", 1)[-1]
    return value if len(value) <= 40 else value[:18] + "…" + value[-18:]


def _inferred_edges(
    indicators: dict[int, Indicator], rows: list[Relationship], roots: set[int]
) -> list[dict[str, Any]]:
    """Domains that point at the same hub (IP / nameserver / certificate), as weak pivots."""
    domain_ids = {i.id for i in indicators.values() if i.type == "domain"}
    interesting = roots | {i.id for i in indicators.values() if i.tracked}
    hubs: dict[tuple[int, str], set[int]] = defaultdict(set)
    for r in rows:
        spec = _SHARING.get(r.rel_type)
        if spec is None:
            continue
        # outward edge domain → hub, or hub → domain for "covers"
        if r.rel_type == "covers":
            hub, member = r.src_id, r.dst_id
        else:
            hub, member = r.dst_id, r.src_id
        if member in domain_ids and member in interesting and hub in indicators:
            hubs[(hub, spec[0])].add(member)
    out: list[dict[str, Any]] = []
    for (hub, kind), members in hubs.items():
        if not 2 <= len(members) <= MAX_HUB_DEGREE:
            continue
        spec = next(v for v in _SHARING.values() if v[0] == kind)
        for a, b in list(combinations(sorted(members), 2))[:MAX_PAIRS_PER_HUB]:
            out.append(
                {
                    "source": a,
                    "target": b,
                    "rel_type": kind,
                    "assurance": Assurance.INFERRED.value,
                    "evidence": [
                        {
                            "source": "hunterintel",
                            "assurance": Assurance.INFERRED.value,
                            "last_seen": None,
                        }
                    ],
                    "attrs": {"via": indicators[hub].value, "strength": spec[1], "caveat": spec[2]},
                }
            )
    return out
