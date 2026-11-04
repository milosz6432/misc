"""Compare indicators: what do they share, and where do they differ?

Everything produced here is an *inference* over stored data — overlaps are leads to
investigate, not conclusions — and each shared item is graded by how strong a clue it is.
"""

from __future__ import annotations

from collections import defaultdict
from itertools import combinations
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from hunterintel.db.models import Indicator, IndicatorTag, Observation, Relationship

_STRENGTH = {
    "resolves_to": "weak",
    "← resolves_to": "weak",
    "has_nameserver": "weak",
    "has_mx": "weak",
    "belongs_to_asn": "weak",
    "has_certificate": "medium",
    "covers": "medium",
    "← covers": "medium",
    "same_file_as": "strong",
    "distributes": "medium",
    "downloaded_from": "medium",
    "hosted_on": "weak",
    "reverse_dns": "weak",
    "redirects_to": "medium",
}
_CAVEAT = {
    "weak": "Common infrastructure (shared hosting, CDN, big DNS or mail providers) — a lead, not attribution.",
    "medium": "Reasonable pivot, but confirm with additional evidence.",
    "strong": "Same artefact seen under different identifiers.",
}
_ATTR_PICKS: dict[str, list[tuple[str, str]]] = {
    "rdap.domain": [("registrar", "registrar"), ("registered", "registered")],
    "rdap.network": [("name", "network_name"), ("registration_country", "registration_country")],
    "network.asn": [("as_name", "as_name"), ("registry_country", "registry_country")],
    "file.info": [("file_type", "file_type"), ("signature", "malware_family")],
}


def _pick(data: dict[str, Any], key: str) -> Any:
    value = data.get(key)
    if key == "registrar" and isinstance(value, dict):
        return value.get("name")
    return value


async def compare_indicators(session: AsyncSession, ids: list[int]) -> dict[str, Any]:
    indicators = {
        i.id: i
        for i in (await session.execute(select(Indicator).where(Indicator.id.in_(ids)))).scalars()
    }
    ordered = [indicators[i] for i in ids if i in indicators]
    present = [i.id for i in ordered]
    names = {
        i.id: i.value
        for i in (
            await session.execute(
                select(Indicator).where(
                    Indicator.id.in_(
                        select(Relationship.dst_id)
                        .where(Relationship.src_id.in_(present))
                        .union(select(Relationship.src_id).where(Relationship.dst_id.in_(present)))
                    )
                )
            )
        ).scalars()
    }
    rels = (
        (
            await session.execute(
                select(Relationship).where(
                    or_(Relationship.src_id.in_(present), Relationship.dst_id.in_(present))
                )
            )
        )
        .scalars()
        .all()
    )

    facets: dict[int, dict[str, set[str]]] = {i: defaultdict(set) for i in present}
    for r in rels:
        if r.src_id in facets and r.dst_id in names:
            facets[r.src_id][r.rel_type].add(names[r.dst_id])
        if r.dst_id in facets and r.src_id in names:
            facets[r.dst_id][f"← {r.rel_type}"].add(names[r.src_id])

    tags: dict[int, set[str]] = defaultdict(set)
    for t in (
        await session.execute(select(IndicatorTag).where(IndicatorTag.indicator_id.in_(present)))
    ).scalars():
        tags[t.indicator_id].add(t.tag)
    for iid, ts in tags.items():
        facets[iid]["tag"] = ts

    attributes: dict[int, dict[str, Any]] = {i: {} for i in present}
    obs = (
        await session.execute(
            select(Observation)
            .where(Observation.indicator_id.in_(present))
            .order_by(Observation.last_seen)
        )
    ).scalars()
    for o in obs:  # ordered by recency, so later rows win
        for key, label in _ATTR_PICKS.get(o.kind, []):
            value = _pick(o.data, key)
            if value:
                attributes[o.indicator_id][label] = value
    for iid, attrs in attributes.items():
        for label in (
            "registrar",
            "network_name",
            "as_name",
            "malware_family",
            "file_type",
            "registration_country",
        ):
            if label in attrs:
                facets[iid][f"attr:{label}"].add(str(attrs[label]))

    shared: list[dict[str, Any]] = []
    all_facets = {f for fs in facets.values() for f in fs}
    for facet in sorted(all_facets):
        by_value: dict[str, list[int]] = defaultdict(list)
        for iid in present:
            for v in facets[iid].get(facet, ()):
                by_value[v].append(iid)
        for value, owners in sorted(by_value.items()):
            if len(owners) >= 2:
                strength = _STRENGTH.get(facet, "weak" if facet != "tag" else "weak")
                shared.append(
                    {
                        "facet": facet,
                        "value": value,
                        "indicator_ids": owners,
                        "strength": strength,
                        "assurance": "inferred",
                        "caveat": _CAVEAT[strength],
                    }
                )

    pairwise = []
    for a, b in combinations(present, 2):
        sa = {(f, v) for f, vs in facets[a].items() for v in vs}
        sb = {(f, v) for f, vs in facets[b].items() for v in vs}
        union = sa | sb
        pairwise.append(
            {
                "a": a,
                "b": b,
                "shared": len(sa & sb),
                "jaccard": round(len(sa & sb) / len(union), 3) if union else 0.0,
            }
        )

    return {
        "indicators": [
            {
                "id": i.id,
                "type": i.type,
                "value": i.value,
                "verdict": i.verdict,
                "risk_score": i.risk_score,
                "confidence": i.confidence,
                "classification": i.classification,
                "tags": sorted(tags.get(i.id, [])),
                "attributes": attributes[i.id],
                "facets": {f: sorted(vs) for f, vs in facets[i.id].items() if f != "tag"},
            }
            for i in ordered
        ],
        "shared": shared,
        "pairwise": pairwise,
        "note": "Overlaps are inferred from stored data and are leads to verify, not attribution.",
    }
