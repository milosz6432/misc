"""Investigation report export: JSON, Markdown and self-contained HTML.

Human-readable formats defang indicators by default (``hxxps://evil[.]example``) so a report
cannot be turned into a live link by accident. Gaps — sources that were unavailable, rate
limited, blocked or not configured — are listed explicitly rather than omitted.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from jinja2 import Environment, select_autoescape
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from hunterintel import __version__
from hunterintel.db.models import (
    Finding,
    Indicator,
    IndicatorTag,
    Investigation,
    InvestigationIndicator,
    Note,
    Observation,
    ProviderRun,
    Relationship,
)
from hunterintel.domain.evidence import utcnow
from hunterintel.services import store
from hunterintel.services.investigations import SEVERITIES

LEGEND = {
    "verified": "Observed first-hand from the source of record (DNS answers, registry RDAP, live probe) or computed locally.",
    "provider_claim": "Asserted by a third-party service. Attributed, not independently confirmed.",
    "inferred": "Derived by HunterIntel from other data (heuristics, shared infrastructure). A lead, not proof.",
}
LIMITATIONS = [
    "'Unknown' and 'No detections' are not statements of safety: absence of data is not evidence of absence.",
    "IP geolocation and registry country are approximate and do not locate a host physically.",
    "Certificate Transparency shows certificates were issued, not that a host currently serves them.",
    "Sources listed under 'Gaps' were not obtained for this report; conclusions do not account for them.",
]
_VERDICT_ORDER = ["malicious", "suspicious", "low_risk", "no_detections", "unknown"]


def defang(value: str, type_: str) -> str:
    if type_ in ("domain", "ip", "url", "email"):
        value = value.replace("http://", "hxxp://").replace("https://", "hxxps://")
        value = value.replace("@", "[@]")
        value = re.sub(r"\.", "[.]", value)
    return value


async def build_report(session: AsyncSession, inv: Investigation) -> dict[str, Any]:
    now = utcnow()
    members = (
        (
            await session.execute(
                select(Indicator)
                .join(InvestigationIndicator, InvestigationIndicator.indicator_id == Indicator.id)
                .where(InvestigationIndicator.investigation_id == inv.id)
                .order_by(Indicator.id)
            )
        )
        .scalars()
        .all()
    )
    ids = [m.id for m in members]
    names = {m.id: m for m in members}

    tags: dict[int, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    if ids:
        for t in (
            await session.execute(select(IndicatorTag).where(IndicatorTag.indicator_id.in_(ids)))
        ).scalars():
            tags[t.indicator_id][t.tag].add(t.source)

    indicators: list[dict[str, Any]] = []
    verdicts: dict[str, int] = defaultdict(int)
    for m in members:
        a = await store.assess_indicator(session, m, now)
        verdicts[a.verdict] += 1
        latest: dict[tuple[str, str], Observation] = {}
        for o in (
            await session.execute(
                select(Observation)
                .where(Observation.indicator_id == m.id)
                .order_by(Observation.last_seen)
            )
        ).scalars():
            latest[(o.provider, o.kind)] = o
        runs: dict[str, ProviderRun] = {}
        for r in (
            await session.execute(
                select(ProviderRun)
                .where(ProviderRun.indicator_id == m.id)
                .order_by(ProviderRun.started_at, ProviderRun.id)
            )
        ).scalars():
            runs[r.provider] = r
        indicators.append(
            {
                "id": m.id,
                "type": m.type,
                "value": m.value,
                "classification": m.classification,
                "do_not_share": m.do_not_share,
                "verdict": a.verdict,
                "risk_score": a.risk_score,
                "confidence": a.confidence,
                "freshness": a.freshness.value,
                "expires_at": a.expires_at.isoformat(),
                "first_seen": m.first_seen.isoformat(),
                "last_seen": m.last_seen.isoformat(),
                "explanation": a.explanation,
                "risk_flags": a.risk_flags,
                "tags": [{"tag": t, "sources": sorted(s)} for t, s in sorted(tags[m.id].items())],
                "evidence": [
                    {
                        "provider": o.provider,
                        "kind": o.kind,
                        "title": o.title,
                        "summary": o.summary,
                        "assurance": o.assurance,
                        "first_seen": o.first_seen.isoformat(),
                        "last_seen": o.last_seen.isoformat(),
                    }
                    for (_, kind), o in sorted(latest.items())
                    if kind != "risk_flags"
                ],
                "gaps": [
                    {"provider": r.provider, "status": r.status, "message": r.message}
                    for r in runs.values()
                    if r.status != "ok"
                ],
            }
        )

    edges: list[dict[str, Any]] = []
    if ids:
        rel_rows = (
            (
                await session.execute(
                    select(Relationship).where(
                        Relationship.src_id.in_(ids) | Relationship.dst_id.in_(ids)
                    )
                )
            )
            .scalars()
            .all()
        )
        other_ids = {r.src_id for r in rel_rows} | {r.dst_id for r in rel_rows}
        lookup = dict(names)
        missing = other_ids - set(lookup)
        if missing:
            for i in (
                await session.execute(select(Indicator).where(Indicator.id.in_(missing)))
            ).scalars():
                lookup[i.id] = i
        merged: dict[tuple[int, int, str], dict[str, Any]] = {}
        for r in rel_rows:
            e = merged.setdefault(
                (r.src_id, r.dst_id, r.rel_type),
                {
                    "source": {"type": lookup[r.src_id].type, "value": lookup[r.src_id].value},
                    "target": {"type": lookup[r.dst_id].type, "value": lookup[r.dst_id].value},
                    "rel_type": r.rel_type,
                    "evidence": [],
                },
            )
            e["evidence"].append({"source": r.source, "assurance": r.assurance})
        for e in merged.values():
            e["assurance"] = store.strongest_assurance([x["assurance"] for x in e["evidence"]])
            edges.append(e)
        edges.sort(key=lambda e: (e["rel_type"], e["source"]["value"], e["target"]["value"]))

    findings = (
        (
            await session.execute(
                select(Finding)
                .where(Finding.investigation_id == inv.id)
                .order_by(Finding.created_at)
            )
        )
        .scalars()
        .all()
    )
    notes = (
        (
            await session.execute(
                select(Note).where(Note.investigation_id == inv.id).order_by(Note.created_at)
            )
        )
        .scalars()
        .all()
    )
    highest = max((SEVERITIES.index(f.severity) for f in findings), default=None)

    return {
        "meta": {
            "title": inv.title,
            "description": inv.description,
            "tlp": inv.tlp,
            "status": inv.status,
            "investigation_id": inv.id,
            "generated_at": now.isoformat(),
            "tool": f"HunterIntel {__version__}",
            "created_at": inv.created_at.isoformat(),
        },
        "summary": {
            "indicator_count": len(indicators),
            "by_verdict": {v: verdicts[v] for v in _VERDICT_ORDER if verdicts.get(v)},
            "finding_count": len(findings),
            "highest_finding_severity": SEVERITIES[highest] if highest is not None else None,
            "relationship_count": len(edges),
        },
        "indicators": indicators,
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity,
                "body": f.body,
                "indicator_id": f.indicator_id,
                "evidence": {
                    k: f.snapshot.get(k)
                    for k in ("provider", "kind", "assurance", "summary", "last_seen")
                }
                if f.snapshot
                else None,
                "created_at": f.created_at.isoformat(),
            }
            for f in findings
        ],
        "notes": [
            {
                "id": n.id,
                "author": n.author,
                "body": n.body,
                "indicator_id": n.indicator_id,
                "created_at": n.created_at.isoformat(),
            }
            for n in notes
        ],
        "relationships": edges[:500],
        "legend": LEGEND,
        "limitations": LIMITATIONS,
    }


# ── renderers ────────────────────────────────────────────────────────────────


def _d(report: dict[str, Any], value: str, type_: str, on: bool) -> str:
    return defang(value, type_) if on else value


def _code(text: str) -> str:
    return "`" + text.replace("`", "'") + "`"


def render_markdown(report: dict[str, Any], *, defang_values: bool = True) -> str:
    m, s = report["meta"], report["summary"]
    by_id = {i["id"]: i for i in report["indicators"]}
    out = [
        f"# {m['title']}",
        "",
        f"**TLP:{m['tlp'].upper().replace('_', '+')}** · status: {m['status']} · generated {m['generated_at']} by {m['tool']}",
        "",
    ]
    if m["description"]:
        out += [m["description"], ""]
    out += [
        "## Summary",
        "",
        f"- Indicators: **{s['indicator_count']}**"
        + (
            f" ({', '.join(f'{n} {v}' for v, n in s['by_verdict'].items())})"
            if s["by_verdict"]
            else ""
        ),
        f"- Findings: **{s['finding_count']}**"
        + (
            f" (highest severity: {s['highest_finding_severity']})"
            if s["highest_finding_severity"]
            else ""
        ),
        f"- Relationships recorded: {s['relationship_count']}",
        "",
    ]
    if report["findings"]:
        out += ["## Findings", ""]
        for f in report["findings"]:
            ind = by_id.get(f["indicator_id"])
            out.append(f"### [{f['severity'].upper()}] {f['title']}")
            if ind:
                out.append(
                    f"Indicator: {_code(_d(report, ind['value'], ind['type'], defang_values))}"
                )
            if f["body"]:
                out += ["", f["body"]]
            ev = f["evidence"]
            if ev and ev.get("summary"):
                out += [
                    "",
                    f"> Evidence ({ev['assurance']}, {ev['provider']}/{ev['kind']}): {ev['summary']}",
                ]
            out.append("")
    out += ["## Indicators", ""]
    for i in report["indicators"]:
        out += [
            f"### {_code(_d(report, i['value'], i['type'], defang_values))} — {i['type']}",
            "",
            f"- Verdict: **{i['verdict'].replace('_', ' ')}** · risk {i['risk_score'] if i['risk_score'] is not None else 'n/a'} · confidence {i['confidence']}% · freshness {i['freshness']} (expires {i['expires_at'][:10]})",
            f"- Analyst classification: {i['classification']}"
            + (" · **do not share**" if i["do_not_share"] else ""),
            f"- First seen {i['first_seen'][:10]} · last seen {i['last_seen'][:10]}",
        ]
        if i["tags"]:
            out.append(
                "- Tags: " + ", ".join(f"{t['tag']} ({'/'.join(t['sources'])})" for t in i["tags"])
            )
        out.append(f"- Assessment: {i['explanation']}")
        for f in i["risk_flags"]:
            out.append(
                f"- Heuristic [{f['severity']}, inferred, {f['source']}]: {f['title']} — {f['detail']}"
            )
        if i["evidence"]:
            out += ["", "Evidence:"]
            out += [
                f"- [{e['assurance']}] **{e['provider']}** · {e['title']}"
                + (f": {e['summary']}" if e["summary"] else "")
                for e in i["evidence"]
            ]
        if i["gaps"]:
            out += ["", "Gaps (not obtained):"]
            out += [
                f"- {g['provider']}: {g['status']}" + (f" — {g['message']}" if g["message"] else "")
                for g in i["gaps"]
            ]
        out.append("")
    if report["relationships"]:
        out += ["## Relationships", ""]
        for e in report["relationships"][:200]:
            src = _d(report, e["source"]["value"], e["source"]["type"], defang_values)
            dst = _d(report, e["target"]["value"], e["target"]["type"], defang_values)
            out.append(
                f"- {_code(src)} —{e['rel_type']}→ {_code(dst)} [{e['assurance']}; {', '.join(sorted({x['source'] for x in e['evidence']}))}]"
            )
        out.append("")
    if report["notes"]:
        out += ["## Analyst notes", ""]
        out += [
            f"- **{n['author']}** ({n['created_at'][:16]}): {n['body']}" for n in report["notes"]
        ] + [""]
    out += ["## How to read this report", ""] + [
        f"- **{k}** — {v}" for k, v in report["legend"].items()
    ]
    out += [""] + [f"- {t}" for t in report["limitations"]]
    return "\n".join(out) + "\n"


_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ r.meta.title }} — HunterIntel report</title>
<style>
body{font:15px/1.5 system-ui,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem;color:#1b2430}
h1{margin-bottom:.2rem} h2{border-bottom:1px solid #d5dbe3;padding-bottom:.2rem;margin-top:2rem}
.tlp{display:inline-block;padding:.1rem .6rem;border-radius:4px;font-weight:700;background:#111;color:#fff}
.tlp-red{color:#ff2b2b}.tlp-amber,.tlp-amber_strict{color:#ffc000}.tlp-green{color:#33ff00}.tlp-clear{color:#fff}
.card{border:1px solid #d5dbe3;border-radius:8px;padding:.8rem 1rem;margin:.8rem 0}
code{background:#eef1f5;padding:.05rem .3rem;border-radius:3px;word-break:break-all}
.pill{display:inline-block;border-radius:999px;padding:0 .6rem;font-size:.8rem;font-weight:600;border:1px solid}
.malicious{color:#b42318}.suspicious{color:#b54708}.low_risk{color:#8a6a00}.no_detections{color:#05603a}.unknown{color:#475467}
.verified{color:#05603a}.provider_claim{color:#175cd3}.inferred{color:#b54708}
.muted{color:#667085}li{margin:.15rem 0}
@media print{body{margin:0}.card{break-inside:avoid}}
</style></head><body>
<span class="tlp tlp-{{ r.meta.tlp }}">TLP:{{ r.meta.tlp|upper|replace('_','+') }}</span>
<h1>{{ r.meta.title }}</h1>
<p class="muted">Status {{ r.meta.status }} · generated {{ r.meta.generated_at }} · {{ r.meta.tool }}</p>
{% if r.meta.description %}<p>{{ r.meta.description }}</p>{% endif %}
<h2>Summary</h2>
<ul><li>{{ r.summary.indicator_count }} indicator(s){% for v,n in r.summary.by_verdict.items() %} · <span class="{{ v }}">{{ n }} {{ v|replace('_',' ') }}</span>{% endfor %}</li>
<li>{{ r.summary.finding_count }} finding(s){% if r.summary.highest_finding_severity %} · highest severity {{ r.summary.highest_finding_severity }}{% endif %}</li>
<li>{{ r.summary.relationship_count }} relationship(s) recorded</li></ul>
{% if r.findings %}<h2>Findings</h2>{% for f in r.findings %}<div class="card"><strong>[{{ f.severity|upper }}] {{ f.title }}</strong>
{% if f.body %}<p style="white-space:pre-wrap">{{ f.body }}</p>{% endif %}
{% if f.evidence and f.evidence.summary %}<p class="muted">Evidence (<span class="{{ f.evidence.assurance }}">{{ f.evidence.assurance }}</span>, {{ f.evidence.provider }}/{{ f.evidence.kind }}): {{ f.evidence.summary }}</p>{% endif %}</div>{% endfor %}{% endif %}
<h2>Indicators</h2>
{% for i in r.indicators %}<div class="card">
<div><code>{{ shown[i.id] }}</code> <span class="muted">{{ i.type }}</span> <span class="pill {{ i.verdict }}">{{ i.verdict|replace('_',' ') }}</span>
{% if i.do_not_share %}<span class="pill unknown">do not share</span>{% endif %}</div>
<p class="muted">risk {{ i.risk_score if i.risk_score is not none else 'n/a' }} · confidence {{ i.confidence }}% · freshness {{ i.freshness }} (expires {{ i.expires_at[:10] }}) · classification {{ i.classification }}</p>
<p>{{ i.explanation }}</p>
{% if i.tags %}<p>Tags: {% for t in i.tags %}<code>{{ t.tag }}</code> <span class="muted">({{ t.sources|join('/') }})</span> {% endfor %}</p>{% endif %}
{% if i.risk_flags %}<ul>{% for f in i.risk_flags %}<li><span class="inferred">[{{ f.severity }}, inferred]</span> {{ f.title }} — {{ f.detail }}</li>{% endfor %}</ul>{% endif %}
{% if i.evidence %}<strong>Evidence</strong><ul>{% for e in i.evidence %}<li><span class="{{ e.assurance }}">[{{ e.assurance }}]</span> <strong>{{ e.provider }}</strong> · {{ e.title }}{% if e.summary %}: {{ e.summary }}{% endif %}</li>{% endfor %}</ul>{% endif %}
{% if i.gaps %}<strong>Gaps (not obtained)</strong><ul>{% for g in i.gaps %}<li>{{ g.provider }}: {{ g.status }}{% if g.message %} — {{ g.message }}{% endif %}</li>{% endfor %}</ul>{% endif %}
</div>{% endfor %}
{% if edges %}<h2>Relationships</h2><ul>{% for e in edges %}<li><code>{{ e.src }}</code> —{{ e.rel_type }}→ <code>{{ e.dst }}</code> <span class="{{ e.assurance }}">[{{ e.assurance }}]</span> <span class="muted">{{ e.sources }}</span></li>{% endfor %}</ul>{% endif %}
{% if r.notes %}<h2>Analyst notes</h2><ul>{% for n in r.notes %}<li><strong>{{ n.author }}</strong> <span class="muted">{{ n.created_at[:16] }}</span>: <span style="white-space:pre-wrap">{{ n.body }}</span></li>{% endfor %}</ul>{% endif %}
<h2>How to read this report</h2>
<ul>{% for k,v in r.legend.items() %}<li><span class="{{ k }}"><strong>{{ k }}</strong></span> — {{ v }}</li>{% endfor %}</ul>
<ul>{% for t in r.limitations %}<li>{{ t }}</li>{% endfor %}</ul>
</body></html>"""

_env = Environment(autoescape=select_autoescape(default=True, default_for_string=True))
_template = _env.from_string(_HTML)


def render_html(report: dict[str, Any], *, defang_values: bool = True) -> str:
    shown = {
        i["id"]: _d(report, i["value"], i["type"], defang_values) for i in report["indicators"]
    }
    edges = [
        {
            "src": _d(report, e["source"]["value"], e["source"]["type"], defang_values),
            "dst": _d(report, e["target"]["value"], e["target"]["type"], defang_values),
            "rel_type": e["rel_type"],
            "assurance": e["assurance"],
            "sources": ", ".join(sorted({x["source"] for x in e["evidence"]})),
        }
        for e in report["relationships"][:200]
    ]
    return _template.render(r=report, shown=shown, edges=edges)
