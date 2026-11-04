"""Orchestrator + store + graph + compare, against a real SQLite database."""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from hunterintel.config import Settings
from hunterintel.core.cache import MemoryCache
from hunterintel.core.http import HttpGateway
from hunterintel.core.ratelimit import MemoryRateLimiter
from hunterintel.db.models import Indicator, IndicatorTag, Observation, ProviderRun, Relationship
from hunterintel.db.session import create_engine, create_schema, create_session_factory
from hunterintel.domain.indicators import parse_indicator
from hunterintel.providers.registry import build_registry
from hunterintel.services.compare import compare_indicators
from hunterintel.services.enrichment import EnrichmentService, PlanState
from hunterintel.services.graph import build_graph
from tests.helpers import FakeDns, json_response
from tests.test_providers_keyed import KEY, SHA256, VT_FILE
from tests.test_providers_keyless import CT_ROWS, domain_doc, rdap_handler

OLD = datetime(2001, 1, 1, tzinfo=UTC)


@pytest.fixture
async def factory(tmp_path: Path) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    s = Settings(_env_file=None, database_url=f"sqlite+aiosqlite:///{tmp_path}/e.db")
    engine = create_engine(s)
    await create_schema(engine)
    yield create_session_factory(engine)
    await engine.dispose()


def example_dns(a: str = "198.51.100.10") -> FakeDns:
    return FakeDns(
        {
            ("example.com", "A"): [a],
            ("example.com", "NS"): ["ns1.dns-host.net"],
            ("example.com", "MX"): [{"preference": 10, "exchange": "mail.example.com"}],
            ("example.com", "TXT"): ["v=spf1 -all"],
        }
    )


def routing_handler(
    calls: list[httpx.Request] | None = None,
) -> Callable[[httpx.Request], httpx.Response]:
    rdap = rdap_handler(domain_doc(OLD))

    def handler(req: httpx.Request) -> httpx.Response:
        if calls is not None:
            calls.append(req)
        if req.url.host == "crt.sh":
            return json_response(CT_ROWS)
        if req.url.host == "www.virustotal.com":
            return json_response(VT_FILE)
        return rdap(req)

    return handler


def service(
    settings: Settings,
    handler: Callable[[httpx.Request], httpx.Response],
    dns: FakeDns | None = None,
) -> EnrichmentService:
    limiter = MemoryRateLimiter()
    gw = HttpGateway(settings, limiter, MemoryCache(), transport=httpx.MockTransport(handler))
    return EnrichmentService(settings, build_registry(settings), gw, dns or example_dns(), limiter)


async def enrich(svc: EnrichmentService, factory: async_sessionmaker[AsyncSession], raw: str, **kw):  # noqa: ANN003, ANN201
    async with factory() as s:
        return await svc.enrich(s, parse_indicator(raw), **kw)


# ── planning / privacy contract ──────────────────────────────────────────────


def test_plan_without_keys_shows_what_is_unavailable_and_why(settings: Settings) -> None:
    plan = {
        e.provider: e
        for e in service(settings, routing_handler()).plan(parse_indicator("example.com"))
    }
    assert plan["local"].selected_by_default and plan["dns"].selected_by_default
    assert plan["rdap"].selected_by_default and plan["crtsh"].selected_by_default
    assert plan["virustotal"].state is PlanState.NOT_CONFIGURED and "VIRUSTOTAL_API_KEY" in (
        plan["virustotal"].reason or ""
    )
    assert "probe" not in plan  # URL-only provider
    url_plan = {
        e.provider: e
        for e in service(settings, routing_handler()).plan(parse_indicator("http://example.com/x"))
    }
    assert url_plan["probe"].state is PlanState.NOT_CONFIGURED and "ALLOW_ACTIVE_PROBES" in (
        url_plan["probe"].reason or ""
    )
    assert "cymru" not in plan and "abuseipdb" not in plan  # irrelevant to domains: not even listed


def test_keyed_providers_are_never_preselected_under_the_default_policy(
    make_settings: Callable[..., Settings],
) -> None:
    s = make_settings(
        virustotal_api_key=KEY, otx_api_key=KEY, abusech_auth_key=KEY, allow_active_probes=True
    )
    plan = {
        e.provider: e
        for e in service(s, routing_handler()).plan(parse_indicator("https://example.com/x"))
    }
    assert (
        plan["virustotal"].state is PlanState.AVAILABLE
        and not plan["virustotal"].selected_by_default
    )
    assert (
        plan["probe"].state is PlanState.AVAILABLE and not plan["probe"].selected_by_default
    )  # active ⇒ always explicit
    assert "example.com/x" in plan["virustotal"].data_shared
    s2 = make_settings(virustotal_api_key=KEY, default_sharing="third_party")
    plan2 = {
        e.provider: e for e in service(s2, routing_handler()).plan(parse_indicator("example.com"))
    }
    assert plan2["virustotal"].selected_by_default


def test_private_indicators_get_no_remote_provider(make_settings: Callable[..., Settings]) -> None:
    s = make_settings(virustotal_api_key=KEY, abuseipdb_api_key=KEY)
    for raw in ["10.1.2.3", "fileserver.corp.internal", "http://192.168.0.7/admin", "AS64512"]:
        plan = {e.provider: e for e in service(s, routing_handler()).plan(parse_indicator(raw))}
        assert plan["local"].state is PlanState.AVAILABLE
        remote = [e for n, e in plan.items() if n != "local" and e.tier != "local"]
        assert remote and all(
            e.state in (PlanState.BLOCKED, PlanState.NOT_CONFIGURED) for e in remote
        ), raw
        assert any(e.state is PlanState.BLOCKED and e.reason for e in remote), raw


def test_do_not_share_blocks_everything_but_local(make_settings: Callable[..., Settings]) -> None:
    s = make_settings(virustotal_api_key=KEY)
    plan = service(s, routing_handler()).plan(parse_indicator("example.com"), do_not_share=True)
    for e in plan:
        assert (e.state is PlanState.AVAILABLE) == (e.tier == "local"), e.provider
        if e.tier != "local" and e.provider == "virustotal":
            assert "do-not-share" in (e.reason or "")


# ── enrichment end to end ────────────────────────────────────────────────────


async def test_domain_enrichment_persists_evidence_runs_and_graph(
    settings: Settings, factory: async_sessionmaker[AsyncSession]
) -> None:
    svc = service(settings, routing_handler())
    out = await enrich(svc, factory, "example.com")
    statuses = {r.provider: r.status for r in out.runs}
    assert statuses == {"local": "ok", "dns": "ok", "rdap": "ok", "crtsh": "ok"}
    async with factory() as s:
        ind = (
            await s.execute(select(Indicator).where(Indicator.value == "example.com"))
        ).scalar_one()
        assert ind.tracked and ind.last_enriched_at
        kinds = {
            o.kind
            for o in (
                await s.execute(select(Observation).where(Observation.indicator_id == ind.id))
            ).scalars()
        }
        assert {"dns.records", "rdap.domain", "ct.certificates", "local.domain_structure"} <= kinds
        untracked = (
            (await s.execute(select(Indicator.value).where(Indicator.tracked.is_(False))))
            .scalars()
            .all()
        )
        assert (
            "198.51.100.10" in untracked and "ns1.dns-host.net" in untracked
        )  # discovered, not adopted
        assert (
            "internal.corp.local" not in untracked
        )  # internal names from CT never become indicators
        g = await build_graph(s, [ind.id], depth=2, max_nodes=100)
        assert {e["rel_type"] for e in g["edges"]} >= {
            "resolves_to",
            "has_nameserver",
            "has_certificate",
            "covers",
        }
        by_rel = {e["rel_type"]: e for e in g["edges"]}
        assert by_rel["resolves_to"]["assurance"] == "verified"
        assert by_rel["has_certificate"]["assurance"] == "provider_claim"
        small = await build_graph(s, [ind.id], depth=1, max_nodes=3)
        assert small["truncated"] and len(small["nodes"]) == 3


async def test_history_dedupes_unchanged_facts_and_keeps_changes(
    settings: Settings, factory: async_sessionmaker[AsyncSession]
) -> None:
    await enrich(
        service(settings, routing_handler(), example_dns("198.51.100.10")),
        factory,
        "example.com",
        providers=["dns"],
    )
    await enrich(
        service(settings, routing_handler(), example_dns("198.51.100.10")),
        factory,
        "example.com",
        providers=["dns"],
    )
    async with factory() as s:
        rows = (
            (await s.execute(select(Observation).where(Observation.kind == "dns.records")))
            .scalars()
            .all()
        )
        assert len(rows) == 1 and rows[0].seen_count == 2  # unchanged answer: one row, seen twice
    await enrich(
        service(settings, routing_handler(), example_dns("203.0.113.99")),
        factory,
        "example.com",
        providers=["dns"],
    )
    async with factory() as s:
        rows = (
            (
                await s.execute(
                    select(Observation)
                    .where(Observation.kind == "dns.records")
                    .order_by(Observation.id)
                )
            )
            .scalars()
            .all()
        )
        assert len(rows) == 2  # the change is a new historical observation, the old one is kept
        assert rows[0].data["records"]["A"] == ["198.51.100.10"] and rows[1].data["records"][
            "A"
        ] == ["203.0.113.99"]
        runs = (
            await s.execute(
                select(func.count()).select_from(ProviderRun).where(ProviderRun.provider == "dns")
            )
        ).scalar_one()
        assert runs == 3


async def test_a_crashing_provider_cannot_sink_the_others_and_secrets_are_scrubbed(
    make_settings: Callable[..., Settings], factory: async_sessionmaker[AsyncSession]
) -> None:
    s = make_settings(virustotal_api_key=KEY)

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.host == "crt.sh":
            raise ValueError(f"boom with {KEY} inside")  # unexpected, non-gateway exception
        if req.url.host == "www.virustotal.com":
            raise httpx.ConnectError(f"cannot connect, x-apikey: {KEY}", request=req)
        return routing_handler()(req)

    svc = service(s, handler)
    out = await enrich(
        svc, factory, "example.com", providers=["dns", "rdap", "crtsh", "virustotal"]
    )
    st = {r.provider: r for r in out.runs}
    assert st["dns"].status == "ok" and st["rdap"].status == "ok"
    assert st["crtsh"].status == "error" and "Unexpected internal error" in (
        st["crtsh"].message or ""
    )
    assert st["virustotal"].status == "error"
    async with factory() as sess:
        stored = " ".join(
            str(r.message) for r in (await sess.execute(select(ProviderRun))).scalars()
        )
    assert KEY not in stored and KEY not in str(out.runs)


async def test_blocked_and_unconfigured_requests_are_recorded_and_never_sent(
    make_settings: Callable[..., Settings], factory: async_sessionmaker[AsyncSession]
) -> None:
    calls: list[httpx.Request] = []
    s = make_settings(virustotal_api_key=KEY)
    svc = service(s, routing_handler(calls))
    out = await enrich(svc, factory, "10.0.0.5", providers=["virustotal", "abuseipdb", "dns"])
    st = {r.provider: r for r in out.runs}
    assert st["virustotal"].status == "blocked" and "private" in (st["virustotal"].message or "")
    assert st["abuseipdb"].status == "not_configured"
    assert (
        st["dns"].status == "blocked"
    )  # even DNS: internal addressing is not sent to public resolvers
    assert st["local"].status == "ok" and not calls and svc._dns.calls == []  # type: ignore[attr-defined]


async def test_do_not_share_flag_is_enforced_even_when_provider_is_explicitly_requested(
    make_settings: Callable[..., Settings], factory: async_sessionmaker[AsyncSession]
) -> None:
    calls: list[httpx.Request] = []
    s = make_settings(virustotal_api_key=KEY)
    svc = service(s, routing_handler(calls))
    await enrich(svc, factory, "example.com", providers=["local"])
    async with factory() as sess:
        ind = (
            await sess.execute(select(Indicator).where(Indicator.value == "example.com"))
        ).scalar_one()
        ind.do_not_share = True
        await sess.commit()
    out = await enrich(svc, factory, "example.com", providers=["virustotal", "dns", "rdap"])
    assert {r.provider: r.status for r in out.runs if r.provider != "local"} == {
        "virustotal": "blocked",
        "dns": "blocked",
        "rdap": "blocked",
    }
    assert calls == []


async def test_unknown_provider_name_is_rejected(
    settings: Settings, factory: async_sessionmaker[AsyncSession]
) -> None:
    with pytest.raises(ValueError, match="nope"):
        await enrich(
            service(settings, routing_handler()), factory, "example.com", providers=["nope"]
        )


async def test_keyed_hash_lookup_drives_verdict_tags_and_aliases(
    make_settings: Callable[..., Settings], factory: async_sessionmaker[AsyncSession]
) -> None:
    s = make_settings(virustotal_api_key=KEY)
    out = await enrich(service(s, routing_handler()), factory, SHA256, providers=["virustotal"])
    assert (
        out.assessment["verdict"] in ("suspicious", "malicious")
        and out.assessment["confidence"] > 0
    )
    assert out.assessment["sources"] == ["virustotal"]
    async with factory() as sess:
        ind = (await sess.execute(select(Indicator).where(Indicator.value == SHA256))).scalar_one()
        assert ind.verdict == out.assessment["verdict"] and ind.risk_score and ind.risk_score > 50
        tags = (
            (await sess.execute(select(IndicatorTag).where(IndicatorTag.indicator_id == ind.id)))
            .scalars()
            .all()
        )
        assert tags and {t.source for t in tags} == {"virustotal"}  # tags keep their attribution
        edges = (
            (
                await sess.execute(
                    select(Relationship).where(Relationship.rel_type == "same_file_as")
                )
            )
            .scalars()
            .all()
        )
        assert len(edges) == 2 and all(e.assurance == "provider_claim" for e in edges)


async def test_no_keyed_data_means_unknown_not_clean(
    settings: Settings, factory: async_sessionmaker[AsyncSession]
) -> None:
    out = await enrich(service(settings, routing_handler()), factory, "example.com")
    assert out.assessment["verdict"] == "unknown" and out.assessment["risk_score"] in (None, 0)
    assert (
        "not the same as safe" in out.assessment["explanation"]
        or out.assessment["risk_flags"] == []
    )


# ── compare + inferred edges ─────────────────────────────────────────────────


async def test_compare_and_inferred_shared_infrastructure(
    settings: Settings, factory: async_sessionmaker[AsyncSession]
) -> None:
    def dns_for(domain: str, ip: str) -> FakeDns:
        return FakeDns({(domain, "A"): [ip, "198.51.100.77"], (domain, "NS"): ["ns1.dns-host.net"]})

    for domain, own_ip in [
        ("alpha-example.com", "203.0.113.1"),
        ("beta-example.com", "203.0.113.2"),
    ]:
        await enrich(
            service(settings, routing_handler(), dns_for(domain, own_ip)),
            factory,
            domain,
            providers=["dns"],
        )

    async with factory() as s:
        ids = {
            i.value: i.id
            for i in (
                await s.execute(select(Indicator).where(Indicator.type == "domain"))
            ).scalars()
        }
        a, b = ids["alpha-example.com"], ids["beta-example.com"]
        cmp = await compare_indicators(s, [a, b])
        shared = {(x["facet"], x["value"]) for x in cmp["shared"]}
        assert ("resolves_to", "198.51.100.77") in shared and (
            "has_nameserver",
            "ns1.dns-host.net",
        ) in shared
        assert ("resolves_to", "203.0.113.1") not in shared
        assert all(x["assurance"] == "inferred" and x["caveat"] for x in cmp["shared"])
        assert cmp["pairwise"][0]["shared"] == 2 and 0 < cmp["pairwise"][0]["jaccard"] < 1

        g = await build_graph(s, [a, b], depth=1, max_nodes=50)
        inferred = [e for e in g["edges"] if e["assurance"] == "inferred"]
        assert {e["rel_type"] for e in inferred} == {"shares_ip", "shares_nameserver"}
        assert all(e["attrs"]["strength"] == "weak" and e["attrs"]["caveat"] for e in inferred)
        assert not [
            e
            for e in (await build_graph(s, [a, b], depth=1, include_inferred=False))["edges"]
            if e["assurance"] == "inferred"
        ]
        # inferred edges are derived on read, never stored
        stored = (await s.execute(select(Relationship.rel_type))).scalars().all()
        assert not any(t.startswith("shares_") for t in stored)
