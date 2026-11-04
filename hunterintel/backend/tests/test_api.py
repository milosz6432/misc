"""Full-stack API tests over ASGI with a real SQLite database and offline transports."""

from __future__ import annotations

import hashlib
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy import update

from hunterintel.api.app import create_app
from hunterintel.config import Settings
from hunterintel.db.models import Indicator
from hunterintel.domain.evidence import utcnow
from tests.helpers import FakeDns, fresh_database_url
from tests.test_enrichment import example_dns, routing_handler
from tests.test_providers_keyed import KEY, SHA256

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
TOKEN = "api-token-0123456789-abcdef"


@asynccontextmanager
async def make_client(
    tmp_path: Path,
    make_settings: Callable[..., Settings],
    calls: list[httpx.Request] | None = None,
    dns: FakeDns | None = None,
    **overrides: Any,
) -> AsyncIterator[httpx.AsyncClient]:
    settings = make_settings(database_url=await fresh_database_url(tmp_path, "api"), **overrides)
    app = create_app(
        settings, transport=httpx.MockTransport(routing_handler(calls)), dns=dns or example_dns()
    )
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            client.app = app  # type: ignore[attr-defined]
            yield client


@pytest.fixture
async def client(
    tmp_path: Path, make_settings: Callable[..., Settings]
) -> AsyncIterator[httpx.AsyncClient]:
    async with make_client(tmp_path, make_settings) as c:
        yield c


API = "/api/v1"


# ── auth, headers, limits ────────────────────────────────────────────────────


async def test_health_is_open_and_discloses_no_secrets(
    tmp_path: Path, make_settings: Callable[..., Settings]
) -> None:
    async with make_client(tmp_path, make_settings, api_token=TOKEN, virustotal_api_key=KEY) as c:
        r = await c.get(f"{API}/health")
        assert r.status_code == 200 and r.json()["auth_required"] is True
        assert TOKEN not in r.text and KEY not in r.text


async def test_bearer_token_required_when_configured(
    tmp_path: Path, make_settings: Callable[..., Settings]
) -> None:
    async with make_client(tmp_path, make_settings, api_token=TOKEN) as c:
        assert (await c.get(f"{API}/providers")).status_code == 401
        assert (
            await c.get(f"{API}/providers", headers={"Authorization": "Bearer nope"})
        ).status_code == 401
        assert (
            await c.get(f"{API}/providers", headers={"Authorization": f"Basic {TOKEN}"})
        ).status_code == 401
        bad = await c.post(f"{API}/enrich", json={"value": "example.com"})
        assert bad.status_code == 401 and bad.headers["www-authenticate"] == "Bearer"
        ok = await c.get(f"{API}/providers", headers={"Authorization": f"Bearer {TOKEN}"})
        assert ok.status_code == 200


async def test_no_auth_means_open_by_design_for_local_use(client: httpx.AsyncClient) -> None:
    assert (await client.get(f"{API}/providers")).status_code == 200


async def test_security_headers_and_cors(client: httpx.AsyncClient) -> None:
    r = await client.get(f"{API}/health")
    assert (
        r.headers["x-content-type-options"] == "nosniff"
        and r.headers["cache-control"] == "no-store"
    )
    assert r.headers["x-frame-options"] == "DENY" and r.headers["referrer-policy"] == "no-referrer"
    pre = await client.options(
        f"{API}/providers",
        headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "GET"},
    )
    assert pre.headers.get("access-control-allow-origin") == "http://localhost:5173"
    evil = await client.options(
        f"{API}/providers",
        headers={"Origin": "https://evil.example.net", "Access-Control-Request-Method": "GET"},
    )
    assert "access-control-allow-origin" not in evil.headers


async def test_oversized_json_body_rejected(client: httpx.AsyncClient) -> None:
    r = await client.post(
        f"{API}/indicators/classify",
        content=b'{"value":"' + b"a" * 1_100_000 + b'"}',
        headers={"content-type": "application/json"},
    )
    assert r.status_code == 413 and r.json()["detail"]["code"] == "too_large"


async def test_inbound_rate_limit(tmp_path: Path, make_settings: Callable[..., Settings]) -> None:
    async with make_client(tmp_path, make_settings, inbound_rate_limit_per_minute=3) as c:
        codes = [(await c.get(f"{API}/providers")).status_code for _ in range(5)]
        assert codes[:3] == [200, 200, 200] and codes[3:] == [429, 429]
        limited = await c.get(f"{API}/providers")
        assert int(limited.headers["retry-after"]) >= 1
        assert (await c.get(f"{API}/health")).status_code == 200  # health is exempt


async def test_unexpected_errors_do_not_leak_internals(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    container = client.app.state.container  # type: ignore[attr-defined]

    def boom(*a: Any, **k: Any) -> None:
        raise RuntimeError("secret internal path /srv/hunterintel/db.sqlite")

    monkeypatch.setattr(container.registry, "all", boom)
    r = await client.get(f"{API}/providers")
    assert (
        r.status_code == 500
        and "secret internal path" not in r.text
        and r.json()["detail"]["code"] == "internal_error"
    )


# ── providers & classify ─────────────────────────────────────────────────────


async def test_providers_report_configuration_without_keys(
    tmp_path: Path, make_settings: Callable[..., Settings]
) -> None:
    async with make_client(tmp_path, make_settings, virustotal_api_key=KEY) as c:
        body = (await c.get(f"{API}/providers")).json()
        by = {p["name"]: p for p in body}
        assert by["virustotal"]["configured"] is True and by["otx"]["configured"] is False
        assert (
            by["dns"]["tier"] == "public"
            and by["local"]["tier"] == "local"
            and by["probe"]["tier"] == "active"
        )
        assert KEY not in str(body)


async def test_classify_normalises_and_plans_with_zero_egress(
    tmp_path: Path, make_settings: Callable[..., Settings]
) -> None:
    calls: list[httpx.Request] = []
    dns = FakeDns()
    async with make_client(tmp_path, make_settings, calls, dns) as c:
        r = await c.post(
            f"{API}/indicators/classify", json={"value": "hxxps://Evil[.]Example[.]COM:443/a/../b"}
        )
        assert r.status_code == 200
        body = r.json()
        assert (
            body["indicator"]["type"] == "url"
            and body["indicator"]["value"] == "https://evil.example.com/b"
        )
        assert any("defanged" in n for n in body["indicator"]["notes"])
        plan = {p["provider"]: p for p in body["plan"]}
        assert (
            plan["local"]["selected_by_default"] and plan["virustotal"]["state"] == "not_configured"
        )
        assert calls == [] and dns.calls == []  # classification never touches the network


async def test_classify_errors_and_private_blocking(client: httpx.AsyncClient) -> None:
    bad = await client.post(f"{API}/indicators/classify", json={"value": "not an indicator"})
    assert bad.status_code == 422 and bad.json()["detail"]["code"] == "invalid_indicator"
    assert (await client.post(f"{API}/indicators/classify", json={"value": ""})).status_code == 422
    assert (
        await client.post(f"{API}/indicators/classify", json={"value": "x.com", "bogus": 1})
    ).status_code == 422  # extra=forbid
    priv = (await client.post(f"{API}/indicators/classify", json={"value": "192.168.1.10"})).json()
    assert (
        priv["indicator"]["remote_lookup_allowed"] is False
        and priv["indicator"]["scope"] == "private"
    )
    assert all(p["state"] != "available" for p in priv["plan"] if p["tier"] != "local")


async def test_certificate_needs_explicit_type(client: httpx.AsyncClient) -> None:
    r = await client.post(
        f"{API}/indicators/classify", json={"value": SHA256, "type": "certificate"}
    )
    assert r.json()["indicator"]["type"] == "certificate"
    assert (await client.post(f"{API}/indicators/classify", json={"value": SHA256})).json()[
        "indicator"
    ]["type"] == "hash"


# ── enrichment & indicator store ─────────────────────────────────────────────


async def test_enrich_then_read_back_everything(client: httpx.AsyncClient) -> None:
    r = await client.post(f"{API}/enrich", json={"value": "Example.COM"})
    assert r.status_code == 200
    out = r.json()
    ind = out["indicator"]
    assert {x["provider"]: x["status"] for x in out["runs"]} == {
        "local": "ok",
        "dns": "ok",
        "rdap": "ok",
        "crtsh": "ok",
    }
    assert ind["value"] == "example.com" and ind["tracked"] and ind["freshness"] == "fresh"
    assert (
        ind["assessment"]["verdict"] == "unknown"
    )  # no reputation sources ⇒ unknown, never "clean"
    kinds = {(o["provider"], o["kind"]): o for o in ind["observations"]}
    assert kinds[("dns", "dns.records")]["assurance"] == "verified"
    assert kinds[("crtsh", "ct.certificates")]["assurance"] == "provider_claim"
    assert {p["provider"]: p["status"] for p in ind["provider_runs"]}["rdap"] == "ok"
    assert ind["relationship_count"] > 5

    again = (await client.get(f"{API}/indicators/{ind['id']}")).json()
    assert again["id"] == ind["id"] and again["observations"]
    hist = (
        await client.get(f"{API}/indicators/{ind['id']}/observations", params={"provider": "dns"})
    ).json()["items"]
    assert hist and all(h["provider"] == "dns" for h in hist)
    runs = (await client.get(f"{API}/indicators/{ind['id']}/runs")).json()["items"]
    assert len(runs) == 4
    assert (await client.get(f"{API}/indicators/99999")).status_code == 404


async def test_enrich_rejects_unknown_provider_and_reports_not_configured(
    client: httpx.AsyncClient,
) -> None:
    bad = await client.post(f"{API}/enrich", json={"value": "example.com", "providers": ["nope"]})
    assert bad.status_code == 422 and "nope" in bad.json()["detail"]["message"]
    ok = await client.post(
        f"{API}/enrich", json={"value": "example.com", "providers": ["virustotal"]}
    )
    runs = {r["provider"]: r for r in ok.json()["runs"]}
    assert (
        runs["virustotal"]["status"] == "not_configured"
        and "VIRUSTOTAL_API_KEY" in runs["virustotal"]["message"]
    )


async def test_keyed_enrichment_only_when_explicitly_selected(
    tmp_path: Path, make_settings: Callable[..., Settings]
) -> None:
    calls: list[httpx.Request] = []
    async with make_client(tmp_path, make_settings, calls, virustotal_api_key=KEY) as c:
        await c.post(f"{API}/enrich", json={"value": SHA256})  # default plan
        assert not [
            x for x in calls if x.url.host == "www.virustotal.com"
        ]  # nothing went to VirusTotal
        r = await c.post(f"{API}/enrich", json={"value": SHA256, "providers": ["virustotal"]})
        assert [x.url.path for x in calls if x.url.host == "www.virustotal.com"] == [
            f"/api/v3/files/{SHA256}"
        ]
        a = r.json()["indicator"]["assessment"]
        assert a["verdict"] in ("suspicious", "malicious") and a["sources"] == ["virustotal"]
        assert any(t["sources"] == ["virustotal"] for t in r.json()["indicator"]["tag_details"])


async def test_patch_classification_tags_and_do_not_share(
    tmp_path: Path, make_settings: Callable[..., Settings]
) -> None:
    calls: list[httpx.Request] = []
    async with make_client(tmp_path, make_settings, calls, virustotal_api_key=KEY) as c:
        ind = (
            await c.post(f"{API}/enrich", json={"value": "example.com", "providers": ["local"]})
        ).json()["indicator"]
        p = await c.patch(
            f"{API}/indicators/{ind['id']}",
            json={
                "classification": "suspicious",
                "add_tags": ["Phish Kit", "apt-x"],
                "do_not_share": True,
            },
        )
        assert p.status_code == 200
        d = p.json()
        assert d["classification"] == "suspicious" and d["do_not_share"] is True
        assert {t["tag"] for t in d["tag_details"]} == {"phish kit", "apt-x"} and all(
            t["analyst"] for t in d["tag_details"]
        )
        assert (
            d["assessment"]["verdict"] == "unknown"
        )  # analyst opinion never rewrites the computed assessment
        blocked = await c.post(
            f"{API}/enrich", json={"value": "example.com", "providers": ["virustotal", "dns"]}
        )
        assert {
            r["provider"]: r["status"] for r in blocked.json()["runs"] if r["provider"] != "local"
        } == {"virustotal": "blocked", "dns": "blocked"}
        assert calls == []
        removed = await c.patch(f"{API}/indicators/{ind['id']}", json={"remove_tags": ["apt-x"]})
        assert [t["tag"] for t in removed.json()["tag_details"]] == ["phish kit"]
        assert (
            await c.patch(f"{API}/indicators/{ind['id']}", json={"classification": "bogus"})
        ).status_code == 422
        assert (await c.delete(f"{API}/indicators/{ind['id']}")).status_code == 204
        assert (await c.get(f"{API}/indicators/{ind['id']}")).status_code == 404


async def test_listing_filters_sorting_and_expiry(client: httpx.AsyncClient) -> None:
    for v in ["example.com", "8.8.8.8", SHA256]:
        await client.post(f"{API}/enrich", json={"value": v, "providers": ["local"]})
    items = (await client.get(f"{API}/indicators")).json()
    assert (
        items["total"] == 3
    )  # only tracked indicators — discovered nodes stay out of the IOC list
    assert (await client.get(f"{API}/indicators", params={"type": "ip"})).json()["total"] == 1
    assert (await client.get(f"{API}/indicators", params={"q": "EXAMPLE"})).json()["items"][0][
        "value"
    ] == "example.com"
    assert (await client.get(f"{API}/indicators", params={"q": "%"})).json()[
        "total"
    ] == 0  # LIKE wildcards are escaped
    assert (await client.get(f"{API}/indicators", params={"tracked": "false"})).json()["total"] == 0
    page = (
        await client.get(f"{API}/indicators", params={"limit": 2, "sort": "value", "desc": "false"})
    ).json()
    assert [i["value"] for i in page["items"]] == sorted(i["value"] for i in page["items"]) and len(
        page["items"]
    ) == 2
    assert (await client.get(f"{API}/indicators", params={"sort": "nonsense"})).status_code == 422

    container = client.app.state.container  # type: ignore[attr-defined]
    async with container.session_factory() as s:
        await s.execute(
            update(Indicator)
            .where(Indicator.value == "8.8.8.8")
            .values(
                last_seen=utcnow() - timedelta(days=400), expires_at=utcnow() - timedelta(days=370)
            )
        )
        await s.commit()
    assert (await client.get(f"{API}/indicators")).json()["total"] == 2  # expired hidden by default
    old = (
        await client.get(f"{API}/indicators", params={"include_expired": "true", "type": "ip"})
    ).json()["items"][0]
    assert old["freshness"] == "expired"
    stats = (await client.get(f"{API}/stats")).json()
    assert stats["indicators"]["expired"] == 1 and stats["indicators"]["total"] == 3


async def test_graph_and_compare_endpoints(
    tmp_path: Path, make_settings: Callable[..., Settings]
) -> None:
    dns = FakeDns(
        {("a-example.com", "A"): ["198.51.100.77"], ("b-example.com", "A"): ["198.51.100.77"]}
    )
    async with make_client(tmp_path, make_settings, dns=dns) as c:
        ids = []
        for d in ("a-example.com", "b-example.com"):
            ids.append(
                (await c.post(f"{API}/enrich", json={"value": d, "providers": ["dns"]})).json()[
                    "indicator"
                ]["id"]
            )
        g = (await c.get(f"{API}/indicators/{ids[0]}/graph", params={"depth": 2})).json()
        assert {n["value"] for n in g["nodes"]} >= {
            "a-example.com",
            "198.51.100.77",
            "b-example.com",
        }
        assert g["stats"]["inferred_edges"] == 1
        assert not (
            await c.get(f"{API}/indicators/{ids[0]}/graph", params={"inferred": "false"})
        ).json()["stats"]["inferred_edges"]
        cmp = await c.post(f"{API}/compare", json={"indicator_ids": ids})
        assert cmp.status_code == 200 and cmp.json()["shared"][0]["value"] == "198.51.100.77"
        assert (
            await c.post(f"{API}/compare", json={"indicator_ids": [ids[0], ids[0]]})
        ).status_code == 422
        assert (
            await c.post(f"{API}/compare", json={"indicator_ids": [ids[0], 999]})
        ).status_code == 404
        assert (
            await c.get(f"{API}/indicators/{ids[0]}/graph", params={"depth": 9})
        ).status_code == 422


# ── investigations ───────────────────────────────────────────────────────────


async def test_investigation_workspace_flow(client: httpx.AsyncClient) -> None:
    inv = (
        await client.post(
            f"{API}/investigations",
            json={"title": "Phish <b>wave</b>", "description": "d", "tlp": "amber"},
        )
    ).json()
    iid = inv["id"]
    d = (
        await client.post(f"{API}/investigations/{iid}/indicators", json={"value": "example.com"})
    ).json()
    assert [i["value"] for i in d["indicators"]] == ["example.com"]
    ind_id = d["indicators"][0]["id"]
    again = (
        await client.post(f"{API}/investigations/{iid}/indicators", json={"indicator_id": ind_id})
    ).json()
    assert len(again["indicators"]) == 1  # idempotent
    assert (await client.post(f"{API}/investigations/{iid}/indicators", json={})).status_code == 422
    assert (
        await client.post(f"{API}/investigations/{iid}/indicators", json={"indicator_id": 999})
    ).status_code == 404

    await client.post(f"{API}/enrich", json={"value": "example.com"})
    detail = (await client.get(f"{API}/indicators/{ind_id}")).json()
    dns_obs = next(o for o in detail["observations"] if o["kind"] == "dns.records")

    note = await client.post(
        f"{API}/investigations/{iid}/notes",
        json={"body": "looks like <script>alert(1)</script>", "indicator_id": ind_id},
    )
    assert note.status_code == 201
    other = (
        await client.post(f"{API}/enrich", json={"value": "8.8.8.8", "providers": ["local"]})
    ).json()["indicator"]["id"]
    assert (
        await client.post(
            f"{API}/investigations/{iid}/notes", json={"body": "x", "indicator_id": other}
        )
    ).status_code == 422

    f = await client.post(
        f"{API}/investigations/{iid}/findings",
        json={
            "title": "Resolves to hosting",
            "severity": "medium",
            "indicator_id": ind_id,
            "observation_id": dns_obs["id"],
            "body": "see DNS",
        },
    )
    assert f.status_code == 201 and f.json()["snapshot"]["assurance"] == "verified"
    assert f.json()["snapshot"]["data"]["records"]["A"] == ["198.51.100.10"]
    assert (
        await client.post(
            f"{API}/investigations/{iid}/findings", json={"title": "x", "indicator_id": other}
        )
    ).status_code == 422  # not a member
    assert (
        await client.post(
            f"{API}/investigations/{iid}/findings", json={"title": "x", "observation_id": 99999}
        )
    ).status_code == 422

    edited = await client.patch(
        f"{API}/investigations/{iid}/findings/{f.json()['id']}", json={"severity": "high"}
    )
    assert edited.json()["severity"] == "high"
    listing = (await client.get(f"{API}/investigations")).json()
    assert listing["items"][0]["indicator_count"] == 1 and listing["items"][0]["finding_count"] == 1

    g = (await client.get(f"{API}/investigations/{iid}/graph")).json()
    assert any(n["is_root"] for n in g["nodes"])

    assert (
        await client.delete(f"{API}/investigations/{iid}/indicators/{ind_id}")
    ).status_code == 204
    assert (
        await client.delete(f"{API}/investigations/{iid}/indicators/{ind_id}")
    ).status_code == 404
    assert (await client.delete(f"{API}/investigations/{iid}")).status_code == 204
    assert (await client.get(f"{API}/investigations/{iid}")).status_code == 404
    assert (
        await client.get(f"{API}/indicators/{ind_id}")
    ).status_code == 200  # indicators outlive investigations


async def test_finding_snapshot_survives_later_reenrichment(client: httpx.AsyncClient) -> None:
    iid = (await client.post(f"{API}/investigations", json={"title": "t"})).json()["id"]
    ind = (
        await client.post(f"{API}/enrich", json={"value": "example.com", "providers": ["dns"]})
    ).json()["indicator"]
    await client.post(f"{API}/investigations/{iid}/indicators", json={"indicator_id": ind["id"]})
    obs = next(o for o in ind["observations"] if o["kind"] == "dns.records")
    fid = (
        await client.post(
            f"{API}/investigations/{iid}/findings",
            json={"title": "f", "indicator_id": ind["id"], "observation_id": obs["id"]},
        )
    ).json()["id"]
    client.app.state.container.dns.table[("example.com", "A")] = ["203.0.113.250"]  # type: ignore[attr-defined]
    await client.post(f"{API}/enrich", json={"value": "example.com", "providers": ["dns"]})
    stored = next(
        x
        for x in (await client.get(f"{API}/investigations/{iid}")).json()["findings"]
        if x["id"] == fid
    )
    assert stored["snapshot"]["data"]["records"]["A"] == [
        "198.51.100.10"
    ]  # evidence as it was when saved


async def test_tlp_red_forces_do_not_share_on_members(
    tmp_path: Path, make_settings: Callable[..., Settings]
) -> None:
    calls: list[httpx.Request] = []
    async with make_client(tmp_path, make_settings, calls, virustotal_api_key=KEY) as c:
        pre = (
            await c.post(f"{API}/enrich", json={"value": "example.com", "providers": ["local"]})
        ).json()["indicator"]
        assert pre["do_not_share"] is False
        iid = (await c.post(f"{API}/investigations", json={"title": "ir", "tlp": "amber"})).json()[
            "id"
        ]
        await c.post(f"{API}/investigations/{iid}/indicators", json={"indicator_id": pre["id"]})
        assert (await c.get(f"{API}/indicators/{pre['id']}")).json()["do_not_share"] is False
        await c.patch(
            f"{API}/investigations/{iid}", json={"tlp": "red"}
        )  # tightening applies retroactively
        assert (await c.get(f"{API}/indicators/{pre['id']}")).json()["do_not_share"] is True
        new = (
            await c.post(
                f"{API}/investigations/{iid}/indicators", json={"value": "new-example.com"}
            )
        ).json()
        assert (
            next(i for i in new["indicators"] if i["value"] == "new-example.com")["do_not_share"]
            is True
        )
        r = await c.post(
            f"{API}/enrich", json={"value": "example.com", "providers": ["virustotal", "rdap"]}
        )
        assert {
            x["provider"]: x["status"] for x in r.json()["runs"] if x["provider"] != "local"
        } == {"virustotal": "blocked", "rdap": "blocked"}
        assert calls == []


async def test_export_formats_defang_escape_and_headers(client: httpx.AsyncClient) -> None:
    iid = (
        await client.post(
            f"{API}/investigations",
            json={"title": "Report <script>alert(1)</script>", "tlp": "red"},
        )
    ).json()["id"]
    ind = (
        await client.post(
            f"{API}/enrich", json={"value": "https://example.com/login", "providers": ["local"]}
        )
    ).json()["indicator"]
    await client.post(f"{API}/investigations/{iid}/indicators", json={"indicator_id": ind["id"]})
    await client.post(
        f"{API}/investigations/{iid}/notes",
        json={"body": "<img src=x onerror=alert(1)>", "author": "mallory<script>"},
    )
    await client.post(
        f"{API}/investigations/{iid}/findings",
        json={"title": "<svg onload=alert(1)>", "indicator_id": ind["id"], "severity": "low"},
    )

    md = await client.get(f"{API}/investigations/{iid}/export", params={"format": "md"})
    assert md.status_code == 200 and md.headers["content-type"].startswith("text/markdown")
    assert (
        "attachment" in md.headers["content-disposition"]
        and ".md" in md.headers["content-disposition"]
    )
    assert "hxxps://example[.]com/login" in md.text and "https://example.com/login" not in md.text
    assert "TLP:RED" in md.text and "absence of data is not evidence of absence" in md.text
    raw = await client.get(
        f"{API}/investigations/{iid}/export", params={"format": "md", "defang": "false"}
    )
    assert "https://example.com/login" in raw.text

    html = await client.get(f"{API}/investigations/{iid}/export", params={"format": "html"})
    assert (
        html.headers["content-security-policy"].startswith("default-src 'none'")
        and "attachment" in html.headers["content-disposition"]
    )
    for needle in ("<script>alert(1)</script>", "<img src=x", "<svg onload", "mallory<script>"):
        assert needle not in html.text  # analyst-supplied text is escaped
    assert (
        "&lt;script&gt;" in html.text
        and "<style>" in html.text
        and "http://" not in html.text.replace("http://www.w3.org", "")
    )

    js = (await client.get(f"{API}/investigations/{iid}/export", params={"format": "json"})).json()
    assert (
        js["meta"]["tlp"] == "red" and js["indicators"][0]["value"] == "https://example.com/login"
    )
    assert js["summary"]["finding_count"] == 1 and js["legend"]["verified"]
    assert (
        await client.get(f"{API}/investigations/{iid}/export", params={"format": "pdf"})
    ).status_code == 422
    assert (await client.get(f"{API}/investigations/999/export")).status_code == 404


async def test_report_lists_gaps_instead_of_hiding_them(client: httpx.AsyncClient) -> None:
    iid = (await client.post(f"{API}/investigations", json={"title": "gaps"})).json()["id"]
    ind = (
        await client.post(
            f"{API}/enrich", json={"value": "example.com", "providers": ["virustotal", "dns"]}
        )
    ).json()["indicator"]
    await client.post(f"{API}/investigations/{iid}/indicators", json={"indicator_id": ind["id"]})
    js = (await client.get(f"{API}/investigations/{iid}/export", params={"format": "json"})).json()
    assert {"provider": "virustotal", "status": "not_configured"}.items() <= js["indicators"][0][
        "gaps"
    ][0].items()
    md = (await client.get(f"{API}/investigations/{iid}/export", params={"format": "md"})).text
    assert "Gaps (not obtained)" in md and "virustotal: not_configured" in md


# ── local file tool ──────────────────────────────────────────────────────────


async def test_file_hash_tool_hashes_identifies_and_forgets(
    client: httpx.AsyncClient, tmp_path: Path
) -> None:
    r = await client.post(
        f"{API}/tools/file-hash",
        content=EICAR,
        headers={"X-Filename": "eicar.com", "content-type": "application/octet-stream"},
    )
    assert r.status_code == 200
    b = r.json()
    assert (
        b["sha256"]
        == hashlib.sha256(EICAR).hexdigest()
        == "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    )
    assert (
        b["md5"] == hashlib.md5(EICAR, usedforsecurity=False).hexdigest()
        and b["sha1"] == hashlib.sha1(EICAR, usedforsecurity=False).hexdigest()
    )
    assert b["size"] == len(EICAR) and b["filename"] == "eicar.com"
    assert (
        b["file_type"]["type"] == "EICAR anti-malware test string"
        and "not a safety verdict" in b["file_type"]["note"]
    )
    assert "discarded" in b["privacy"]

    pe = bytearray(b"MZ" + b"\x00" * 0x3E)
    pe[0x3C:0x40] = (0x80).to_bytes(4, "little")
    pe += b"\x00" * (0x80 - len(pe)) + b"PE\x00\x00" + b"\x00" * 18 + (0x2102).to_bytes(2, "little")
    t = (await client.post(f"{API}/tools/file-hash", content=bytes(pe))).json()["file_type"]
    assert t["type"] == "Windows DLL (PE)" and t["basis"] == "magic bytes"
    zipdoc = (
        await client.post(
            f"{API}/tools/file-hash", content=b"PK\x03\x04" + b"\x00" * 26 + b"word/document.xml"
        )
    ).json()
    assert zipdoc["file_type"]["type"].startswith("Word document")
    assert (await client.post(f"{API}/tools/file-hash", content=b"")).status_code == 422
    assert not list(tmp_path.glob("*eicar*"))  # noqa: ASYNC240  # nothing persisted


async def test_file_hash_size_limit(tmp_path: Path, make_settings: Callable[..., Settings]) -> None:
    async with make_client(tmp_path, make_settings, max_upload_bytes=2048) as c:
        assert (await c.post(f"{API}/tools/file-hash", content=b"a" * 2048)).status_code == 200
        r = await c.post(f"{API}/tools/file-hash", content=b"a" * 3000)
        assert r.status_code == 413 and r.json()["detail"]["code"] == "too_large"


async def test_file_hash_result_can_be_investigated_only_on_explicit_request(
    tmp_path: Path, make_settings: Callable[..., Settings]
) -> None:
    calls: list[httpx.Request] = []
    async with make_client(tmp_path, make_settings, calls, virustotal_api_key=KEY) as c:
        h = (await c.post(f"{API}/tools/file-hash", content=EICAR)).json()["sha256"]
        assert calls == []  # hashing alone contacts nobody
        out = (await c.post(f"{API}/enrich", json={"value": h})).json()["indicator"]
        assert (
            out["type"] == "hash"
            and [o for o in out["observations"] if o["kind"] == "local.hash_info"][0]["data"][
                "known_test_file"
            ]
            == "EICAR"
        )
        assert calls == []  # even enriching with the default plan stays local for hashes
        assert "test-file:eicar" in out["tags"]
