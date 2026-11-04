from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import create_engine as create_sync_engine
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from alembic import command
from hunterintel.config import Settings
from hunterintel.db.models import (
    Base,
    Finding,
    Indicator,
    Investigation,
    InvestigationIndicator,
    Observation,
    Relationship,
)
from hunterintel.db.session import create_engine, create_schema, create_session_factory
from tests.helpers import TEST_DB_ENV, fresh_database_url

BACKEND = Path(__file__).resolve().parent.parent


@pytest.fixture
async def session_factory(tmp_path: Path) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    settings = Settings(_env_file=None, database_url=await fresh_database_url(tmp_path, "t"))
    engine = create_engine(settings)
    await create_schema(engine)
    yield create_session_factory(engine)
    await engine.dispose()


def test_migrations_apply_and_match_models(tmp_path: Path) -> None:
    """`alembic upgrade head` must produce exactly the schema the ORM expects."""
    db = tmp_path / "mig.db"
    cfg = Config(str(BACKEND / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND / "alembic"))
    cfg.cmd_opts = type("X", (), {"x": [f"url=sqlite+aiosqlite:///{db}"]})()  # type: ignore[attr-defined]
    command.upgrade(cfg, "head")

    sync = create_sync_engine(f"sqlite:///{db}")
    with sync.connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn), Base.metadata)
    sync.dispose()
    assert diff == [], f"models and migration disagree: {diff}"

    command.downgrade(cfg, "base")
    sync = create_sync_engine(f"sqlite:///{db}")
    with sync.connect() as conn:
        tables = set(MigrationContext.configure(conn).connection.dialect.get_table_names(conn))  # type: ignore[union-attr]
    sync.dispose()
    assert tables <= {"alembic_version"}


async def test_unique_indicator_and_utc_roundtrip(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    from datetime import UTC, datetime

    async with session_factory() as s:
        ts = datetime(2024, 5, 1, 12, 0, tzinfo=UTC)
        s.add(Indicator(type="domain", value="example.com", first_seen=ts, last_seen=ts))
        await s.commit()
    async with session_factory() as s:
        got = (await s.execute(select(Indicator))).scalar_one()
        assert got.first_seen == ts and got.first_seen.tzinfo is not None
        s.add(Indicator(type="domain", value="example.com"))
        with pytest.raises(IntegrityError):
            await s.commit()


async def test_naive_datetimes_are_rejected(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    from datetime import datetime

    async with session_factory() as s:
        s.add(Indicator(type="ip", value="1.1.1.1", last_seen=datetime(2024, 1, 1)))
        with pytest.raises(Exception, match="naive datetime"):
            await s.commit()


async def test_cascades_and_set_null(session_factory: async_sessionmaker[AsyncSession]) -> None:
    async with session_factory() as s:
        a, b = (
            Indicator(type="domain", value="a.example.com"),
            Indicator(type="ip", value="8.8.8.8"),
        )
        inv = Investigation(title="t")
        s.add_all([a, b, inv])
        await s.flush()
        s.add(
            Observation(
                indicator_id=a.id,
                provider="dns",
                kind="dns.records",
                assurance="verified",
                title="x",
                data={"k": 1},
                fingerprint="f",
            )
        )
        s.add(
            Relationship(
                src_id=a.id, dst_id=b.id, rel_type="resolves_to", assurance="verified", source="dns"
            )
        )
        s.add(InvestigationIndicator(investigation_id=inv.id, indicator_id=a.id))
        s.add(Finding(investigation_id=inv.id, indicator_id=a.id, title="f", snapshot={"x": 1}))
        await s.commit()
        aid, finding_id = a.id, None

    async with session_factory() as s:
        await s.delete(await s.get(Indicator, aid))
        await s.commit()
        assert (await s.execute(select(Observation))).first() is None  # cascaded
        assert (await s.execute(select(Relationship))).first() is None  # cascaded
        assert (await s.execute(select(InvestigationIndicator))).first() is None
        finding = (await s.execute(select(Finding))).scalar_one()
        assert finding.indicator_id is None and finding.snapshot == {"x": 1}  # finding survives
        finding_id = finding.id
        inv = (await s.execute(select(Investigation))).scalar_one()
        await s.delete(inv)
        await s.commit()
        assert (await s.execute(select(Finding).where(Finding.id == finding_id))).first() is None


@pytest.mark.skipif(
    not os.environ.get(TEST_DB_ENV, "").startswith("postgresql"),
    reason=f"set {TEST_DB_ENV}=postgresql+asyncpg://… to verify migrations on PostgreSQL",
)
async def test_migrations_apply_and_match_models_on_postgres(tmp_path: Path) -> None:
    url = await fresh_database_url(tmp_path, "pg")
    cfg = Config(str(BACKEND / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND / "alembic"))
    cfg.cmd_opts = type("X", (), {"x": [f"url={url}"]})()  # type: ignore[attr-defined]
    await asyncio.to_thread(command.upgrade, cfg, "head")

    engine = create_async_engine(url)
    async with engine.connect() as conn:
        diff = await conn.run_sync(
            lambda c: compare_metadata(MigrationContext.configure(c), Base.metadata)
        )
    await engine.dispose()
    assert diff == [], f"models and migration disagree on PostgreSQL: {diff}"
    await asyncio.to_thread(command.downgrade, cfg, "base")
