"""Tests for the database engine, session factory and table creation."""

from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from sqlalchemy import inspect, select
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine

from app.core.db_config import db_config
from app.db import database
from app.db.database import SessionLocal, create_db_and_tables
from app.db.virustotal_repository import VirusTotal

pytestmark = pytest.mark.anyio

COLUMNS = {
    "id",
    "ip",
    "vt_response",
    "vt_status_code",
    "ai_response",
    "ai_status_code",
    "requested_at",
}


@pytest.fixture
async def engine(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[AsyncEngine]:
    """Engine on a throwaway SQLite file, patched in as the module-level engine."""
    test_engine = create_async_engine(
        f"sqlite+aiosqlite:///{tmp_path / 'database_test.db'}"
    )
    monkeypatch.setattr(database, "engine", test_engine)
    yield test_engine
    await test_engine.dispose()


def test_engine_uses_configured_db_url():
    """The module-level engine connects to db_url from the settings."""
    assert database.engine.url.render_as_string(hide_password=False) == db_config.db_url


def test_session_factory_is_bound_to_engine_and_keeps_objects_usable_after_commit():
    """SessionLocal is bound to the engine and does not autoflush.

    It keeps objects usable after commit (expire_on_commit=False).
    """
    assert SessionLocal.kw["bind"] is database.engine
    assert SessionLocal.kw["autoflush"] is False
    assert SessionLocal.kw["expire_on_commit"] is False


async def test_create_db_and_tables_creates_virustotal_table(engine: AsyncEngine):
    """create_db_and_tables creates the virustotal table with every column.

    Only the AI summary columns are nullable.
    """
    await create_db_and_tables()

    async with engine.connect() as conn:
        tables = await conn.run_sync(
            lambda sync_conn: inspect(sync_conn).get_table_names()
        )
        columns = await conn.run_sync(
            lambda sync_conn: inspect(sync_conn).get_columns("virustotal")
        )
    assert tables == ["virustotal"]
    assert {column["name"] for column in columns} == COLUMNS
    assert {column["name"] for column in columns if column["nullable"]} == {
        "ai_response",
        "ai_status_code",
    }


async def test_create_db_and_tables_indexes_lookup_columns(engine: AsyncEngine):
    """The ip and requested_at columns get an index."""
    await create_db_and_tables()

    async with engine.connect() as conn:
        indexes = await conn.run_sync(
            lambda sync_conn: inspect(sync_conn).get_indexes("virustotal")
        )
    assert {column for index in indexes for column in index["column_names"]} == {
        "ip",
        "requested_at",
    }


async def test_create_db_and_tables_keeps_existing_rows(engine: AsyncEngine):
    """Running create_db_and_tables again leaves the existing rows in place."""
    session_factory = async_sessionmaker(bind=engine, expire_on_commit=False)
    await create_db_and_tables()
    async with session_factory() as session:
        session.add(
            VirusTotal(
                ip="8.8.8.8",
                vt_response={},
                vt_status_code=200,
                ai_response="Harmless.",
                ai_status_code=200,
            )
        )
        await session.commit()

    await create_db_and_tables()

    async with session_factory() as session:
        assert [row.ip for row in await session.scalars(select(VirusTotal))] == [
            "8.8.8.8"
        ]
