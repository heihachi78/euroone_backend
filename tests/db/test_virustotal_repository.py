"""Tests for the VirusTotal ORM model and repository."""

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import String, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.db.base import Base
from app.db.virustotal_repository import (
    ReportNotFoundError,
    VirusTotal,
    VirusTotalRepository,
)
from app.models.ai.summary import Summary
from app.models.virustotal.ip import Ip
from app.models.virustotal.ip_report import IpReport
from app.models.virustotal.stored_ip_report import StoredIpReport

pytestmark = pytest.mark.anyio

VT_IP_REPORT: dict[str, Any] = {
    "data": {
        "id": "8.8.8.8",
        "type": "ip_address",
        "attributes": {
            "as_owner": "GOOGLE",
            "tags": ["dns"],
            "reputation": 0,
            "whois": None,
            "score": 1.5,
        },
    }
}

SUMMARY_TEXT = "8.8.8.8 is Google Public DNS, no engine flags it as malicious."

REPORT = IpReport(status_code=200, data=VT_IP_REPORT)
SUMMARY = Summary(status_code=200, text=SUMMARY_TEXT)


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[AsyncEngine]:
    """Engine on a fresh SQLite file with the tables created."""
    test_engine = create_async_engine(
        f"sqlite+aiosqlite:///{tmp_path / 'repository_test.db'}"
    )
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield test_engine
    await test_engine.dispose()


@pytest.fixture
def session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """Session factory on the test engine."""
    return async_sessionmaker(bind=engine, expire_on_commit=False)


@pytest.fixture
def repository(
    session_factory: async_sessionmaker[AsyncSession],
) -> VirusTotalRepository:
    """Repository under test, on the test database."""
    return VirusTotalRepository(session_factory)


async def saved_rows(
    session_factory: async_sessionmaker[AsyncSession],
) -> list[VirusTotal]:
    """Read every row of the test database, ordered by id."""
    async with session_factory() as session:
        return list(
            (await session.scalars(select(VirusTotal).order_by(VirusTotal.id))).all()
        )


def ip(value: str) -> Ip:
    """Validate an IP address string into an Ip."""
    return Ip.model_validate({"ip": value})


def test_virustotal_table_is_registered_on_base_metadata():
    """The VirusTotal model registers its table on Base.metadata."""
    assert Base.metadata.tables["virustotal"] is VirusTotal.__table__


def test_ip_column_fits_longest_ipv6_text_form():
    """The ip column holds 45 characters, the longest text form of an IPv6 address."""
    ip_type = Base.metadata.tables["virustotal"].c.ip.type

    assert isinstance(ip_type, String)
    assert ip_type.length == 45


async def test_requested_at_defaults_to_current_utc_time(
    session_factory: async_sessionmaker[AsyncSession],
):
    """A new row gets the current time, timezone-aware in UTC, as requested_at."""
    row = VirusTotal(ip="8.8.8.8", vt_response=VT_IP_REPORT, vt_status_code=200)

    before = datetime.now(UTC)
    async with session_factory() as session:
        session.add(row)
        await session.commit()
    after = datetime.now(UTC)

    assert row.requested_at.tzinfo is UTC
    assert before <= row.requested_at <= after


async def test_save_report_stores_report_without_summary(
    repository: VirusTotalRepository, session_factory: async_sessionmaker[AsyncSession]
):
    """save_report stores the IP and the report and returns the new row's id.

    The summary columns stay empty.
    """
    report_id = await repository.save_report(ip("8.8.8.8"), REPORT)

    [row] = await saved_rows(session_factory)
    assert row.id == report_id
    assert row.ip == "8.8.8.8"
    assert row.vt_response == VT_IP_REPORT
    assert row.vt_status_code == 200
    assert row.ai_response is None
    assert row.ai_status_code is None


async def test_save_report_stores_status_code_as_given(
    repository: VirusTotalRepository, session_factory: async_sessionmaker[AsyncSession]
):
    """The VirusTotal status code is saved as is, even if it is not 200."""
    await repository.save_report(
        ip("8.8.8.8"), IpReport(status_code=203, data=VT_IP_REPORT)
    )

    [row] = await saved_rows(session_factory)
    assert row.vt_status_code == 203


async def test_save_report_sets_requested_at_to_current_time(
    repository: VirusTotalRepository, session_factory: async_sessionmaker[AsyncSession]
):
    """save_report sets requested_at to the time of the call."""
    before = datetime.now(UTC).replace(tzinfo=None)
    await repository.save_report(ip("8.8.8.8"), REPORT)
    after = datetime.now(UTC).replace(tzinfo=None)

    [row] = await saved_rows(session_factory)
    assert before <= row.requested_at.replace(tzinfo=None) <= after


@pytest.mark.parametrize(
    ("value", "expected_saved_ip"),
    [
        ("2001:4860:4860::8888", "2001:4860:4860::8888"),
        (
            "2001:4860:4860:0000:0000:0000:0000:8888",
            "2001:4860:4860::8888",
        ),
        ("::ffff:8.8.8.8", "8.8.8.8"),
    ],
)
async def test_save_report_stores_ip_in_normalized_form(
    repository: VirusTotalRepository,
    session_factory: async_sessionmaker[AsyncSession],
    value: str,
    expected_saved_ip: str,
):
    """The IP is saved in its compressed, normalized text form.

    An IPv4-mapped IPv6 address is saved as plain IPv4.
    """
    await repository.save_report(ip(value), REPORT)

    [row] = await saved_rows(session_factory)
    assert row.ip == expected_saved_ip


async def test_each_save_report_adds_a_new_row(
    repository: VirusTotalRepository, session_factory: async_sessionmaker[AsyncSession]
):
    """Every save adds a new row with its own id, even for the same IP."""
    ids = [
        await repository.save_report(ip("8.8.8.8"), REPORT),
        await repository.save_report(ip("8.8.8.8"), REPORT),
        await repository.save_report(ip("1.1.1.1"), REPORT),
    ]

    rows = await saved_rows(session_factory)
    assert [row.ip for row in rows] == ["8.8.8.8", "8.8.8.8", "1.1.1.1"]
    assert [row.id for row in rows] == ids
    assert len(set(ids)) == 3


async def test_save_report_returns_id_even_if_session_expires_objects_on_commit(
    engine: AsyncEngine,
):
    """The id is returned even if the sessions expire objects on commit."""
    repository = VirusTotalRepository(
        async_sessionmaker(bind=engine, expire_on_commit=True)
    )

    assert await repository.save_report(ip("8.8.8.8"), REPORT) == 1


async def test_save_report_error_is_propagated(tmp_path: Path):
    """A database error during save_report is raised to the caller."""
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'empty.db'}")
    repository = VirusTotalRepository(async_sessionmaker(bind=engine))

    with pytest.raises(OperationalError, match="no such table: virustotal"):
        await repository.save_report(ip("8.8.8.8"), REPORT)

    await engine.dispose()


@pytest.mark.parametrize(
    ("requested_ip", "expected_ip"),
    [
        ("::ffff:8.8.8.8", IPv4Address("8.8.8.8")),
        ("2001:4860:4860::8888", IPv6Address("2001:4860:4860::8888")),
    ],
)
async def test_get_report_returns_the_saved_report(
    repository: VirusTotalRepository,
    requested_ip: str,
    expected_ip: IPv4Address | IPv6Address,
):
    """get_report gives back the saved report, with the IP parsed into an address."""
    report_id = await repository.save_report(
        ip(requested_ip), IpReport(status_code=203, data=VT_IP_REPORT)
    )

    assert await repository.get_report(report_id) == StoredIpReport(
        id=report_id, ip=expected_ip, status_code=203, data=VT_IP_REPORT
    )


async def test_get_report_returns_the_requested_row(repository: VirusTotalRepository):
    """With several rows saved, get_report returns the one with the given id."""
    other_report: dict[str, Any] = {
        "data": {"id": "1.1.1.1", "attributes": {"as_owner": "CLOUDFLARENET"}}
    }
    await repository.save_report(ip("8.8.8.8"), REPORT)
    report_id = await repository.save_report(
        ip("1.1.1.1"), IpReport(status_code=200, data=other_report)
    )

    stored = await repository.get_report(report_id)

    assert stored.ip == IPv4Address("1.1.1.1")
    assert stored.data == other_report


async def test_get_report_of_unknown_id_raises(repository: VirusTotalRepository):
    """get_report raises ReportNotFoundError for an id that is not in the database."""
    with pytest.raises(ReportNotFoundError, match="VirusTotal report 42 not found"):
        await repository.get_report(42)


async def test_save_summary_fills_in_the_summary_of_the_report(
    repository: VirusTotalRepository, session_factory: async_sessionmaker[AsyncSession]
):
    """save_summary stores the summary text and status code in the report's row.

    The VirusTotal columns of the row stay unchanged.
    """
    report_id = await repository.save_report(ip("8.8.8.8"), REPORT)

    await repository.save_summary(
        report_id, Summary(status_code=201, text=SUMMARY_TEXT)
    )

    [row] = await saved_rows(session_factory)
    assert row.ai_response == SUMMARY_TEXT
    assert row.ai_status_code == 201
    assert row.ip == "8.8.8.8"
    assert row.vt_response == VT_IP_REPORT
    assert row.vt_status_code == 200


async def test_save_summary_only_changes_the_given_report(
    repository: VirusTotalRepository, session_factory: async_sessionmaker[AsyncSession]
):
    """save_summary leaves the other rows untouched."""
    first_id = await repository.save_report(ip("8.8.8.8"), REPORT)
    second_id = await repository.save_report(ip("1.1.1.1"), REPORT)

    await repository.save_summary(second_id, SUMMARY)

    rows = {row.id: row for row in await saved_rows(session_factory)}
    assert rows[first_id].ai_response is None
    assert rows[second_id].ai_response == SUMMARY_TEXT


async def test_save_summary_overwrites_previous_summary(
    repository: VirusTotalRepository, session_factory: async_sessionmaker[AsyncSession]
):
    """Saving a summary again replaces the earlier one."""
    report_id = await repository.save_report(ip("8.8.8.8"), REPORT)
    await repository.save_summary(report_id, SUMMARY)

    await repository.save_summary(
        report_id, Summary(status_code=200, text="Newer summary.")
    )

    [row] = await saved_rows(session_factory)
    assert row.ai_response == "Newer summary."


async def test_save_summary_of_unknown_id_raises_and_saves_nothing(
    repository: VirusTotalRepository, session_factory: async_sessionmaker[AsyncSession]
):
    """save_summary raises ReportNotFoundError for an unknown id and adds no row."""
    with pytest.raises(ReportNotFoundError, match="VirusTotal report 42 not found"):
        await repository.save_summary(42, SUMMARY)

    assert await saved_rows(session_factory) == []


async def test_find_latest_summary_of_unknown_ip_returns_none(
    repository: VirusTotalRepository,
):
    """find_latest_summary returns None for an IP without any saved report."""
    assert await repository.find_latest_summary(ip("8.8.8.8")) is None


async def test_find_latest_summary_ignores_report_without_summary(
    repository: VirusTotalRepository,
):
    """A report whose summary was never saved, e.g. because Gemini failed, is ignored."""
    await repository.save_report(ip("8.8.8.8"), REPORT)

    assert await repository.find_latest_summary(ip("8.8.8.8")) is None


@pytest.mark.parametrize(
    ("saved_ip", "looked_up_ip"),
    [
        ("8.8.8.8", "8.8.8.8"),
        ("8.8.8.8", "::ffff:8.8.8.8"),
        ("2001:4860:4860::8888", "2001:4860:4860:0000:0000:0000:0000:8888"),
    ],
)
async def test_find_latest_summary_returns_the_saved_summary_of_the_ip(
    repository: VirusTotalRepository, saved_ip: str, looked_up_ip: str
):
    """The saved summary is found by any text form of the same IP address."""
    report_id = await repository.save_report(ip(saved_ip), REPORT)
    await repository.save_summary(report_id, SUMMARY)

    assert await repository.find_latest_summary(ip(looked_up_ip)) == SUMMARY_TEXT


async def test_find_latest_summary_ignores_other_ips(repository: VirusTotalRepository):
    """The summaries of other IP addresses are not returned."""
    report_id = await repository.save_report(ip("1.1.1.1"), REPORT)
    await repository.save_summary(report_id, SUMMARY)

    assert await repository.find_latest_summary(ip("8.8.8.8")) is None


async def test_find_latest_summary_returns_the_newest_summary(
    repository: VirusTotalRepository,
):
    """With several summarized reports of the IP, the newest summary is returned."""
    older_id = await repository.save_report(ip("8.8.8.8"), REPORT)
    await repository.save_summary(
        older_id, Summary(status_code=200, text="Older summary.")
    )
    newer_id = await repository.save_report(ip("8.8.8.8"), REPORT)
    await repository.save_summary(newer_id, SUMMARY)

    assert await repository.find_latest_summary(ip("8.8.8.8")) == SUMMARY_TEXT


async def test_find_latest_summary_skips_newer_report_without_summary(
    repository: VirusTotalRepository,
):
    """A newer report without a summary does not hide the summary of an older one."""
    report_id = await repository.save_report(ip("8.8.8.8"), REPORT)
    await repository.save_summary(report_id, SUMMARY)
    await repository.save_report(ip("8.8.8.8"), REPORT)

    assert await repository.find_latest_summary(ip("8.8.8.8")) == SUMMARY_TEXT
