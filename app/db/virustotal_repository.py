"""ORM model and repository of the VirusTotal reports and their summaries."""

import logging
from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Any

from sqlalchemy import JSON, DateTime, Integer, String, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models.ai.summary import Summary
from app.models.virustotal.ip import Ip
from app.models.virustotal.ip_report import IpReport
from app.models.virustotal.stored_ip_report import StoredIpReport

logger = logging.getLogger(__name__)


class VirusTotal(Base):
    """A VirusTotal IP report and, once summarized, its Gemini summary.

    Attributes:
        id: Primary key, used as the report id.
        ip: The looked-up IP address as text.
        vt_response: JSON body of the VirusTotal response.
        vt_status_code: HTTP status code of the VirusTotal response.
        ai_response: Gemini summary of the report; None until summarized.
        ai_status_code: HTTP status code of the Gemini response; None until summarized.
        requested_at: When the report was saved, in UTC.
    """

    __tablename__ = "virustotal"

    id: Mapped[int] = mapped_column(primary_key=True)
    ip: Mapped[str] = mapped_column(String(45), index=True)
    vt_response: Mapped[dict[str, Any]] = mapped_column(JSON)
    vt_status_code: Mapped[int] = mapped_column(Integer)
    ai_response: Mapped[str | None] = mapped_column(String)
    ai_status_code: Mapped[int | None] = mapped_column(Integer)
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), index=True
    )


class ReportNotFoundError(LookupError):
    """Raised when no stored report exists with the requested id."""

    def __init__(self, report_id: int) -> None:
        """Create the error with a message naming the missing report.

        Args:
            report_id: Id of the report that was not found.
        """
        super().__init__(f"VirusTotal report {report_id} not found")


class VirusTotalRepository:
    """Saves and loads VirusTotal reports and their summaries."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        """Store the session factory; every operation runs in a session of its own.

        Args:
            session_factory: Creates the database sessions.
        """
        self._session_factory = session_factory

    async def save_report(self, ip: Ip, report: IpReport) -> int:
        """Save a VirusTotal report as a new row, without a summary.

        Args:
            ip: The IP address the report belongs to.
            report: The VirusTotal response to save.

        Returns:
            The id of the new report.

        Raises:
            sqlalchemy.exc.SQLAlchemyError: If the database operation fails.
        """
        row = VirusTotal(
            ip=str(ip.ip), vt_response=report.data, vt_status_code=report.status_code
        )
        async with self._session_factory() as session:
            session.add(row)
            await session.flush()  # assigns the id
            report_id = row.id
            await session.commit()
        logger.info("Saved report id=%d for ip=%s", report_id, ip.ip)
        return report_id

    async def get_report(self, report_id: int) -> StoredIpReport:
        """Load a saved VirusTotal report.

        Args:
            report_id: Id of the report to load.

        Returns:
            The report with its id, IP address, status code and data.

        Raises:
            ReportNotFoundError: If no report exists with this id.
            sqlalchemy.exc.SQLAlchemyError: If the database operation fails.
        """
        async with self._session_factory() as session:
            row = await self._get_row(session, report_id)
            logger.info("Loaded report id=%d", report_id)
            return StoredIpReport(
                id=row.id,
                ip=ip_address(row.ip),
                status_code=row.vt_status_code,
                data=row.vt_response,
            )

    async def save_summary(self, report_id: int, summary: Summary) -> None:
        """Add a Gemini summary to a saved report.

        Args:
            report_id: Id of the report the summary belongs to.
            summary: The summary to save.

        Raises:
            ReportNotFoundError: If no report exists with this id.
            sqlalchemy.exc.SQLAlchemyError: If the database operation fails.
        """
        async with self._session_factory() as session:
            row = await self._get_row(session, report_id)
            row.ai_response = summary.text
            row.ai_status_code = summary.status_code
            await session.commit()
        logger.info("Saved summary for report id=%d", report_id)

    async def find_latest_summary(self, ip: Ip) -> str | None:
        """Load the newest saved summary of an IP address.

        Reports without a summary, e.g. because Gemini failed, are ignored.

        Args:
            ip: The IP address to look up.

        Returns:
            The text of the newest summary, or None if the IP has none saved.

        Raises:
            sqlalchemy.exc.SQLAlchemyError: If the database operation fails.
        """
        query = (
            select(VirusTotal.ai_response)
            .where(VirusTotal.ip == str(ip.ip), VirusTotal.ai_response.is_not(None))
            .order_by(VirusTotal.id.desc())
            .limit(1)
        )
        async with self._session_factory() as session:
            return await session.scalar(query)

    @staticmethod
    async def _get_row(session: AsyncSession, report_id: int) -> VirusTotal:
        """Load a report row in an open session.

        Args:
            session: The session to load the row in.
            report_id: Id of the row to load.

        Returns:
            The row with this id.

        Raises:
            ReportNotFoundError: If no row exists with this id.
        """
        row = await session.get(VirusTotal, report_id)
        if row is None:
            raise ReportNotFoundError(report_id)
        return row
