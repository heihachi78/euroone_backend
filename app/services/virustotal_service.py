"""Fetches VirusTotal IP address reports and saves them."""

from app.clients.virustotal_client import VirusTotalClient
from app.db.virustotal_repository import VirusTotalRepository
from app.models.virustotal.ip import Ip


class VirusTotalService:
    """Fetches IP address reports from VirusTotal and saves them to the database."""

    def __init__(
        self, vt_client: VirusTotalClient, repository: VirusTotalRepository
    ) -> None:
        """Store the collaborators of the service.

        Args:
            vt_client: Fetches the reports from VirusTotal.
            repository: Saves the reports.
        """
        self._vt_client = vt_client
        self._repository = repository

    async def fetch_report(self, ip: Ip) -> int:
        """Fetch the VirusTotal report of an IP address and save it.

        Args:
            ip: The IP address to look up.

        Returns:
            The id of the saved report.

        Raises:
            httpx.HTTPStatusError: If VirusTotal returns an error status.
            httpx.RequestError: If the request cannot be sent or times out.
            UnusableResponseError: If the response body is not a JSON object.
            sqlalchemy.exc.SQLAlchemyError: If the report cannot be saved.
        """
        report = await self._vt_client.get_ip_report(ip)
        report_id = await self._repository.save_report(ip, report)
        return report_id
