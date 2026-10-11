"""Async client for the VirusTotal API v3."""

import logging

import httpx

from app.clients.errors import UnusableResponseError
from app.core.virustotal_config import VirusTotalConfig
from app.models.virustotal.ip import Ip
from app.models.virustotal.ip_report import IpReport

logger = logging.getLogger(__name__)


class VirusTotalClient:
    """Fetches IP address reports from VirusTotal."""

    def __init__(self, config: VirusTotalConfig) -> None:
        """Create the underlying HTTP client with the API key and timeout set.

        Args:
            config: VirusTotal API key, base URL, endpoint and request timeout.
        """
        self._ip_address_report_endpoint = config.ip_address_report_endpoint
        self._client = httpx.AsyncClient(
            base_url=config.base_url,
            timeout=config.timeout_seconds,
            headers={
                "accept": "application/json",
                "x-apikey": config.api_key.get_secret_value(),
            },
        )

    async def get_ip_report(self, ip: Ip) -> IpReport:
        """Fetch the VirusTotal report of an IP address.

        Args:
            ip: The IP address to look up.

        Returns:
            The status code and the JSON body of the response.

        Raises:
            httpx.HTTPStatusError: If VirusTotal returns an error status.
            httpx.RequestError: If the request cannot be sent or times out.
            UnusableResponseError: If the response body is not a JSON object.
            RuntimeError: If the client has already been closed.
        """
        response = await self._client.get(f"{self._ip_address_report_endpoint}/{ip.ip}")
        logger.info("VirusTotal responded %d for ip=%s", response.status_code, ip.ip)
        response.raise_for_status()
        try:
            return IpReport(status_code=response.status_code, data=response.json())
        except ValueError as exc:  # invalid JSON, or JSON that is not an object
            raise UnusableResponseError(
                "VirusTotal response body is not a JSON object"
            ) from exc

    async def aclose(self) -> None:
        """Close the underlying connections; the client cannot be used afterwards."""
        await self._client.aclose()
