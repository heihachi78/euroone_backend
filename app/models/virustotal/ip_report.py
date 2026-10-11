"""VirusTotal IP address report model."""

from typing import Any

from pydantic import BaseModel


class IpReport(BaseModel):
    """VirusTotal response to an IP address report request.

    Attributes:
        status_code: HTTP status code of the response.
        data: JSON body of the response.
    """

    status_code: int
    data: dict[str, Any]
