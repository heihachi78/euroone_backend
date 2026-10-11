"""Stored VirusTotal IP address report model."""

from typing import Any

from pydantic import BaseModel, IPvAnyAddress


class StoredIpReport(BaseModel):
    """VirusTotal IP address report loaded from the database.

    Attributes:
        id: Id of the stored report.
        ip: The IP address the report belongs to.
        status_code: HTTP status code of the VirusTotal response.
        data: JSON body of the VirusTotal response.
    """

    id: int
    ip: IPvAnyAddress
    status_code: int
    data: dict[str, Any]
