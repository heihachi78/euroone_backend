"""IP address analysis response model."""

from pydantic import BaseModel, IPvAnyAddress


class IpAnalysis(BaseModel):
    """Summary of the VirusTotal report of an IP address.

    Attributes:
        ip: The looked-up IP address.
        summary: The Gemini summary of its VirusTotal report.
    """

    ip: IPvAnyAddress
    summary: str
