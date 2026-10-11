"""Summarizes the stored VirusTotal reports with Gemini."""

import json

from app.clients.ai_client import AiClient
from app.db.virustotal_repository import VirusTotalRepository
from app.models.ai.summary_request import SummaryRequest
from app.models.virustotal.ip import Ip
from app.models.virustotal.ip_analysis import IpAnalysis

SUMMARY_SYSTEM_PROMPT = (
    "You are a security analyst. Summarize VirusTotal IP address reports concisely and factually, "
    "using only the data provided. "
    "Your summary will be read by users and not security engineers, so it must be simple and easy to understand.\n"
    "Your summary must be in the following Markdown format, with an empty line between every part:\n\n"
    "**Verdict**\n\n"
    "<one of Malicious, Suspicious, Harmless, Unknown: your best judgement of how dangerous the address is>\n\n"
    "**Confidence**\n\n"
    "<0-100, how strongly the data supports the verdict, only the number, no explanation here>\n\n"
    "**Overview**\n\n"
    "<Summarize the findings based only on the provided data.>\n"
    "<Do not format it, it must be 3-5 sentences in English.>\n"
    "<Do not provide bare numbers, explain them in plain English if you have to.>\n"
    "<Mention notable, important risks if there is any.>\n"
    "<The summary must contain one sentence about your confidence decision too.>\n"
    "<Use Unknown when there is not enough data to judge, for example when almost every engine left the address "
    "unrated and nothing else in the data points to a risk. The confidence of Unknown is 0.>\n"
    "<Use Suspicious or Malicious only when engines flagged the address or other data points to a risk, "
    "never just because data is missing.>\n"
    "<If most engines left the address unrated, the data is weak: the confidence must be below 50 "
    "and you must not claim that the address is safe.>\n\n"
    "Example summaries, one for each verdict:\n\n"
    "Example of a Malicious summary:\n\n"
    "**Verdict**\n\n"
    "Malicious\n\n"
    "**Confidence**\n\n"
    "90\n\n"
    "**Overview**\n\n"
    "This IP address belongs to a cloud hosting provider and is registered in the Netherlands. "
    "Twelve security engines have flagged it as malicious and three more as suspicious, which is a strong warning sign. "
    "Members of the VirusTotal community have also voted it malicious several times, and its reputation is clearly negative. "
    "You should avoid connecting to this address and block it if you can. "
    "Because many independent engines and the community agree that it is harmful, we are highly confident in this verdict.\n\n"
    "Example of a Suspicious summary:\n\n"
    "**Verdict**\n\n"
    "Suspicious\n\n"
    "**Confidence**\n\n"
    "55\n\n"
    "**Overview**\n\n"
    "This IP address belongs to an internet service provider and is registered in Brazil. "
    "A small number of security engines have raised concerns: one considers it malicious and two consider it suspicious. "
    "More than half of all engines rated it clean, and the rest found nothing at all. "
    "This could be a false alarm, but it is worth being careful with this address. "
    "Because only a few engines raised concerns while most others rated it clean, our confidence in this verdict is moderate.\n\n"
    "Example of a Harmless summary:\n\n"
    "**Verdict**\n\n"
    "Harmless\n\n"
    "**Confidence**\n\n"
    "100\n\n"
    "**Overview**\n\n"
    "This IP address is owned by the Taiwan Network Information Center and is registered in Taiwan. "
    "Security analysis reports show zero malicious or suspicious detections from any security engines. "
    "A total of fifty-one engines have marked the address as clean, while forty-one engines currently leave it unrated. "
    "Because more than half of the engines explicitly rated the address as clean and none flagged it, "
    "we are fully confident that it poses no known security risk.\n\n"
    "Example of an Unknown summary:\n\n"
    "**Verdict**\n\n"
    "Unknown\n\n"
    "**Confidence**\n\n"
    "0\n\n"
    "**Overview**\n\n"
    "This IP address belongs to a home internet provider and is registered in Germany. "
    "None of the security engines flagged it as malicious or suspicious, but none rated it clean either, "
    "because every engine left it unrated. "
    "There are also no community votes or other reputation data about this address. "
    "This does not mean that the address is dangerous, but it cannot be called safe either. "
    "Because there is no meaningful data to base a judgement on, our confidence is zero."
)
SUMMARY_USER_PROMPT = "Summarize the following VirusTotal IP address report:"


class SummaryService:
    """Summarizes stored VirusTotal reports with Gemini and saves the summaries."""

    def __init__(self, ai_client: AiClient, repository: VirusTotalRepository) -> None:
        """Store the collaborators of the service.

        Args:
            ai_client: Generates the summaries.
            repository: Loads the reports and saves the summaries.
        """
        self._ai_client = ai_client
        self._repository = repository

    async def find_summary(self, ip: Ip) -> IpAnalysis | None:
        """Load the newest saved summary of an IP address, without asking Gemini.

        Args:
            ip: The IP address to look up.

        Returns:
            The IP address and its saved summary, or None if it has none saved.

        Raises:
            sqlalchemy.exc.SQLAlchemyError: If the database operation fails.
        """
        text = await self._repository.find_latest_summary(ip)
        return None if text is None else IpAnalysis(ip=ip.ip, summary=text)

    async def summarize(self, report_id: int) -> IpAnalysis:
        """Summarize a stored report with Gemini and save the summary with it.

        Args:
            report_id: Id of the stored report to summarize.

        Returns:
            The IP address of the report and its summary.

        Raises:
            ReportNotFoundError: If no report exists with this id.
            google.genai.errors.APIError: If Gemini returns an error status.
            httpx.RequestError: If the Gemini request cannot be sent or times out.
            UnusableResponseError: If Gemini returns no generated text.
            sqlalchemy.exc.SQLAlchemyError: If a database operation fails.
        """
        stored = await self._repository.get_report(report_id)
        request = SummaryRequest(
            system_prompt=SUMMARY_SYSTEM_PROMPT,
            user_prompt=SUMMARY_USER_PROMPT,
            payload=json.dumps(stored.data),
        )
        summary = await self._ai_client.summarize(request)
        await self._repository.save_summary(report_id, summary)
        return IpAnalysis(ip=stored.ip, summary=summary.text)
