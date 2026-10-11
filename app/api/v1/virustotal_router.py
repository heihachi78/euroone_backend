"""IP address report endpoint and the lifespan that creates its services."""

import logging
from contextlib import asynccontextmanager

from fastapi import APIRouter, FastAPI, Request

from app.clients.ai_client import AiClient
from app.clients.virustotal_client import VirusTotalClient
from app.core.ai_config import ai_config
from app.core.virustotal_config import virus_total_config
from app.db.database import SessionLocal, create_db_and_tables
from app.db.virustotal_repository import VirusTotalRepository
from app.models.virustotal.ip import Ip
from app.models.virustotal.ip_analysis import IpAnalysis
from app.services.summary_service import SummaryService
from app.services.virustotal_service import VirusTotalService

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Create the tables and services on startup, and close the API clients on shutdown.

    The services are stored on `app.state`, where the endpoints look them up.

    Args:
        app: The application being started.

    Yields:
        Nothing; FastAPI serves requests while the generator is suspended here.

    Raises:
        sqlalchemy.exc.SQLAlchemyError: If the database tables cannot be created.
    """
    await create_db_and_tables()
    vt_client = VirusTotalClient(virus_total_config)
    ai_client = AiClient(ai_config)
    repository = VirusTotalRepository(SessionLocal)
    app.state.virustotal_service = VirusTotalService(vt_client, repository)
    app.state.summary_service = SummaryService(ai_client, repository)
    yield
    await vt_client.aclose()
    await ai_client.aclose()


router = APIRouter(lifespan=lifespan)


@router.post("/ip_address_report")
async def get_ip_address_report(ip: Ip, request: Request) -> IpAnalysis:
    """Look up an IP address on VirusTotal and summarize the report with Gemini.

    Both the report and its summary are saved to the database. If the IP address
    already has a saved summary, that is returned without calling either API.
    \f

    Args:
        ip: The public IP address to look up, from the request body.
        request: The current request, used to reach the services on `app.state`.

    Returns:
        The IP address and the summary of its VirusTotal report.

    Raises:
        httpx.HTTPError: If a VirusTotal or Gemini request fails, or VirusTotal
            returns an error status.
        google.genai.errors.APIError: If Gemini returns an error status.
        UnusableResponseError: If the VirusTotal response is not a JSON object, or
            Gemini returns no text.
        sqlalchemy.exc.SQLAlchemyError: If a database operation fails.
    """
    virustotal_service: VirusTotalService = request.app.state.virustotal_service
    summary_service: SummaryService = request.app.state.summary_service
    logger.info("Received report request for ip=%s", ip.ip)
    saved = await summary_service.find_summary(ip)
    if saved is not None:
        logger.info("Returning saved summary for ip=%s", ip.ip)
        return saved
    report_id = await virustotal_service.fetch_report(ip)
    logger.info("Received report id=%d for ip=%s", report_id, ip.ip)
    summary = await summary_service.summarize(report_id)
    logger.info("Returning report id=%d for ip=%s", report_id, ip.ip)
    return summary
