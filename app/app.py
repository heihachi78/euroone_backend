"""FastAPI application: sets up logging, error handling and mounts the API routers. Entry point of the app."""

from fastapi import FastAPI

from app.api.error_handlers import EXCEPTION_HANDLERS
from app.api.v1 import virustotal_router
from app.core.app_config import app_config
from app.core.logging import setup_logging

setup_logging()

app = FastAPI(title=app_config.title, exception_handlers=EXCEPTION_HANDLERS)


@app.get("/")
def get_root():
    """Report that the server is running.

    Used as a health check.
    \f

    Returns:
        A fixed status message.
    """
    return "Server is running."


app.include_router(virustotal_router.router, prefix="/api/v1")
