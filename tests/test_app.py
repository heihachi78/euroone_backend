"""Tests for the FastAPI application setup."""

from fastapi.testclient import TestClient

from app.app import app
from app.core.app_config import app_config


def test_root_reports_server_is_running():
    """The root endpoint answers 200 with a server-is-running message."""
    client = TestClient(app)

    response = client.get("/")

    assert response.status_code == 200
    assert response.json() == "Server is running."


def test_title_comes_from_config():
    """The app's title is taken from the app settings."""
    assert app.title == app_config.title == "EuroOne test"


def test_virustotal_router_is_mounted_under_api_v1():
    """The IP address report route is served under the /api/v1 prefix."""
    assert app.url_path_for("get_ip_address_report") == "/api/v1/ip_address_report"


def test_ip_address_report_endpoint_is_documented():
    """The OpenAPI schema lists the IP address report endpoint, with POST only."""
    client = TestClient(app)

    response = client.get("/openapi.json")

    assert response.status_code == 200
    assert set(response.json()["paths"]["/api/v1/ip_address_report"]) == {"post"}
