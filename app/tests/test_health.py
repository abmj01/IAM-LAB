"""Tests for the /health endpoint."""

from fastapi.testclient import TestClient

from expenses_app.main import create_app


def test_health_reports_ok_without_login(settings):
    client = TestClient(create_app(settings))

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
