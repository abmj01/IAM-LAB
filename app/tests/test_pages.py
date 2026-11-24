"""Tests for the home page: what a visitor and a logged-in user see."""

import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from expenses_app.main import create_app

HOME_ROUTE = "/"
LOGIN_LINK = 'href="/auth/login"'
LOGOUT_FORM = '<form method="post" action="/auth/logout">'
REFRESH_TOKEN = "test-refresh-token"
ID_TOKEN = "test-id-token"


@pytest.fixture
def application(settings, validator) -> FastAPI:
    """The app, trusting only the test signing key."""
    application = create_app(settings)
    application.state.token_validator = validator
    return application


@pytest.fixture
def client(application) -> TestClient:
    return TestClient(application)


@pytest.fixture
def log_in(application, client, make_token, valid_claims):
    """Log a user in by putting a session straight into the store, then return its tokens.

    The access token is really signed, so the page really validates it, and it stays valid
    for an hour, so the page never tries a refresh.
    """

    def _log_in(username: str) -> list[str]:
        access_token = make_token({**valid_claims, "preferred_username": username})
        session_id = application.state.session_store.create(
            subject=valid_claims["sub"],
            username=username,
            access_token=access_token,
            refresh_token=REFRESH_TOKEN,
            id_token=ID_TOKEN,
            access_token_expires_at=time.time() + 3600,
        )
        client.cookies.set(application.state.settings.session_cookie_name, session_id)
        return [access_token, REFRESH_TOKEN, ID_TOKEN]

    return _log_in


class TestHomePage:
    def test_visitor_without_session_sees_login_link(self, client):
        response = client.get(HOME_ROUTE)

        assert response.status_code == 200
        assert LOGIN_LINK in response.text
        assert LOGOUT_FORM not in response.text

    def test_logged_in_user_sees_username_and_post_logout_form(self, client, log_in):
        log_in("bonnie.smith")

        response = client.get(HOME_ROUTE)

        assert "Hello, bonnie.smith" in response.text
        assert LOGOUT_FORM in response.text
        assert LOGIN_LINK not in response.text

    def test_username_with_html_is_escaped(self, client, log_in):
        log_in("<script>alert(1)</script>")

        response = client.get(HOME_ROUTE)

        assert "<script>" not in response.text
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in response.text

    def test_page_has_no_tokens_and_is_not_cached(self, client, log_in):
        tokens = log_in("bonnie.smith")

        response = client.get(HOME_ROUTE)

        for token in tokens:
            assert token not in response.text
        assert response.headers["cache-control"] == "no-store"


class TestErrorPages:
    def test_unknown_page_shows_styled_error_page(self, client):
        response = client.get("/no-such-page")

        assert response.status_code == 404
        assert response.headers["content-type"].startswith("text/html")
        assert "Page not found" in response.text

    def test_unknown_api_route_stays_json(self, client):
        response = client.get("/api/no-such-route")

        assert response.status_code == 404
        assert response.json() == {"detail": "Not Found"}

    def test_api_401_keeps_its_bearer_challenge_header(self, client):
        response = client.get("/api/claims")

        assert response.status_code == 401
        assert response.headers["www-authenticate"] == "Bearer"
