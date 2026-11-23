"""Tests for the home page: what a visitor and a logged-in user see."""

import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from expenses_app.main import create_app

HOME_ROUTE = "/"
LOGIN_LINK = '<a href="/auth/login">'
LOGOUT_FORM = '<form method="post" action="/auth/logout">'
TOKENS = {
    "access_token": "test-access-token",
    "refresh_token": "test-refresh-token",
    "id_token": "test-id-token",
}


@pytest.fixture
def application(settings) -> FastAPI:
    return create_app(settings)


@pytest.fixture
def client(application) -> TestClient:
    return TestClient(application)


def log_in(application: FastAPI, client: TestClient, username: str) -> None:
    """Put a session straight into the store and give the browser its cookie.

    The access token stays valid for an hour, so the page never tries a refresh.
    """
    session_id = application.state.session_store.create(
        subject="5801f676-bbf6-4150-8eab-d0878c28b58d",
        username=username,
        access_token_expires_at=time.time() + 3600,
        **TOKENS,
    )
    client.cookies.set(application.state.settings.session_cookie_name, session_id)


class TestHomePage:
    def test_visitor_without_session_sees_login_link(self, client):
        response = client.get(HOME_ROUTE)

        assert response.status_code == 200
        assert LOGIN_LINK in response.text
        assert LOGOUT_FORM not in response.text

    def test_logged_in_user_sees_username_and_post_logout_form(self, application, client):
        log_in(application, client, "bonnie.smith")

        response = client.get(HOME_ROUTE)

        assert "Logged in as bonnie.smith" in response.text
        assert LOGOUT_FORM in response.text
        assert LOGIN_LINK not in response.text

    def test_username_with_html_is_escaped(self, application, client):
        log_in(application, client, "<script>alert(1)</script>")

        response = client.get(HOME_ROUTE)

        assert "<script>" not in response.text
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in response.text

    def test_page_has_no_tokens_and_is_not_cached(self, application, client):
        log_in(application, client, "bonnie.smith")

        response = client.get(HOME_ROUTE)

        for token in TOKENS.values():
            assert token not in response.text
        assert response.headers["cache-control"] == "no-store"
