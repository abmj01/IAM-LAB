"""Tests for page access: who a page's user is, from the session cookie."""

import logging
import time
from typing import Annotated

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from expenses_app.auth.page_access import get_optional_page_user, get_page_user
from expenses_app.auth.token_validator import TokenClaims
from expenses_app.main import create_app
from tests.claim_helpers import MANAGER

REQUIRED_ROUTE = "/test/login-required"
OPTIONAL_ROUTE = "/test/login-optional"
PAGE_ACCESS_LOGGER = "expenses_app.auth.page_access"


@pytest.fixture
def application(settings, validator) -> FastAPI:
    """The app with two temporary pages, trusting only the test signing key."""
    application = create_app(settings)
    application.state.token_validator = validator

    @application.get(REQUIRED_ROUTE)
    def login_required(user: Annotated[TokenClaims, Depends(get_page_user)]) -> dict:
        return {"username": user.username, "roles": list(user.roles)}

    @application.get(OPTIONAL_ROUTE)
    def login_optional(
        user: Annotated[TokenClaims | None, Depends(get_optional_page_user)],
    ) -> dict:
        return {"username": user.username if user else None}

    return application


@pytest.fixture
def client(application) -> TestClient:
    return TestClient(application, follow_redirects=False)


@pytest.fixture
def log_in_with_token(application, client):
    """Put a session with the given access token straight into the store."""

    def _log_in_with_token(access_token: str) -> None:
        session_id = application.state.session_store.create(
            subject=MANAGER.subject,
            username=MANAGER.username,
            access_token=access_token,
            refresh_token="test-refresh-token",
            id_token="test-id-token",
            access_token_expires_at=time.time() + 3600,
        )
        client.cookies.set(application.state.settings.session_cookie_name, session_id)

    return _log_in_with_token


class TestRequiredLogin:
    def test_visitor_is_sent_to_login(self, client):
        response = client.get(REQUIRED_ROUTE)

        assert response.status_code == 303
        assert response.headers["location"] == "/auth/login"

    def test_valid_session_gives_the_tokens_user_and_roles(
        self, client, log_in_with_token, token_for
    ):
        log_in_with_token(token_for(MANAGER))

        response = client.get(REQUIRED_ROUTE)

        assert response.json() == {"username": MANAGER.username, "roles": list(MANAGER.roles)}

    @pytest.mark.parametrize("token_problem", ["forged-signature", "wrong-audience"])
    def test_rejected_token_gives_403_without_redirect_loop(
        self,
        client,
        log_in_with_token,
        make_token,
        valid_claims,
        attacker_key,
        caplog,
        token_problem,
    ):
        if token_problem == "forged-signature":
            log_in_with_token(make_token(valid_claims, key=attacker_key))
        else:
            log_in_with_token(make_token({**valid_claims, "aud": "another-app"}))

        response = client.get(REQUIRED_ROUTE)

        assert response.status_code == 403
        assert "location" not in response.headers
        assert any(
            record.name == PAGE_ACCESS_LOGGER and record.levelno == logging.ERROR
            for record in caplog.records
        )


class TestOptionalLogin:
    def test_visitor_gets_none_instead_of_a_redirect(self, client):
        response = client.get(OPTIONAL_ROUTE)

        assert response.status_code == 200
        assert response.json() == {"username": None}

    def test_valid_session_gives_the_user(self, client, log_in_with_token, token_for):
        log_in_with_token(token_for(MANAGER))

        response = client.get(OPTIONAL_ROUTE)

        assert response.json() == {"username": MANAGER.username}
