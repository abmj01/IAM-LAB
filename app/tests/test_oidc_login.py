"""Tests for the Keycloak login: where the browser is sent, and what a finished login stores."""

import dataclasses
import json
import logging
import time
from collections.abc import Callable
from types import SimpleNamespace
from typing import Annotated
from urllib.parse import parse_qs, urlparse

import httpx
import httpx2
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from expenses_app.auth import oidc_login
from expenses_app.auth.oidc_login import get_current_session
from expenses_app.auth.session_store import Session
from expenses_app.main import create_app
from expenses_app.settings import Settings
from tests.jwt_helpers import TEST_KEY_ID

LOGIN_ROUTE = "/auth/login"
CALLBACK_ROUTE = "/auth/callback"
LOGOUT_ROUTE = "/auth/logout"
CURRENT_SESSION_ROUTE = "/current-session"
AUTHORIZATION_CODE = "test-authorization-code"
USER = {"sub": "5801f676-bbf6-4150-8eab-d0878c28b58d", "preferred_username": "ryan.landry"}
TOKEN_LIFETIME_SECONDS = 300
ACCESS_TOKEN = "test-access-token"
REFRESH_TOKEN = "test-refresh-token"
NEW_ACCESS_TOKEN = "test-new-access-token"
NEW_REFRESH_TOKEN = "test-new-refresh-token"
NEW_ID_TOKEN = "test-new-id-token"
LOGIN_LOGGER = "expenses_app.auth.oidc_login"
FROZEN_NOW = 1_000_000.0


class FakeKeycloak:
    """Stands in for Keycloak's back channel: serves the public key and hands out tokens.

    Authlib sends its requests through ``httpx2`` and our token refresh through ``httpx``, so a
    ``MockTransport`` answers each and no network is used. The login's ID token is really
    signed, so Authlib really verifies it.

    Tests change how a refresh goes with ``refresh_failure`` (an HTTP status or an exception),
    ``refresh_omits`` (fields left out of the answer) and ``on_refresh`` (runs mid-refresh).
    """

    def __init__(
        self,
        settings: Settings,
        signing_key: rsa.RSAPrivateKey,
        make_token: Callable[..., str],
    ) -> None:
        self._settings = settings
        self._make_token = make_token
        public_jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(signing_key.public_key()))
        self._key_set = {"keys": [{**public_jwk, "kid": TEST_KEY_ID, "alg": "RS256"}]}
        self.nonce: str | None = None
        self.refresh_failure: int | type[httpx.HTTPError] | None = None
        self.refresh_omits: tuple[str, ...] = ()
        self.on_refresh: Callable[[], None] | None = None
        self.refresh_requests: list[dict[str, str]] = []

    def handle(self, request: httpx2.Request) -> httpx2.Response:
        """Answer one back-channel request, like Keycloak's certs and token endpoints."""
        if request.url == self._settings.jwks_uri:
            return httpx2.Response(200, json=self._key_set)
        if request.url == self._settings.token_endpoint:
            return httpx2.Response(200, json=self._tokens())
        return httpx2.Response(404)

    def handle_refresh(self, request: httpx.Request) -> httpx.Response:
        """Answer a refresh request from ``_refresh_tokens``, like Keycloak's token endpoint."""
        form = {name: values[0] for name, values in parse_qs(request.content.decode()).items()}
        self.refresh_requests.append(form)
        if self.on_refresh:
            self.on_refresh()
        if isinstance(self.refresh_failure, int):
            return httpx.Response(self.refresh_failure, json={"error": "invalid_grant"})
        if self.refresh_failure:
            raise self.refresh_failure("Keycloak did not answer", request=request)
        tokens = {
            "access_token": NEW_ACCESS_TOKEN,
            "refresh_token": NEW_REFRESH_TOKEN,
            "id_token": NEW_ID_TOKEN,
            "token_type": "Bearer",
            "expires_in": TOKEN_LIFETIME_SECONDS,
        }
        for field_name in self.refresh_omits:
            tokens.pop(field_name)
        return httpx.Response(200, json=tokens)

    def _tokens(self) -> dict[str, object]:
        now = int(time.time())
        id_token_claims = {
            **USER,
            "iss": self._settings.issuer,
            "aud": self._settings.web_client_id,
            "nonce": self.nonce,
            "iat": now,
            "exp": now + TOKEN_LIFETIME_SECONDS,
        }
        return {
            "access_token": ACCESS_TOKEN,
            "refresh_token": REFRESH_TOKEN,
            "id_token": self._make_token(id_token_claims),
            "token_type": "Bearer",
            "expires_in": TOKEN_LIFETIME_SECONDS,
        }


@pytest.fixture
def fake_keycloak(settings, signing_key, make_token) -> FakeKeycloak:
    return FakeKeycloak(settings, signing_key, make_token)


@pytest.fixture
def application(settings, fake_keycloak, monkeypatch) -> FastAPI:
    """The app, with all back-channel requests answered by the fake Keycloak.

    It also gets a route that shows who ``get_current_session`` thinks is logged in.
    """
    application = create_app(settings)
    transport = httpx2.MockTransport(fake_keycloak.handle)
    application.state.oauth_client.client_kwargs["transport"] = transport

    real_async_client = httpx.AsyncClient

    def async_client_with_fake_keycloak(**kwargs) -> httpx.AsyncClient:
        return real_async_client(
            transport=httpx.MockTransport(fake_keycloak.handle_refresh), **kwargs
        )

    # Only this module's view of httpx is replaced, so no other code is affected.
    fake_httpx = SimpleNamespace(
        AsyncClient=async_client_with_fake_keycloak, HTTPError=httpx.HTTPError
    )
    monkeypatch.setattr(oidc_login, "httpx", fake_httpx)

    @application.get(CURRENT_SESSION_ROUTE)
    def current_session(
        session: Annotated[Session | None, Depends(get_current_session)],
    ) -> dict[str, str | None]:
        return {"username": session.username if session else None}

    return application


@pytest.fixture
def client(application) -> TestClient:
    """A browser that shows redirects instead of following them."""
    return TestClient(application, follow_redirects=False)


@pytest.fixture
def frozen_time(monkeypatch) -> float:
    """Stop the login module's clock at ``FROZEN_NOW``, so expiry checks are exact."""
    monkeypatch.setattr(oidc_login, "time", SimpleNamespace(time=lambda: FROZEN_NOW))
    return FROZEN_NOW


def start_login(client: TestClient, fake_keycloak: FakeKeycloak) -> dict[str, str]:
    """Begin a login and return the query parameters of the redirect to Keycloak.

    The fake Keycloak learns the ``nonce``, as the real one would from the redirect.
    """
    response = client.get(LOGIN_ROUTE)
    query = {
        name: values[0]
        for name, values in parse_qs(urlparse(response.headers["location"]).query).items()
    }
    fake_keycloak.nonce = query["nonce"]
    return query


def finish_login(client: TestClient, fake_keycloak: FakeKeycloak):
    """Log in from start to finish and return the callback's response."""
    state = start_login(client, fake_keycloak)["state"]
    return client.get(CALLBACK_ROUTE, params={"code": AUTHORIZATION_CODE, "state": state})


def log_in_with_seconds_left(
    client: TestClient,
    application: FastAPI,
    fake_keycloak: FakeKeycloak,
    seconds_left: float,
) -> str:
    """Log in, then make the access token expire ``seconds_left`` after ``FROZEN_NOW``.

    Returns:
        The new session's ID.
    """
    settings = application.state.settings
    session_id = finish_login(client, fake_keycloak).cookies[settings.session_cookie_name]
    sessions = application.state.session_store._sessions
    sessions[session_id] = dataclasses.replace(
        sessions[session_id], access_token_expires_at=FROZEN_NOW + seconds_left
    )
    return session_id


def session_cookie_header(response, cookie_name: str) -> str:
    """Return the ``Set-Cookie`` header for the app's session cookie."""
    return next(
        header
        for header in response.headers.get_list("set-cookie")
        if header.startswith(f"{cookie_name}=")
    )


class TestLogin:
    def test_login_redirects_to_keycloak_with_pkce_state_and_nonce(self, client, settings):
        response = client.get(LOGIN_ROUTE)

        location = response.headers["location"]
        query = parse_qs(urlparse(location).query)
        assert response.status_code == 302
        assert location.startswith(settings.authorization_endpoint + "?")
        assert query["client_id"] == [settings.web_client_id]
        assert query["response_type"] == ["code"]
        assert "openid" in query["scope"][0].split()
        assert query["code_challenge_method"] == ["S256"]
        assert query["code_challenge"][0]
        assert query["state"][0]
        assert query["nonce"][0]

    def test_forged_host_header_does_not_change_redirect_uri(self, client, settings):
        response = client.get(LOGIN_ROUTE, headers={"Host": "evil.example"})

        query = parse_qs(urlparse(response.headers["location"]).query)
        assert query["redirect_uri"] == [settings.redirect_uri]


class TestCallback:
    def test_successful_callback_stores_session_and_sets_secure_cookie(
        self, client, application, fake_keycloak, settings
    ):
        state = start_login(client, fake_keycloak)["state"]

        response = client.get(CALLBACK_ROUTE, params={"code": AUTHORIZATION_CODE, "state": state})

        assert response.status_code == 303
        assert response.headers["location"] == "/"
        session_id = response.cookies[settings.session_cookie_name]
        session = application.state.session_store.get(session_id)
        assert session.subject == USER["sub"]
        assert session.username == USER["preferred_username"]
        assert session.access_token == ACCESS_TOKEN
        assert session.refresh_token == REFRESH_TOKEN
        assert session.id_token
        cookie_header = session_cookie_header(response, settings.session_cookie_name).lower()
        assert "httponly" in cookie_header
        assert "samesite=lax" in cookie_header
        assert "path=/" in cookie_header
        assert f"max-age={settings.session_lifetime_seconds}" in cookie_header

    def test_callback_response_contains_no_tokens(
        self, client, application, fake_keycloak, settings
    ):
        response = finish_login(client, fake_keycloak)

        session_id = response.cookies[settings.session_cookie_name]
        session = application.state.session_store.get(session_id)
        visible_to_browser = response.text + str(response.headers)
        for token in (session.access_token, session.refresh_token, session.id_token):
            assert token not in visible_to_browser

    def test_wrong_state_returns_400_and_creates_no_session(
        self, client, application, fake_keycloak
    ):
        start_login(client, fake_keycloak)

        response = client.get(CALLBACK_ROUTE, params={"code": AUTHORIZATION_CODE, "state": "wrong"})

        assert response.status_code == 400
        assert application.state.session_store._sessions == {}

    def test_reused_state_returns_400_and_creates_no_extra_session(
        self, client, application, fake_keycloak
    ):
        state = start_login(client, fake_keycloak)["state"]
        client.get(CALLBACK_ROUTE, params={"code": AUTHORIZATION_CODE, "state": state})

        response = client.get(CALLBACK_ROUTE, params={"code": AUTHORIZATION_CODE, "state": state})

        assert response.status_code == 400
        assert len(application.state.session_store._sessions) == 1

    def test_cancelled_login_returns_400_with_generic_message(self, client, fake_keycloak):
        state = start_login(client, fake_keycloak)["state"]
        error_description = "User cancelled the login"

        response = client.get(
            CALLBACK_ROUTE,
            params={
                "error": "access_denied",
                "error_description": error_description,
                "state": state,
            },
        )

        assert response.status_code == 400
        assert response.json() == {"detail": "Login failed"}
        assert error_description not in response.text

    def test_newline_in_error_cannot_fake_a_log_line(self, client, fake_keycloak, caplog):
        start_login(client, fake_keycloak)
        forged_error = "access_denied\nINFO Login succeeded for admin"

        with caplog.at_level(logging.WARNING, logger=LOGIN_LOGGER):
            client.get(CALLBACK_ROUTE, params={"error": forged_error})

        messages = [record.getMessage() for record in caplog.records if record.name == LOGIN_LOGGER]
        assert messages
        assert all("\n" not in message for message in messages)

    def test_new_login_deletes_old_session(self, client, application, fake_keycloak, settings):
        old_session_id = finish_login(client, fake_keycloak).cookies[settings.session_cookie_name]

        new_session_id = finish_login(client, fake_keycloak).cookies[settings.session_cookie_name]

        session_store = application.state.session_store
        assert session_store.get(old_session_id) is None
        assert session_store.get(new_session_id) is not None


class TestLogout:
    def test_logout_ends_session_clears_cookie_and_redirects_to_keycloak(
        self, client, application, fake_keycloak, settings
    ):
        session_id = finish_login(client, fake_keycloak).cookies[settings.session_cookie_name]
        id_token = application.state.session_store.get(session_id).id_token

        response = client.post(LOGOUT_ROUTE)

        location = response.headers["location"]
        query = parse_qs(urlparse(location).query)
        assert response.status_code == 303
        assert location.startswith(settings.end_session_endpoint + "?")
        assert query["id_token_hint"] == [id_token]
        assert query["post_logout_redirect_uri"] == [settings.post_logout_redirect_uri]
        assert query["client_id"] == [settings.web_client_id]
        assert application.state.session_store.get(session_id) is None
        cookie_header = session_cookie_header(response, settings.session_cookie_name).lower()
        assert "max-age=0" in cookie_header
        assert settings.session_cookie_name not in client.cookies

    def test_logout_with_get_is_rejected_and_keeps_session(
        self, client, application, fake_keycloak, settings
    ):
        session_id = finish_login(client, fake_keycloak).cookies[settings.session_cookie_name]

        response = client.get(LOGOUT_ROUTE)

        assert response.status_code == 405
        assert application.state.session_store.get(session_id) is not None

    def test_logout_without_session_cookie_redirects_home(self, client):
        response = client.post(LOGOUT_ROUTE)

        assert response.status_code == 303
        assert response.headers["location"] == "/"

    def test_local_session_is_deleted_even_if_keycloak_step_fails(
        self, client, application, fake_keycloak, settings, monkeypatch
    ):
        session_id = finish_login(client, fake_keycloak).cookies[settings.session_cookie_name]

        async def failing_logout_redirect(*args, **kwargs):
            raise RuntimeError("Keycloak logout failed")

        monkeypatch.setattr(
            application.state.oauth_client, "logout_redirect", failing_logout_redirect
        )

        with pytest.raises(RuntimeError):
            client.post(LOGOUT_ROUTE)

        assert application.state.session_store.get(session_id) is None


@pytest.mark.usefixtures("frozen_time")
class TestCurrentSession:
    def test_token_with_more_than_30_seconds_left_is_not_refreshed(
        self, client, application, fake_keycloak
    ):
        session_id = log_in_with_seconds_left(client, application, fake_keycloak, 31)

        response = client.get(CURRENT_SESSION_ROUTE)

        assert response.json() == {"username": USER["preferred_username"]}
        assert fake_keycloak.refresh_requests == []
        assert application.state.session_store.get(session_id).access_token == ACCESS_TOKEN

    def test_token_with_30_seconds_left_is_refreshed_and_stored(
        self, client, application, fake_keycloak, settings
    ):
        session_id = log_in_with_seconds_left(client, application, fake_keycloak, 30)

        response = client.get(CURRENT_SESSION_ROUTE)

        assert response.json() == {"username": USER["preferred_username"]}
        assert fake_keycloak.refresh_requests == [
            {
                "grant_type": "refresh_token",
                "refresh_token": REFRESH_TOKEN,
                "client_id": settings.web_client_id,
                "client_secret": settings.web_client_secret.get_secret_value(),
            }
        ]
        session = application.state.session_store.get(session_id)
        assert session.access_token == NEW_ACCESS_TOKEN
        assert session.refresh_token == NEW_REFRESH_TOKEN
        assert session.id_token == NEW_ID_TOKEN
        assert session.access_token_expires_at == FROZEN_NOW + TOKEN_LIFETIME_SECONDS

    def test_refresh_without_new_refresh_or_id_token_keeps_old_ones(
        self, client, application, fake_keycloak
    ):
        session_id = log_in_with_seconds_left(client, application, fake_keycloak, 0)
        old_session = application.state.session_store.get(session_id)
        fake_keycloak.refresh_omits = ("refresh_token", "id_token")

        client.get(CURRENT_SESSION_ROUTE)

        session = application.state.session_store.get(session_id)
        assert session.access_token == NEW_ACCESS_TOKEN
        assert session.refresh_token == old_session.refresh_token
        assert session.id_token == old_session.id_token

    @pytest.mark.parametrize(
        "refresh_failure",
        [400, httpx.ConnectError, httpx.ReadTimeout],
        ids=["refused", "keycloak-down", "timed-out"],
    )
    def test_failed_refresh_deletes_session_and_returns_none(
        self, client, application, fake_keycloak, refresh_failure
    ):
        session_id = log_in_with_seconds_left(client, application, fake_keycloak, 0)
        fake_keycloak.refresh_failure = refresh_failure

        response = client.get(CURRENT_SESSION_ROUTE)

        assert response.json() == {"username": None}
        assert application.state.session_store.get(session_id) is None

    def test_user_who_logged_out_during_refresh_is_not_brought_back(
        self, client, application, fake_keycloak
    ):
        session_id = log_in_with_seconds_left(client, application, fake_keycloak, 0)
        session_store = application.state.session_store
        fake_keycloak.on_refresh = lambda: session_store.delete(session_id)

        response = client.get(CURRENT_SESSION_ROUTE)

        assert response.json() == {"username": None}
        assert session_store.get(session_id) is None

    @pytest.mark.parametrize("session_id", [None, "unknown"], ids=["no-cookie", "unknown-cookie"])
    def test_missing_or_unknown_cookie_returns_none(self, client, settings, session_id):
        if session_id:
            client.cookies.set(settings.session_cookie_name, session_id)

        response = client.get(CURRENT_SESSION_ROUTE)

        assert response.json() == {"username": None}
