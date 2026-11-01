"""Tests for access control: who gets a 401, who gets a 403, and who gets through."""

import logging
from typing import Annotated

import pytest
from fastapi import Depends, Request
from fastapi.testclient import TestClient

from expenses_app.auth.access_control import get_current_claims, get_token_validator, require_role
from expenses_app.auth.token_validator import TokenClaims, TokenValidator
from expenses_app.main import create_app

LOGIN_ROUTE = "/login-required"
ROLE_ROUTE = "/role-required"
REQUIRED_ROLE = "finance-approver"
BASIC_AUTH_HEADER = {"Authorization": "Basic dXNlcjpwYXNzd29yZA=="}


def bearer_header(token: str) -> dict[str, str]:
    """Build the ``Authorization`` header that carries a bearer token."""
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def client(settings, validator) -> TestClient:
    """A client for an app with two temporary routes, trusting only the test signing key."""
    application = create_app(settings)
    application.state.token_validator = validator

    @application.get(LOGIN_ROUTE)
    def login_required(
        claims: Annotated[TokenClaims, Depends(get_current_claims)],
    ) -> dict[str, str]:
        return {"subject": claims.subject, "username": claims.username}

    @application.get(ROLE_ROUTE)
    def role_required(
        claims: Annotated[TokenClaims, Depends(require_role(REQUIRED_ROLE))],
    ) -> dict[str, str]:
        return {"subject": claims.subject, "username": claims.username}

    return TestClient(application)


class TestAuthentication:
    def test_request_without_authorization_header_returns_401(self, client):
        response = client.get(LOGIN_ROUTE)

        assert response.status_code == 401

    def test_request_with_basic_scheme_returns_401(self, client):
        response = client.get(LOGIN_ROUTE, headers=BASIC_AUTH_HEADER)

        assert response.status_code == 401

    @pytest.mark.parametrize("malformed_token", ["not-a-jwt", "a.b.c"])
    def test_request_with_malformed_token_returns_401(self, client, malformed_token):
        response = client.get(LOGIN_ROUTE, headers=bearer_header(malformed_token))

        assert response.status_code == 401

    def test_request_with_token_signed_by_untrusted_key_returns_401(
        self, client, make_token, valid_claims, attacker_key
    ):
        forged_token = make_token(valid_claims, key=attacker_key)

        response = client.get(LOGIN_ROUTE, headers=bearer_header(forged_token))

        assert response.status_code == 401

    def test_every_401_has_same_body_and_bearer_challenge(
        self, client, make_token, valid_claims, attacker_key
    ):
        expired_claims = {**valid_claims, "iat": 0, "exp": 1}
        rejected_requests = [
            {},
            BASIC_AUTH_HEADER,
            bearer_header("not-a-jwt"),
            bearer_header(make_token(valid_claims, key=attacker_key)),
            bearer_header(make_token(expired_claims)),
        ]

        for headers in rejected_requests:
            response = client.get(LOGIN_ROUTE, headers=headers)

            assert response.status_code == 401
            assert response.json() == {"detail": "Invalid or missing token"}
            assert response.headers["WWW-Authenticate"] == "Bearer"

    def test_valid_token_reaches_route_with_correct_claims(self, client, make_token, valid_claims):
        response = client.get(LOGIN_ROUTE, headers=bearer_header(make_token(valid_claims)))

        assert response.status_code == 200
        assert response.json() == {"subject": valid_claims["sub"], "username": "ryan.landry"}


class TestAuthorization:
    def test_valid_token_with_required_role_returns_200(self, client, make_token, valid_claims):
        valid_claims["resource_access"][valid_claims["aud"]]["roles"] = [REQUIRED_ROLE]

        response = client.get(ROLE_ROUTE, headers=bearer_header(make_token(valid_claims)))

        assert response.status_code == 200
        assert response.json() == {"subject": valid_claims["sub"], "username": "ryan.landry"}

    def test_valid_token_with_different_role_returns_403(self, client, make_token, valid_claims):
        response = client.get(ROLE_ROUTE, headers=bearer_header(make_token(valid_claims)))

        assert response.status_code == 403

    def test_valid_token_without_roles_returns_403(self, client, make_token, valid_claims):
        valid_claims["resource_access"][valid_claims["aud"]]["roles"] = []

        response = client.get(ROLE_ROUTE, headers=bearer_header(make_token(valid_claims)))

        assert response.status_code == 403

    def test_required_role_under_another_app_returns_403(self, client, make_token, valid_claims):
        valid_claims["resource_access"]["grafana"]["roles"] = [REQUIRED_ROLE]

        response = client.get(ROLE_ROUTE, headers=bearer_header(make_token(valid_claims)))

        assert response.status_code == 403

    def test_403_response_does_not_reveal_required_role(self, client, make_token, valid_claims):
        response = client.get(ROLE_ROUTE, headers=bearer_header(make_token(valid_claims)))

        assert response.status_code == 403
        assert response.json() == {"detail": "Insufficient permissions"}
        assert REQUIRED_ROLE not in response.text


class TestOrderAndBypass:
    def test_invalid_token_on_role_route_returns_401_not_403(
        self, client, make_token, valid_claims, attacker_key
    ):
        forged_token = make_token(valid_claims, key=attacker_key)

        response = client.get(ROLE_ROUTE, headers=bearer_header(forged_token))

        assert response.status_code == 401

    def test_made_up_claims_in_body_without_token_return_401(self, client):
        made_up_claims = {"subject": "x", "username": "attacker", "roles": [REQUIRED_ROLE]}

        response = client.request("GET", ROLE_ROUTE, json=made_up_claims)

        assert response.status_code == 401


class TestLogging:
    def test_rejected_token_logs_reason_but_not_token(
        self, client, make_token, valid_claims, caplog
    ):
        expired_token = make_token({**valid_claims, "iat": 0, "exp": 1})

        with caplog.at_level(logging.WARNING):
            client.get(LOGIN_ROUTE, headers=bearer_header(expired_token))

        assert "expired" in caplog.text
        assert expired_token not in caplog.text

    def test_403_logs_caller_and_required_role(self, client, make_token, valid_claims, caplog):
        with caplog.at_level(logging.WARNING):
            client.get(ROLE_ROUTE, headers=bearer_header(make_token(valid_claims)))

        assert valid_claims["sub"] in caplog.text
        assert REQUIRED_ROLE in caplog.text


class TestAppSetup:
    def test_create_app_stores_validator_for_get_token_validator(self, settings):
        application = create_app(settings)
        request = Request({"type": "http", "app": application})

        stored_validator = get_token_validator(request)

        assert isinstance(stored_validator, TokenValidator)
        assert stored_validator is application.state.token_validator
