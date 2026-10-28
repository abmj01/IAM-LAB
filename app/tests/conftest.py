"""Shared test setup: throw-away RSA keys, test settings and a token factory.

Tests never contact Keycloak. They sign their own tokens with a test key and give the
validator a fake key client that serves the matching public key.
"""

import json
import time
from collections.abc import Callable
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt import PyJWK
from jwt.exceptions import PyJWKClientError

from expenses_app.auth.token_validator import TokenValidator
from expenses_app.settings import Settings
from tests.jwt_helpers import TEST_KEY_ID


class FakeSigningKeyClient:
    """Stands in for ``PyJWKClient``: knows exactly one public key, under ``TEST_KEY_ID``."""

    def __init__(self, public_key: PyJWK) -> None:
        self._public_key = public_key

    def get_signing_key_from_jwt(self, raw_token: str) -> PyJWK:
        """Return the known key if the token's ``kid`` matches, like Keycloak's JWKS would."""
        key_id = jwt.get_unverified_header(raw_token).get("kid")
        if key_id != TEST_KEY_ID:
            raise PyJWKClientError(f"Unable to find a signing key that matches: {key_id}")
        return self._public_key


@pytest.fixture(scope="session")
def signing_key() -> rsa.RSAPrivateKey:
    """The key our fake Keycloak signs tokens with."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def attacker_key() -> rsa.RSAPrivateKey:
    """A key the validator does not trust."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def settings() -> Settings:
    """Settings with dummy secrets, independent of any ``.env`` file."""
    return Settings(web_client_secret="test", session_secret_key="test", _env_file=None)


@pytest.fixture
def validator(settings: Settings, signing_key: rsa.RSAPrivateKey) -> TokenValidator:
    """A validator that trusts only ``signing_key``."""
    public_jwk_dict = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(signing_key.public_key()))
    public_jwk = PyJWK.from_dict({**public_jwk_dict, "kid": TEST_KEY_ID, "alg": "RS256"})
    return TokenValidator(settings, signing_key_client=FakeSigningKeyClient(public_jwk))


@pytest.fixture
def valid_claims(settings: Settings) -> dict[str, Any]:
    """Claims of a correct access token for Ryan, valid for 5 minutes."""
    now = int(time.time())
    return {
        "sub": "5801f676-bbf6-4150-8eab-d0878c28b58d",
        "preferred_username": "ryan.landry",
        "iss": settings.issuer,
        "aud": settings.api_audience,
        "iat": now,
        "exp": now + 300,
        "resource_access": {
            settings.api_audience: {"roles": ["employee"]},
            "grafana": {"roles": ["admin"]},
        },
    }


@pytest.fixture
def make_token(signing_key: rsa.RSAPrivateKey) -> Callable[..., str]:
    """Factory that signs any claims, by default the way Keycloak would."""

    def _make_token(
        claims: dict[str, Any],
        key: rsa.RSAPrivateKey | None = None,
        key_id: str = TEST_KEY_ID,
    ) -> str:
        return jwt.encode(claims, key or signing_key, algorithm="RS256", headers={"kid": key_id})

    return _make_token
