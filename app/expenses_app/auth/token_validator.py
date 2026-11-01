"""Verifies Keycloak access tokens (JWTs) before the API trusts them.

A token is accepted only if it is signed by Keycloak, uses the expected algorithm,
was issued by our realm, is meant for this API and has not expired.
"""

from dataclasses import dataclass, field
from typing import Any

import jwt
from jwt import PyJWKClient
from jwt.exceptions import InvalidTokenError, PyJWKClientError

from expenses_app.settings import Settings


@dataclass(frozen=True)
class TokenClaims:
    """The verified facts the app needs from an access token.

    Attributes:
        subject: Keycloak's permanent user ID (``sub``). Use this, not the username,
            to identify a user, because usernames can change.
        username: Human-readable login name (``preferred_username``), e.g. ``ryan.landry``.
        roles: This API's client roles (``resource_access.<api_audience>.roles``),
            e.g. ``("employee", "manager")``.
        raw_claims: Every claim in the token, for rare cases the fields above don't cover.
            Hidden from ``repr`` so logs don't print whole tokens.
    """

    subject: str
    username: str
    roles: tuple[str, ...] = ()
    raw_claims: dict[str, Any] = field(default_factory=dict, repr=False)

    def has_role(self, role: str) -> bool:
        """Return whether the token grants the given role."""
        return role in self.roles


class TokenValidationError(Exception):
    """Raised when a token must not be trusted, for any reason.

    The message says what failed (e.g. expired, wrong audience) for logs. The original
    PyJWT error is kept as ``__cause__``. Never show the details to the caller: an API
    should answer with a plain 401.
    """


class TokenValidator:
    """Checks that an access token was issued by our Keycloak realm for this API.

    One instance is created at startup and reused, so Keycloak's public keys are
    downloaded once and cached instead of on every request.
    """

    ALLOWED_ALGORITHMS: tuple[str, ...] = ("RS256",)
    CLOCK_LEEWAY_SECONDS: int = 30
    REQUIRED_CLAIMS: tuple[str, ...] = ("exp", "iat", "iss", "aud", "sub")

    def __init__(self, settings: Settings, signing_key_client: PyJWKClient | None = None) -> None:
        """Prepare the validator.

        Args:
            settings: Supplies the realm's issuer, this API's audience and the JWKS address.
            signing_key_client: Source of Keycloak's public keys. Leave empty in production;
                tests pass a client that serves their own test keys.
        """
        self._signing_key_client = signing_key_client or PyJWKClient(settings.jwks_uri)
        self._expected_issuer = settings.issuer
        self._expected_audience = settings.api_audience

    def validate(self, raw_token: str) -> TokenClaims:
        """Verify a token and return its claims.

        Args:
            raw_token: The JWT taken from the ``Authorization: Bearer`` header.

        Returns:
            The verified claims.

        Raises:
            TokenValidationError: If the token is missing, malformed, signed by an unknown
                key or with a forbidden algorithm, from another issuer, for another audience,
                expired, or lacking a required claim.
        """
        if not raw_token:
            raise TokenValidationError("No token provided")

        try:
            signing_key = self._signing_key_client.get_signing_key_from_jwt(raw_token)
            claims = jwt.decode(
                raw_token,
                key=signing_key.key,
                algorithms=list(self.ALLOWED_ALGORITHMS),
                audience=self._expected_audience,
                issuer=self._expected_issuer,
                leeway=self.CLOCK_LEEWAY_SECONDS,
                options={"require": list(self.REQUIRED_CLAIMS)},
            )
        except (InvalidTokenError, PyJWKClientError) as error:
            raise TokenValidationError(f"Token rejected: {error}") from error

        return TokenClaims(
            subject=claims["sub"],
            username=claims.get("preferred_username", ""),
            roles=self._roles_for_this_api(claims),
            raw_claims=claims,
        )

    def _roles_for_this_api(self, claims: dict[str, Any]) -> tuple[str, ...]:
        """Read this API's client roles from ``resource_access.<audience>.roles``."""
        client_access = claims.get("resource_access", {}).get(self._expected_audience, {})
        return tuple(client_access.get("roles", ()))
