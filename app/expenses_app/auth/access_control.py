"""Connects token validation to FastAPI routes: who is calling, and may they do this?

A route declares what it needs, and FastAPI runs these checks before the route's code:

* No or invalid token: **401** ("I don't know who you are").
* Valid token, missing role: **403** ("I know who you are, and the answer is no").

Business rules such as "may Bonnie approve THIS claim?" depend on the claim, so they belong
in the claims module, not here.
"""

import logging
from collections.abc import Callable
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from expenses_app.auth.token_validator import TokenClaims, TokenValidationError, TokenValidator

logger = logging.getLogger(__name__)

bearer_scheme = HTTPBearer(auto_error=False)


def get_token_validator(request: Request) -> TokenValidator:
    """Return the validator created at startup, so Keycloak's keys stay cached."""
    return request.app.state.token_validator


def _unauthorized() -> HTTPException:
    """Build the one 401 response, the same for every failure so attackers learn nothing."""
    return HTTPException(
        status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing token",
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_current_claims(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    validator: Annotated[TokenValidator, Depends(get_token_validator)],
) -> TokenClaims:
    """Authenticate the caller from their bearer token.

    Args:
        credentials: The token from the ``Authorization`` header, or None if there is none.
        validator: The shared token validator.

    Returns:
        The verified claims of the token.

    Raises:
        HTTPException: 401 if the token is missing or invalid.
    """
    if credentials is None:
        raise _unauthorized()

    try:
        return validator.validate(credentials.credentials)
    except TokenValidationError as error:
        logger.warning("Rejected token: %r", error)
        raise _unauthorized() from error


def require_role(role: str) -> Callable[..., TokenClaims]:
    """Authorize the caller for a specific role.

    Args:
        role: The role required to access the route.

    Returns:
        A dependency function that checks the caller's role.
    """

    def check_role(claims: Annotated[TokenClaims, Depends(get_current_claims)]) -> TokenClaims:
        """Check that the caller has the required role.

        Args:
            claims: The verified claims of the caller's token.

        Returns:
            The same claims, if the caller is authorized.

        Raises:
            HTTPException: 403 if the caller lacks the required role.
        """
        if not claims.has_role(role):
            logger.warning("Caller %r lacks required role %r", claims.subject, role)
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return claims

    return check_role
