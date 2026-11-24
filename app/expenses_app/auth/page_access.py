"""Finds out who is using a web page, from the session cookie.

Pages get the same verified ``TokenClaims`` as the API, so both are checked by the same
claims policy. Only the token's source differs: the server-side session instead of an
``Authorization`` header.

* No session: the browser is sent to ``/auth/login``.
* A session whose access token fails validation: **403**. Logging in again would give a
  token that fails the same way, so a redirect would loop between the app and Keycloak.
"""

import logging
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse

from expenses_app.auth.access_control import get_token_validator
from expenses_app.auth.oidc_login import get_current_session
from expenses_app.auth.session_store import Session
from expenses_app.auth.token_validator import TokenClaims, TokenValidationError, TokenValidator

logger = logging.getLogger(__name__)

LOGIN_ROUTE = "/auth/login"


class LoginRequiredError(Exception):
    """Raised when a page needs a logged-in user and there is none."""


def get_optional_page_user(
    session: Annotated[Session | None, Depends(get_current_session)],
    validator: Annotated[TokenValidator, Depends(get_token_validator)],
) -> TokenClaims | None:
    """Authenticate the page's user if logged in, for pages that visitors may also see.

    Args:
        session: The browser's session, already refreshed if needed, or None.
        validator: The shared token validator.

    Returns:
        The verified claims of the session's access token, or None without a session.

    Raises:
        HTTPException: 403 if the session's token is not valid for this app.
    """
    if session is None:
        return None

    try:
        return validator.validate(session.access_token)
    except TokenValidationError as error:
        logger.error("Session token rejected for %s: %r", session.username, error)
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Access denied") from error


def get_page_user(
    user: Annotated[TokenClaims | None, Depends(get_optional_page_user)],
) -> TokenClaims:
    """Authenticate the page's user, sending visitors to log in.

    Raises:
        LoginRequiredError: If there is no session, so the user is sent to log in.
    """
    if user is None:
        raise LoginRequiredError
    return user


def redirect_to_login(request: Request, error: LoginRequiredError) -> RedirectResponse:
    """Send the browser to log in. Registered in ``create_app`` for ``LoginRequiredError``."""
    return RedirectResponse(LOGIN_ROUTE, status_code=status.HTTP_303_SEE_OTHER)
