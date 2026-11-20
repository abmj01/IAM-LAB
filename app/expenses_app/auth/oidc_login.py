"""Logs users in through Keycloak using Authorization Code + PKCE.

The browser never receives a token. After login the tokens go into the server-side session
store, and the browser only gets a random session ID in a cookie.

This module only answers "who is logged in to this browser?". What they may do is decided in
``access_control``. Tokens, codes and session IDs are never logged.
"""

import logging
import time

import httpx
from authlib.integrations.starlette_client import OAuth, OAuthError, StarletteOAuth2App
from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import RedirectResponse

from expenses_app.auth.session_store import Session, SessionStore
from expenses_app.settings import Settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

TOKEN_REFRESH_MARGIN_SECONDS = 30
TOKEN_REQUEST_TIMEOUT_SECONDS = 10


def build_oauth_client(settings: Settings) -> StarletteOAuth2App:
    """Create the client that logs users in through Keycloak.

    Each URL is set by hand instead of using ``server_metadata_url``, because the browser
    and the app server reach Keycloak at different addresses. Authlib then handles
    ``state``, ``nonce`` and PKCE, and verifies the ID token.

    Args:
        settings: Supplies the client credentials and Keycloak's addresses.

    Returns:
        The configured Keycloak client.
    """
    oauth = OAuth()
    return oauth.register(
        name="keycloak",
        client_id=settings.web_client_id,
        client_secret=settings.web_client_secret.get_secret_value(),
        authorize_url=settings.authorization_endpoint,
        access_token_url=settings.token_endpoint,
        jwks_uri=settings.jwks_uri,
        issuer=settings.issuer,
        end_session_endpoint=settings.end_session_endpoint,
        client_kwargs={"scope": "openid profile email", "code_challenge_method": "S256"},
    )


@router.get("/login")
async def login(request: Request) -> RedirectResponse:
    """Send the browser to Keycloak's login page.

    The redirect URI comes from settings, never from the request, because the ``Host``
    header can be forged.
    """
    settings = request.app.state.settings
    return await request.app.state.oauth_client.authorize_redirect(request, settings.redirect_uri)


@router.get("/callback")
async def callback(request: Request) -> RedirectResponse:
    """Finish the login that Keycloak sends the browser back from.

    Swaps the one-time code for tokens, then keeps them in the session store. Any old session
    in this browser is deleted, so a session ID from before the login stops working.

    Raises:
        HTTPException: 400 if the login failed, for example a bad ``state`` or a cancelled
            login. The reason is logged, not shown to the browser.
    """
    settings = request.app.state.settings
    session_store: SessionStore = request.app.state.session_store

    try:
        token = await request.app.state.oauth_client.authorize_access_token(request)
    except OAuthError as error:
        # %r because error.error can come from the URL and could hold a fake log line.
        logger.warning("Login failed: %r", error.error)
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Login failed") from error

    user_info = token["userinfo"]

    old_session_id = request.cookies.get(settings.session_cookie_name)
    if old_session_id:
        session_store.delete(old_session_id)

    session_id = session_store.create(
        subject=user_info["sub"],
        username=user_info["preferred_username"],
        access_token=token["access_token"],
        refresh_token=token["refresh_token"],
        id_token=token["id_token"],
        access_token_expires_at=token["expires_at"],
    )

    response = RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(
        key=settings.session_cookie_name,
        value=session_id,
        httponly=True,
        samesite="lax",
        secure=settings.session_cookie_secure,
        max_age=settings.session_lifetime_seconds,
        path="/",
    )
    return response


@router.post("/logout")
async def logout(request: Request) -> RedirectResponse:
    """End the session in this app and in Keycloak.

    Uses POST so another site can't log a user out with a simple link. The local session is
    deleted first, so the user is logged out of this app even if the Keycloak step fails.
    """
    settings = request.app.state.settings
    session_store: SessionStore = request.app.state.session_store

    session = None
    session_id = request.cookies.get(settings.session_cookie_name)
    if session_id:
        session = session_store.get(session_id)
        session_store.delete(session_id)

    if session:
        response = await request.app.state.oauth_client.logout_redirect(
            request,
            post_logout_redirect_uri=settings.post_logout_redirect_uri,
            id_token_hint=session.id_token,
            client_id=settings.web_client_id,
        )
        response.status_code = status.HTTP_303_SEE_OTHER
    else:
        response = RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)

    response.delete_cookie(settings.session_cookie_name, path="/")
    return response


async def get_current_session(request: Request) -> Session | None:
    """Find who is logged in to this browser, refreshing their tokens when needed.

    Pages use this with ``Depends`` and send the browser to ``/auth/login`` when it returns
    None.

    Returns:
        The active session, or None if the user has to log in again.
    """
    settings = request.app.state.settings
    session_store: SessionStore = request.app.state.session_store

    session_id = request.cookies.get(settings.session_cookie_name)
    if not session_id:
        return None
    session = session_store.get(session_id)
    if session is None:
        return None

    if session.access_token_expires_at - time.time() > TOKEN_REFRESH_MARGIN_SECONDS:
        return session

    new_tokens = await _refresh_tokens(settings, session)
    if new_tokens is None:
        session_store.delete(session_id)
        return None

    if not session_store.update_tokens(session_id, **new_tokens):
        return None
    return session_store.get(session_id)


async def _refresh_tokens(settings: Settings, session: Session) -> dict | None:
    """Ask Keycloak for new tokens using the session's refresh token.

    Args:
        settings: Supplies the token endpoint and client credentials.
        session: The session whose access token is about to expire.

    Returns:
        The new tokens in the form ``SessionStore.update_tokens`` takes, or None if Keycloak
        refused or could not be reached.
    """
    try:
        async with httpx.AsyncClient(timeout=TOKEN_REQUEST_TIMEOUT_SECONDS) as http_client:
            response = await http_client.post(
                settings.token_endpoint,
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": session.refresh_token,
                    "client_id": settings.web_client_id,
                    "client_secret": settings.web_client_secret.get_secret_value(),
                },
            )
    except httpx.HTTPError as error:
        logger.warning("Token refresh failed: %s", type(error).__name__)
        return None

    if response.status_code != status.HTTP_200_OK:
        logger.info("Token refresh refused: HTTP %s", response.status_code)
        return None

    tokens = response.json()
    return {
        "access_token": tokens["access_token"],
        "refresh_token": tokens.get("refresh_token", session.refresh_token),
        "id_token": tokens.get("id_token", session.id_token),
        "access_token_expires_at": time.time() + tokens["expires_in"],
    }
