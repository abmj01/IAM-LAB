"""Builds the FastAPI application.

Run locally with::

    uvicorn expenses_app.main:create_app --factory --reload
"""

from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware

from expenses_app import __version__
from expenses_app.auth.oidc_login import build_oauth_client
from expenses_app.auth.oidc_login import router as auth_router
from expenses_app.auth.session_store import SessionStore
from expenses_app.auth.token_validator import TokenValidator
from expenses_app.pages import router as pages_router
from expenses_app.settings import Settings, get_settings


def create_app(settings: Settings | None = None) -> FastAPI:
    """Create and configure the application.

    Args:
        settings: Configuration to use. Tests pass their own; when omitted,
            settings are read from the environment.

    Returns:
        The ready-to-serve FastAPI application.
    """
    application_settings = settings or get_settings()

    application = FastAPI(title="Greenfield Expense Claims", version=__version__)
    application.state.settings = application_settings
    application.state.token_validator = TokenValidator(application_settings)
    application.state.oauth_client = build_oauth_client(application_settings)
    application.state.session_store = SessionStore(application_settings.session_lifetime_seconds)

    application.add_middleware(
        SessionMiddleware,
        secret_key=application_settings.session_secret_key.get_secret_value(),
        same_site="lax",
        https_only=application_settings.session_cookie_secure,
    )
    application.include_router(auth_router)
    application.include_router(pages_router)

    @application.get("/health", tags=["operations"])
    def health() -> dict[str, str]:
        """Report that the service is running. Needs no login, for monitoring and Docker."""
        return {"status": "ok"}

    return application
