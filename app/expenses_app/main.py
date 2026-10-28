"""Builds the FastAPI application.

Run locally with::

    uvicorn expenses_app.main:create_app --factory --reload
"""

from fastapi import FastAPI

from expenses_app import __version__
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

    @application.get("/health", tags=["operations"])
    def health() -> dict[str, str]:
        """Report that the service is running. Needs no login, for monitoring and Docker."""
        return {"status": "ok"}

    return application
