"""Browser protections for the HTML pages.

* Security headers tell the browser to run no scripts, load styles only from this app,
  never show the page inside another site's frame, and never cache it.
* ``require_same_origin`` rejects form posts made by other sites (CSRF). The
  ``SameSite=Lax`` session cookie already blocks most of them; this is the second layer.
"""

import logging

from fastapi import HTTPException, Request, status

from expenses_app.settings import Settings

logger = logging.getLogger(__name__)


def security_headers(settings: Settings) -> dict[str, str]:
    """Return the headers every page is sent with.

    Forms may post to Keycloak too, because logout redirects the browser there, and
    browsers apply ``form-action`` to that redirect.
    """
    content_security_policy = "; ".join(
        [
            "default-src 'none'",
            "style-src 'self'",
            "img-src 'self'",
            f"form-action 'self' {settings.keycloak_public_url}",
            "frame-ancestors 'none'",
            "base-uri 'none'",
        ]
    )
    return {
        "Content-Security-Policy": content_security_policy,
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "same-origin",
    }


def require_same_origin(request: Request) -> None:
    """Reject a form post unless it comes from one of this app's own pages.

    Browsers send ``Origin`` with every POST. If it's missing, ``Referer`` is checked instead.
    A request with neither is rejected, because the app can't tell where it came from.

    Raises:
        HTTPException: 403 if the post comes from another site or an unknown place.
    """
    expected_origin = request.app.state.settings.app_base_url
    origin = request.headers.get("origin")
    if origin is not None:
        is_same_origin = origin == expected_origin
    else:
        is_same_origin = request.headers.get("referer", "").startswith(expected_origin + "/")

    if not is_same_origin:
        logger.warning("Blocked cross-site form post from origin %r", origin)
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Cross-site request blocked")
