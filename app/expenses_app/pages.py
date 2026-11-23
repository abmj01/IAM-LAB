"""Web pages the browser sees. They know the user from the session cookie, not a bearer token."""

from html import escape
from typing import Annotated

from fastapi import APIRouter, Depends
from fastapi.responses import HTMLResponse

from expenses_app.auth.oidc_login import get_current_session
from expenses_app.auth.session_store import Session

router = APIRouter(tags=["pages"])

NO_STORE_HEADERS = {"Cache-Control": "no-store"}


@router.get("/", response_class=HTMLResponse)
def home(session: Annotated[Session | None, Depends(get_current_session)]) -> HTMLResponse:
    """Show who is logged in with a logout button, or a login link.

    Logout is a form that sends a POST, because ``/auth/logout`` refuses GET. The page is
    never cached, so a shared browser can't show one user's page to the next.
    """
    if session is None:
        body = '<p>You are not logged in.</p>\n<p><a href="/auth/login">Log in</a></p>'
    else:
        body = (
            f"<p>Logged in as {escape(session.username)}</p>\n"
            '<form method="post" action="/auth/logout">'
            '<button type="submit">Log out</button></form>'
        )
    return HTMLResponse(_page(body), headers=NO_STORE_HEADERS)


def _page(body: str) -> str:
    """Wrap a page body in the shared HTML layout."""
    return f"""<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Greenfield Expense Claims</title></head>
<body>
<h1>Greenfield Expense Claims</h1>
{body}
</body>
</html>
"""
