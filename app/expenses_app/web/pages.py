"""Web pages for people using a browser. They know the user from the session cookie.

Pages get their data from ``ClaimService``, so they follow the same rules as the API, and
only show links the policy allows. After a form is sent the browser is redirected
(Post/Redirect/Get), so reloading a page never sends the form twice.
"""

from collections.abc import Callable
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Form, Request, status
from fastapi.exception_handlers import http_exception_handler
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import Response

from expenses_app.auth.page_access import get_optional_page_user, get_page_user
from expenses_app.auth.token_validator import TokenClaims
from expenses_app.claims.dependencies import get_claim_service
from expenses_app.claims.models import Claim
from expenses_app.claims.policy import Action, is_allowed
from expenses_app.claims.service import (
    ClaimError,
    ClaimForbiddenError,
    ClaimNotFoundError,
    ClaimService,
    ClaimStatusConflictError,
    InvalidClaimError,
)
from expenses_app.web.security import require_same_origin, security_headers

templates = Jinja2Templates(directory=Path(__file__).parent / "templates")

router = APIRouter(tags=["pages"])

OptionalUser = Annotated[TokenClaims | None, Depends(get_optional_page_user)]
PageUser = Annotated[TokenClaims, Depends(get_page_user)]
Service = Annotated[ClaimService, Depends(get_claim_service)]
SameOrigin = [Depends(require_same_origin)]

# Notices are chosen by a fixed key in the URL, never by text from the URL, so a link
# can't make the page show an attacker's message.
NOTICES = {
    "submitted": ("success", "Your claim was submitted."),
    "approved": ("success", "Claim approved."),
    "paid": ("success", "Claim marked as paid."),
    "conflict": ("warning", "That claim was already handled by someone else."),
}
HTTP_ERROR_TITLES = {
    400: "Request failed",
    403: "Not allowed",
    404: "Page not found",
    405: "Not allowed",
}
JSON_ERROR_PATH_PREFIXES = ("/api/", "/static/", "/health")
ERROR_PAGES = {
    ClaimForbiddenError: (403, "Not allowed", "You don't have permission to do that."),
    ClaimNotFoundError: (404, "Claim not found", "This claim doesn't exist, or you can't see it."),
}


@router.get("/")
def home(request: Request, user: OptionalUser, service: Service) -> HTMLResponse:
    """Show a landing page to visitors, and an overview to logged-in users."""
    if user is None:
        return _render(request, "home.html", None)

    return _render(
        request,
        "home.html",
        user,
        active_page="home",
        own_claims=service.list_own(user),
        awaiting_approval=(
            service.list_awaiting_approval(user) if is_allowed(user, Action.APPROVE) else None
        ),
        awaiting_payment=(
            service.list_awaiting_payment(user) if is_allowed(user, Action.PAY) else None
        ),
    )


@router.get("/claims")
def my_claims(
    request: Request, user: PageUser, service: Service, notice: str | None = None
) -> HTMLResponse:
    """Show the user's claims and the form to submit a new one."""
    return _render_my_claims(request, user, service, notice=NOTICES.get(notice or ""))


@router.post("/claims", dependencies=SameOrigin, response_model=None)
def submit_claim(
    request: Request,
    user: PageUser,
    service: Service,
    amount: Annotated[str, Form()],
    description: Annotated[str, Form()],
) -> HTMLResponse | RedirectResponse:
    """Submit a claim from the form. Wrong input shows the form again with the reason."""
    try:
        service.submit(user, _parse_amount(amount), description)
    except InvalidClaimError as error:
        return _render_my_claims(
            request,
            user,
            service,
            status_code=status.HTTP_400_BAD_REQUEST,
            form_error=str(error),
            form_values={"amount": amount, "description": description},
        )
    except ClaimError as error:
        return _render_error(request, user, error)
    return _redirect("/claims", notice="submitted")


@router.get("/approvals")
def approvals(
    request: Request, user: PageUser, service: Service, notice: str | None = None
) -> HTMLResponse:
    """Show claims waiting for a manager's approval."""
    try:
        claims = service.list_awaiting_approval(user)
    except ClaimError as error:
        return _render_error(request, user, error)
    return _render(
        request,
        "queue.html",
        user,
        active_page="approvals",
        title="Approvals",
        intro="Claims waiting for a manager's approval.",
        claims=claims,
        action="approve",
        action_label="Approve",
        empty_message="Nothing is waiting for approval.",
        notice=NOTICES.get(notice or ""),
    )


@router.post("/claims/{claim_id}/approve", dependencies=SameOrigin, response_model=None)
def approve_claim(
    request: Request, claim_id: str, user: PageUser, service: Service
) -> HTMLResponse | RedirectResponse:
    """Approve a claim from the approvals page."""
    return _handle_action(
        request, user, lambda: service.approve(user, claim_id), "/approvals", "approved"
    )


@router.get("/payments")
def payments(
    request: Request, user: PageUser, service: Service, notice: str | None = None
) -> HTMLResponse:
    """Show approved claims waiting for a finance approver to pay them."""
    try:
        claims = service.list_awaiting_payment(user)
    except ClaimError as error:
        return _render_error(request, user, error)
    return _render(
        request,
        "queue.html",
        user,
        active_page="payments",
        title="Payments",
        intro="Approved claims waiting to be paid.",
        claims=claims,
        action="pay",
        action_label="Mark as paid",
        empty_message="Nothing is waiting for payment.",
        notice=NOTICES.get(notice or ""),
    )


@router.post("/claims/{claim_id}/pay", dependencies=SameOrigin, response_model=None)
def pay_claim(
    request: Request, claim_id: str, user: PageUser, service: Service
) -> HTMLResponse | RedirectResponse:
    """Mark a claim as paid from the payments page."""
    return _handle_action(request, user, lambda: service.pay(user, claim_id), "/payments", "paid")


async def render_http_error(request: Request, error: StarletteHTTPException) -> Response:
    """Show browser errors as the styled error page, and keep JSON for API callers.

    Registered in ``create_app``. It catches errors raised outside the page code, such as
    the ``Origin`` check, a failed login, or an unknown URL. Every ``detail`` the app raises
    is a fixed text, so it is safe to show.
    """
    if request.url.path.startswith(JSON_ERROR_PATH_PREFIXES):
        return await http_exception_handler(request, error)
    return _render(
        request,
        "error.html",
        None,
        status_code=error.status_code,
        title=HTTP_ERROR_TITLES.get(error.status_code, "Something went wrong"),
        message=error.detail,
    )


def _handle_action(
    request: Request,
    user: TokenClaims,
    action: Callable[[], Claim],
    return_path: str,
    success_notice: str,
) -> HTMLResponse | RedirectResponse:
    """Run an approve or pay action, then send the browser back to the list it came from."""
    try:
        action()
    except ClaimStatusConflictError:
        return _redirect(return_path, notice="conflict")
    except ClaimError as error:
        return _render_error(request, user, error)
    return _redirect(return_path, notice=success_notice)


def _render_my_claims(
    request: Request,
    user: TokenClaims,
    service: ClaimService,
    status_code: int = status.HTTP_200_OK,
    **context: Any,
) -> HTMLResponse:
    return _render(
        request,
        "claims.html",
        user,
        status_code=status_code,
        active_page="claims",
        claims=service.list_own(user),
        **context,
    )


def _render_error(request: Request, user: TokenClaims, error: ClaimError) -> HTMLResponse:
    status_code, title, message = ERROR_PAGES.get(
        type(error), (400, "Something went wrong", "The request could not be completed.")
    )
    return _render(
        request, "error.html", user, status_code=status_code, title=title, message=message
    )


def _render(
    request: Request,
    template_name: str,
    user: TokenClaims | None,
    status_code: int = status.HTTP_200_OK,
    **context: Any,
) -> HTMLResponse:
    """Render a page with the navigation the user may see and the security headers.

    Templates escape every value, so text from users can't become HTML.
    """
    response = templates.TemplateResponse(
        request,
        template_name,
        {
            "user": user,
            "can_approve": user is not None and is_allowed(user, Action.APPROVE),
            "can_pay": user is not None and is_allowed(user, Action.PAY),
            **context,
        },
        status_code=status_code,
    )
    response.headers.update(security_headers(request.app.state.settings))
    return response


def _redirect(path: str, notice: str) -> RedirectResponse:
    return RedirectResponse(f"{path}?notice={notice}", status_code=status.HTTP_303_SEE_OTHER)


def _parse_amount(amount: str) -> Decimal:
    """Turn the form's text into a number. The service checks the value itself."""
    try:
        return Decimal(amount.strip())
    except InvalidOperation as error:
        raise InvalidClaimError("Amount must be a number") from error
