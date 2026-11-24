"""JSON API for expense claims, for callers that send a bearer token.

Routes stay thin: they parse the request, call ``ClaimService`` and turn its errors into
HTTP answers. Who may do what is decided in ``claims.policy``, never here.
"""

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from decimal import Decimal
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict

from expenses_app.auth.access_control import get_current_claims
from expenses_app.auth.token_validator import TokenClaims
from expenses_app.claims.dependencies import get_claim_service
from expenses_app.claims.models import Claim, ClaimStatus
from expenses_app.claims.service import (
    ClaimError,
    ClaimForbiddenError,
    ClaimNotFoundError,
    ClaimService,
    ClaimStatusConflictError,
    InvalidClaimError,
)

router = APIRouter(prefix="/api/claims", tags=["claims"])

ERROR_RESPONSES: dict[type[ClaimError], tuple[int, str]] = {
    ClaimForbiddenError: (status.HTTP_403_FORBIDDEN, "Insufficient permissions"),
    ClaimNotFoundError: (status.HTTP_404_NOT_FOUND, "Claim not found"),
    ClaimStatusConflictError: (status.HTTP_409_CONFLICT, "Claim status does not allow this"),
}


class ClaimSubmission(BaseModel):
    """What a caller sends to submit a claim.

    Unknown fields are rejected, so a caller can't sneak in ``status`` or an owner
    (mass assignment). The service checks the values themselves.
    """

    model_config = ConfigDict(extra="forbid")

    amount: Decimal
    description: str


class ClaimResponse(BaseModel):
    """What the API shows about a claim. Keycloak user IDs stay internal."""

    claim_id: str
    owner_username: str
    amount: Decimal
    description: str
    status: ClaimStatus
    submitted_at: datetime

    @classmethod
    def from_claim(cls, claim: Claim) -> "ClaimResponse":
        return cls(
            claim_id=claim.claim_id,
            owner_username=claim.owner_username,
            amount=claim.amount,
            description=claim.description,
            status=claim.status,
            submitted_at=claim.submitted_at,
        )


CurrentUser = Annotated[TokenClaims, Depends(get_current_claims)]
Service = Annotated[ClaimService, Depends(get_claim_service)]


@contextmanager
def claim_errors_as_http() -> Iterator[None]:
    """Turn a ``ClaimError`` raised inside the block into the matching HTTP error.

    Input errors explain what is wrong. All others get a fixed message, so callers learn
    nothing about claims they may not see.
    """
    try:
        yield
    except InvalidClaimError as error:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(error)) from error
    except ClaimError as error:
        status_code, detail = ERROR_RESPONSES[type(error)]
        raise HTTPException(status_code, detail=detail) from error


@router.post("", status_code=status.HTTP_201_CREATED)
def submit_claim(submission: ClaimSubmission, user: CurrentUser, service: Service) -> ClaimResponse:
    """Submit a claim as the calling employee."""
    with claim_errors_as_http():
        claim = service.submit(user, submission.amount, submission.description)
    return ClaimResponse.from_claim(claim)


@router.get("")
def list_own_claims(user: CurrentUser, service: Service) -> list[ClaimResponse]:
    """List the caller's own claims."""
    return [ClaimResponse.from_claim(claim) for claim in service.list_own(user)]


@router.get("/awaiting-approval")
def list_claims_awaiting_approval(user: CurrentUser, service: Service) -> list[ClaimResponse]:
    """List submitted claims, for managers."""
    with claim_errors_as_http():
        claims = service.list_awaiting_approval(user)
    return [ClaimResponse.from_claim(claim) for claim in claims]


@router.get("/awaiting-payment")
def list_claims_awaiting_payment(user: CurrentUser, service: Service) -> list[ClaimResponse]:
    """List approved claims, for finance approvers."""
    with claim_errors_as_http():
        claims = service.list_awaiting_payment(user)
    return [ClaimResponse.from_claim(claim) for claim in claims]


@router.get("/{claim_id}")
def get_claim(claim_id: str, user: CurrentUser, service: Service) -> ClaimResponse:
    """Show one claim the caller may see."""
    with claim_errors_as_http():
        claim = service.get(user, claim_id)
    return ClaimResponse.from_claim(claim)


@router.post("/{claim_id}/approve")
def approve_claim(claim_id: str, user: CurrentUser, service: Service) -> ClaimResponse:
    """Approve a submitted claim, as a manager."""
    with claim_errors_as_http():
        claim = service.approve(user, claim_id)
    return ClaimResponse.from_claim(claim)


@router.post("/{claim_id}/pay")
def pay_claim(claim_id: str, user: CurrentUser, service: Service) -> ClaimResponse:
    """Mark an approved claim as paid, as a finance approver."""
    with claim_errors_as_http():
        claim = service.pay(user, claim_id)
    return ClaimResponse.from_claim(claim)
