"""Gives FastAPI routes the claim service created at startup."""

from fastapi import Request

from expenses_app.claims.service import ClaimService


def get_claim_service(request: Request) -> ClaimService:
    """Return the claim service created at startup."""
    return request.app.state.claim_service
