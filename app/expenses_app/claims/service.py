"""The claim use cases: submit, view, approve and pay.

Every use case checks the input, asks ``policy`` whether the user may act, then updates the
store. Pages and the API both call this module, so the rules exist once. It doesn't import
FastAPI: callers turn the errors below into HTTP answers.
"""

import logging
import uuid
from collections.abc import Callable
from dataclasses import replace
from datetime import datetime, timezone
from decimal import Decimal

from expenses_app.auth.token_validator import TokenClaims
from expenses_app.claims.models import Claim, ClaimStatus
from expenses_app.claims.policy import Action, is_allowed
from expenses_app.claims.store import ClaimStore

logger = logging.getLogger(__name__)

MAX_AMOUNT = Decimal("10000.00")
MAX_DESCRIPTION_LENGTH = 200


class ClaimError(Exception):
    """Base class for every error a use case raises."""


class InvalidClaimError(ClaimError):
    """The input is wrong, e.g. a negative amount. Safe to show to the user (HTTP 400)."""


class ClaimNotFoundError(ClaimError):
    """The claim doesn't exist, or the user may not see it (HTTP 404).

    Both cases give the same error, so nobody can find out which claim IDs exist.
    """


class ClaimForbiddenError(ClaimError):
    """The user may see the claim but not do this to it (HTTP 403)."""


class ClaimStatusConflictError(ClaimError):
    """The claim isn't in the right status, e.g. paying an unapproved claim (HTTP 409)."""


class ClaimService:
    """Runs the claim use cases for a verified user."""

    def __init__(
        self,
        store: ClaimStore,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        """Prepare the service.

        Args:
            store: Where claims are kept.
            clock: Returns the current UTC time. Tests pass a fixed one.
        """
        self._store = store
        self._clock = clock

    def submit(self, user: TokenClaims, amount: Decimal, description: str) -> Claim:
        """Submit a new claim for the user.

        Raises:
            ClaimForbiddenError: If the user isn't an employee.
            InvalidClaimError: If the amount or description is not acceptable.
        """
        self._require(user, Action.SUBMIT)
        claim = Claim(
            claim_id=str(uuid.uuid4()),
            owner_subject=user.subject,
            owner_username=user.username,
            amount=_checked_amount(amount),
            description=_checked_description(description),
            status=ClaimStatus.SUBMITTED,
            submitted_at=self._clock(),
        )
        self._store.add(claim)
        logger.info("Claim %s submitted by %s", claim.claim_id, user.username)
        return claim

    def get(self, user: TokenClaims, claim_id: str) -> Claim:
        """Return one claim the user may see.

        Raises:
            ClaimNotFoundError: If it doesn't exist or the user may not see it.
        """
        claim = self._store.get(claim_id)
        if claim is None or not is_allowed(user, Action.VIEW, claim):
            raise ClaimNotFoundError(claim_id)
        return claim

    def list_own(self, user: TokenClaims) -> list[Claim]:
        """Return the user's own claims, oldest first."""
        return self._store.list_by_owner(user.subject)

    def list_awaiting_approval(self, user: TokenClaims) -> list[Claim]:
        """Return submitted claims, for managers.

        Raises:
            ClaimForbiddenError: If the user may not approve claims.
        """
        self._require(user, Action.APPROVE)
        return self._store.list_by_status(ClaimStatus.SUBMITTED)

    def list_awaiting_payment(self, user: TokenClaims) -> list[Claim]:
        """Return approved claims, for finance approvers.

        Raises:
            ClaimForbiddenError: If the user may not pay claims.
        """
        self._require(user, Action.PAY)
        return self._store.list_by_status(ClaimStatus.APPROVED)

    def approve(self, user: TokenClaims, claim_id: str) -> Claim:
        """Approve a submitted claim.

        Raises:
            ClaimNotFoundError: If it doesn't exist or the user may not see it.
            ClaimForbiddenError: If the user may not approve it.
            ClaimStatusConflictError: If it isn't waiting for approval.
        """
        claim = self.get(user, claim_id)
        self._require(user, Action.APPROVE, claim)
        approved_claim = replace(claim, status=ClaimStatus.APPROVED, approved_by=user.subject)
        self._save_transition(approved_claim, expected_status=ClaimStatus.SUBMITTED)
        logger.info("Claim %s approved by %s", claim_id, user.username)
        return approved_claim

    def pay(self, user: TokenClaims, claim_id: str) -> Claim:
        """Mark an approved claim as paid.

        Raises:
            ClaimNotFoundError: If it doesn't exist or the user may not see it.
            ClaimForbiddenError: If the user may not pay it.
            ClaimStatusConflictError: If it isn't approved, or is already paid.
        """
        claim = self.get(user, claim_id)
        self._require(user, Action.PAY, claim)
        paid_claim = replace(claim, status=ClaimStatus.PAID, paid_by=user.subject)
        self._save_transition(paid_claim, expected_status=ClaimStatus.APPROVED)
        logger.info("Claim %s paid by %s", claim_id, user.username)
        return paid_claim

    def _require(self, user: TokenClaims, action: Action, claim: Claim | None = None) -> None:
        """Raise ``ClaimForbiddenError`` unless the policy allows the action."""
        if not is_allowed(user, action, claim):
            logger.warning("Denied %s for %s", action.value, user.username)
            raise ClaimForbiddenError(action.value)

    def _save_transition(self, updated_claim: Claim, expected_status: ClaimStatus) -> None:
        """Store the new status, unless someone changed the claim first."""
        if not self._store.replace_if_status(updated_claim, expected_status):
            raise ClaimStatusConflictError(updated_claim.claim_id)


def _checked_amount(amount: Decimal) -> Decimal:
    """Return the amount if it's a positive number of euros and cents, up to the maximum."""
    if not amount.is_finite():
        raise InvalidClaimError("Amount must be a number")
    if amount <= 0 or amount > MAX_AMOUNT:
        raise InvalidClaimError(f"Amount must be more than 0 and at most {MAX_AMOUNT}")
    if amount.as_tuple().exponent < -2:
        raise InvalidClaimError("Amount can have at most 2 decimal places")
    return amount.quantize(Decimal("0.01"))


def _checked_description(description: str) -> str:
    """Return the description without surrounding spaces, if it's not empty or too long."""
    cleaned_description = description.strip()
    if not cleaned_description:
        raise InvalidClaimError("Description is required")
    if len(cleaned_description) > MAX_DESCRIPTION_LENGTH:
        raise InvalidClaimError(f"Description can be at most {MAX_DESCRIPTION_LENGTH} characters")
    return cleaned_description
