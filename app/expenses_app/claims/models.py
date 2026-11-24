"""The data of an expense claim. Plain data only: the rules live in ``policy`` and ``service``."""

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from enum import Enum


class ClaimStatus(str, Enum):
    """Where a claim is in its life. It only moves forward: submitted → approved → paid."""

    SUBMITTED = "submitted"
    APPROVED = "approved"
    PAID = "paid"


@dataclass(frozen=True)
class Claim:
    """One expense claim.

    Frozen, so a claim read from the store can't be changed by accident. Changes go
    through the store, which swaps in a new copy.

    Attributes:
        claim_id: Random ID, so IDs can't be guessed by counting.
        owner_subject: Keycloak ``sub`` of the employee who submitted it.
        owner_username: Their login name, for display only.
        amount: In euros. ``Decimal``, never ``float``, because money must be exact.
        description: What the money was spent on.
        status: Where the claim is in its life.
        submitted_at: When it was submitted, in UTC.
        approved_by: Keycloak ``sub`` of the manager who approved it, once approved.
        paid_by: Keycloak ``sub`` of the finance approver who paid it, once paid.
    """

    claim_id: str
    owner_subject: str
    owner_username: str
    amount: Decimal
    description: str
    status: ClaimStatus
    submitted_at: datetime
    approved_by: str | None = None
    paid_by: str | None = None
