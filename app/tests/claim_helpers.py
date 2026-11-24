"""Test users and a claim factory shared by the claims tests.

Each user has one clear job, so a test shows which role made the difference. All data is
made up.
"""

from datetime import datetime, timedelta, timezone
from decimal import Decimal

from expenses_app.auth.token_validator import TokenClaims
from expenses_app.claims.models import Claim, ClaimStatus

EMPLOYEE = TokenClaims("sub-eve", "eve.employee", ("employee",))
OTHER_EMPLOYEE = TokenClaims("sub-oscar", "oscar.other", ("employee",))
MANAGER = TokenClaims("sub-ryan", "ryan.manager", ("employee", "manager"))
FINANCE_APPROVER = TokenClaims("sub-fiona", "fiona.finance", ("employee", "finance-approver"))
NO_ROLES = TokenClaims("sub-nora", "nora.noroles", ())

START_TIME = datetime(2026, 11, 2, 9, 0, tzinfo=timezone.utc)


class FakeClock:
    """A clock that moves one minute forward each time it is read, so claims sort clearly."""

    def __init__(self, start: datetime = START_TIME) -> None:
        self.now = start

    def __call__(self) -> datetime:
        current_time = self.now
        self.now += timedelta(minutes=1)
        return current_time


def make_claim(
    claim_id: str = "claim-1",
    owner: TokenClaims = EMPLOYEE,
    status: ClaimStatus = ClaimStatus.SUBMITTED,
    submitted_at: datetime = START_TIME,
) -> Claim:
    """Build a claim directly, for tests that don't go through the service."""
    return Claim(
        claim_id=claim_id,
        owner_subject=owner.subject,
        owner_username=owner.username,
        amount=Decimal("12.50"),
        description="Train ticket",
        status=status,
        submitted_at=submitted_at,
    )
