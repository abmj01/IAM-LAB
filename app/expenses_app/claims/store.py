"""Keeps claims in memory. Storage only: it doesn't know who may do what.

Claims are lost on restart. Production would use a database, with the same compare-and-set
idea done as ``UPDATE ... WHERE status = ...``.
"""

import threading

from expenses_app.claims.models import Claim, ClaimStatus


class ClaimStore:
    """Holds claims in memory, safely shared between request threads."""

    def __init__(self) -> None:
        self._claims: dict[str, Claim] = {}
        self._lock = threading.Lock()

    def add(self, claim: Claim) -> None:
        """Store a new claim.

        Raises:
            ValueError: If a claim with the same ID already exists.
        """
        with self._lock:
            if claim.claim_id in self._claims:
                raise ValueError("Claim ID already exists")
            self._claims[claim.claim_id] = claim

    def get(self, claim_id: str) -> Claim | None:
        """Return the claim, or None if the ID is unknown."""
        with self._lock:
            return self._claims.get(claim_id)

    def list_by_owner(self, owner_subject: str) -> list[Claim]:
        """Return one employee's claims, oldest first."""
        with self._lock:
            claims = [
                claim for claim in self._claims.values() if claim.owner_subject == owner_subject
            ]
        return sorted(claims, key=lambda claim: claim.submitted_at)

    def list_by_status(self, status: ClaimStatus) -> list[Claim]:
        """Return all claims with the given status, oldest first."""
        with self._lock:
            claims = [claim for claim in self._claims.values() if claim.status == status]
        return sorted(claims, key=lambda claim: claim.submitted_at)

    def replace_if_status(self, updated_claim: Claim, expected_status: ClaimStatus) -> bool:
        """Swap in a changed claim, but only if the stored one still has the expected status.

        This is compare-and-set: the check and the swap happen under one lock. Without it,
        two finance approvers clicking "Pay" at the same moment could both see "approved"
        and pay the claim twice.

        Args:
            updated_claim: The new version of the claim.
            expected_status: The status the stored claim must still have.

        Returns:
            True if swapped. False if the claim is unknown or its status has changed.
        """
        with self._lock:
            stored_claim = self._claims.get(updated_claim.claim_id)
            if stored_claim is None or stored_claim.status != expected_status:
                return False
            self._claims[updated_claim.claim_id] = updated_claim
            return True
