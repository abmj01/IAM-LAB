"""Every access decision about claims, in one place.

Phase 4 decides by role only. Phase 5 moves these decisions to Open Policy Agent and adds
business rules, such as "nobody approves their own claim". Only this file will change then.
"""

from enum import Enum

from expenses_app.auth.token_validator import TokenClaims
from expenses_app.claims.models import Claim

ROLE_EMPLOYEE = "employee"
ROLE_MANAGER = "manager"
ROLE_FINANCE_APPROVER = "finance-approver"


class Action(str, Enum):
    """Things a user can try to do with claims."""

    SUBMIT = "submit"
    VIEW = "view"
    APPROVE = "approve"
    PAY = "pay"


def is_allowed(user: TokenClaims, action: Action, claim: Claim | None = None) -> bool:
    """Decide whether a user may perform an action.

    Anything not explicitly allowed is denied.

    Args:
        user: The verified user.
        action: What they want to do.
        claim: The claim it concerns. Needed for ``VIEW``. For ``APPROVE`` and ``PAY`` it may
            be left out, to ask "may this user approve or pay claims at all?".

    Returns:
        True if allowed.
    """
    if action is Action.SUBMIT:
        return user.has_role(ROLE_EMPLOYEE)
    if action is Action.VIEW:
        return claim is not None and (
            claim.owner_subject == user.subject
            or user.has_role(ROLE_MANAGER)
            or user.has_role(ROLE_FINANCE_APPROVER)
        )
    if action is Action.APPROVE:
        return user.has_role(ROLE_MANAGER)
    if action is Action.PAY:
        return user.has_role(ROLE_FINANCE_APPROVER)
    return False
