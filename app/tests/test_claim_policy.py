"""Tests for the claims policy: who may do what. Anything not allowed must be denied."""

import pytest

from expenses_app.claims.policy import Action, is_allowed
from tests.claim_helpers import (
    EMPLOYEE,
    FINANCE_APPROVER,
    MANAGER,
    NO_ROLES,
    OTHER_EMPLOYEE,
    make_claim,
)

EMPLOYEES_CLAIM = make_claim(owner=EMPLOYEE)


class TestRoleActions:
    @pytest.mark.parametrize(
        ("user", "action", "expected"),
        [
            (EMPLOYEE, Action.SUBMIT, True),
            (NO_ROLES, Action.SUBMIT, False),
            (MANAGER, Action.APPROVE, True),
            (EMPLOYEE, Action.APPROVE, False),
            (FINANCE_APPROVER, Action.APPROVE, False),
            (FINANCE_APPROVER, Action.PAY, True),
            (MANAGER, Action.PAY, False),
            (EMPLOYEE, Action.PAY, False),
        ],
        ids=lambda value: getattr(value, "username", value),
    )
    def test_role_decides_action(self, user, action, expected):
        assert is_allowed(user, action, EMPLOYEES_CLAIM) is expected
        assert is_allowed(user, action) is expected


class TestView:
    @pytest.mark.parametrize(
        ("user", "expected"),
        [
            (EMPLOYEE, True),
            (OTHER_EMPLOYEE, False),
            (MANAGER, True),
            (FINANCE_APPROVER, True),
            (NO_ROLES, False),
        ],
        ids=lambda value: getattr(value, "username", value),
    )
    def test_who_may_view_a_claim(self, user, expected):
        assert is_allowed(user, Action.VIEW, EMPLOYEES_CLAIM) is expected

    def test_view_without_a_claim_is_denied(self):
        assert is_allowed(MANAGER, Action.VIEW) is False


class TestDenyByDefault:
    def test_action_the_policy_does_not_know_is_denied(self):
        assert is_allowed(MANAGER, "delete", EMPLOYEES_CLAIM) is False
