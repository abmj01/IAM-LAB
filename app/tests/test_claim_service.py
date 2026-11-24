"""Tests for ClaimService: input checks, who may act, and the order claims move through."""

import logging
import threading
from decimal import Decimal

import pytest

from expenses_app.claims.models import ClaimStatus
from expenses_app.claims.service import (
    MAX_DESCRIPTION_LENGTH,
    ClaimForbiddenError,
    ClaimNotFoundError,
    ClaimService,
    ClaimStatusConflictError,
    InvalidClaimError,
)
from expenses_app.claims.store import ClaimStore
from tests.claim_helpers import (
    EMPLOYEE,
    FINANCE_APPROVER,
    MANAGER,
    NO_ROLES,
    OTHER_EMPLOYEE,
    START_TIME,
    FakeClock,
)

SERVICE_LOGGER = "expenses_app.claims.service"
THREAD_COUNT = 20
THREAD_TIMEOUT_SECONDS = 10


@pytest.fixture
def store() -> ClaimStore:
    return ClaimStore()


@pytest.fixture
def service(store) -> ClaimService:
    return ClaimService(store, clock=FakeClock())


def submit(service: ClaimService, amount: str = "12.50", description: str = "Train ticket"):
    """Submit a claim as the employee."""
    return service.submit(EMPLOYEE, Decimal(amount), description)


def approved_claim(service: ClaimService):
    """Submit a claim as the employee and have the manager approve it."""
    return service.approve(MANAGER, submit(service).claim_id)


class TestSubmit:
    def test_employee_submits_claim_with_owner_status_and_time(self, service, store):
        claim = service.submit(EMPLOYEE, Decimal("12.5"), "  Train ticket  ")

        assert store.get(claim.claim_id) == claim
        assert claim.owner_subject == EMPLOYEE.subject
        assert claim.owner_username == EMPLOYEE.username
        assert claim.status is ClaimStatus.SUBMITTED
        assert claim.submitted_at == START_TIME
        assert claim.amount == Decimal("12.50")
        assert claim.description == "Train ticket"

    def test_each_claim_gets_a_different_random_id(self, service):
        first_claim = submit(service)
        second_claim = submit(service)

        assert first_claim.claim_id != second_claim.claim_id
        assert len(first_claim.claim_id) == 36

    def test_user_without_employee_role_cannot_submit(self, service, store):
        with pytest.raises(ClaimForbiddenError):
            service.submit(NO_ROLES, Decimal("10"), "Lunch")

        assert store.list_by_owner(NO_ROLES.subject) == []

    @pytest.mark.parametrize("amount", ["0", "-1", "10000.01", "1.001", "NaN", "Infinity"])
    def test_unacceptable_amount_is_rejected(self, service, amount):
        with pytest.raises(InvalidClaimError):
            submit(service, amount=amount)

    def test_maximum_amount_is_accepted(self, service):
        assert submit(service, amount="10000.00").amount == Decimal("10000.00")

    @pytest.mark.parametrize("description", ["", "   ", "x" * (MAX_DESCRIPTION_LENGTH + 1)])
    def test_empty_or_too_long_description_is_rejected(self, service, description):
        with pytest.raises(InvalidClaimError):
            submit(service, description=description)

    def test_description_of_maximum_length_is_accepted(self, service):
        description = "x" * MAX_DESCRIPTION_LENGTH

        assert submit(service, description=description).description == description


class TestGetAndList:
    @pytest.mark.parametrize(
        "user", [EMPLOYEE, MANAGER, FINANCE_APPROVER], ids=lambda u: u.username
    )
    def test_owner_manager_and_finance_can_see_a_claim(self, service, user):
        claim = submit(service)

        assert service.get(user, claim.claim_id) == claim

    def test_other_employee_gets_same_error_as_for_unknown_id(self, service):
        claim = submit(service)

        with pytest.raises(ClaimNotFoundError):
            service.get(OTHER_EMPLOYEE, claim.claim_id)
        with pytest.raises(ClaimNotFoundError):
            service.get(MANAGER, "unknown")

    def test_list_own_returns_only_the_users_claims_oldest_first(self, service):
        first_claim = submit(service)
        service.submit(OTHER_EMPLOYEE, Decimal("5"), "Coffee")
        second_claim = submit(service)

        assert service.list_own(EMPLOYEE) == [first_claim, second_claim]

    def test_manager_sees_only_submitted_claims_awaiting_approval(self, service):
        waiting_claim = submit(service)
        approved_claim(service)

        assert service.list_awaiting_approval(MANAGER) == [waiting_claim]

    def test_finance_sees_only_approved_claims_awaiting_payment(self, service):
        submit(service)
        waiting_claim = approved_claim(service)

        assert service.list_awaiting_payment(FINANCE_APPROVER) == [waiting_claim]

    @pytest.mark.parametrize(
        ("user", "list_method"),
        [
            (EMPLOYEE, "list_awaiting_approval"),
            (FINANCE_APPROVER, "list_awaiting_approval"),
            (EMPLOYEE, "list_awaiting_payment"),
            (MANAGER, "list_awaiting_payment"),
        ],
    )
    def test_work_lists_are_refused_without_the_role(self, service, user, list_method):
        with pytest.raises(ClaimForbiddenError):
            getattr(service, list_method)(user)


class TestApprove:
    def test_manager_approves_submitted_claim(self, service, store):
        claim = submit(service)

        approved = service.approve(MANAGER, claim.claim_id)

        assert approved.status is ClaimStatus.APPROVED
        assert approved.approved_by == MANAGER.subject
        assert store.get(claim.claim_id) == approved

    def test_employee_cannot_approve_own_claim(self, service, store):
        claim = submit(service)

        with pytest.raises(ClaimForbiddenError):
            service.approve(EMPLOYEE, claim.claim_id)

        assert store.get(claim.claim_id).status is ClaimStatus.SUBMITTED

    def test_other_employee_cannot_even_find_the_claim(self, service):
        claim = submit(service)

        with pytest.raises(ClaimNotFoundError):
            service.approve(OTHER_EMPLOYEE, claim.claim_id)

    def test_approving_twice_is_a_conflict(self, service):
        claim = approved_claim(service)

        with pytest.raises(ClaimStatusConflictError):
            service.approve(MANAGER, claim.claim_id)

    def test_paid_claim_cannot_be_approved_again(self, service):
        claim = service.pay(FINANCE_APPROVER, approved_claim(service).claim_id)

        with pytest.raises(ClaimStatusConflictError):
            service.approve(MANAGER, claim.claim_id)


class TestPay:
    def test_finance_approver_pays_approved_claim(self, service, store):
        claim = approved_claim(service)

        paid = service.pay(FINANCE_APPROVER, claim.claim_id)

        assert paid.status is ClaimStatus.PAID
        assert paid.paid_by == FINANCE_APPROVER.subject
        assert paid.approved_by == MANAGER.subject
        assert store.get(claim.claim_id) == paid

    def test_unapproved_claim_cannot_be_paid(self, service):
        claim = submit(service)

        with pytest.raises(ClaimStatusConflictError):
            service.pay(FINANCE_APPROVER, claim.claim_id)

    def test_manager_cannot_pay(self, service):
        claim = approved_claim(service)

        with pytest.raises(ClaimForbiddenError):
            service.pay(MANAGER, claim.claim_id)

    def test_paying_twice_is_a_conflict(self, service):
        claim = service.pay(FINANCE_APPROVER, approved_claim(service).claim_id)

        with pytest.raises(ClaimStatusConflictError):
            service.pay(FINANCE_APPROVER, claim.claim_id)

    def test_claim_is_paid_only_once_when_many_pay_at_the_same_moment(self, service):
        claim = approved_claim(service)
        start_together = threading.Barrier(THREAD_COUNT)
        results = []

        def try_to_pay() -> None:
            start_together.wait()
            try:
                service.pay(FINANCE_APPROVER, claim.claim_id)
                results.append("paid")
            except ClaimStatusConflictError:
                results.append("conflict")

        threads = [threading.Thread(target=try_to_pay, daemon=True) for _ in range(THREAD_COUNT)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=THREAD_TIMEOUT_SECONDS)

        assert results.count("paid") == 1
        assert results.count("conflict") == THREAD_COUNT - 1


class TestAuditLog:
    def test_approval_and_payment_are_logged_with_who_did_them(self, service, caplog):
        caplog.set_level(logging.INFO, logger=SERVICE_LOGGER)
        claim = approved_claim(service)
        service.pay(FINANCE_APPROVER, claim.claim_id)

        messages = [record.getMessage() for record in caplog.records]

        assert f"Claim {claim.claim_id} approved by {MANAGER.username}" in messages
        assert f"Claim {claim.claim_id} paid by {FINANCE_APPROVER.username}" in messages

    def test_denied_action_is_logged_as_warning(self, service, caplog):
        claim = submit(service)

        with pytest.raises(ClaimForbiddenError):
            service.approve(EMPLOYEE, claim.claim_id)

        warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
        assert f"Denied approve for {EMPLOYEE.username}" in warnings
