"""Tests for the claims JSON API: status codes, input checks and the approve-and-pay flow."""

import pytest
from fastapi.testclient import TestClient

from expenses_app.auth.token_validator import TokenClaims
from expenses_app.main import create_app
from tests.claim_helpers import EMPLOYEE, FINANCE_APPROVER, MANAGER, NO_ROLES, OTHER_EMPLOYEE

CLAIMS_ROUTE = "/api/claims"
VALID_SUBMISSION = {"amount": "12.5", "description": "Train ticket"}


@pytest.fixture
def client(settings, validator) -> TestClient:
    """A client for the app, trusting only the test signing key."""
    application = create_app(settings)
    application.state.token_validator = validator
    return TestClient(application)


@pytest.fixture
def call_as(client, token_for):
    """Send a request with a bearer token for the given user."""

    def _call_as(user: TokenClaims, method: str, path: str, **kwargs):
        headers = {"Authorization": f"Bearer {token_for(user)}"}
        return client.request(method, path, headers=headers, **kwargs)

    return _call_as


@pytest.fixture
def submitted_claim_id(call_as) -> str:
    """ID of a claim the employee has submitted."""
    return call_as(EMPLOYEE, "POST", CLAIMS_ROUTE, json=VALID_SUBMISSION).json()["claim_id"]


@pytest.fixture
def approved_claim_id(call_as, submitted_claim_id) -> str:
    """ID of a claim the employee submitted and the manager approved."""
    call_as(MANAGER, "POST", f"{CLAIMS_ROUTE}/{submitted_claim_id}/approve")
    return submitted_claim_id


class TestAuthentication:
    @pytest.mark.parametrize(
        ("method", "path"),
        [
            ("POST", CLAIMS_ROUTE),
            ("GET", CLAIMS_ROUTE),
            ("GET", f"{CLAIMS_ROUTE}/awaiting-approval"),
            ("GET", f"{CLAIMS_ROUTE}/awaiting-payment"),
            ("GET", f"{CLAIMS_ROUTE}/some-id"),
            ("POST", f"{CLAIMS_ROUTE}/some-id/approve"),
            ("POST", f"{CLAIMS_ROUTE}/some-id/pay"),
        ],
    )
    def test_every_route_needs_a_token(self, client, method, path):
        response = client.request(method, path, json=VALID_SUBMISSION)

        assert response.status_code == 401
        assert response.headers["www-authenticate"] == "Bearer"


class TestSubmit:
    def test_employee_submits_claim(self, call_as):
        response = call_as(EMPLOYEE, "POST", CLAIMS_ROUTE, json=VALID_SUBMISSION)

        body = response.json()
        assert response.status_code == 201
        assert body["owner_username"] == EMPLOYEE.username
        assert body["amount"] == "12.50"
        assert body["description"] == "Train ticket"
        assert body["status"] == "submitted"

    def test_response_does_not_reveal_keycloak_user_ids(self, call_as):
        response = call_as(EMPLOYEE, "POST", CLAIMS_ROUTE, json=VALID_SUBMISSION)

        assert EMPLOYEE.subject not in response.text

    def test_extra_fields_such_as_status_are_rejected(self, call_as):
        response = call_as(
            EMPLOYEE, "POST", CLAIMS_ROUTE, json={**VALID_SUBMISSION, "status": "paid"}
        )

        assert response.status_code == 422

    def test_unacceptable_amount_gives_400_with_reason(self, call_as):
        response = call_as(
            EMPLOYEE, "POST", CLAIMS_ROUTE, json={**VALID_SUBMISSION, "amount": "-5"}
        )

        assert response.status_code == 400
        assert "Amount" in response.json()["detail"]

    def test_amount_that_is_not_a_number_gives_422(self, call_as):
        response = call_as(
            EMPLOYEE, "POST", CLAIMS_ROUTE, json={**VALID_SUBMISSION, "amount": "lots"}
        )

        assert response.status_code == 422

    def test_user_without_employee_role_gets_403(self, call_as):
        response = call_as(NO_ROLES, "POST", CLAIMS_ROUTE, json=VALID_SUBMISSION)

        assert response.status_code == 403
        assert response.json() == {"detail": "Insufficient permissions"}


class TestRead:
    def test_list_shows_only_own_claims(self, call_as, submitted_claim_id):
        call_as(OTHER_EMPLOYEE, "POST", CLAIMS_ROUTE, json=VALID_SUBMISSION)

        response = call_as(EMPLOYEE, "GET", CLAIMS_ROUTE)

        assert [claim["claim_id"] for claim in response.json()] == [submitted_claim_id]

    def test_owner_can_get_their_claim(self, call_as, submitted_claim_id):
        response = call_as(EMPLOYEE, "GET", f"{CLAIMS_ROUTE}/{submitted_claim_id}")

        assert response.status_code == 200
        assert response.json()["claim_id"] == submitted_claim_id

    def test_other_employee_gets_same_404_as_unknown_id(self, call_as, submitted_claim_id):
        other_users_claim = call_as(OTHER_EMPLOYEE, "GET", f"{CLAIMS_ROUTE}/{submitted_claim_id}")
        unknown_claim = call_as(OTHER_EMPLOYEE, "GET", f"{CLAIMS_ROUTE}/unknown")

        assert other_users_claim.status_code == unknown_claim.status_code == 404
        assert other_users_claim.json() == unknown_claim.json()

    @pytest.mark.parametrize(
        ("user", "path", "expected_status"),
        [
            (MANAGER, "awaiting-approval", 200),
            (EMPLOYEE, "awaiting-approval", 403),
            (FINANCE_APPROVER, "awaiting-payment", 200),
            (MANAGER, "awaiting-payment", 403),
        ],
        ids=["manager-approvals", "employee-approvals", "finance-payments", "manager-payments"],
    )
    def test_work_lists_need_the_right_role(self, call_as, user, path, expected_status):
        response = call_as(user, "GET", f"{CLAIMS_ROUTE}/{path}")

        assert response.status_code == expected_status


class TestApproveAndPay:
    def test_manager_approves_submitted_claim(self, call_as, submitted_claim_id):
        response = call_as(MANAGER, "POST", f"{CLAIMS_ROUTE}/{submitted_claim_id}/approve")

        assert response.status_code == 200
        assert response.json()["status"] == "approved"

    def test_employee_cannot_approve_own_claim(self, call_as, submitted_claim_id):
        response = call_as(EMPLOYEE, "POST", f"{CLAIMS_ROUTE}/{submitted_claim_id}/approve")

        assert response.status_code == 403

    def test_approving_twice_gives_409(self, call_as, approved_claim_id):
        response = call_as(MANAGER, "POST", f"{CLAIMS_ROUTE}/{approved_claim_id}/approve")

        assert response.status_code == 409

    def test_finance_approver_pays_approved_claim(self, call_as, approved_claim_id):
        response = call_as(FINANCE_APPROVER, "POST", f"{CLAIMS_ROUTE}/{approved_claim_id}/pay")

        assert response.status_code == 200
        assert response.json()["status"] == "paid"

    def test_paying_unapproved_claim_gives_409(self, call_as, submitted_claim_id):
        response = call_as(FINANCE_APPROVER, "POST", f"{CLAIMS_ROUTE}/{submitted_claim_id}/pay")

        assert response.status_code == 409

    def test_manager_cannot_pay(self, call_as, approved_claim_id):
        response = call_as(MANAGER, "POST", f"{CLAIMS_ROUTE}/{approved_claim_id}/pay")

        assert response.status_code == 403

    def test_actions_cannot_be_triggered_with_get(self, call_as, submitted_claim_id):
        response = call_as(MANAGER, "GET", f"{CLAIMS_ROUTE}/{submitted_claim_id}/approve")

        assert response.status_code == 405
