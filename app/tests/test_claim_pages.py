"""Tests for the claim pages: what each user sees, the forms, and the browser protections."""

import re
import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from expenses_app.auth.token_validator import TokenClaims
from expenses_app.claims.models import ClaimStatus
from expenses_app.main import create_app
from tests.claim_helpers import EMPLOYEE, FINANCE_APPROVER, MANAGER, OTHER_EMPLOYEE

APP_ORIGIN = "http://localhost:8000"
SAME_ORIGIN = {"Origin": APP_ORIGIN}
CLAIM_DESCRIPTION = "Hotel night for the Utrecht audit"
VALID_FORM = {"amount": "12.5", "description": CLAIM_DESCRIPTION}
CLAIM_ID_PATTERN = re.compile(r"/claims/([0-9a-f-]{36})/(?:approve|pay)")


@pytest.fixture
def application(settings, validator) -> FastAPI:
    """The app, trusting only the test signing key."""
    application = create_app(settings)
    application.state.token_validator = validator
    return application


@pytest.fixture
def browser_for(application, token_for):
    """Open a separate browser, with its own cookies, logged in as the given user."""

    def _browser_for(user: TokenClaims) -> TestClient:
        browser = TestClient(application, follow_redirects=False)
        session_id = application.state.session_store.create(
            subject=user.subject,
            username=user.username,
            access_token=token_for(user),
            refresh_token="test-refresh-token",
            id_token="test-id-token",
            access_token_expires_at=time.time() + 3600,
        )
        browser.cookies.set(application.state.settings.session_cookie_name, session_id)
        return browser

    return _browser_for


@pytest.fixture
def visitor(application) -> TestClient:
    return TestClient(application, follow_redirects=False)


@pytest.fixture
def submitted_claim_id(application, browser_for) -> str:
    """ID of a claim the employee submitted through the form."""
    browser_for(EMPLOYEE).post("/claims", data=VALID_FORM, headers=SAME_ORIGIN)
    return application.state.claim_service.list_own(EMPLOYEE)[0].claim_id


def claim_status(application: FastAPI, claim_id: str) -> ClaimStatus:
    return application.state.claim_service.get(MANAGER, claim_id).status


class TestLoginRequired:
    @pytest.mark.parametrize("path", ["/claims", "/approvals", "/payments"])
    def test_visitor_is_sent_to_login(self, visitor, path):
        response = visitor.get(path)

        assert response.status_code == 303
        assert response.headers["location"] == "/auth/login"

    def test_visitor_form_post_is_sent_to_login(self, visitor):
        response = visitor.post("/claims", data=VALID_FORM, headers=SAME_ORIGIN)

        assert response.headers["location"] == "/auth/login"


class TestNavigation:
    @pytest.mark.parametrize(
        ("user", "shows_approvals", "shows_payments"),
        [(EMPLOYEE, False, False), (MANAGER, True, False), (FINANCE_APPROVER, False, True)],
        ids=lambda value: getattr(value, "username", value),
    )
    def test_links_follow_the_policy(self, browser_for, user, shows_approvals, shows_payments):
        page = browser_for(user).get("/").text

        assert ('href="/approvals"' in page) is shows_approvals
        assert ('href="/payments"' in page) is shows_payments


class TestMyClaims:
    def test_submitting_the_form_stores_claim_and_redirects_with_notice(
        self, application, browser_for
    ):
        response = browser_for(EMPLOYEE).post("/claims", data=VALID_FORM, headers=SAME_ORIGIN)

        assert response.status_code == 303
        assert response.headers["location"] == "/claims?notice=submitted"
        assert len(application.state.claim_service.list_own(EMPLOYEE)) == 1

    def test_claims_page_lists_own_claims_and_the_notice(self, browser_for, submitted_claim_id):
        page = browser_for(EMPLOYEE).get("/claims?notice=submitted").text

        assert "Your claim was submitted." in page
        assert "€12.50" in page
        assert CLAIM_DESCRIPTION in page

    def test_other_employee_does_not_see_the_claim(self, browser_for, submitted_claim_id):
        page = browser_for(OTHER_EMPLOYEE).get("/claims").text

        assert CLAIM_DESCRIPTION not in page

    def test_wrong_amount_shows_form_again_with_reason_and_input(self, browser_for):
        response = browser_for(EMPLOYEE).post(
            "/claims", data={"amount": "abc", "description": "Lunch"}, headers=SAME_ORIGIN
        )

        assert response.status_code == 400
        assert "Amount must be a number" in response.text
        assert 'value="Lunch"' in response.text

    def test_description_is_shown_as_text_not_html(self, browser_for):
        browser = browser_for(EMPLOYEE)
        browser.post(
            "/claims",
            data={"amount": "5", "description": "<script>alert(1)</script>"},
            headers=SAME_ORIGIN,
        )

        page = browser.get("/claims").text

        assert "<script>" not in page
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page

    def test_unknown_notice_key_shows_nothing(self, browser_for):
        page = browser_for(EMPLOYEE).get("/claims?notice=<b>fake</b>").text

        assert "fake" not in page


class TestApprovalsAndPayments:
    def test_manager_sees_approve_button_and_approves(
        self, application, browser_for, submitted_claim_id
    ):
        browser = browser_for(MANAGER)

        page = browser.get("/approvals").text
        response = browser.post(f"/claims/{submitted_claim_id}/approve", headers=SAME_ORIGIN)

        assert CLAIM_ID_PATTERN.findall(page) == [submitted_claim_id]
        assert response.headers["location"] == "/approvals?notice=approved"
        assert claim_status(application, submitted_claim_id) is ClaimStatus.APPROVED

    def test_approving_an_already_approved_claim_shows_conflict_notice(
        self, browser_for, submitted_claim_id
    ):
        browser = browser_for(MANAGER)
        browser.post(f"/claims/{submitted_claim_id}/approve", headers=SAME_ORIGIN)

        response = browser.post(f"/claims/{submitted_claim_id}/approve", headers=SAME_ORIGIN)

        assert response.headers["location"] == "/approvals?notice=conflict"

    def test_finance_approver_pays_approved_claim(
        self, application, browser_for, submitted_claim_id
    ):
        browser_for(MANAGER).post(f"/claims/{submitted_claim_id}/approve", headers=SAME_ORIGIN)

        response = browser_for(FINANCE_APPROVER).post(
            f"/claims/{submitted_claim_id}/pay", headers=SAME_ORIGIN
        )

        assert response.headers["location"] == "/payments?notice=paid"
        assert claim_status(application, submitted_claim_id) is ClaimStatus.PAID

    @pytest.mark.parametrize(
        ("user", "path"),
        [(EMPLOYEE, "/approvals"), (EMPLOYEE, "/payments"), (MANAGER, "/payments")],
        ids=["employee-approvals", "employee-payments", "manager-payments"],
    )
    def test_work_pages_show_403_page_without_the_role(self, browser_for, user, path):
        response = browser_for(user).get(path)

        assert response.status_code == 403
        assert "Not allowed" in response.text

    def test_employee_approving_own_claim_gets_403_page(
        self, application, browser_for, submitted_claim_id
    ):
        response = browser_for(EMPLOYEE).post(
            f"/claims/{submitted_claim_id}/approve", headers=SAME_ORIGIN
        )

        assert response.status_code == 403
        assert claim_status(application, submitted_claim_id) is ClaimStatus.SUBMITTED

    def test_other_employee_acting_on_a_claim_gets_404_page(self, browser_for, submitted_claim_id):
        response = browser_for(OTHER_EMPLOYEE).post(
            f"/claims/{submitted_claim_id}/approve", headers=SAME_ORIGIN
        )

        assert response.status_code == 404
        assert "Claim not found" in response.text


class TestCrossSiteProtection:
    @pytest.mark.parametrize(
        ("headers", "expected_status"),
        [
            ({"Origin": APP_ORIGIN}, 303),
            ({"Referer": f"{APP_ORIGIN}/claims"}, 303),
            ({"Origin": "https://evil.example"}, 403),
            ({"Origin": "null"}, 403),
            ({"Referer": "http://localhost:8000.evil.example/claims"}, 403),
            ({}, 403),
        ],
        ids=[
            "same-origin",
            "same-site-referer",
            "other-site",
            "null-origin",
            "lookalike-referer",
            "no-origin-or-referer",
        ],
    )
    def test_form_post_is_accepted_only_from_own_pages(
        self, application, browser_for, headers, expected_status
    ):
        response = browser_for(EMPLOYEE).post("/claims", data=VALID_FORM, headers=headers)

        stored_claims = application.state.claim_service.list_own(EMPLOYEE)
        assert response.status_code == expected_status
        assert len(stored_claims) == (1 if expected_status == 303 else 0)

    def test_cross_site_approval_is_blocked_and_changes_nothing(
        self, application, browser_for, submitted_claim_id
    ):
        response = browser_for(MANAGER).post(
            f"/claims/{submitted_claim_id}/approve", headers={"Origin": "https://evil.example"}
        )

        assert response.status_code == 403
        assert claim_status(application, submitted_claim_id) is ClaimStatus.SUBMITTED


class TestSecurityHeaders:
    @pytest.mark.parametrize("path", ["/", "/claims", "/no-such-page"])
    def test_pages_get_strict_security_headers(self, browser_for, settings, path):
        response = browser_for(EMPLOYEE).get(path)

        policy = response.headers["content-security-policy"]
        assert "default-src 'none'" in policy
        assert "frame-ancestors 'none'" in policy
        assert f"form-action 'self' {settings.keycloak_public_url}" in policy
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["x-content-type-options"] == "nosniff"
