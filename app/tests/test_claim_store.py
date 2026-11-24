"""Tests for ClaimStore: claims are kept, found and changed only when they should be."""

import threading
from dataclasses import replace
from datetime import timedelta

import pytest

from expenses_app.claims.models import ClaimStatus
from expenses_app.claims.store import ClaimStore
from tests.claim_helpers import EMPLOYEE, OTHER_EMPLOYEE, START_TIME, make_claim

THREAD_COUNT = 20
THREAD_TIMEOUT_SECONDS = 10


@pytest.fixture
def store() -> ClaimStore:
    return ClaimStore()


class TestAddAndGet:
    def test_added_claim_can_be_found(self, store):
        claim = make_claim()

        store.add(claim)

        assert store.get(claim.claim_id) == claim

    def test_get_returns_none_for_unknown_id(self, store):
        assert store.get("unknown") is None

    def test_adding_same_id_twice_raises_and_keeps_first_claim(self, store):
        first_claim = make_claim()
        store.add(first_claim)

        with pytest.raises(ValueError):
            store.add(replace(first_claim, description="Replacement"))

        assert store.get(first_claim.claim_id) == first_claim


class TestLists:
    def test_list_by_owner_returns_only_their_claims_oldest_first(self, store):
        newer_claim = make_claim("newer", submitted_at=START_TIME + timedelta(hours=1))
        older_claim = make_claim("older", submitted_at=START_TIME)
        store.add(newer_claim)
        store.add(older_claim)
        store.add(make_claim("someone-else", owner=OTHER_EMPLOYEE))

        claims = store.list_by_owner(EMPLOYEE.subject)

        assert claims == [older_claim, newer_claim]

    def test_list_by_status_returns_only_that_status_oldest_first(self, store):
        newer_claim = make_claim("newer", status=ClaimStatus.APPROVED, submitted_at=START_TIME)
        older_claim = make_claim(
            "older", status=ClaimStatus.APPROVED, submitted_at=START_TIME - timedelta(hours=1)
        )
        store.add(newer_claim)
        store.add(older_claim)
        store.add(make_claim("submitted", status=ClaimStatus.SUBMITTED))

        claims = store.list_by_status(ClaimStatus.APPROVED)

        assert claims == [older_claim, newer_claim]


class TestReplaceIfStatus:
    def test_replaces_claim_when_status_matches(self, store):
        claim = make_claim()
        store.add(claim)
        approved_claim = replace(claim, status=ClaimStatus.APPROVED)

        was_replaced = store.replace_if_status(approved_claim, ClaimStatus.SUBMITTED)

        assert was_replaced is True
        assert store.get(claim.claim_id) == approved_claim

    def test_refuses_when_status_has_changed(self, store):
        claim = make_claim(status=ClaimStatus.APPROVED)
        store.add(claim)

        was_replaced = store.replace_if_status(
            replace(claim, status=ClaimStatus.APPROVED, description="Changed"),
            ClaimStatus.SUBMITTED,
        )

        assert was_replaced is False
        assert store.get(claim.claim_id) == claim

    def test_refuses_unknown_claim_and_does_not_add_it(self, store):
        claim = make_claim()

        was_replaced = store.replace_if_status(claim, ClaimStatus.SUBMITTED)

        assert was_replaced is False
        assert store.get(claim.claim_id) is None

    def test_only_one_of_many_simultaneous_changes_wins(self, store):
        claim = make_claim(status=ClaimStatus.APPROVED)
        store.add(claim)
        paid_claim = replace(claim, status=ClaimStatus.PAID)
        start_together = threading.Barrier(THREAD_COUNT)
        results = []

        def try_to_pay() -> None:
            start_together.wait()
            results.append(store.replace_if_status(paid_claim, ClaimStatus.APPROVED))

        threads = [threading.Thread(target=try_to_pay, daemon=True) for _ in range(THREAD_COUNT)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=THREAD_TIMEOUT_SECONDS)

        assert results.count(True) == 1
        assert results.count(False) == THREAD_COUNT - 1
