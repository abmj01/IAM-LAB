"""Tests for SessionStore: sessions start, expire and end exactly when they should."""

import threading

import pytest

from expenses_app.auth.session_store import SessionStore

START_TIME = 1000.0
LIFETIME_SECONDS = 3600
SESSION_DATA = {
    "subject": "5801f676-bbf6-4150-8eab-d0878c28b58d",
    "username": "ryan.landry",
    "access_token": "access-token",
    "refresh_token": "refresh-token",
    "id_token": "id-token",
    "access_token_expires_at": START_TIME + 300,
}
NEW_TOKENS = {
    "access_token": "new-access-token",
    "refresh_token": "new-refresh-token",
    "id_token": "new-id-token",
    "access_token_expires_at": START_TIME + 600,
}
THREAD_COUNT = 8
OPERATIONS_PER_THREAD = 200
THREAD_TIMEOUT_SECONDS = 10


class FakeClock:
    """A clock that only moves when a test tells it to."""

    def __init__(self, now: float) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock(START_TIME)


@pytest.fixture
def store(clock) -> SessionStore:
    return SessionStore(LIFETIME_SECONDS, clock=clock)


class TestCreate:
    def test_new_session_can_be_found_with_correct_data(self, store):
        session_id = store.create(**SESSION_DATA)

        session = store.get(session_id)

        assert session.subject == SESSION_DATA["subject"]
        assert session.username == SESSION_DATA["username"]
        assert session.access_token == SESSION_DATA["access_token"]
        assert session.refresh_token == SESSION_DATA["refresh_token"]
        assert session.id_token == SESSION_DATA["id_token"]
        assert session.access_token_expires_at == SESSION_DATA["access_token_expires_at"]

    def test_two_logins_by_same_user_get_different_session_ids(self, store):
        first_session_id = store.create(**SESSION_DATA)
        second_session_id = store.create(**SESSION_DATA)

        assert first_session_id != second_session_id

    def test_new_session_expires_at_current_time_plus_lifetime(self, store):
        session_id = store.create(**SESSION_DATA)

        assert store.get(session_id).session_expires_at == START_TIME + LIFETIME_SECONDS


class TestGet:
    def test_get_returns_none_for_unknown_session_id(self, store):
        assert store.get("unknown") is None

    def test_session_just_before_expiry_can_be_retrieved(self, store, clock):
        session_id = store.create(**SESSION_DATA)

        clock.advance(LIFETIME_SECONDS - 1)

        assert store.get(session_id) is not None

    def test_session_at_expiry_returns_none_and_is_removed(self, store, clock):
        session_id = store.create(**SESSION_DATA)

        clock.advance(LIFETIME_SECONDS)

        assert store.get(session_id) is None
        assert session_id not in store._sessions


class TestTokensUpdate:
    def test_updating_active_session_stores_new_tokens(self, store):
        session_id = store.create(**SESSION_DATA)

        was_updated = store.update_tokens(session_id, **NEW_TOKENS)

        updated_session = store.get(session_id)
        assert was_updated is True
        assert updated_session.access_token == NEW_TOKENS["access_token"]
        assert updated_session.refresh_token == NEW_TOKENS["refresh_token"]
        assert updated_session.id_token == NEW_TOKENS["id_token"]
        assert updated_session.access_token_expires_at == NEW_TOKENS["access_token_expires_at"]

    def test_updating_tokens_does_not_change_session_expiry(self, store, clock):
        session_id = store.create(**SESSION_DATA)
        clock.advance(LIFETIME_SECONDS / 2)

        store.update_tokens(session_id, **NEW_TOKENS)

        assert store.get(session_id).session_expires_at == START_TIME + LIFETIME_SECONDS

    def test_updating_unknown_session_returns_false(self, store):
        assert store.update_tokens("unknown", **NEW_TOKENS) is False

    def test_updating_expired_session_returns_false(self, store, clock):
        session_id = store.create(**SESSION_DATA)
        clock.advance(LIFETIME_SECONDS)

        assert store.update_tokens(session_id, **NEW_TOKENS) is False

    def test_updating_logged_out_session_does_not_bring_it_back(self, store):
        session_id = store.create(**SESSION_DATA)
        store.delete(session_id)

        was_updated = store.update_tokens(session_id, **NEW_TOKENS)

        assert was_updated is False
        assert store.get(session_id) is None


class TestDelete:
    def test_deleted_session_can_no_longer_be_found(self, store):
        session_id = store.create(**SESSION_DATA)

        store.delete(session_id)

        assert store.get(session_id) is None

    def test_deleting_twice_or_unknown_id_raises_no_error(self, store):
        session_id = store.create(**SESSION_DATA)

        store.delete(session_id)
        store.delete(session_id)
        store.delete("unknown")


class TestCleanup:
    def test_create_removes_expired_sessions_and_keeps_active_ones(self, store, clock):
        expiring_session_id = store.create(**SESSION_DATA)
        clock.advance(LIFETIME_SECONDS / 2)
        active_session_id = store.create(**SESSION_DATA)
        clock.advance(LIFETIME_SECONDS / 2)

        store.create(**SESSION_DATA)

        assert expiring_session_id not in store._sessions
        assert active_session_id in store._sessions


class TestSecurityAndThreads:
    def test_printing_session_does_not_show_tokens(self, store):
        session_id = store.create(**SESSION_DATA)

        printed_session = repr(store.get(session_id))

        assert SESSION_DATA["access_token"] not in printed_session
        assert SESSION_DATA["refresh_token"] not in printed_session
        assert SESSION_DATA["id_token"] not in printed_session

    def test_concurrent_use_finishes_without_errors_or_leftover_sessions(self, store):
        errors = []

        def use_store() -> None:
            try:
                for _ in range(OPERATIONS_PER_THREAD):
                    session_id = store.create(**SESSION_DATA)
                    assert store.get(session_id) is not None
                    assert store.update_tokens(session_id, **NEW_TOKENS) is True
                    store.delete(session_id)
            except Exception as error:
                errors.append(error)

        threads = [threading.Thread(target=use_store, daemon=True) for _ in range(THREAD_COUNT)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=THREAD_TIMEOUT_SECONDS)

        assert not any(thread.is_alive() for thread in threads), "A thread is stuck: deadlock?"
        assert errors == []
        assert store._sessions == {}
