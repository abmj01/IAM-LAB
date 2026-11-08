"""Keeps login sessions on the server, so tokens never reach the browser.

The browser only holds a random session ID in a cookie. The ID is a key into this store,
where the user's tokens live. Sessions are kept in memory, so they are lost on restart and
are not shared between app instances. Production would use something like Redis.

This module only stores sessions: reading cookies and refreshing tokens belong in the login
code. Never log a session ID or a token, because either one lets the reader act as the user.
"""

import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field, replace


@dataclass(frozen=True)
class Session:
    """The data kept on the server for one logged-in user.

    Attributes:
        subject: Keycloak's permanent user ID (``sub``).
        username: Human-readable login name, e.g. ``ryan.landry``.
        access_token: Sent to the API. Hidden from ``repr`` so logs can't leak it.
        refresh_token: Gets new tokens from Keycloak. Hidden from ``repr``.
        id_token: Sent to Keycloak as the logout hint. Hidden from ``repr``.
        access_token_expires_at: When the access token expires, in Unix time (seconds).
        session_expires_at: When this session ends, in Unix time (seconds).
    """

    subject: str
    username: str
    access_token: str = field(repr=False)
    refresh_token: str = field(repr=False)
    id_token: str = field(repr=False)
    access_token_expires_at: float
    session_expires_at: float


class SessionStore:
    """Holds sessions in memory, safely shared between request threads.

    FastAPI runs normal ``def`` routes in several threads, so every read or change of the
    sessions happens while holding the lock.
    """

    def __init__(self, lifetime_seconds: int, clock: Callable[[], float] = time.time) -> None:
        """Prepare an empty store.

        Args:
            lifetime_seconds: How long a session lasts after login.
            clock: Returns the current Unix time. Tests pass a fake one, so they can test
                expiry without waiting.
        """
        self._lifetime_seconds = lifetime_seconds
        self._clock = clock
        self._sessions: dict[str, Session] = {}
        self._lock = threading.Lock()

    def create(
        self,
        *,
        subject: str,
        username: str,
        access_token: str,
        refresh_token: str,
        id_token: str,
        access_token_expires_at: float,
    ) -> str:
        """Start a new session after a successful login.

        A new ID is generated for every login, and one sent by the browser is never reused.
        This prevents session fixation, where an attacker gets a victim to log in with an ID
        the attacker already knows.

        Args:
            subject: Keycloak's permanent user ID (``sub``).
            username: Human-readable login name.
            access_token: The user's access token.
            refresh_token: The user's refresh token.
            id_token: The user's ID token.
            access_token_expires_at: When the access token expires, in Unix time (seconds).

        Returns:
            The new session ID, to be placed in the browser's cookie.
        """
        session_id = secrets.token_urlsafe(32)

        with self._lock:
            self._remove_expired()
            self._sessions[session_id] = Session(
                subject=subject,
                username=username,
                access_token=access_token,
                refresh_token=refresh_token,
                id_token=id_token,
                access_token_expires_at=access_token_expires_at,
                session_expires_at=self._clock() + self._lifetime_seconds,
            )

        return session_id

    def get(self, session_id: str) -> Session | None:
        """Look up an active session.

        Args:
            session_id: The ID from the browser's cookie.

        Returns:
            The session, or None if the ID is unknown or the session has expired. Callers
            don't need to know which, because the user must log in either way.
        """
        with self._lock:
            return self._find_active(session_id)

    def update_tokens(
        self,
        session_id: str,
        *,
        access_token: str,
        refresh_token: str,
        id_token: str,
        access_token_expires_at: float,
    ) -> bool:
        """Store new tokens after a refresh.

        The session's own expiry stays unchanged, or refreshing would keep it alive forever.

        Args:
            session_id: The ID of the session to update.
            access_token: The new access token.
            refresh_token: The new refresh token.
            id_token: The new ID token.
            access_token_expires_at: When the new access token expires, in Unix time (seconds).

        Returns:
            True if the tokens were stored. False if the session no longer exists, so a
            refresh that finishes late can't bring back a logged-out user.
        """
        with self._lock:
            session = self._find_active(session_id)
            if session is None:
                return False

            self._sessions[session_id] = replace(
                session,
                access_token=access_token,
                refresh_token=refresh_token,
                id_token=id_token,
                access_token_expires_at=access_token_expires_at,
            )
            return True

    def delete(self, session_id: str) -> None:
        """End a session at logout. Deleting an unknown session is not an error.

        Args:
            session_id: The ID of the session to end.
        """
        with self._lock:
            self._sessions.pop(session_id, None)

    def _find_active(self, session_id: str) -> Session | None:
        """Return a session if it is still active, deleting it if expired.

        The caller must already hold the lock.
        """
        session = self._sessions.get(session_id)
        if session is None:
            return None

        if self._clock() >= session.session_expires_at:
            del self._sessions[session_id]
            return None

        return session

    def _remove_expired(self) -> None:
        """Delete every expired session, so memory can't keep growing.

        The caller must already hold the lock. A ``threading.Lock`` can't be taken twice by
        the same thread, so taking it here would freeze the app.
        """
        now = self._clock()
        expired_ids = [
            session_id
            for session_id, session in self._sessions.items()
            if now >= session.session_expires_at
        ]
        for session_id in expired_ids:
            del self._sessions[session_id]
