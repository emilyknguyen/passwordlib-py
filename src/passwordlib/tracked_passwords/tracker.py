# -*- coding=utf-8 -*-
r"""
Password history tracker.

Stores a fixed-size list of previously used password hashes per user
and checks whether a candidate password matches any entry in the history.

Supports pluggable storage backends, thread-safe concurrent access,
input validation, and error handling.
"""
import threading
import typing as t

from ..core import hash_password, compare_password
from .backends import HistoryBackend, InMemoryBackend


class PasswordHistoryError(Exception):
    """Raised when a password history operation fails."""


class PasswordHistory:
    r"""
    Track password history for multiple users.

        history = PasswordHistory(max_size=5)
        history.add_password("alice", "secret1")
        history.is_password_used("alice", "secret1")  # True
        history.is_password_used("alice", "other")    # False

    When the history for a user exceeds *max_size*, the oldest entry is
    automatically discarded.

    :param max_size: maximum passwords to retain per user
    :param backend: a :class:`HistoryBackend` (defaults to in-memory)
    """

    def __init__(
        self,
        max_size: int = 5,
        *,
        backend: t.Optional[HistoryBackend] = None,
    ):
        if max_size <= 0:
            raise ValueError("max_size must be a positive integer")
        self._max_size = max_size
        self._backend = backend or InMemoryBackend()
        self._lock = threading.Lock()

    @property
    def max_size(self) -> int:
        return self._max_size

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_user_id(user_id: str) -> None:
        if not isinstance(user_id, str) or not user_id:
            raise ValueError("user_id must be a non-empty string")
        if user_id.strip() == "":
            raise ValueError("user_id must not be whitespace-only")

    @staticmethod
    def _validate_password(password: t.AnyStr) -> None:
        if password is None:
            raise ValueError("password must not be None")
        if not isinstance(password, (str, bytes)):
            raise TypeError("password must be str or bytes")
        if len(password) == 0:
            raise ValueError("password must not be empty")
        if isinstance(password, str) and password.strip() == "":
            raise ValueError("password must not be whitespace-only")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_password(self, user_id: str, password: t.AnyStr) -> None:
        r"""
        Hash *password* and append it to the history for *user_id*.

        If the password already exists in the history it is **not** added
        again, preventing duplicate entries from concurrent writes.

        :raises ValueError: if *user_id* or *password* is invalid
        :raises PasswordHistoryError: if hashing or storage fails
        """
        self._validate_user_id(user_id)
        self._validate_password(password)

        try:
            hashed = hash_password(password)
        except Exception as exc:
            raise PasswordHistoryError(f"Failed to hash password: {exc}") from exc

        with self._lock:
            try:
                existing = self._backend.get_entries(user_id)
            except Exception as exc:
                raise PasswordHistoryError(
                    f"Failed to read history for user '{user_id}': {exc}"
                ) from exc

            for stored in existing:
                if compare_password(password, stored):
                    return

            try:
                self._backend.append(user_id, hashed, self._max_size)
            except Exception as exc:
                raise PasswordHistoryError(
                    f"Failed to store password for user '{user_id}': {exc}"
                ) from exc

    def is_password_used(self, user_id: str, password: t.AnyStr) -> bool:
        r"""
        Check whether *password* exactly matches any entry in history.

        Uses the algorithm, iterations, and salt embedded in each stored
        hash — so passwords hashed with different algorithms are still
        verified correctly.

        :raises ValueError: if *user_id* or *password* is invalid
        :raises PasswordHistoryError: if reading history fails
        """
        self._validate_user_id(user_id)
        self._validate_password(password)

        with self._lock:
            try:
                entries = self._backend.get_entries(user_id)
            except Exception as exc:
                raise PasswordHistoryError(
                    f"Failed to read history for user '{user_id}': {exc}"
                ) from exc

        for entry_data in entries:
            if compare_password(password, entry_data):
                return True
        return False

    def get_history_size(self, user_id: str) -> int:
        r"""
        Return the number of passwords stored for *user_id*.

        :raises PasswordHistoryError: if reading history fails
        """
        with self._lock:
            try:
                return self._backend.size(user_id)
            except Exception as exc:
                raise PasswordHistoryError(
                    f"Failed to read history size for user '{user_id}': {exc}"
                ) from exc

    def clear_history(self, user_id: str) -> None:
        r"""
        Remove all stored password history for *user_id*.

        :raises PasswordHistoryError: if clearing history fails
        """
        with self._lock:
            try:
                self._backend.clear(user_id)
            except Exception as exc:
                raise PasswordHistoryError(
                    f"Failed to clear history for user '{user_id}': {exc}"
                ) from exc
