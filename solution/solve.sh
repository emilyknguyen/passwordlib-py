#!/bin/bash
set -euo pipefail

# Create the tracked_passwords subpackage
mkdir -p src/passwordlib/tracked_passwords

# --- __init__.py ---
cat > src/passwordlib/tracked_passwords/__init__.py << 'PYEOF'
# -*- coding=utf-8 -*-
r"""
Submodule to track password history per user.
"""
from .tracker import PasswordHistory, PasswordHistoryError
from .backends import HistoryBackend, InMemoryBackend
PYEOF

# --- backends.py ---
cat > src/passwordlib/tracked_passwords/backends.py << 'PYEOF'
# -*- coding=utf-8 -*-
r"""
Pluggable storage backends for password history tracking.
"""
import typing as t
from abc import ABC, abstractmethod
from collections import deque


class HistoryBackend(ABC):
    """Abstract interface for password history storage."""

    @abstractmethod
    def append(self, user_id: str, entry: bytes, max_size: int) -> None:
        """Store an entry, evicting the oldest if at capacity."""
        ...

    @abstractmethod
    def get_entries(self, user_id: str) -> t.List[bytes]:
        """Return all stored entries for a user (oldest first)."""
        ...

    @abstractmethod
    def size(self, user_id: str) -> int:
        """Return the number of stored entries for a user."""
        ...

    @abstractmethod
    def clear(self, user_id: str) -> None:
        """Remove all entries for a user."""
        ...


class InMemoryBackend(HistoryBackend):
    """Default in-memory backend using dict[str, deque]."""

    def __init__(self) -> None:
        self._store: t.Dict[str, deque] = {}

    def append(self, user_id: str, entry: bytes, max_size: int) -> None:
        if user_id not in self._store:
            self._store[user_id] = deque(maxlen=max_size)
        self._store[user_id].append(entry)

    def get_entries(self, user_id: str) -> t.List[bytes]:
        if user_id not in self._store:
            return []
        return list(self._store[user_id])

    def size(self, user_id: str) -> int:
        if user_id not in self._store:
            return 0
        return len(self._store[user_id])

    def clear(self, user_id: str) -> None:
        self._store.pop(user_id, None)
PYEOF

# --- similarity.py ---
cat > src/passwordlib/tracked_passwords/similarity.py << 'PYEOF'
# -*- coding=utf-8 -*-
r"""
Similarity detection and entry packing for tracked passwords.

Similarity works by generating normalized variants of a password (e.g.
lowercased, trailing digits/spaces stripped, leet-speak reversed), hashing
each variant, and storing them alongside the primary hash.  At check time
the same normalizations are applied to the candidate and compared against
the stored variant hashes.  Plaintext is never stored.
"""
import re
import struct
import typing as t


__all__ = ['generate_variants', 'pack_entry', 'unpack_entry']


_LEET_MAP: t.Dict[str, str] = {
    "@": "a", "4": "a",
    "3": "e",
    "1": "l", "!": "i",
    "0": "o",
    "$": "s", "5": "s",
    "7": "t",
}


def _reverse_leet(text: str) -> str:
    return "".join(_LEET_MAP.get(ch, ch) for ch in text).lower()


def generate_variants(password: t.AnyStr) -> t.List[bytes]:
    r"""
    Generate normalized variants of *password* for similarity detection.

    Returns a deduplicated list of variant byte strings. The original
    password itself is excluded from the list.
    """
    try:
        text = password.decode() if isinstance(password, bytes) else password
    except UnicodeDecodeError:
        return []

    variants: t.List[str] = []

    lowered = text.lower()
    if lowered != text:
        variants.append(lowered)

    no_trailing_digits = re.sub(r'\d+$', '', text)
    if no_trailing_digits and no_trailing_digits != text:
        variants.append(no_trailing_digits)

    stripped = text.strip()
    if stripped and stripped != text:
        variants.append(stripped)

    de_leeted = _reverse_leet(text)
    if de_leeted != text.lower():
        variants.append(de_leeted)

    seen: t.Set[str] = set()
    unique: t.List[bytes] = []
    for v in variants:
        if v not in seen:
            seen.add(v)
            unique.append(v.encode())
    return unique


# ---------------------------------------------------------------------------
# Entry packing
# ---------------------------------------------------------------------------
# Format:
#   [2 bytes big-endian uint16: count of sub-entries]
#   for each sub-entry:
#       [4 bytes big-endian uint32: length]
#       [length bytes: data]
# ---------------------------------------------------------------------------

def pack_entry(primary: bytes, variants: t.List[bytes]) -> bytes:
    r"""Pack a primary hash dump and its variant dumps into a single blob."""
    count = 1 + len(variants)
    parts: t.List[bytes] = [struct.pack('>H', count)]
    for item in [primary] + variants:
        parts.append(struct.pack('>I', len(item)))
        parts.append(item)
    return b''.join(parts)


def unpack_entry(data: bytes) -> t.Tuple[bytes, t.List[bytes]]:
    r"""
    Unpack a (possibly legacy) entry.

    Legacy entries (raw dumps without packing) are detected via a
    count-threshold heuristic and returned as ``(data, [])``.
    """
    if len(data) < 2:
        return data, []

    count = struct.unpack_from('>H', data, 0)[0]
    if count == 0 or count > 200:
        return data, []

    try:
        offset = 2
        entries: t.List[bytes] = []
        for _ in range(count):
            length = struct.unpack_from('>I', data, offset)[0]
            offset += 4
            entries.append(data[offset:offset + length])
            offset += length
        return entries[0], entries[1:]
    except (struct.error, IndexError):
        return data, []
PYEOF

# --- tracker.py ---
cat > src/passwordlib/tracked_passwords/tracker.py << 'PYEOF'
# -*- coding=utf-8 -*-
r"""
Password history tracker.

Stores a fixed-size list of previously used password hashes per user
and checks whether a candidate password matches (or is similar to)
any entry in the history.

Supports pluggable storage backends, thread-safe concurrent access,
input validation, error handling, and optional similarity detection.
"""
import threading
import typing as t

from ..core import hash_password, compare_password
from .backends import HistoryBackend, InMemoryBackend
from .similarity import generate_variants, pack_entry, unpack_entry


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
    :param similarity: enable similarity detection for
                       :meth:`is_password_similar`
    """

    def __init__(
        self,
        max_size: int = 5,
        *,
        backend: t.Optional[HistoryBackend] = None,
        similarity: bool = False,
    ):
        if max_size <= 0:
            raise ValueError("max_size must be a positive integer")
        self._max_size = max_size
        self._backend = backend or InMemoryBackend()
        self._similarity = similarity
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
            primary_hash = hash_password(password)
        except Exception as exc:
            raise PasswordHistoryError(f"Failed to hash password: {exc}") from exc

        if self._similarity:
            try:
                variant_hashes = [hash_password(v) for v in generate_variants(password)]
            except Exception as exc:
                raise PasswordHistoryError(
                    f"Failed to hash password variant: {exc}"
                ) from exc
            entry = pack_entry(primary_hash, variant_hashes)
        else:
            entry = primary_hash

        with self._lock:
            try:
                existing = self._backend.get_entries(user_id)
            except Exception as exc:
                raise PasswordHistoryError(
                    f"Failed to read history for user '{user_id}': {exc}"
                ) from exc

            for stored in existing:
                primary, _ = unpack_entry(stored)
                if compare_password(password, primary):
                    return

            try:
                self._backend.append(user_id, entry, self._max_size)
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
            primary, _ = unpack_entry(entry_data)
            if compare_password(password, primary):
                return True
        return False

    def is_password_similar(self, user_id: str, password: t.AnyStr) -> bool:
        r"""
        Check whether *password* is similar to any entry in history.
        Also returns ``True`` for exact matches.

        Requires ``similarity=True`` on construction.

        :raises RuntimeError: if similarity detection is not enabled
        :raises ValueError: if *user_id* or *password* is invalid
        :raises PasswordHistoryError: if reading history fails
        """
        if not self._similarity:
            raise RuntimeError(
                "Similarity detection is not enabled. "
                "Pass similarity=True to PasswordHistory()."
            )
        self._validate_user_id(user_id)
        self._validate_password(password)

        with self._lock:
            try:
                entries = self._backend.get_entries(user_id)
            except Exception as exc:
                raise PasswordHistoryError(
                    f"Failed to read history for user '{user_id}': {exc}"
                ) from exc

        candidate_variants = generate_variants(password)

        for entry_data in entries:
            primary, stored_variants = unpack_entry(entry_data)
            if compare_password(password, primary):
                return True
            for sv in stored_variants:
                if compare_password(password, sv):
                    return True
                for cv in candidate_variants:
                    if compare_password(cv, sv):
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
PYEOF

echo "solve.sh: tracked_passwords module created successfully"
