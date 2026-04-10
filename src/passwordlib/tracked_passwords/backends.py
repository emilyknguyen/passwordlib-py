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
