# -*- coding=utf-8 -*-
r"""
Tests for the tracked_passwords module.

Tests are organized by requirement from pw_tracking_instructions.md and
verify observable behavior without coupling to implementation details.
"""
import threading
import typing as t
import unittest


# ===================================================================
# Basic password reuse detection
# ===================================================================


class TestPasswordReuse(unittest.TestCase):
    """A stored password must be detected; an unstored one must not."""

    def setUp(self):
        from passwordlib.tracked_passwords import PasswordHistory

        self.history = PasswordHistory(max_size=5)

    def test_stored_password_is_detected(self):
        self.history.add_password("alice", "secret")
        self.assertTrue(self.history.is_password_used("alice", "secret"))

    def test_unstored_password_is_not_detected(self):
        self.history.add_password("alice", "secret")
        self.assertFalse(self.history.is_password_used("alice", "other"))

    def test_unknown_user_returns_false(self):
        self.assertFalse(self.history.is_password_used("nobody", "anything"))

    def test_multiple_passwords_all_detected(self):
        for pw in ("p1", "p2", "p3"):
            self.history.add_password("alice", pw)
        for pw in ("p1", "p2", "p3"):
            self.assertTrue(self.history.is_password_used("alice", pw))
        self.assertFalse(self.history.is_password_used("alice", "p4"))

    def test_users_are_isolated(self):
        self.history.add_password("alice", "onlyalice")
        self.history.add_password("bob", "onlybob")
        self.assertFalse(self.history.is_password_used("bob", "onlyalice"))
        self.assertFalse(self.history.is_password_used("alice", "onlybob"))

    def test_eviction_drops_oldest(self):
        h = self._make_history(max_size=2)
        h.add_password("u", "first")
        h.add_password("u", "second")
        h.add_password("u", "third")
        self.assertFalse(h.is_password_used("u", "first"))
        self.assertTrue(h.is_password_used("u", "second"))
        self.assertTrue(h.is_password_used("u", "third"))

    def test_clear_removes_all(self):
        self.history.add_password("alice", "pw")
        self.history.clear_history("alice")
        self.assertFalse(self.history.is_password_used("alice", "pw"))
        self.assertEqual(self.history.get_history_size("alice"), 0)

    def test_clear_unknown_user_no_error(self):
        self.history.clear_history("ghost")  # must not raise

    def test_history_size_tracks_additions(self):
        self.assertEqual(self.history.get_history_size("alice"), 0)
        self.history.add_password("alice", "a")
        self.assertEqual(self.history.get_history_size("alice"), 1)
        self.history.add_password("alice", "b")
        self.assertEqual(self.history.get_history_size("alice"), 2)

    def test_bytes_password(self):
        self.history.add_password("alice", b"raw_bytes")
        self.assertTrue(self.history.is_password_used("alice", b"raw_bytes"))
        self.assertFalse(self.history.is_password_used("alice", b"other"))

    def test_default_max_size(self):
        from passwordlib.tracked_passwords import PasswordHistory

        self.assertEqual(PasswordHistory().max_size, 5)

    def _make_history(self, **kwargs):
        from passwordlib.tracked_passwords import PasswordHistory

        return PasswordHistory(**kwargs)


# ===================================================================
# Input validation
# ===================================================================


class TestInputValidation(unittest.TestCase):
    """Invalid inputs must be rejected before touching storage."""

    def setUp(self):
        from passwordlib.tracked_passwords import PasswordHistory

        self.history = PasswordHistory(max_size=5)

    def test_none_password_rejected(self):
        with self.assertRaises((ValueError, TypeError)):
            self.history.add_password("alice", None)

    def test_empty_string_rejected(self):
        with self.assertRaises(ValueError):
            self.history.add_password("alice", "")

    def test_empty_bytes_rejected(self):
        with self.assertRaises(ValueError):
            self.history.add_password("alice", b"")

    def test_whitespace_only_password_rejected(self):
        with self.assertRaises(ValueError):
            self.history.add_password("alice", "   ")

    def test_wrong_password_type_rejected(self):
        with self.assertRaises(TypeError):
            self.history.add_password("alice", 12345)

    def test_none_user_id_rejected(self):
        with self.assertRaises((ValueError, TypeError)):
            self.history.add_password(None, "secret")

    def test_empty_user_id_rejected(self):
        with self.assertRaises(ValueError):
            self.history.add_password("", "secret")

    def test_whitespace_only_user_id_rejected(self):
        with self.assertRaises(ValueError):
            self.history.add_password("   ", "secret")

    def test_invalid_max_size_rejected(self):
        from passwordlib.tracked_passwords import PasswordHistory

        with self.assertRaises(ValueError):
            PasswordHistory(max_size=0)
        with self.assertRaises(ValueError):
            PasswordHistory(max_size=-1)

    def test_check_also_validates_password(self):
        with self.assertRaises((ValueError, TypeError)):
            self.history.is_password_used("alice", None)
        with self.assertRaises(ValueError):
            self.history.is_password_used("alice", "")

    def test_check_also_validates_user_id(self):
        with self.assertRaises(ValueError):
            self.history.is_password_used("", "secret")


# ===================================================================
# Pluggable storage backends
# ===================================================================


class TestPluggableBackend(unittest.TestCase):
    """PasswordHistory must work with any conforming backend."""

    def test_custom_backend_is_used(self):
        from passwordlib.tracked_passwords import HistoryBackend, PasswordHistory

        class ListBackend(HistoryBackend):
            def __init__(self):
                self._store: t.Dict[str, t.List[bytes]] = {}

            def append(self, user_id, entry, max_size):
                lst = self._store.setdefault(user_id, [])
                lst.append(entry)
                while len(lst) > max_size:
                    lst.pop(0)

            def get_entries(self, user_id):
                return list(self._store.get(user_id, []))

            def size(self, user_id):
                return len(self._store.get(user_id, []))

            def clear(self, user_id):
                self._store.pop(user_id, None)

        h = PasswordHistory(max_size=3, backend=ListBackend())
        h.add_password("u", "pw1")
        h.add_password("u", "pw2")
        self.assertTrue(h.is_password_used("u", "pw1"))
        self.assertEqual(h.get_history_size("u"), 2)

    def test_default_backend_without_explicit_arg(self):
        from passwordlib.tracked_passwords import PasswordHistory

        h = PasswordHistory()
        h.add_password("u", "pw")
        self.assertTrue(h.is_password_used("u", "pw"))


# ===================================================================
# Error handling
# ===================================================================


class TestErrorHandling(unittest.TestCase):
    """Backend failures must surface as PasswordHistoryError with cause."""

    def _make_failing_history(self, **overrides):
        from passwordlib.tracked_passwords import HistoryBackend, PasswordHistory

        methods = dict(
            append=lambda *a: None,
            get_entries=lambda *a: [],
            size=lambda *a: 0,
            clear=lambda *a: None,
        )
        methods.update(overrides)

        backend = type("Bad", (HistoryBackend,), methods)()
        return PasswordHistory(max_size=5, backend=backend)

    def test_append_failure(self):
        from passwordlib.tracked_passwords import PasswordHistoryError

        def boom(*a):
            raise IOError("disk full")

        h = self._make_failing_history(append=boom)
        with self.assertRaises(PasswordHistoryError) as ctx:
            h.add_password("u", "pw")
        self.assertIsInstance(ctx.exception.__cause__, IOError)

    def test_get_entries_failure(self):
        from passwordlib.tracked_passwords import PasswordHistoryError

        def boom(*a):
            raise IOError("conn lost")

        h = self._make_failing_history(get_entries=boom)
        with self.assertRaises(PasswordHistoryError):
            h.is_password_used("u", "pw")

    def test_size_failure(self):
        from passwordlib.tracked_passwords import PasswordHistoryError

        def boom(*a):
            raise IOError("timeout")

        h = self._make_failing_history(size=boom)
        with self.assertRaises(PasswordHistoryError):
            h.get_history_size("u")

    def test_clear_failure(self):
        from passwordlib.tracked_passwords import PasswordHistoryError

        def boom(*a):
            raise IOError("denied")

        h = self._make_failing_history(clear=boom)
        with self.assertRaises(PasswordHistoryError):
            h.clear_history("u")


# ===================================================================
# Concurrent reads and writes
# ===================================================================


class TestConcurrency(unittest.TestCase):
    """Concurrent operations must not corrupt state or crash."""

    def test_parallel_adds_no_crash(self):
        from passwordlib.tracked_passwords import PasswordHistory

        h = PasswordHistory(max_size=50)
        errors: t.List[Exception] = []
        barrier = threading.Barrier(8)

        def worker(tid):
            try:
                barrier.wait()
                for i in range(5):
                    h.add_password("shared", f"t{tid}_p{i}")
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()

        self.assertEqual(errors, [])
        self.assertGreater(h.get_history_size("shared"), 0)

    def test_parallel_add_and_check_no_crash(self):
        from passwordlib.tracked_passwords import PasswordHistory

        h = PasswordHistory(max_size=20)
        h.add_password("u", "seed")
        errors: t.List[Exception] = []

        def adder():
            try:
                for i in range(5):
                    h.add_password("u", f"new_{i}")
            except Exception as exc:
                errors.append(exc)

        def checker():
            try:
                for _ in range(5):
                    h.is_password_used("u", "seed")
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=adder) for _ in range(4)] + [
            threading.Thread(target=checker) for _ in range(4)
        ]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        self.assertEqual(errors, [])

    def test_duplicate_password_not_stored_twice(self):
        from passwordlib.tracked_passwords import PasswordHistory

        h = PasswordHistory(max_size=10)
        barrier = threading.Barrier(4)
        errors: t.List[Exception] = []

        def worker():
            try:
                barrier.wait()
                h.add_password("u", "same")
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()

        self.assertEqual(errors, [])
        self.assertEqual(h.get_history_size("u"), 1)


# ===================================================================
# Similarity detection
# ===================================================================


class TestSimilarityDetection(unittest.TestCase):
    """Similar (not just identical) passwords must be flagged."""

    def setUp(self):
        from passwordlib.tracked_passwords import PasswordHistory

        self.history = PasswordHistory(max_size=5, similarity=True)

    def test_case_variant_detected(self):
        self.history.add_password("u", "Password1")
        self.assertTrue(self.history.is_password_similar("u", "password1"))

    def test_trailing_digits_detected(self):
        self.history.add_password("u", "mypass123")
        self.assertTrue(self.history.is_password_similar("u", "mypass"))

    def test_trailing_spaces_detected(self):
        # "hello  " has trailing spaces — its stripped form "hello" should
        # be detected as similar
        self.history.add_password("u", "hello  ")
        self.assertTrue(self.history.is_password_similar("u", "hello"))
        # The original exact form must also still work
        self.assertTrue(self.history.is_password_used("u", "hello  "))

    def test_leet_speak_detected(self):
        self.history.add_password("u", "p@$$w0rd")
        self.assertTrue(self.history.is_password_similar("u", "password"))

    def test_exact_match_also_detected(self):
        self.history.add_password("u", "exact")
        self.assertTrue(self.history.is_password_similar("u", "exact"))

    def test_unrelated_password_not_flagged(self):
        self.history.add_password("u", "apple")
        self.assertFalse(self.history.is_password_similar("u", "orange"))

    def test_exact_check_ignores_variants(self):
        self.history.add_password("u", "Password1")
        self.assertTrue(self.history.is_password_used("u", "Password1"))
        self.assertFalse(self.history.is_password_used("u", "password1"))

    def test_similarity_disabled_raises(self):
        from passwordlib.tracked_passwords import PasswordHistory

        h = PasswordHistory(max_size=5, similarity=False)
        h.add_password("u", "pw")
        with self.assertRaises(RuntimeError):
            h.is_password_similar("u", "pw")


# ===================================================================
# Algorithm-agnostic rehashing
# ===================================================================


class TestAlgorithmRehashing(unittest.TestCase):
    """Passwords hashed with different algorithms must still verify."""

    def test_verify_across_algorithm_change(self):
        """Store a password under one default algorithm, change the
        default, then verify the old password still matches."""
        from passwordlib import config
        from passwordlib.tracked_passwords import PasswordHistory

        h = PasswordHistory(max_size=5)
        original_algo = config.DEFAULT_ALGORITHM

        # Store under current default
        h.add_password("u", "crosscheck")

        # Flip default to a different algorithm
        try:
            config.DEFAULT_ALGORITHM = "sha512" if original_algo != "sha512" else "sha1"
            # New password stored with the new algorithm
            h.add_password("u", "newhash")
            # Old password must still verify against its original algorithm
            self.assertTrue(h.is_password_used("u", "crosscheck"))
            self.assertTrue(h.is_password_used("u", "newhash"))
            self.assertFalse(h.is_password_used("u", "wrong"))
        finally:
            config.DEFAULT_ALGORITHM = original_algo

    def test_two_algorithms_same_password_both_verify(self):
        """The same password hashed with different algorithms must each
        be independently verifiable."""
        from passwordlib import config
        from passwordlib.tracked_passwords import PasswordHistory

        original_algo = config.DEFAULT_ALGORITHM
        h = PasswordHistory(max_size=5)

        h.add_password("u", "mypassword")
        try:
            config.DEFAULT_ALGORITHM = "sha512" if original_algo != "sha512" else "sha1"
            # add_password deduplicates by exact match — but the same
            # plaintext hashed with a different algorithm produces a
            # different dump, so it should be added as a new entry
            h.add_password("u", "mypassword")
        finally:
            config.DEFAULT_ALGORITHM = original_algo

        # Must still verify regardless of current default
        self.assertTrue(h.is_password_used("u", "mypassword"))


# ===================================================================
# Regression tests
# ===================================================================


class TestRegressions(unittest.TestCase):
    """Guard against specific bugs that were caught during development."""

    def test_none_password_does_not_reach_hasher(self):
        """Regression: None used to slip through to hashlib and crash."""
        from passwordlib.tracked_passwords import PasswordHistory

        h = PasswordHistory(max_size=5)
        with self.assertRaises((ValueError, TypeError)):
            h.add_password("u", None)
        # History must be untouched
        self.assertEqual(h.get_history_size("u"), 0)

    def test_empty_password_does_not_reach_hasher(self):
        """Regression: empty string was silently hashed and stored."""
        from passwordlib.tracked_passwords import PasswordHistory

        h = PasswordHistory(max_size=5)
        with self.assertRaises(ValueError):
            h.add_password("u", "")
        self.assertEqual(h.get_history_size("u"), 0)

    def test_concurrent_same_password_produces_single_entry(self):
        """Regression: duplicate add from two threads stored the password
        twice, wasting a history slot."""
        from passwordlib.tracked_passwords import PasswordHistory

        h = PasswordHistory(max_size=10)
        barrier = threading.Barrier(4)

        def worker():
            barrier.wait()
            h.add_password("u", "dup")

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        self.assertEqual(h.get_history_size("u"), 1)

    def test_backend_error_wraps_original_cause(self):
        """Regression: raw backend exceptions leaked to callers instead
        of being wrapped in PasswordHistoryError."""
        from passwordlib.tracked_passwords import (
            HistoryBackend,
            PasswordHistory,
            PasswordHistoryError,
        )

        class BadBackend(HistoryBackend):
            def append(self, *a):
                raise ConnectionError("db down")

            def get_entries(self, *a):
                return []

            def size(self, *a):
                return 0

            def clear(self, *a):
                pass

        h = PasswordHistory(max_size=5, backend=BadBackend())
        with self.assertRaises(PasswordHistoryError) as ctx:
            h.add_password("u", "pw")
        self.assertIsInstance(ctx.exception.__cause__, ConnectionError)

    def test_whitespace_password_does_not_store(self):
        """Regression: whitespace-only passwords were silently accepted."""
        from passwordlib.tracked_passwords import PasswordHistory

        h = PasswordHistory(max_size=5)
        with self.assertRaises(ValueError):
            h.add_password("u", "   \t  ")
        self.assertEqual(h.get_history_size("u"), 0)

    def test_eviction_does_not_lose_recent_passwords(self):
        """Regression: verify that eviction only drops the oldest entry
        and retains all others up to max_size."""
        from passwordlib.tracked_passwords import PasswordHistory

        h = PasswordHistory(max_size=3)
        for i in range(5):
            h.add_password("u", f"pw{i}")
        self.assertEqual(h.get_history_size("u"), 3)
        # Only the two oldest should be gone
        self.assertFalse(h.is_password_used("u", "pw0"))
        self.assertFalse(h.is_password_used("u", "pw1"))
        self.assertTrue(h.is_password_used("u", "pw2"))
        self.assertTrue(h.is_password_used("u", "pw3"))
        self.assertTrue(h.is_password_used("u", "pw4"))


# ===================================================================
# Behavioral invariants with random data
# ===================================================================


class TestBehavioralInvariants(unittest.TestCase):
    """Properties that must hold for any password, not just specific strings."""

    def test_add_then_find_roundtrip(self):
        """Any valid password that is added must be found."""
        import os
        import string

        from passwordlib.tracked_passwords import PasswordHistory

        h = PasswordHistory(max_size=10)
        # Generate a random password that can't be hardcoded
        pw = os.urandom(12).hex()
        h.add_password("u", pw)
        self.assertTrue(h.is_password_used("u", pw))

    def test_never_added_never_found(self):
        """A password that was never added must never be found."""
        import os

        from passwordlib.tracked_passwords import PasswordHistory

        h = PasswordHistory(max_size=10)
        h.add_password("u", os.urandom(12).hex())
        # A different random password must not match
        self.assertFalse(h.is_password_used("u", os.urandom(12).hex()))

    def test_eviction_preserves_most_recent(self):
        """After N additions to a size-K history, the K most recent
        passwords must be found and the rest must not."""
        import os

        from passwordlib.tracked_passwords import PasswordHistory

        k = 3
        passwords = [os.urandom(8).hex() for _ in range(k + 4)]
        h = PasswordHistory(max_size=k)
        for pw in passwords:
            h.add_password("u", pw)

        # Most recent k must be found
        for pw in passwords[-k:]:
            self.assertTrue(
                h.is_password_used("u", pw), f"Recent password should be found"
            )
        # Older ones must not
        for pw in passwords[:-k]:
            self.assertFalse(
                h.is_password_used("u", pw), f"Evicted password should not be found"
            )

    def test_similarity_detects_case_from_mixed_to_lower(self):
        """Storing a mixed-case password and checking its lowercase
        form must be detected as similar."""
        from passwordlib.tracked_passwords import PasswordHistory

        h = PasswordHistory(max_size=5, similarity=True)
        h.add_password("u", "MySecret")
        self.assertTrue(h.is_password_similar("u", "mysecret"))

    def test_different_passwords_not_similar(self):
        """Two completely unrelated random passwords must not be
        flagged as similar."""
        import os

        from passwordlib.tracked_passwords import PasswordHistory

        h = PasswordHistory(max_size=5, similarity=True)
        h.add_password("u", os.urandom(16).hex())
        self.assertFalse(h.is_password_similar("u", os.urandom(16).hex()))

    def test_validation_rejects_before_any_side_effect(self):
        """Invalid input must not modify history size at all."""
        from passwordlib.tracked_passwords import PasswordHistory

        h = PasswordHistory(max_size=5)
        h.add_password("u", "valid")
        size_before = h.get_history_size("u")

        for bad_input in [None, "", b"", "   ", 42]:
            try:
                h.add_password("u", bad_input)
            except (ValueError, TypeError):
                pass
        self.assertEqual(h.get_history_size("u"), size_before)


if __name__ == "__main__":
    unittest.main()
