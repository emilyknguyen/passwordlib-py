# -*- coding=utf-8 -*-
r"""
Tests for the tracked_passwords module.

Tests are organized by requirement from instruction.md and verify
observable behavior without coupling to implementation details.

Design principles:
  - Prefer random / generated inputs over fixed strings so that a model
    cannot satisfy the tests by hardcoding expected outputs.
  - Where fixed strings are used (e.g. similarity smoke tests), pair them
    with random-data counterparts that test the same invariant.
  - Anti-gaming tests inspect backend storage to confirm that real hashing
    occurred and that plaintext is never stored.
"""
import hashlib
import os
import string
import threading
import typing as t
import unittest


# ===================================================================
# Helpers
# ===================================================================

def _random_password(length: int = 16) -> str:
    """Return a hex-encoded random password that cannot be predicted."""
    return os.urandom(length).hex()


def _random_password_with_upper(length: int = 8) -> str:
    """Return a random password guaranteed to have mixed case.
    The result will differ from its .lower() form."""
    # Use hex for the body, then prepend an uppercase ASCII letter
    body = os.urandom(length).hex()
    # Pick a random uppercase letter A-Z
    prefix = chr(ord('A') + (os.urandom(1)[0] % 26))
    return prefix + body


# ===================================================================
# Basic password reuse detection
# ===================================================================


class TestPasswordReuse(unittest.TestCase):
    """A stored password must be detected; an unstored one must not."""

    def setUp(self):
        from passwordlib.tracked_passwords import PasswordHistory

        self.history = PasswordHistory(max_size=5)

    def test_stored_password_is_detected(self):
        pw = _random_password()
        self.history.add_password("alice", pw)
        self.assertTrue(self.history.is_password_used("alice", pw))

    def test_unstored_password_is_not_detected(self):
        self.history.add_password("alice", _random_password())
        self.assertFalse(self.history.is_password_used("alice", _random_password()))

    def test_unknown_user_returns_false(self):
        self.assertFalse(self.history.is_password_used("nobody", _random_password()))

    def test_multiple_passwords_all_detected(self):
        passwords = [_random_password() for _ in range(3)]
        for pw in passwords:
            self.history.add_password("alice", pw)
        for pw in passwords:
            self.assertTrue(self.history.is_password_used("alice", pw))
        self.assertFalse(self.history.is_password_used("alice", _random_password()))

    def test_users_are_isolated(self):
        pw_alice = _random_password()
        pw_bob = _random_password()
        self.history.add_password("alice", pw_alice)
        self.history.add_password("bob", pw_bob)
        self.assertFalse(self.history.is_password_used("bob", pw_alice))
        self.assertFalse(self.history.is_password_used("alice", pw_bob))

    def test_eviction_drops_oldest(self):
        from passwordlib.tracked_passwords import PasswordHistory

        h = PasswordHistory(max_size=2)
        passwords = [_random_password() for _ in range(3)]
        for pw in passwords:
            h.add_password("u", pw)
        self.assertFalse(h.is_password_used("u", passwords[0]))
        self.assertTrue(h.is_password_used("u", passwords[1]))
        self.assertTrue(h.is_password_used("u", passwords[2]))

    def test_clear_removes_all(self):
        pw = _random_password()
        self.history.add_password("alice", pw)
        self.history.clear_history("alice")
        self.assertFalse(self.history.is_password_used("alice", pw))
        self.assertEqual(self.history.get_history_size("alice"), 0)

    def test_clear_unknown_user_no_error(self):
        self.history.clear_history("ghost")  # must not raise

    def test_history_size_tracks_additions(self):
        self.assertEqual(self.history.get_history_size("alice"), 0)
        self.history.add_password("alice", _random_password())
        self.assertEqual(self.history.get_history_size("alice"), 1)
        self.history.add_password("alice", _random_password())
        self.assertEqual(self.history.get_history_size("alice"), 2)

    def test_bytes_password(self):
        pw = os.urandom(12)
        self.history.add_password("alice", pw)
        self.assertTrue(self.history.is_password_used("alice", pw))
        self.assertFalse(self.history.is_password_used("alice", os.urandom(12)))

    def test_default_max_size(self):
        from passwordlib.tracked_passwords import PasswordHistory

        self.assertEqual(PasswordHistory().max_size, 5)


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

    def test_similar_also_validates_inputs(self):
        from passwordlib.tracked_passwords import PasswordHistory

        h = PasswordHistory(max_size=5, similarity=True)
        with self.assertRaises((ValueError, TypeError)):
            h.is_password_similar("alice", None)
        with self.assertRaises(ValueError):
            h.is_password_similar("alice", "")
        with self.assertRaises(ValueError):
            h.is_password_similar("", "secret")

    def test_valid_password_works_after_rejected_invalids(self):
        """Rejected invalid inputs must not corrupt state so that
        subsequent valid operations still succeed."""
        pw = _random_password()
        for bad in [None, "", b"", "   ", 42]:
            try:
                self.history.add_password("alice", bad)
            except (ValueError, TypeError):
                pass
        self.history.add_password("alice", pw)
        self.assertTrue(self.history.is_password_used("alice", pw))


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

        pw = _random_password()
        h = PasswordHistory(max_size=3, backend=ListBackend())
        h.add_password("u", pw)
        h.add_password("u", _random_password())
        self.assertTrue(h.is_password_used("u", pw))
        self.assertEqual(h.get_history_size("u"), 2)

    def test_default_backend_without_explicit_arg(self):
        from passwordlib.tracked_passwords import PasswordHistory

        pw = _random_password()
        h = PasswordHistory()
        h.add_password("u", pw)
        self.assertTrue(h.is_password_used("u", pw))


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
            h.add_password("u", _random_password())
        self.assertIsInstance(ctx.exception.__cause__, IOError)

    def test_get_entries_failure(self):
        from passwordlib.tracked_passwords import PasswordHistoryError

        def boom(*a):
            raise IOError("conn lost")

        h = self._make_failing_history(get_entries=boom)
        with self.assertRaises(PasswordHistoryError):
            h.is_password_used("u", _random_password())

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
                    h.add_password("shared", f"t{tid}_p{i}_{_random_password(4)}")
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
        seed_pw = _random_password()
        h.add_password("u", seed_pw)
        errors: t.List[Exception] = []

        def adder():
            try:
                for i in range(5):
                    h.add_password("u", _random_password())
            except Exception as exc:
                errors.append(exc)

        def checker():
            try:
                for _ in range(5):
                    h.is_password_used("u", seed_pw)
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
        dup_pw = _random_password()
        barrier = threading.Barrier(4)
        errors: t.List[Exception] = []

        def worker():
            try:
                barrier.wait()
                h.add_password("u", dup_pw)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()

        self.assertEqual(errors, [])
        self.assertEqual(h.get_history_size("u"), 1)

    def test_concurrent_different_passwords_all_stored(self):
        """Concurrent writes of distinct passwords must not lose entries."""
        from passwordlib.tracked_passwords import PasswordHistory

        h = PasswordHistory(max_size=50)
        passwords = [_random_password() for _ in range(8)]
        barrier = threading.Barrier(8)
        errors: t.List[Exception] = []

        def worker(pw):
            try:
                barrier.wait()
                h.add_password("u", pw)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(pw,)) for pw in passwords]
        for th in threads:
            th.start()
        for th in threads:
            th.join()

        self.assertEqual(errors, [])
        # Every distinct password must be findable
        for pw in passwords:
            self.assertTrue(h.is_password_used("u", pw),
                            "Concurrent write lost a password entry")

    def test_concurrent_writes_different_users_no_cross_contamination(self):
        """Concurrent writes to different users must not mix entries."""
        from passwordlib.tracked_passwords import PasswordHistory

        h = PasswordHistory(max_size=10)
        user_passwords = {f"user_{i}": _random_password() for i in range(4)}
        barrier = threading.Barrier(4)
        errors: t.List[Exception] = []

        def worker(uid, pw):
            try:
                barrier.wait()
                h.add_password(uid, pw)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(uid, pw))
                   for uid, pw in user_passwords.items()]
        for th in threads:
            th.start()
        for th in threads:
            th.join()

        self.assertEqual(errors, [])
        for uid, pw in user_passwords.items():
            self.assertTrue(h.is_password_used(uid, pw))
            for other_uid, other_pw in user_passwords.items():
                if other_uid != uid:
                    self.assertFalse(h.is_password_used(uid, other_pw),
                                     f"{other_uid}'s password found under {uid}")

    def test_read_after_concurrent_write_is_consistent(self):
        """A password added during concurrent activity must be findable
        after all writers finish."""
        from passwordlib.tracked_passwords import PasswordHistory

        h = PasswordHistory(max_size=30)
        target_pw = _random_password()
        noise_pws = [_random_password() for _ in range(10)]
        barrier = threading.Barrier(6)
        errors: t.List[Exception] = []

        def target_writer():
            try:
                barrier.wait()
                h.add_password("u", target_pw)
            except Exception as exc:
                errors.append(exc)

        def noise_writer(pws):
            try:
                barrier.wait()
                for pw in pws:
                    h.add_password("u", pw)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=target_writer)]
        # Split noise across 5 threads
        for i in range(5):
            threads.append(threading.Thread(target=noise_writer,
                                            args=(noise_pws[i*2:(i+1)*2],)))
        for th in threads:
            th.start()
        for th in threads:
            th.join()

        self.assertEqual(errors, [])
        self.assertTrue(h.is_password_used("u", target_pw),
                        "Target password not found after concurrent writes")


# ===================================================================
# Similarity detection
# ===================================================================


class TestSimilarityDetection(unittest.TestCase):
    """Similar (not just identical) passwords must be flagged."""

    def setUp(self):
        from passwordlib.tracked_passwords import PasswordHistory

        self.history = PasswordHistory(max_size=5, similarity=True)

    def test_case_variant_detected_random(self):
        """Random mixed-case password; its lowercased form must be similar."""
        base = _random_password_with_upper()
        self.history.add_password("u", base)
        self.assertTrue(self.history.is_password_similar("u", base.lower()))

    def test_trailing_digits_detected(self):
        base = _random_password(8)
        with_digits = base + "789"
        self.history.add_password("u", with_digits)
        self.assertTrue(self.history.is_password_similar("u", base))

    def test_trailing_spaces_detected(self):
        base = _random_password(8)
        with_spaces = base + "  "
        self.history.add_password("u", with_spaces)
        self.assertTrue(self.history.is_password_similar("u", base))
        # The original exact form must also still work
        self.assertTrue(self.history.is_password_used("u", with_spaces))

    def test_leet_speak_detected(self):
        self.history.add_password("u", "p@$$w0rd")
        self.assertTrue(self.history.is_password_similar("u", "password"))

    def test_exact_match_also_detected(self):
        pw = _random_password()
        self.history.add_password("u", pw)
        self.assertTrue(self.history.is_password_similar("u", pw))

    def test_unrelated_password_not_flagged(self):
        self.history.add_password("u", _random_password())
        self.assertFalse(self.history.is_password_similar("u", _random_password()))

    def test_exact_check_ignores_variants(self):
        """is_password_used must only match exact, not variants."""
        pw = _random_password_with_upper()
        self.history.add_password("u", pw)
        self.assertTrue(self.history.is_password_used("u", pw))
        self.assertFalse(self.history.is_password_used("u", pw.lower()))

    def test_similarity_disabled_raises(self):
        from passwordlib.tracked_passwords import PasswordHistory

        h = PasswordHistory(max_size=5, similarity=False)
        h.add_password("u", _random_password())
        with self.assertRaises(RuntimeError):
            h.is_password_similar("u", _random_password())


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
        pw_old = _random_password()
        pw_new = _random_password()

        # Store under current default
        h.add_password("u", pw_old)

        # Flip default to a different algorithm
        try:
            config.DEFAULT_ALGORITHM = "sha512" if original_algo != "sha512" else "sha1"
            # New password stored with the new algorithm
            h.add_password("u", pw_new)
            # Old password must still verify against its original algorithm
            self.assertTrue(h.is_password_used("u", pw_old))
            self.assertTrue(h.is_password_used("u", pw_new))
            self.assertFalse(h.is_password_used("u", _random_password()))
        finally:
            config.DEFAULT_ALGORITHM = original_algo

    def test_two_algorithms_same_password_both_verify(self):
        """The same password hashed with different algorithms must each
        be independently verifiable."""
        from passwordlib import config
        from passwordlib.tracked_passwords import PasswordHistory

        original_algo = config.DEFAULT_ALGORITHM
        h = PasswordHistory(max_size=5)
        pw = _random_password()

        h.add_password("u", pw)
        try:
            config.DEFAULT_ALGORITHM = "sha512" if original_algo != "sha512" else "sha1"
            h.add_password("u", pw)
        finally:
            config.DEFAULT_ALGORITHM = original_algo

        # Must still verify regardless of current default
        self.assertTrue(h.is_password_used("u", pw))


# ===================================================================
# Anti-gaming: verify real hashing, no plaintext storage
# ===================================================================


class TestNoPlaintextStorage(unittest.TestCase):
    """The backend must never see or store plaintext passwords."""

    def test_backend_entries_do_not_contain_plaintext(self):
        """Inspect raw backend storage: the plaintext password must
        not appear anywhere in the stored bytes."""
        from passwordlib.tracked_passwords import InMemoryBackend, PasswordHistory

        backend = InMemoryBackend()
        h = PasswordHistory(max_size=5, backend=backend)

        pw = _random_password()
        h.add_password("u", pw)

        entries = backend.get_entries("u")
        self.assertEqual(len(entries), 1)

        raw_blob = entries[0]
        # The plaintext (as both str-encoded and raw) must NOT be in the blob
        self.assertNotIn(pw.encode(), raw_blob,
                         "Plaintext password found in stored entry")

    def test_backend_entries_do_not_contain_plaintext_bytes(self):
        """Same check for bytes-type passwords."""
        from passwordlib.tracked_passwords import InMemoryBackend, PasswordHistory

        backend = InMemoryBackend()
        h = PasswordHistory(max_size=5, backend=backend)

        pw = os.urandom(16)
        h.add_password("u", pw)

        entries = backend.get_entries("u")
        raw_blob = entries[0]
        self.assertNotIn(pw, raw_blob,
                         "Plaintext bytes password found in stored entry")

    def test_stored_entry_is_parseable_hash_dump(self):
        """Each stored entry must be a valid hash dump that the core
        dumping module can parse — proving real hashing occurred."""
        from passwordlib.core.dumping import loads
        from passwordlib.tracked_passwords import InMemoryBackend, PasswordHistory

        backend = InMemoryBackend()
        h = PasswordHistory(max_size=5, backend=backend)

        pw = _random_password()
        h.add_password("u", pw)

        entries = backend.get_entries("u")
        # Should not raise — entry must be a valid hash dump
        parsed = loads(entries[0])
        self.assertIn(parsed.algorithm, hashlib.algorithms_available)
        self.assertGreater(parsed.iterations, 0)
        self.assertGreater(len(parsed.salt), 0)
        self.assertGreater(len(parsed.hashed), 0)

    def test_different_passwords_produce_different_entries(self):
        """Two different random passwords must produce different stored
        entries — a trivial constant-output fake would fail this."""
        from passwordlib.tracked_passwords import InMemoryBackend, PasswordHistory

        backend = InMemoryBackend()
        h = PasswordHistory(max_size=5, backend=backend)

        pw1 = _random_password()
        pw2 = _random_password()
        h.add_password("u", pw1)
        h.add_password("u", pw2)

        entries = backend.get_entries("u")
        self.assertEqual(len(entries), 2)
        self.assertNotEqual(entries[0], entries[1],
                            "Different passwords must produce different entries")

    def test_spy_backend_never_receives_plaintext(self):
        """A spy backend records everything passed to append(); verify
        that no argument contains plaintext."""
        from passwordlib.tracked_passwords import HistoryBackend, PasswordHistory

        calls: t.List[t.Tuple[str, bytes, int]] = []

        class SpyBackend(HistoryBackend):
            def __init__(self):
                self._store: t.Dict[str, t.List[bytes]] = {}

            def append(self, user_id, entry, max_size):
                calls.append((user_id, entry, max_size))
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

        pw = _random_password()
        h = PasswordHistory(max_size=5, backend=SpyBackend())
        h.add_password("u", pw)

        self.assertEqual(len(calls), 1)
        _, stored_entry, _ = calls[0]
        self.assertNotIn(pw.encode(), stored_entry,
                         "Spy backend received plaintext in entry argument")


class TestSimilarityNoPlaintext(unittest.TestCase):
    """When similarity is enabled, variant hashes must also be real."""

    def test_similarity_entries_are_parseable(self):
        """With similarity=True, stored entry must unpack into a primary
        hash and variant hashes, all of which are valid dumps."""
        from passwordlib.core.dumping import loads
        from passwordlib.tracked_passwords import InMemoryBackend, PasswordHistory
        from passwordlib.tracked_passwords.similarity import unpack_entry

        backend = InMemoryBackend()
        h = PasswordHistory(max_size=5, backend=backend, similarity=True)

        pw = _random_password_with_upper()
        h.add_password("u", pw)

        entries = backend.get_entries("u")
        self.assertEqual(len(entries), 1)

        primary_bytes, variant_list = unpack_entry(entries[0])

        # Primary must be a valid hash dump
        parsed = loads(primary_bytes)
        self.assertIn(parsed.algorithm, hashlib.algorithms_available)

        # At least one variant should exist (the lowercased form)
        self.assertGreater(len(variant_list), 0,
                           "Expected at least one similarity variant hash")

        # Each variant must also be a valid hash dump
        for v in variant_list:
            parsed_v = loads(v)
            self.assertIn(parsed_v.algorithm, hashlib.algorithms_available)

    def test_similarity_entry_does_not_contain_plaintext(self):
        """Even with similarity packing, no plaintext must appear."""
        from passwordlib.tracked_passwords import InMemoryBackend, PasswordHistory

        backend = InMemoryBackend()
        h = PasswordHistory(max_size=5, backend=backend, similarity=True)

        pw = _random_password_with_upper()
        h.add_password("u", pw)

        entries = backend.get_entries("u")
        raw = entries[0]
        self.assertNotIn(pw.encode(), raw)
        self.assertNotIn(pw.lower().encode(), raw)


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
        dup_pw = _random_password()
        barrier = threading.Barrier(4)

        def worker():
            barrier.wait()
            h.add_password("u", dup_pw)

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
            h.add_password("u", _random_password())
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
        passwords = [_random_password() for _ in range(5)]
        for pw in passwords:
            h.add_password("u", pw)
        self.assertEqual(h.get_history_size("u"), 3)
        # Only the two oldest should be gone
        self.assertFalse(h.is_password_used("u", passwords[0]))
        self.assertFalse(h.is_password_used("u", passwords[1]))
        self.assertTrue(h.is_password_used("u", passwords[2]))
        self.assertTrue(h.is_password_used("u", passwords[3]))
        self.assertTrue(h.is_password_used("u", passwords[4]))


# ===================================================================
# Behavioral invariants with random data
# ===================================================================


class TestBehavioralInvariants(unittest.TestCase):
    """Properties that must hold for any password, not just specific strings."""

    def test_add_then_find_roundtrip(self):
        """Any valid password that is added must be found."""
        from passwordlib.tracked_passwords import PasswordHistory

        h = PasswordHistory(max_size=10)
        pw = _random_password()
        h.add_password("u", pw)
        self.assertTrue(h.is_password_used("u", pw))

    def test_never_added_never_found(self):
        """A password that was never added must never be found."""
        from passwordlib.tracked_passwords import PasswordHistory

        h = PasswordHistory(max_size=10)
        h.add_password("u", _random_password())
        # A different random password must not match
        self.assertFalse(h.is_password_used("u", _random_password()))

    def test_eviction_preserves_most_recent(self):
        """After N additions to a size-K history, the K most recent
        passwords must be found and the rest must not."""
        from passwordlib.tracked_passwords import PasswordHistory

        k = 3
        passwords = [_random_password() for _ in range(k + 4)]
        h = PasswordHistory(max_size=k)
        for pw in passwords:
            h.add_password("u", pw)

        # Most recent k must be found
        for pw in passwords[-k:]:
            self.assertTrue(
                h.is_password_used("u", pw), "Recent password should be found"
            )
        # Older ones must not
        for pw in passwords[:-k]:
            self.assertFalse(
                h.is_password_used("u", pw), "Evicted password should not be found"
            )

    def test_similarity_detects_case_from_random_input(self):
        """Storing a random mixed-case password and checking its lowercase
        form must be detected as similar."""
        from passwordlib.tracked_passwords import PasswordHistory

        h = PasswordHistory(max_size=5, similarity=True)
        pw = _random_password_with_upper()
        h.add_password("u", pw)
        self.assertTrue(h.is_password_similar("u", pw.lower()))

    def test_different_passwords_not_similar(self):
        """Two completely unrelated random passwords must not be
        flagged as similar."""
        from passwordlib.tracked_passwords import PasswordHistory

        h = PasswordHistory(max_size=5, similarity=True)
        h.add_password("u", _random_password())
        self.assertFalse(h.is_password_similar("u", _random_password()))

    def test_validation_rejects_before_any_side_effect(self):
        """Invalid input must not modify history size at all."""
        from passwordlib.tracked_passwords import PasswordHistory

        h = PasswordHistory(max_size=5)
        h.add_password("u", _random_password())
        size_before = h.get_history_size("u")

        for bad_input in [None, "", b"", "   ", 42]:
            try:
                h.add_password("u", bad_input)
            except (ValueError, TypeError):
                pass
        self.assertEqual(h.get_history_size("u"), size_before)

    def test_multiple_random_roundtrips(self):
        """Batch of random passwords: each must be independently findable
        after being added."""
        from passwordlib.tracked_passwords import PasswordHistory

        h = PasswordHistory(max_size=20)
        passwords = [_random_password() for _ in range(10)]
        for pw in passwords:
            h.add_password("u", pw)

        for pw in passwords:
            self.assertTrue(h.is_password_used("u", pw),
                            f"Password added but not found in history")

    def test_cross_user_isolation_random(self):
        """Passwords stored for one random user must not leak to another."""
        from passwordlib.tracked_passwords import PasswordHistory

        h = PasswordHistory(max_size=10)
        users = [f"user_{i}_{_random_password(4)}" for i in range(3)]
        user_passwords: t.Dict[str, t.List[str]] = {}

        for user in users:
            pws = [_random_password() for _ in range(3)]
            user_passwords[user] = pws
            for pw in pws:
                h.add_password(user, pw)

        for user in users:
            for other_user in users:
                if other_user == user:
                    continue
                for pw in user_passwords[other_user]:
                    self.assertFalse(
                        h.is_password_used(user, pw),
                        f"Password from {other_user} leaked to {user}",
                    )

    def test_eviction_with_varying_sizes(self):
        """Eviction invariant must hold for multiple max_size values."""
        from passwordlib.tracked_passwords import PasswordHistory

        for k in (1, 2, 5, 8):
            n = k + 3
            passwords = [_random_password() for _ in range(n)]
            h = PasswordHistory(max_size=k)
            for pw in passwords:
                h.add_password("u", pw)

            self.assertEqual(h.get_history_size("u"), k)
            for pw in passwords[-k:]:
                self.assertTrue(h.is_password_used("u", pw),
                                f"max_size={k}: recent password not found")
            for pw in passwords[:-k]:
                self.assertFalse(h.is_password_used("u", pw),
                                 f"max_size={k}: evicted password still found")


if __name__ == "__main__":
    unittest.main()
