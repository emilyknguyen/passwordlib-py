# -*- coding=utf-8 -*-
r"""
Tests for the tracked_passwords module — similarity detection.

These tests verify the similarity detection feature added on top of the
core password history tracking module.  They assume the core module
(PasswordHistory, HistoryBackend, InMemoryBackend) already exists and
works correctly.

Design principles:
  - Prefer random / generated inputs over fixed strings so that a model
    cannot satisfy the tests by hardcoding expected outputs.
  - Where fixed strings are used (e.g. leet-speak smoke tests), pair them
    with random-data counterparts that test the same invariant.
  - Anti-gaming tests inspect backend storage to confirm that real hashing
    occurred and that plaintext is never stored.
"""
import hashlib
import os
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
# Input validation for similarity
# ===================================================================


class TestSimilarityInputValidation(unittest.TestCase):
    """Similarity methods must validate inputs the same way as core."""

    def test_similar_validates_password(self):
        from passwordlib.tracked_passwords import PasswordHistory

        h = PasswordHistory(max_size=5, similarity=True)
        with self.assertRaises((ValueError, TypeError)):
            h.is_password_similar("alice", None)
        with self.assertRaises(ValueError):
            h.is_password_similar("alice", "")

    def test_similar_validates_user_id(self):
        from passwordlib.tracked_passwords import PasswordHistory

        h = PasswordHistory(max_size=5, similarity=True)
        with self.assertRaises(ValueError):
            h.is_password_similar("", "secret")


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
# Anti-gaming: verify no plaintext in similarity entries
# ===================================================================


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
# Behavioral invariants for similarity
# ===================================================================


class TestSimilarityBehavioralInvariants(unittest.TestCase):
    """Properties that must hold for similarity detection with any input."""

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


if __name__ == "__main__":
    unittest.main()
