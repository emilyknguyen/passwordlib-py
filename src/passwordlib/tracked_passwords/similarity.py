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
