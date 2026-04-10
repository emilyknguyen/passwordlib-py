# instruction.md

Implement a tracked_passwords subpackage under src/passwordlib/ that provides per-user password history tracking.

Create a PasswordHistory class that accepts max_size (int, default 5), an optional backend (conforming to an abstract HistoryBackend interface with append, get, size, and clear methods), and an optional flag to detect similarty (bool, default False).

Public methods:
1. add_password(user_id, password) stores a hashed password (FIFO eviction at max_size, skip duplicates under concurrency)
2. is_password_used(user_id, password) checks exact reuse
3. is_password_similar(user_id, password) checks similarity (raises RuntimeError if similarity is disabled)
4. get_history_size(user_id) returns count
5. clear_history(user_id) removes all entries
Expose max_size as a read-only property.

Input validation for passwords and user IDs:
1. reject None, empty, whitespace-only
2. reject non-str/bytes passwords with TypeError
3. reject max_size <= 0
Wrap all exceptions in PasswordHistoryError with cause chaining.
Ensure operations are thread-safe.

Similarity detection must identify case variants, trailing digits, trailing spaces, and leet-speak substitutions (@->a, 4->a, 3->e, 1->l, !->i, 0->o, $->s, 5->s, 7->t) without storing plaintext password strings. Use the existing hash_password and compare_password from passwordlib.core for all hashing.

Provide a default InMemoryBackend.
Passwords hashed with different algorithms must still verify correctly by reading algorithm/salt/iterations from stored dumps.
