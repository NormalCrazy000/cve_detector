"""Admin password check, session tokens and login throttling."""

import hashlib
import hmac
import secrets
import threading
import time
from collections import defaultdict, deque

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(configured: str, candidate: str) -> bool:
    """Check a login attempt against the configured password (plain text or argon2 hash)."""
    if configured.startswith("$argon2"):
        try:
            return _hasher.verify(configured, candidate)
        except (VerificationError, InvalidHashError):
            return False
    return hmac.compare_digest(configured.encode(), candidate.encode())


def new_token() -> str:
    return secrets.token_urlsafe(32)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class LoginThrottle:
    """Blocks a client after too many failed logins within a time window."""

    def __init__(self, max_failures: int = 5, window_seconds: float = 900.0) -> None:
        self._max = max_failures
        self._window = window_seconds
        self._failures: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def retry_after(self, client: str) -> int:
        """Seconds until the client may try again; 0 when it is not blocked."""
        with self._lock:
            failures = self._prune(client)
            if len(failures) < self._max:
                return 0
            return max(1, int(failures[0] + self._window - time.monotonic()) + 1)

    def failed(self, client: str) -> None:
        with self._lock:
            self._prune(client).append(time.monotonic())

    def succeeded(self, client: str) -> None:
        with self._lock:
            self._failures.pop(client, None)

    def _prune(self, client: str) -> deque[float]:
        failures = self._failures[client]
        cutoff = time.monotonic() - self._window
        while failures and failures[0] < cutoff:
            failures.popleft()
        return failures
