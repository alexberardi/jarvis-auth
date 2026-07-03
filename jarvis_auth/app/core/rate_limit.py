"""In-memory brute-force protection for the auth endpoints.

Auth runs single-worker (the refresh-token grace cache in ``core/refresh_cache``
is process-local, so auth must stay single-worker until it's backed by
Redis/Postgres — see api/auth.py). That makes a process-local limiter sufficient.

Two layers:

- A **global per-IP** sliding window across ``/auth/{login,register,refresh}`` to
  blunt a single flooder.
- A **per-(email, IP) failed-login** lockout: after N failures for the same email
  FROM the same IP within a window, that pair is locked out briefly. Keying on
  ``(email, IP)`` — not the email alone — means an attacker on one IP can't lock
  the real user out from a different IP (no account-lockout DoS).

Both maps are bounded (``max_keys``) so a flood of distinct IPs/emails can't grow
memory without limit.
"""

from __future__ import annotations

import threading
import time


class _Window:
    """A sliding-window hit counter."""

    __slots__ = ("hits",)

    def __init__(self) -> None:
        self.hits: list[float] = []

    def count(self, now: float, window: float) -> int:
        cutoff = now - window
        self.hits = [t for t in self.hits if t > cutoff]
        return len(self.hits)

    def add(self, now: float) -> None:
        self.hits.append(now)


class AuthRateLimiter:
    def __init__(self, max_keys: int = 50_000) -> None:
        self._ip: dict[str, _Window] = {}
        self._fail: dict[tuple[str, str], _Window] = {}
        self.max_keys = max_keys
        self._lock = threading.Lock()

    def _evict(self, buckets: dict, window: float, now: float) -> None:
        """Bound memory: at capacity drop idle windows, then the oldest tenth."""
        if len(buckets) < self.max_keys:
            return
        idle = [k for k, w in buckets.items() if w.count(now, window) == 0]
        for k in idle:
            del buckets[k]
        if len(buckets) >= self.max_keys:
            ordered = sorted(
                buckets.items(),
                key=lambda kv: kv[1].hits[-1] if kv[1].hits else 0.0,
            )
            for k, _ in ordered[: max(1, self.max_keys // 10)]:
                buckets.pop(k, None)

    def check_ip(self, ip: str, limit: int, window: float = 60.0) -> bool:
        """Record a request from ``ip`` and return True if it's UNDER ``limit``."""
        now = time.time()
        with self._lock:
            w = self._ip.get(ip)
            if w is None:
                self._evict(self._ip, window, now)
                w = self._ip[ip] = _Window()
            if w.count(now, window) >= limit:
                return False
            w.add(now)
            return True

    def is_locked(self, email: str, ip: str, max_failures: int, window: float) -> bool:
        now = time.time()
        with self._lock:
            w = self._fail.get((email.lower(), ip))
            if w is None:
                return False
            return w.count(now, window) >= max_failures

    def record_failure(self, email: str, ip: str, window: float) -> None:
        now = time.time()
        key = (email.lower(), ip)
        with self._lock:
            w = self._fail.get(key)
            if w is None:
                self._evict(self._fail, window, now)
                w = self._fail[key] = _Window()
            w.add(now)

    def clear_failures(self, email: str, ip: str) -> None:
        with self._lock:
            self._fail.pop((email.lower(), ip), None)

    def reset(self) -> None:
        with self._lock:
            self._ip.clear()
            self._fail.clear()


def client_ip(request, trust_forwarded_for: bool) -> str:
    """Best-effort caller IP for rate-limit keying (not auth).

    Only trust ``X-Forwarded-For`` when explicitly configured (auth behind a
    proxy that sets it); then use the RIGHT-most hop — the one the trusted proxy
    appended — never the caller-controlled left-most. Otherwise use the socket
    peer, which a direct-to-auth client cannot forge.
    """
    if trust_forwarded_for:
        xff = request.headers.get("x-forwarded-for")
        if xff:
            hops = [p.strip() for p in xff.split(",") if p.strip()]
            if hops:
                return hops[-1]
    return request.client.host if request.client else "unknown"


# Process-local singleton.
rate_limiter = AuthRateLimiter()
