"""In-process cache for the grace-window race on `/auth/refresh`.

The plain successor refresh token is held in memory for
`refresh_token_grace_seconds`. This makes jarvis-auth single-process by
design: if we ever horizontally scale, replace with a Redis/Postgres-backed
store. Per the rotation ticket (jarvis-roadmap#5), Alex accepted this
constraint.
"""
from __future__ import annotations

import time
from threading import Lock

_STORE: dict[int, tuple[str, float]] = {}
_LOCK = Lock()


def set(parent_id: int, plain: str, ttl_seconds: int) -> None:
    expires_at = time.monotonic() + ttl_seconds
    with _LOCK:
        _STORE[parent_id] = (plain, expires_at)


def get(parent_id: int) -> str | None:
    now = time.monotonic()
    with _LOCK:
        entry = _STORE.get(parent_id)
        if entry is None:
            return None
        plain, expires_at = entry
        if now >= expires_at:
            _STORE.pop(parent_id, None)
            return None
        return plain


def clear() -> None:
    with _LOCK:
        _STORE.clear()
