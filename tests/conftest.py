"""Shared test fixtures for jarvis-auth.

Auth brute-force protection uses a process-local limiter singleton. Reset it
between tests so per-IP/per-email counters from one test can't bleed into the
next (the whole suite hammers auth from a single "testclient" IP).
"""
import pytest


@pytest.fixture(autouse=True)
def _reset_auth_rate_limiter():
    # Lazy import: the limiter module is dependency-free, but importing it eagerly
    # at collection time (before a test module sets its env) is avoided defensively.
    try:
        from jarvis_auth.app.core.rate_limit import rate_limiter

        rate_limiter.reset()
    except Exception:
        rate_limiter = None
    yield
    if rate_limiter is not None:
        rate_limiter.reset()
