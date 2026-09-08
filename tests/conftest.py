"""Shared fixtures and helpers for the Axiosky SDK test suite."""
import httpx
import pytest

import axiosky.client as client_mod
from axiosky import AsyncGovernor, Governor, __version__

API_KEY = "test-key-1234567890"


# ---------------------------------------------------------------------------
# Sleep patching — keeps retry tests fast without breaking the event loop.
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def fast_sleep(monkeypatch):
    """Patch ``time.sleep`` in the SDK module to a no-op (autouse).

    This makes SYNC retry tests fast — without it, retry tests with
    exponential backoff would sleep 2+4+8 = 14 s each. We intentionally
    do NOT patch ``asyncio.sleep`` here because pytest-asyncio's event
    loop relies on it for coroutine scheduling; patching it can hang
    the loop. Async retry tests use the ``fast_sleep_async`` fixture
    explicitly when needed.
    """
    monkeypatch.setattr(client_mod.time, "sleep", lambda *a, **kw: None)


@pytest.fixture
def fast_sleep_async(monkeypatch):
    """Patch asyncio.sleep to yield once but not wait, for async tests.

    Safer than a pure no-op: yields control so other tasks make
    progress, but never actually sleeps. The original ``asyncio.sleep``
    is captured BEFORE patching so the fake can delegate ``sleep(0)``
    to it.
    """
    import asyncio as _asyncio

    _real_sleep = _asyncio.sleep

    async def _fast(delay, *a, **kw):
        # Always yield once (mirrors asyncio.sleep(0) semantics) so
        # the event loop can run pending callbacks.
        await _real_sleep(0)

    monkeypatch.setattr(_asyncio, "sleep", _fast)
    # Also patch the module-level reference used by the SDK.
    monkeypatch.setattr(client_mod.asyncio, "sleep", _fast)


# ---------------------------------------------------------------------------
# Governor factories with injected MockTransport
# ---------------------------------------------------------------------------
def make_governor(handler, **kwargs):
    """Build a sync Governor whose httpx client uses a MockTransport."""
    kwargs.setdefault("base_url", "http://test.local")
    gov = Governor(api_key=API_KEY, **kwargs)
    gov._client = httpx.Client(
        base_url=gov.base_url,
        transport=httpx.MockTransport(handler),
        headers=gov._default_headers(),
        timeout=gov.timeout,
    )
    return gov


def make_async_governor(handler, **kwargs):
    """Build an async AsyncGovernor whose httpx client uses MockTransport."""
    kwargs.setdefault("base_url", "http://test.local")
    gov = AsyncGovernor(api_key=API_KEY, **kwargs)
    gov._client = httpx.AsyncClient(
        base_url=gov.base_url,
        transport=httpx.MockTransport(handler),
        headers=gov._default_headers(),
        timeout=gov.timeout,
    )
    return gov


# ---------------------------------------------------------------------------
# Response builders — return a complete Decision body.
# ---------------------------------------------------------------------------
def decision_body(
    status: str = "APPROVE",
    decision_id: str = "dec-123",
    reason: str = "ok",
    reason_code: str = "OK",
    **extra,
):
    body = {
        "decision_id": decision_id,
        "status": status,
        "reason": reason,
        "reason_code": reason_code,
    }
    body.update(extra)
    return body


def approve_body(**extra):
    return decision_body("APPROVE", reason="approved", reason_code="APPROVED", **extra)


def block_body(**extra):
    return decision_body("BLOCK", reason="blocked", reason_code="DENIED", **extra)


def escalate_body(**extra):
    return decision_body(
        "ESCALATE",
        reason="needs human review",
        reason_code="ESCALATE",
        escalation_id="esc-456",
        **extra,
    )
