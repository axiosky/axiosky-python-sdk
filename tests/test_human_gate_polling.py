"""Tests for the HITL restructure: pending-confirmation contract + polling.

These tests verify the SDK's new asynchronous execute contract:
  - execute() returns a pending Decision (execution_status='pending_human_review'),
    NOT an executed result.
  - poll_for_decision() fetches the current state in a single HTTP call.
  - wait_for_decision() polls until terminal (or timeout).
  - The Decision dataclass parses the new origin + policy_recommendation fields.
  - The terminal-states set correctly identifies final outcomes.
"""
import asyncio
import json
from unittest.mock import patch

import httpx
import pytest

from axiosky import AsyncGovernor, AxioskyError, Governor, Decision
from tests.conftest import (
    approve_body,
    make_async_governor,
    make_governor,
    API_KEY,
)


# ---------------------------------------------------------------------------
# execute() returns pending — NOT executed
# ---------------------------------------------------------------------------
def test_unconfirmed_delivery_is_a_bounded_operator_outcome():
    calls = []
    def handler(request):
        calls.append(request)
        return httpx.Response(200, json={'execution_status': 'delivery_unconfirmed'})
    gov = make_governor(handler)
    assert gov.wait_for_decision('decision-1', timeout=1)['execution_status'] == 'delivery_unconfirmed'
    assert len(calls) == 1
    gov.close()


@pytest.mark.asyncio
async def test_async_unconfirmed_delivery_stops_waiting():
    gov = make_async_governor(lambda request: httpx.Response(200, json={'execution_status': 'delivery_unconfirmed'}))
    assert (await gov.wait_for_decision('decision-1', timeout=1))['execution_status'] == 'delivery_unconfirmed'
    await gov.aclose()


class TestExecuteReturnsPending:
    """HITL: execute() returns execution_status='pending_human_review'."""

    @pytest.mark.asyncio
    async def test_async_execute_returns_pending(self):
        """Async execute() returns a pending Decision, not an executed one."""
        def handler(req):
            # The server now returns execution_status='pending_human_review'
            # + origin='human_gate' + policy_recommendation='APPROVE'.
            body = approve_body(
                execution_status="pending_human_review",
                origin="human_gate",
                policy_recommendation="APPROVE",
                escalation_id="esc-001",
                escalation_expires_minutes=60,
            )
            return httpx.Response(200, json=body)

        gov = make_async_governor(handler)
        d = await gov.execute("a1", "act1", "https://api.example.com/hooks")
        assert d.execution_status == "pending_human_review"
        assert d.origin == "human_gate"
        assert d.policy_recommendation == "APPROVE"
        assert d.escalation_id == "esc-001"
        assert d.escalation_expires_minutes == 60

    def test_sync_execute_returns_pending(self):
        """Sync execute() also returns a pending Decision."""
        def handler(req):
            body = approve_body(
                execution_status="pending_human_review",
                origin="human_gate",
                policy_recommendation="APPROVE",
                escalation_id="esc-002",
            )
            return httpx.Response(200, json=body)

        gov = make_governor(handler)
        d = gov.execute("a1", "act1", "https://api.example.com/hooks")
        assert d.execution_status == "pending_human_review"
        assert d.origin == "human_gate"
        assert d.policy_recommendation == "APPROVE"

    @pytest.mark.asyncio
    async def test_async_execute_shadow_skipped_is_terminal(self):
        """Shadow mode returns 'shadow_skipped' (terminal at execute time)."""
        def handler(req):
            body = approve_body(
                execution_status="shadow_skipped",
                shadow_result="APPROVE",
            )
            return httpx.Response(200, json=body)

        gov = make_async_governor(handler)
        d = await gov.execute(
            "a1", "act1", "https://api.example.com/hooks",
            environment="shadow",
        )
        assert d.execution_status == "shadow_skipped"
        assert d.shadow_result == "APPROVE"


# ---------------------------------------------------------------------------
# poll_for_decision — single-shot poll
# ---------------------------------------------------------------------------
class TestPollForDecision:
    @pytest.mark.asyncio
    async def test_async_poll_returns_current_state(self):
        """poll_for_decision returns the raw JSON from GET /v1/decisions/{id}."""
        seen_urls = []

        def handler(req):
            seen_urls.append(str(req.url))
            return httpx.Response(200, json={
                "decision_id": "dec-123",
                "tenant_id": "1",
                "policy_recommendation": "APPROVE",
                "policy_reason": "all policies passed",
                "escalation_id": "esc-001",
                "escalation_status": "pending",
                "origin": "human_gate",
                "execution_status": "pending_human_review",
                "execution_response_code": None,
                "resolved_by": None,
                "resolved_at": None,
                "expires_at": "2026-01-01T00:00:00Z",
            })

        gov = make_async_governor(handler)
        state = await gov.poll_for_decision("dec-123")
        assert state["decision_id"] == "dec-123"
        assert state["execution_status"] == "pending_human_review"
        assert state["origin"] == "human_gate"
        # The poll hit the right endpoint.
        assert any("/v1/decisions/dec-123" in u for u in seen_urls)

    def test_sync_poll_returns_current_state(self):
        """Sync poll_for_decision."""
        def handler(req):
            return httpx.Response(200, json={
                "decision_id": "dec-456",
                "execution_status": "executed",
                "execution_response_code": 200,
                "origin": "human_gate",
            })

        gov = make_governor(handler)
        state = gov.poll_for_decision("dec-456")
        assert state["execution_status"] == "executed"
        assert state["execution_response_code"] == 200

    @pytest.mark.asyncio
    async def test_async_poll_raises_on_4xx(self):
        """poll_for_decision raises AxioskyError on 4xx (not 429)."""
        def handler(req):
            return httpx.Response(404, json={"detail": "not found"})

        gov = make_async_governor(handler)
        with pytest.raises(AxioskyError, match="not found"):
            await gov.poll_for_decision("nonexistent-dec")


# ---------------------------------------------------------------------------
# wait_for_decision — polls until terminal
# ---------------------------------------------------------------------------
class TestWaitForDecision:
    @pytest.mark.asyncio
    async def test_async_wait_returns_terminal_state(self, monkeypatch):
        """wait_for_decision polls until execution_status is terminal."""
        # Use fast asyncio.sleep for the test.
        real_sleep = asyncio.sleep

        async def fast_sleep(delay, *a, **kw):
            await real_sleep(0)

        monkeypatch.setattr(asyncio, "sleep", fast_sleep)

        call_count = [0]

        def handler(req):
            call_count[0] += 1
            if call_count[0] < 3:
                # First two polls: still pending.
                return httpx.Response(200, json={
                    "decision_id": "dec-789",
                    "execution_status": "pending_human_review",
                })
            # Third poll: human approved, target fired.
            return httpx.Response(200, json={
                "decision_id": "dec-789",
                "execution_status": "executed",
                "execution_response_code": 200,
            })

        gov = make_async_governor(handler)
        state = await gov.wait_for_decision(
            "dec-789", timeout=5.0, poll_interval=0.01
        )
        assert state["execution_status"] == "executed"
        assert state["execution_response_code"] == 200
        # We polled 3 times (2 pending + 1 terminal).
        assert call_count[0] == 3

    @pytest.mark.asyncio
    async def test_async_wait_times_out(self, monkeypatch):
        """wait_for_decision raises AxioskyError on timeout."""
        real_sleep = asyncio.sleep

        async def fast_sleep(delay, *a, **kw):
            await real_sleep(0)

        monkeypatch.setattr(asyncio, "sleep", fast_sleep)

        # Always returns pending — never reaches terminal.
        def handler(req):
            return httpx.Response(200, json={
                "decision_id": "dec-timeout",
                "execution_status": "pending_human_review",
            })

        gov = make_async_governor(handler)
        with pytest.raises(AxioskyError, match="Timed out"):
            await gov.wait_for_decision(
                "dec-timeout", timeout=0.1, poll_interval=0.01
            )

    @pytest.mark.asyncio
    async def test_async_wait_handles_blocked_by_human(self, monkeypatch):
        """wait_for_decision returns 'blocked_by_human' as a terminal state."""
        real_sleep = asyncio.sleep

        async def fast_sleep(delay, *a, **kw):
            await real_sleep(0)

        monkeypatch.setattr(asyncio, "sleep", fast_sleep)

        def handler(req):
            return httpx.Response(200, json={
                "decision_id": "dec-blocked",
                "execution_status": "blocked_by_human",
            })

        gov = make_async_governor(handler)
        state = await gov.wait_for_decision(
            "dec-blocked", timeout=2.0, poll_interval=0.01
        )
        assert state["execution_status"] == "blocked_by_human"

    @pytest.mark.asyncio
    async def test_async_wait_handles_expired_auto_blocked(self, monkeypatch):
        """wait_for_decision returns 'expired_auto_blocked' as terminal."""
        real_sleep = asyncio.sleep

        async def fast_sleep(delay, *a, **kw):
            await real_sleep(0)

        monkeypatch.setattr(asyncio, "sleep", fast_sleep)

        def handler(req):
            return httpx.Response(200, json={
                "decision_id": "dec-expired",
                "execution_status": "expired_auto_blocked",
            })

        gov = make_async_governor(handler)
        state = await gov.wait_for_decision(
            "dec-expired", timeout=2.0, poll_interval=0.01
        )
        assert state["execution_status"] == "expired_auto_blocked"


# ---------------------------------------------------------------------------
# Decision dataclass parses new fields
# ---------------------------------------------------------------------------
class TestDecisionParsesHITLFields:
    def test_parse_decision_with_origin_and_recommendation(self):
        """_parse_decision reads origin + policy_recommendation from the response."""
        body = approve_body(
            execution_status="pending_human_review",
            origin="human_gate",
            policy_recommendation="APPROVE",
            escalation_id="esc-123",
        )
        d = Governor._parse_decision(body)
        assert d.origin == "human_gate"
        assert d.policy_recommendation == "APPROVE"
        assert d.execution_status == "pending_human_review"
        assert d.escalation_id == "esc-123"

    def test_parse_decision_without_hitl_fields_defaults_to_none(self):
        """Old-style responses (no origin/policy_recommendation) still parse."""
        body = approve_body()
        d = Governor._parse_decision(body)
        assert d.origin is None
        assert d.policy_recommendation is None

    def test_decision_dataclass_accepts_new_fields(self):
        """The Decision dataclass accepts origin + policy_recommendation kwargs."""
        d = Decision(
            decision_id="dec-1",
            status="APPROVE",
            reason="ok",
            reason_code="OK",
            origin="human_gate",
            policy_recommendation="APPROVE",
            execution_status="pending_human_review",
        )
        assert d.origin == "human_gate"
        assert d.policy_recommendation == "APPROVE"
        assert d.execution_status == "pending_human_review"


class TestDecisionParsesTargetRole:
    """Risk-tiered approval: _parse_decision reads target_role from the
    response so SDK callers can route pending confirmations to the right
    reviewer."""

    def test_parse_decision_with_target_role(self):
        """A tiered rule's target_role is surfaced on the Decision."""
        body = approve_body(
            execution_status="pending_human_review",
            origin="human_gate",
            policy_recommendation="BLOCK",
            target_role="chief_risk_officer",
            escalation_id="esc-tiered",
        )
        d = Governor._parse_decision(body)
        assert d.target_role == "chief_risk_officer"
        assert d.origin == "human_gate"
        assert d.policy_recommendation == "BLOCK"

    def test_parse_decision_without_target_role_defaults_to_none(self):
        """Untiered rules (no target_role in response) default to None."""
        body = approve_body(
            execution_status="pending_human_review",
            origin="human_gate",
            policy_recommendation="APPROVE",
        )
        d = Governor._parse_decision(body)
        assert d.target_role is None

    def test_decision_dataclass_accepts_target_role(self):
        """The Decision dataclass accepts target_role kwarg."""
        d = Decision(
            decision_id="dec-1",
            status="BLOCK",
            reason="high value",
            reason_code="POLICY_001",
            origin="human_gate",
            policy_recommendation="BLOCK",
            execution_status="pending_human_review",
            target_role="chief_risk_officer",
        )
        assert d.target_role == "chief_risk_officer"


# ---------------------------------------------------------------------------
# Terminal-states set
# ---------------------------------------------------------------------------
class TestTerminalStatuses:
    def test_terminal_statuses_include_all_final_outcomes(self):
        """The _TERMINAL_EXECUTION_STATUSES set covers every final state."""
        terminal = Governor._TERMINAL_EXECUTION_STATUSES
        # All the outcomes the HITL spec mentions.
        assert "executed" in terminal
        assert "blocked_by_human" in terminal
        assert "failed" in terminal
        assert "expired_auto_blocked" in terminal
        assert "shadow_skipped" in terminal
        assert "not_replayed_cached" in terminal

    def test_pending_is_not_terminal(self):
        """'pending_human_review' is NOT in the terminal set (it's the
        non-terminal polling state)."""
        assert "pending_human_review" not in Governor._TERMINAL_EXECUTION_STATUSES


# ---------------------------------------------------------------------------
# Full lifecycle: execute → poll → wait → terminal
# ---------------------------------------------------------------------------
class TestFullPollingLifecycle:
    @pytest.mark.asyncio
    async def test_execute_then_wait_for_decision(self, monkeypatch):
        """End-to-end: execute() returns pending, then wait_for_decision()
        polls until the human acts and the target is fired."""
        real_sleep = asyncio.sleep

        async def fast_sleep(delay, *a, **kw):
            await real_sleep(0)

        monkeypatch.setattr(asyncio, "sleep", fast_sleep)

        # The mock transport handler distinguishes /v1/execute from
        # /v1/decisions/{id} based on the URL path.
        poll_count = [0]

        def handler(req):
            path = str(req.url.path)
            if path == "/v1/execute":
                # execute() → pending
                return httpx.Response(200, json=approve_body(
                    decision_id="dec-lifecycle-001",
                    execution_status="pending_human_review",
                    origin="human_gate",
                    policy_recommendation="APPROVE",
                    escalation_id="esc-lifecycle-001",
                ))
            elif path.startswith("/v1/decisions/"):
                # poll → first pending, then executed.
                poll_count[0] += 1
                if poll_count[0] < 2:
                    return httpx.Response(200, json={
                        "decision_id": "dec-lifecycle-001",
                        "execution_status": "pending_human_review",
                        "origin": "human_gate",
                    })
                return httpx.Response(200, json={
                    "decision_id": "dec-lifecycle-001",
                    "execution_status": "executed",
                    "execution_response_code": 200,
                    "origin": "human_gate",
                })
            return httpx.Response(404)

        gov = make_async_governor(handler)
        # Step 1: execute
        d = await gov.execute("a1", "act1", "https://target.example.com/run")
        assert d.execution_status == "pending_human_review"
        assert d.decision_id == "dec-lifecycle-001"
        assert d.origin == "human_gate"

        # Step 2: wait for the human to act
        final = await gov.wait_for_decision(
            d.decision_id, timeout=5.0, poll_interval=0.01
        )
        assert final["execution_status"] == "executed"
        assert final["execution_response_code"] == 200
