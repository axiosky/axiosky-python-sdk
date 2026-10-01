"""Tests for the @governed decorator and govern/agovern context managers."""
import asyncio

import httpx
import pytest

from axiosky import (
    AsyncGovernor,
    AxioskyError,
    Governor,
    GovernanceDeniedError,
    GovernanceEscalatedError,
    governed,
    govern,
    agovern,
)
from tests.conftest import (
    approve_body,
    block_body,
    decision_body,
    escalate_body,
    make_async_governor,
    make_governor,
)


# ---------------------------------------------------------------------------
# Sync @governed
# ---------------------------------------------------------------------------
class TestGovernedSync:
    def test_approve_runs_function(self):
        gov = make_governor(lambda req: httpx.Response(200, json=approve_body()))

        @governed("data_export", enforcement="evaluate_only", _axiosky_governor=gov)
        def export(user_id):
            return f"exported {user_id}"

        assert export(user_id=42) == "exported 42"

    def test_block_raises_governance_denied(self):
        gov = make_governor(lambda req: httpx.Response(200, json=block_body()))

        @governed("data_export", enforcement="evaluate_only", _axiosky_governor=gov)
        def export(user_id):
            return "should not run"

        with pytest.raises(GovernanceDeniedError):
            export(user_id=42)

    def test_escalate_raises_governance_escalated(self):
        gov = make_governor(lambda req: httpx.Response(200, json=escalate_body()))

        @governed("data_export", enforcement="evaluate_only", _axiosky_governor=gov)
        def export(user_id):
            return "should not run"

        with pytest.raises(GovernanceEscalatedError):
            export(user_id=42)

    def test_governor_supplied_at_call_time(self):
        gov = make_governor(lambda req: httpx.Response(200, json=approve_body()))

        @governed("data_export", enforcement="evaluate_only")
        def export(user_id):
            return f"exported {user_id}"

        # Governor not supplied at decoration time — must pass at call time.
        assert export(user_id=42, _axiosky_governor=gov) == "exported 42"

    def test_no_governor_raises(self):
        @governed("data_export", enforcement="evaluate_only")
        def export(user_id):
            return "should not run"

        with pytest.raises(AxioskyError, match="no Governor"):
            export(user_id=42)

    def test_agent_id_defaults_to_qualname(self):
        seen = {}

        def handler(req):
            import json as _json
            body = _json.loads(req.content)
            seen["agent_id"] = body["agent_id"]
            return httpx.Response(200, json=approve_body())

        gov = make_governor(handler)

        @governed("data_export", enforcement="evaluate_only", _axiosky_governor=gov)
        def export_user_data(user_id):
            return "ok"

        export_user_data(user_id=1)
        # qualname includes the class path and function name
        assert "export_user_data" in seen["agent_id"]
        assert "TestGovernedSync" in seen["agent_id"]

    def test_explicit_agent_id(self):
        seen = {}

        def handler(req):
            import json as _json
            body = _json.loads(req.content)
            seen["agent_id"] = body["agent_id"]
            return httpx.Response(200, json=approve_body())

        gov = make_governor(handler)

        @governed("data_export", agent_id="my-agent", enforcement="evaluate_only", _axiosky_governor=gov)
        def export(user_id):
            return "ok"

        export(user_id=1)
        assert seen["agent_id"] == "my-agent"

    def test_payload_fn_called_with_args(self):
        seen = {}

        def handler(req):
            import json as _json
            body = _json.loads(req.content)
            seen["payload"] = body["payload"]
            return httpx.Response(200, json=approve_body())

        gov = make_governor(handler)

        def make_payload(user_id, **kwargs):
            return {"user_id": user_id, "extra": "data"}

        @governed("data_export", payload_fn=make_payload, enforcement="evaluate_only", _axiosky_governor=gov)
        def export(user_id):
            return f"exported {user_id}"

        export(user_id=99)
        assert seen["payload"] == {"user_id": 99, "extra": "data"}

    def test_action_type_sent(self):
        seen = {}

        def handler(req):
            import json as _json
            body = _json.loads(req.content)
            seen["action_type"] = body["action_type"]
            return httpx.Response(200, json=approve_body())

        gov = make_governor(handler)

        @governed("custom_action", enforcement="evaluate_only", _axiosky_governor=gov)
        def do_thing():
            return "done"

        do_thing()
        assert seen["action_type"] == "custom_action"

    def test_kwargs_forwarded_to_evaluate(self):
        seen = {}

        def handler(req):
            import json as _json
            body = _json.loads(req.content)
            seen["environment"] = body["environment"]
            return httpx.Response(200, json=approve_body())

        gov = make_governor(handler)

        @governed("data_export", environment="shadow", enforcement="evaluate_only", _axiosky_governor=gov)
        def export():
            return "ok"

        export()
        assert seen["environment"] == "shadow"

    def test_decorator_preserves_function_metadata(self):
        gov = make_governor(lambda req: httpx.Response(200, json=approve_body()))

        @governed("data_export", enforcement="evaluate_only", _axiosky_governor=gov)
        def export(user_id):
            """My docstring."""
            return "ok"

        assert export.__name__ == "export"
        assert export.__doc__ == "My docstring."

    def test_nesting_decorators(self):
        gov = make_governor(lambda req: httpx.Response(200, json=approve_body()))
        call_log = []

        def deco(func):
            def wrapper(*args, **kwargs):
                call_log.append("outer-before")
                result = func(*args, **kwargs)
                call_log.append("outer-after")
                return result
            return wrapper

        @deco
        @governed("data_export", enforcement="evaluate_only", _axiosky_governor=gov)
        def export(user_id):
            call_log.append("inner")
            return f"exported {user_id}"

        result = export(user_id=1)
        assert result == "exported 1"
        assert call_log == ["outer-before", "inner", "outer-after"]

    def test_fallback_deny_blocks_when_api_unreachable(self):
        # Transport error → fallback="deny" → synthetic BLOCK → denied.
        def handler(req):
            raise httpx.ConnectError("connection refused")

        gov = make_governor(handler, fallback="deny")

        @governed("data_export", enforcement="evaluate_only", _axiosky_governor=gov)
        def export(user_id):
            return "should not run"

        with pytest.raises(GovernanceDeniedError):
            export(user_id=1)


# ---------------------------------------------------------------------------
# Async @governed
# ---------------------------------------------------------------------------
class TestGovernedAsync:
    @pytest.mark.asyncio
    async def test_async_approve_runs(self):
        gov = make_async_governor(lambda req: httpx.Response(200, json=approve_body()))

        @governed("data_export", enforcement="evaluate_only", _axiosky_governor=gov)
        async def export(user_id):
            await asyncio.sleep(0)
            return f"exported {user_id}"

        assert await export(user_id=42) == "exported 42"

    @pytest.mark.asyncio
    async def test_async_block_raises(self):
        gov = make_async_governor(lambda req: httpx.Response(200, json=block_body()))

        @governed("data_export", enforcement="evaluate_only", _axiosky_governor=gov)
        async def export(user_id):
            return "should not run"

        with pytest.raises(GovernanceDeniedError):
            await export(user_id=42)

    @pytest.mark.asyncio
    async def test_async_escalate_raises(self):
        gov = make_async_governor(lambda req: httpx.Response(200, json=escalate_body()))

        @governed("data_export", enforcement="evaluate_only", _axiosky_governor=gov)
        async def export(user_id):
            return "should not run"

        with pytest.raises(GovernanceEscalatedError):
            await export(user_id=42)

    @pytest.mark.asyncio
    async def test_async_governor_at_call_time(self):
        gov = make_async_governor(lambda req: httpx.Response(200, json=approve_body()))

        @governed("data_export", enforcement="evaluate_only")
        async def export(user_id):
            return f"exported {user_id}"

        assert await export(user_id=42, _axiosky_governor=gov) == "exported 42"

    @pytest.mark.asyncio
    async def test_async_payload_fn(self):
        seen = {}

        def handler(req):
            import json as _json
            body = _json.loads(req.content)
            seen["payload"] = body["payload"]
            return httpx.Response(200, json=approve_body())

        gov = make_async_governor(handler)

        def make_payload(user_id, **kwargs):
            return {"user_id": user_id}

        @governed("data_export", payload_fn=make_payload, enforcement="evaluate_only", _axiosky_governor=gov)
        async def export(user_id):
            return "ok"

        await export(user_id=7)
        assert seen["payload"] == {"user_id": 7}

    @pytest.mark.asyncio
    async def test_async_agent_id_qualname(self):
        seen = {}

        def handler(req):
            import json as _json
            body = _json.loads(req.content)
            seen["agent_id"] = body["agent_id"]
            return httpx.Response(200, json=approve_body())

        gov = make_async_governor(handler)

        @governed("data_export", enforcement="evaluate_only", _axiosky_governor=gov)
        async def export_async_fn(user_id):
            return "ok"

        await export_async_fn(user_id=1)
        assert "export_async_fn" in seen["agent_id"]


# ---------------------------------------------------------------------------
# govern / agovern context managers
# ---------------------------------------------------------------------------
class TestGovernContextManager:
    def test_govern_approve(self):
        gov = make_governor(lambda req: httpx.Response(200, json=approve_body()))
        with govern(gov, "data_export", agent_id="a1", payload={"x": 1}) as dec:
            assert dec.approved is True

    def test_govern_block_raises(self):
        gov = make_governor(lambda req: httpx.Response(200, json=block_body()))
        with pytest.raises(GovernanceDeniedError):
            with govern(gov, "data_export", agent_id="a1"):
                pass

    def test_govern_requires_agent_id(self):
        gov = make_governor(lambda req: httpx.Response(200, json=approve_body()))
        with pytest.raises(ValueError, match="agent_id"):
            with govern(gov, "data_export"):
                pass

    @pytest.mark.asyncio
    async def test_agovern_approve(self):
        gov = make_async_governor(lambda req: httpx.Response(200, json=approve_body()))
        async with agovern(gov, "data_export", agent_id="a1") as dec:
            assert dec.approved is True

    @pytest.mark.asyncio
    async def test_agovern_block_raises(self):
        gov = make_async_governor(lambda req: httpx.Response(200, json=block_body()))
        with pytest.raises(GovernanceDeniedError):
            async with agovern(gov, "data_export", agent_id="a1"):
                pass


# ---------------------------------------------------------------------------
# @governed default enforcement="human_gate" — the security-critical path.
# The wrapped function must run only after execute() + wait_for_decision()
# reach execution_status="executed" (human approved AND target confirmed).
# ---------------------------------------------------------------------------
def _human_gate_handler(final_execution_status, decision_id="dec-hg-1"):
    """Route /v1/execute -> pending, then /v1/decisions/{id} -> terminal."""
    def handler(req):
        if req.url.path == "/v1/execute":
            return httpx.Response(
                200,
                json=decision_body(
                    "APPROVE",
                    decision_id=decision_id,
                    origin="human_gate",
                    execution_status="pending_human_review",
                ),
            )
        if req.url.path == f"/v1/decisions/{decision_id}":
            return httpx.Response(
                200,
                json=decision_body(
                    "APPROVE",
                    decision_id=decision_id,
                    origin="human_gate",
                    execution_status=final_execution_status,
                ),
            )
        raise AssertionError(f"unexpected path {req.url.path}")
    return handler


class TestGovernedHumanGateDefault:
    def test_requires_target_url(self):
        with pytest.raises(ValueError, match="target_url"):
            @governed("loan_disbursal")
            def disburse(loan_id):
                return "should not be reachable"

    def test_approved_and_executed_runs_function(self):
        gov = make_governor(_human_gate_handler("executed"))

        @governed(
            "loan_disbursal",
            target_url="https://core.bank/disburse",
            poll_interval=0,
            _axiosky_governor=gov,
        )
        def disburse(loan_id):
            return f"disbursed {loan_id}"

        assert disburse(loan_id=7) == "disbursed 7"

    def test_human_rejection_raises_denied_and_skips_function(self):
        gov = make_governor(_human_gate_handler("blocked_by_human"))
        calls = []

        @governed(
            "loan_disbursal",
            target_url="https://core.bank/disburse",
            poll_interval=0,
            _axiosky_governor=gov,
        )
        def disburse(loan_id):
            calls.append(loan_id)
            return "should not run"

        with pytest.raises(GovernanceDeniedError):
            disburse(loan_id=7)
        assert calls == []

    def test_expired_auto_blocked_raises_denied(self):
        gov = make_governor(_human_gate_handler("expired_auto_blocked"))

        @governed(
            "loan_disbursal",
            target_url="https://core.bank/disburse",
            poll_interval=0,
            _axiosky_governor=gov,
        )
        def disburse(loan_id):
            return "should not run"

        with pytest.raises(GovernanceDeniedError):
            disburse(loan_id=7)

    def test_ambiguous_outcome_raises_not_governance_denied(self):
        # delivery_unconfirmed means "we don't know" — must not be treated
        # as either a clean approve or a clean deny; needs a human to
        # reconcile, so the wrapped function must NOT silently run.
        gov = make_governor(_human_gate_handler("delivery_unconfirmed"))
        calls = []

        @governed(
            "loan_disbursal",
            target_url="https://core.bank/disburse",
            poll_interval=0,
            _axiosky_governor=gov,
        )
        def disburse(loan_id):
            calls.append(loan_id)
            return "should not run"

        with pytest.raises(AxioskyError, match="delivery_unconfirmed"):
            disburse(loan_id=7)
        assert calls == []

    @pytest.mark.asyncio
    async def test_async_approved_and_executed_runs_function(self, fast_sleep_async):
        gov = make_async_governor(_human_gate_handler("executed"))

        @governed(
            "loan_disbursal",
            target_url="https://core.bank/disburse",
            poll_interval=0,
            _axiosky_governor=gov,
        )
        async def disburse(loan_id):
            return f"disbursed {loan_id}"

        assert await disburse(loan_id=9) == "disbursed 9"

    @pytest.mark.asyncio
    async def test_async_human_rejection_raises_denied(self, fast_sleep_async):
        gov = make_async_governor(_human_gate_handler("blocked_by_human"))

        @governed(
            "loan_disbursal",
            target_url="https://core.bank/disburse",
            poll_interval=0,
            _axiosky_governor=gov,
        )
        async def disburse(loan_id):
            return "should not run"

        with pytest.raises(GovernanceDeniedError):
            await disburse(loan_id=9)

    def test_evaluate_only_still_bypasses_human_review_when_explicitly_chosen(self):
        # The unsafe path still exists, but only when opted into by name.
        gov = make_governor(lambda req: httpx.Response(200, json=approve_body()))

        @governed("data_export", enforcement="evaluate_only", _axiosky_governor=gov)
        def export(user_id):
            return f"exported {user_id}"

        assert export(user_id=1) == "exported 1"

    def test_invalid_enforcement_value_rejected(self):
        with pytest.raises(ValueError, match="enforcement"):
            @governed("data_export", enforcement="whatever")
            def export(user_id):
                return "x"
