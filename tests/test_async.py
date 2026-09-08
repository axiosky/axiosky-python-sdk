"""Tests for AsyncGovernor — async path of every major method."""
import asyncio

import httpx
import pytest

from axiosky import AsyncGovernor, AxioskyError, GovernanceDeniedError
from tests.conftest import (
    approve_body,
    block_body,
    escalate_body,
    make_async_governor,
)


class TestAsyncEvaluate:
    @pytest.mark.asyncio
    async def test_approve(self):
        gov = make_async_governor(lambda req: httpx.Response(200, json=approve_body()))
        d = await gov.evaluate("a1", "act1")
        assert d.approved is True

    @pytest.mark.asyncio
    async def test_block(self):
        gov = make_async_governor(lambda req: httpx.Response(200, json=block_body()))
        d = await gov.evaluate("a1", "act1")
        assert d.blocked is True

    @pytest.mark.asyncio
    async def test_escalate(self):
        gov = make_async_governor(lambda req: httpx.Response(200, json=escalate_body()))
        d = await gov.evaluate("a1", "act1")
        assert d.escalated is True

    @pytest.mark.asyncio
    async def test_fallback_deny_on_transport_error(self):
        def handler(req):
            raise httpx.ConnectError("nope")

        gov = make_async_governor(handler, fallback="deny")
        d = await gov.evaluate("a1", "act1")
        assert d.blocked is True
        assert d.reason_code == "FALLBACK_BLOCK"

    @pytest.mark.asyncio
    async def test_4xx_raises(self):
        def handler(req):
            return httpx.Response(403, json={"detail": "forbidden"})

        gov = make_async_governor(handler)
        with pytest.raises(AxioskyError) as exc_info:
            await gov.evaluate("a1", "act1")
        assert exc_info.value.status_code == 403


class TestAsyncExecute:
    @pytest.mark.asyncio
    async def test_execute_with_target_url(self):
        seen = {}

        def handler(req):
            import json as _json
            body = _json.loads(req.content)
            seen["target_url"] = body.get("target_url")
            return httpx.Response(200, json=approve_body())

        gov = make_async_governor(handler)
        d = await gov.execute("a1", "act1", "https://api.example.com/hooks")
        assert d.approved is True
        assert seen["target_url"] == "https://api.example.com/hooks"

    @pytest.mark.asyncio
    async def test_execute_rejects_bad_scheme(self):
        gov = make_async_governor(lambda req: httpx.Response(200, json=approve_body()))
        with pytest.raises(AxioskyError, match="scheme"):
            await gov.execute("a1", "act1", "file:///etc/passwd")


class TestAsyncOtherMethods:
    @pytest.mark.asyncio
    async def test_verify_chain(self):
        gov = make_async_governor(lambda req: httpx.Response(200, json={"chain_intact": True}))
        result = await gov.verify_chain("tenant1")
        assert result["chain_intact"] is True

    @pytest.mark.asyncio
    async def test_get_audit_logs(self):
        gov = make_async_governor(lambda req: httpx.Response(200, json={"entries": []}))
        result = await gov.get_audit_logs("tenant1")
        assert result["entries"] == []

    @pytest.mark.asyncio
    async def test_get_shadow_report(self):
        gov = make_async_governor(lambda req: httpx.Response(200, json={"summary": {}}))
        result = await gov.get_shadow_report("tenant1")
        assert "summary" in result

    @pytest.mark.asyncio
    async def test_get_escalations(self):
        gov = make_async_governor(lambda req: httpx.Response(200, json={"escalations": []}))
        result = await gov.get_escalations()
        assert result["escalations"] == []

    @pytest.mark.asyncio
    async def test_resolve_escalation(self):
        gov = make_async_governor(lambda req: httpx.Response(200, json={"status": "approved"}))
        result = await gov.resolve_escalation("esc-1", "approve", "alice", "admin")
        assert result["status"] == "approved"

    @pytest.mark.asyncio
    async def test_resolve_escalation_path_injection(self):
        gov = make_async_governor(lambda req: httpx.Response(200, json={}))
        with pytest.raises(AxioskyError, match="escalation_id"):
            await gov.resolve_escalation("../admin", "approve", "a", "b")

    @pytest.mark.asyncio
    async def test_get_policy_templates(self):
        gov = make_async_governor(lambda req: httpx.Response(200, json={"templates": []}))
        result = await gov.get_policy_templates(jwt="jwt.token")
        assert result["templates"] == []


class TestAsyncRetry:
    @pytest.mark.asyncio
    async def test_retries_on_503(self, fast_sleep_async):
        attempts = {"n": 0}

        def handler(req):
            attempts["n"] += 1
            if attempts["n"] < 3:
                return httpx.Response(503, json={"detail": "down"})
            return httpx.Response(200, json=approve_body())

        gov = make_async_governor(handler, max_retries=3)
        d = await gov.evaluate("a1", "act1")
        assert d.approved is True
        assert attempts["n"] == 3

    @pytest.mark.asyncio
    async def test_retries_on_429_with_retry_after(self, fast_sleep_async):
        attempts = {"n": 0}

        def handler(req):
            attempts["n"] += 1
            if attempts["n"] < 2:
                return httpx.Response(
                    429, json={"detail": "slow"},
                    headers={"Retry-After": "0.1"},
                )
            return httpx.Response(200, json=approve_body())

        gov = make_async_governor(handler, max_retries=2)
        d = await gov.evaluate("a1", "act1")
        assert d.approved is True
        assert attempts["n"] == 2

    @pytest.mark.asyncio
    async def test_no_retry_on_400(self):
        attempts = {"n": 0}

        def handler(req):
            attempts["n"] += 1
            return httpx.Response(400, json={"detail": "bad"})

        gov = make_async_governor(handler, max_retries=3)
        with pytest.raises(AxioskyError):
            await gov.evaluate("a1", "act1")
        assert attempts["n"] == 1


class TestAsyncLifecycle:
    @pytest.mark.asyncio
    async def test_aclose(self):
        gov = make_async_governor(lambda req: httpx.Response(200, json=approve_body()))
        await gov.aclose()
        # Client should be closed now
        assert gov._client.is_closed is True

    @pytest.mark.asyncio
    async def test_close_alias(self):
        gov = make_async_governor(lambda req: httpx.Response(200, json=approve_body()))
        await gov.close()
        assert gov._client.is_closed is True

    @pytest.mark.asyncio
    async def test_async_context_manager(self):
        async with make_async_governor(lambda req: httpx.Response(200, json=approve_body())) as gov:
            d = await gov.evaluate("a1", "act1")
            assert d.approved is True
        assert gov._client.is_closed is True
