"""Tests for fallback / offline mode."""
import httpx
import pytest

from axiosky import AxioskyError, Governor
from tests.conftest import make_governor


class TestFallbackDeny:
    def test_transport_error_returns_synthetic_block(self):
        def handler(req):
            raise httpx.ConnectError("connection refused")

        gov = make_governor(handler, fallback="deny")
        decision = gov.evaluate("agent1", "action1")
        assert decision.blocked is True
        assert decision.reason_code == "FALLBACK_BLOCK"
        assert decision.decision_id.startswith("fallback-block-")

    def test_timeout_returns_synthetic_block(self):
        def handler(req):
            raise httpx.TimeoutException("timed out")

        gov = make_governor(handler, fallback="deny")
        decision = gov.evaluate("agent1", "action1")
        assert decision.blocked is True

    def test_5xx_after_retries_returns_block(self, fast_sleep):
        attempts = {"n": 0}

        def handler(req):
            attempts["n"] += 1
            return httpx.Response(503, json={"detail": "service unavailable"})

        gov = make_governor(handler, fallback="deny", max_retries=2)
        decision = gov.evaluate("agent1", "action1")
        assert decision.blocked is True
        assert decision.reason_code == "FALLBACK_BLOCK"
        # 1 initial + 2 retries = 3 attempts
        assert attempts["n"] == 3

    def test_no_info_leakage_in_reason(self):
        def handler(req):
            raise httpx.ConnectError(
                "connection refused to 10.0.0.5:8000 with api_key=secret"
            )

        gov = make_governor(handler, fallback="deny")
        decision = gov.evaluate("agent1", "action1")
        # The reason must NOT contain internal network details or the
        # exception message.
        assert "10.0.0.5" not in decision.reason
        assert "secret" not in decision.reason
        assert "connection refused" not in decision.reason
        assert decision.reason == "Governance API unreachable"


class TestFallbackAllow:
    def test_transport_error_returns_synthetic_approve(self):
        def handler(req):
            raise httpx.ConnectError("connection refused")

        gov = make_governor(handler, fallback="allow")
        decision = gov.evaluate("agent1", "action1")
        assert decision.approved is True
        assert decision.reason_code == "FALLBACK_ALLOW"

    def test_5xx_after_retries_returns_allow(self, fast_sleep):
        def handler(req):
            return httpx.Response(503, json={"detail": "down"})

        gov = make_governor(handler, fallback="allow", max_retries=1)
        decision = gov.evaluate("agent1", "action1")
        assert decision.approved is True


class TestFallbackRaise:
    def test_transport_error_raises(self):
        def handler(req):
            raise httpx.ConnectError("connection refused")

        gov = make_governor(handler, fallback="raise")
        with pytest.raises(AxioskyError):
            gov.evaluate("agent1", "action1")


class TestFallbackWith4xx:
    def test_4xx_never_falls_back(self):
        """A 4xx client error should raise, not fall back — the request
        is malformed and retrying / falling back won't help."""
        def handler(req):
            return httpx.Response(400, json={"detail": "bad request"})

        gov = make_governor(handler, fallback="deny")
        with pytest.raises(AxioskyError) as exc_info:
            gov.evaluate("agent1", "action1")
        assert exc_info.value.status_code == 400

    def test_401_never_falls_back(self):
        def handler(req):
            return httpx.Response(401, json={"detail": "unauthorized"})

        gov = make_governor(handler, fallback="deny")
        with pytest.raises(AxioskyError) as exc_info:
            gov.evaluate("agent1", "action1")
        assert exc_info.value.status_code == 401

    def test_404_never_falls_back(self):
        def handler(req):
            return httpx.Response(404, json={"detail": "not found"})

        gov = make_governor(handler, fallback="allow")
        with pytest.raises(AxioskyError):
            gov.evaluate("agent1", "action1")


class TestFallbackPerCall:
    def test_per_call_override(self):
        def handler(req):
            raise httpx.ConnectError("nope")

        gov = make_governor(handler, fallback="deny")
        # Override at call time
        with pytest.raises(AxioskyError):
            gov.evaluate("agent1", "action1", fallback="raise")
        # Default still denies
        d = gov.evaluate("agent1", "action1")
        assert d.blocked is True

    def test_invalid_fallback_at_init(self):
        with pytest.raises(ValueError):
            Governor(api_key="k", fallback="bogus")

    def test_invalid_fallback_at_call(self):
        gov = make_governor(lambda req: httpx.Response(200, json={}), fallback="deny")
        with pytest.raises(ValueError):
            gov.evaluate("a", "b", fallback="bogus")
