"""Tests for retry logic, Retry-After parsing, and max_retries validation."""
import httpx
import pytest

from axiosky import AxioskyError, Governor
from axiosky.client import _parse_retry_after, MIN_RETRY_AFTER
from tests.conftest import make_governor, approve_body


class TestMaxRetriesValidation:
    def test_negative_max_retries_rejected(self):
        with pytest.raises(ValueError, match="max_retries"):
            Governor(api_key="k", max_retries=-1)

    def test_zero_max_retries_allowed(self):
        gov = Governor(api_key="k", max_retries=0)
        assert gov.max_retries == 0

    def test_positive_max_retries_allowed(self):
        gov = Governor(api_key="k", max_retries=5)
        assert gov.max_retries == 5


class TestRetryOn5xx:
    def test_retries_on_503(self, fast_sleep):
        attempts = {"n": 0}

        def handler(req):
            attempts["n"] += 1
            if attempts["n"] < 3:
                return httpx.Response(503, json={"detail": "down"})
            return httpx.Response(200, json=approve_body())

        gov = make_governor(handler, max_retries=3)
        decision = gov.evaluate("a1", "act1")
        assert decision.approved is True
        assert attempts["n"] == 3

    def test_retries_on_500(self, fast_sleep):
        attempts = {"n": 0}

        def handler(req):
            attempts["n"] += 1
            if attempts["n"] < 2:
                return httpx.Response(500, json={"detail": "err"})
            return httpx.Response(200, json=approve_body())

        gov = make_governor(handler, max_retries=2)
        decision = gov.evaluate("a1", "act1")
        assert decision.approved is True
        assert attempts["n"] == 2

    def test_5xx_exhausts_then_falls_back(self, fast_sleep):
        attempts = {"n": 0}

        def handler(req):
            attempts["n"] += 1
            return httpx.Response(503, json={"detail": "down"})

        gov = make_governor(handler, max_retries=2, fallback="deny")
        decision = gov.evaluate("a1", "act1")
        assert decision.blocked is True
        # 1 initial + 2 retries = 3 attempts
        assert attempts["n"] == 3


class TestRetryOn429:
    def test_retries_on_429(self, fast_sleep):
        attempts = {"n": 0}

        def handler(req):
            attempts["n"] += 1
            if attempts["n"] < 3:
                return httpx.Response(429, json={"detail": "slow down"})
            return httpx.Response(200, json=approve_body())

        gov = make_governor(handler, max_retries=3)
        decision = gov.evaluate("a1", "act1")
        assert decision.approved is True
        assert attempts["n"] == 3

    def test_429_honors_retry_after_seconds(self, fast_sleep):
        attempts = {"n": 0}

        def handler(req):
            attempts["n"] += 1
            if attempts["n"] < 2:
                return httpx.Response(
                    429, json={"detail": "slow"},
                    headers={"Retry-After": "0.1"},
                )
            return httpx.Response(200, json=approve_body())

        gov = make_governor(handler, max_retries=2)
        decision = gov.evaluate("a1", "act1")
        assert decision.approved is True
        assert attempts["n"] == 2

    def test_429_honors_retry_after_http_date(self, fast_sleep):
        import datetime as dt
        import email.utils

        attempts = {"n": 0}

        def handler(req):
            attempts["n"] += 1
            if attempts["n"] < 2:
                future = dt.datetime.now(
                    dt.timezone.utc
                ) + dt.timedelta(seconds=1)
                http_date = email.utils.format_datetime(future)
                return httpx.Response(
                    429, json={"detail": "slow"},
                    headers={"Retry-After": http_date},
                )
            return httpx.Response(200, json=approve_body())

        gov = make_governor(handler, max_retries=2)
        decision = gov.evaluate("a1", "act1")
        assert decision.approved is True
        assert attempts["n"] == 2


class TestNoRetryOn4xx:
    def test_no_retry_on_400(self):
        attempts = {"n": 0}

        def handler(req):
            attempts["n"] += 1
            return httpx.Response(400, json={"detail": "bad"})

        gov = make_governor(handler, max_retries=3)
        with pytest.raises(AxioskyError):
            gov.evaluate("a1", "act1")
        # Should NOT retry on 4xx
        assert attempts["n"] == 1

    def test_no_retry_on_401(self):
        attempts = {"n": 0}

        def handler(req):
            attempts["n"] += 1
            return httpx.Response(401, json={"detail": "nope"})

        gov = make_governor(handler, max_retries=3)
        with pytest.raises(AxioskyError):
            gov.evaluate("a1", "act1")
        assert attempts["n"] == 1

    def test_no_retry_on_404(self):
        attempts = {"n": 0}

        def handler(req):
            attempts["n"] += 1
            return httpx.Response(404, json={"detail": "missing"})

        gov = make_governor(handler, max_retries=3)
        with pytest.raises(AxioskyError):
            gov.evaluate("a1", "act1")
        assert attempts["n"] == 1


class TestRetryAfterParsing:
    def test_delta_seconds(self):
        assert _parse_retry_after("120") == 120
        assert _parse_retry_after("0.5") == 0.5

    def test_negative_clamped_to_min(self):
        assert _parse_retry_after("-5") == MIN_RETRY_AFTER

    def test_zero_clamped_to_min(self):
        assert _parse_retry_after("0") == MIN_RETRY_AFTER

    def test_http_date_future(self):
        import datetime as dt
        import email.utils

        future = dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=30)
        http_date = email.utils.format_datetime(future)
        result = _parse_retry_after(http_date)
        assert result is not None
        assert 25 <= result <= 35

    def test_http_date_past_clamped_to_min(self):
        import datetime as dt
        import email.utils

        past = dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=60)
        http_date = email.utils.format_datetime(past)
        result = _parse_retry_after(http_date)
        assert result == MIN_RETRY_AFTER

    def test_none_returns_none(self):
        assert _parse_retry_after(None) is None
        assert _parse_retry_after("") is None
        assert _parse_retry_after("   ") is None

    def test_garbage_returns_none(self):
        assert _parse_retry_after("not-a-date-or-number") is None

    def test_nan_returns_none(self):
        assert _parse_retry_after("nan") is None


class TestNonIdempotentNoRetry:
    def test_resolve_escalation_no_retry_on_transport_error(self, fast_sleep):
        """resolve_escalation mutates state and has no idempotency key,
        so it must NOT retry on transport errors."""
        attempts = {"n": 0}

        def handler(req):
            attempts["n"] += 1
            raise httpx.ConnectError("nope")

        gov = make_governor(handler, max_retries=3)
        with pytest.raises(AxioskyError):
            gov.resolve_escalation("esc-123", "approve", "alice", "admin")
        # Only one attempt — no retry on transport error
        assert attempts["n"] == 1

    def test_resolve_escalation_retries_on_429(self, fast_sleep):
        """429 is safe to retry (request was not processed)."""
        attempts = {"n": 0}

        def handler(req):
            attempts["n"] += 1
            if attempts["n"] < 2:
                return httpx.Response(429, json={"detail": "slow"})
            return httpx.Response(200, json={"escalation_id": "esc-123", "status": "approved"})

        gov = make_governor(handler, max_retries=3)
        result = gov.resolve_escalation("esc-123", "approve", "alice", "admin")
        assert attempts["n"] == 2
        assert result["status"] == "approved"


class TestTransportErrorRetry:
    def test_retries_on_connect_error(self, fast_sleep):
        attempts = {"n": 0}

        def handler(req):
            attempts["n"] += 1
            if attempts["n"] < 3:
                raise httpx.ConnectError("refused")
            return httpx.Response(200, json=approve_body())

        gov = make_governor(handler, max_retries=3)
        decision = gov.evaluate("a1", "act1")
        assert decision.approved is True
        assert attempts["n"] == 3

    def test_retries_on_timeout(self, fast_sleep):
        attempts = {"n": 0}

        def handler(req):
            attempts["n"] += 1
            if attempts["n"] < 2:
                raise httpx.TimeoutException("timed out")
            return httpx.Response(200, json=approve_body())

        gov = make_governor(handler, max_retries=2)
        decision = gov.evaluate("a1", "act1")
        assert decision.approved is True
        assert attempts["n"] == 2
