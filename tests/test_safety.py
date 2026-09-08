"""Tests for malformed response handling, headers, repr, and exception hierarchy."""
import httpx
import pytest

from axiosky import (
    AsyncGovernor,
    AxioskyError,
    Decision,
    DecisionStatus,
    Governor,
    GovernanceDeniedError,
    GovernanceEscalatedError,
    __version__,
)
from tests.conftest import (
    approve_body,
    block_body,
    escalate_body,
    make_async_governor,
    make_governor,
)


class TestMalformedResponse:
    def test_missing_required_field_raises_axiosky_error(self):
        """A response missing 'status' must raise AxioskyError, not KeyError."""
        def handler(req):
            return httpx.Response(200, json={
                "decision_id": "d1",
                # missing "status"
                "reason": "ok",
                "reason_code": "OK",
            })

        gov = make_governor(handler)
        with pytest.raises(AxioskyError, match="Malformed"):
            gov.evaluate("a1", "act1")

    def test_missing_decision_id_raises_axiosky_error(self):
        def handler(req):
            return httpx.Response(200, json={
                "status": "APPROVE",
                "reason": "ok",
                "reason_code": "OK",
            })

        gov = make_governor(handler)
        with pytest.raises(AxioskyError, match="Malformed"):
            gov.evaluate("a1", "act1")

    def test_non_object_response_raises_axiosky_error(self):
        def handler(req):
            return httpx.Response(200, json=[1, 2, 3])

        gov = make_governor(handler)
        with pytest.raises(AxioskyError, match="Malformed"):
            gov.evaluate("a1", "act1")

    def test_null_field_raises_axiosky_error(self):
        def handler(req):
            return httpx.Response(200, json={
                "decision_id": None,  # null
                "status": "APPROVE",
                "reason": "ok",
                "reason_code": "OK",
            })

        gov = make_governor(handler)
        with pytest.raises(AxioskyError):
            gov.evaluate("a1", "act1")

    def test_no_keyerror_leaks(self):
        """Ensure no raw KeyError or TypeError surfaces."""
        def handler(req):
            return httpx.Response(200, json={})

        gov = make_governor(handler)
        try:
            gov.evaluate("a1", "act1")
            assert False, "should have raised"
        except AxioskyError:
            pass
        except (KeyError, TypeError):
            assert False, "raw KeyError/TypeError leaked"


class TestUserAgentHeader:
    def test_user_agent_on_evaluate(self):
        seen = {}

        def handler(req):
            seen["ua"] = req.headers.get("user-agent")
            return httpx.Response(200, json=approve_body())

        gov = make_governor(handler)
        gov.evaluate("a1", "act1")
        assert seen["ua"] == f"axiosky-python/{__version__}"

    def test_user_agent_on_get_audit_logs(self):
        seen = {}

        def handler(req):
            seen["ua"] = req.headers.get("user-agent")
            return httpx.Response(200, json={"entries": []})

        gov = make_governor(handler)
        gov.get_audit_logs("tenant1")
        assert seen["ua"] == f"axiosky-python/{__version__}"

    def test_user_agent_on_resolve_escalation(self):
        seen = {}

        def handler(req):
            seen["ua"] = req.headers.get("user-agent")
            return httpx.Response(200, json={"status": "approved"})

        gov = make_governor(handler)
        gov.resolve_escalation("esc-1", "approve", "a", "b")
        assert seen["ua"] == f"axiosky-python/{__version__}"

    def test_user_agent_on_get_policy_templates(self):
        seen = {}

        def handler(req):
            seen["ua"] = req.headers.get("user-agent")
            return httpx.Response(200, json={"templates": []})

        gov = make_governor(handler)
        gov.get_policy_templates(jwt="some.jwt.token")
        assert seen["ua"] == f"axiosky-python/{__version__}"


class TestAuthorizationHeader:
    def test_api_key_in_authorization_header(self):
        seen = {}

        def handler(req):
            seen["auth"] = req.headers.get("authorization")
            return httpx.Response(200, json=approve_body())

        gov = make_governor(handler)
        gov.evaluate("a1", "act1")
        assert seen["auth"] == "Bearer test-key-1234567890"

    def test_jwt_overrides_api_key_for_policy_templates(self):
        seen = {}

        def handler(req):
            seen["auth"] = req.headers.get("authorization")
            return httpx.Response(200, json={"templates": []})

        gov = make_governor(handler)
        gov.get_policy_templates(jwt="my.jwt.token")
        assert seen["auth"] == "Bearer my.jwt.token"

    def test_idempotency_key_header(self):
        seen = {}

        def handler(req):
            seen["idem"] = req.headers.get("x-idempotency-key")
            return httpx.Response(200, json=approve_body())

        gov = make_governor(handler)
        gov.evaluate("a1", "act1", idempotency_key="custom-key-123")
        assert seen["idem"] == "custom-key-123"

    def test_auto_generated_idempotency_key(self):
        seen = {}

        def handler(req):
            seen["idem"] = req.headers.get("x-idempotency-key")
            return httpx.Response(200, json=approve_body())

        gov = make_governor(handler)
        gov.evaluate("a1", "act1")
        assert seen["idem"] is not None
        assert len(seen["idem"]) > 0


class TestReprDoesNotLeakApiKey:
    def test_repr_masks_api_key(self):
        secret = "sk-super-secret-key-abc123-xyz789"
        gov = Governor(api_key=secret, base_url="http://test.local")
        r = repr(gov)
        assert secret not in r
        assert "super-secret" not in r
        assert "abc123" not in r
        assert "xyz789" not in r
        assert "***" in r

    def test_str_masks_api_key(self):
        secret = "sk-super-secret-key-abc123-xyz789"
        gov = Governor(api_key=secret, base_url="http://test.local")
        s = str(gov)
        assert secret not in s
        assert "super-secret" not in s

    def test_repr_of_async_governor_masks(self):
        secret = "sk-super-secret-key-abc123-xyz789"
        gov = AsyncGovernor(api_key=secret, base_url="http://test.local")
        r = repr(gov)
        assert secret not in r

    def test_error_messages_dont_leak_api_key(self):
        secret = "sk-super-secret-key-abc123"
        def handler(req):
            return httpx.Response(401, json={"detail": "bad key"})

        gov = make_governor(handler)
        gov._api_key = secret  # override for test
        # Rebuild client with new key
        gov._client = httpx.Client(
            base_url=gov.base_url,
            transport=httpx.MockTransport(handler),
            headers=gov._default_headers(),
            timeout=gov.timeout,
        )
        with pytest.raises(AxioskyError) as exc_info:
            gov.evaluate("a1", "act1")
        assert secret not in str(exc_info.value)


class TestExceptionHierarchy:
    def test_governance_denied_is_axiosky_error(self):
        d = Decision("d1", "BLOCK", "no", "DENIED")
        err = GovernanceDeniedError(d)
        assert isinstance(err, AxioskyError)
        assert isinstance(err, Exception)

    def test_governance_escalated_is_axiosky_error(self):
        d = Decision("d1", "ESCALATE", "review", "ESC")
        err = GovernanceEscalatedError(d)
        assert isinstance(err, AxioskyError)

    def test_catch_all_with_axiosky_error(self):
        """A caller should be able to catch all SDK errors with one except."""
        d = Decision("d1", "BLOCK", "no", "DENIED")
        errors = [AxioskyError(500, "x"), GovernanceDeniedError(d), GovernanceEscalatedError(d)]
        for e in errors:
            assert isinstance(e, AxioskyError)

    def test_denied_error_carries_decision(self):
        d = Decision("d1", "BLOCK", "blocked by rule X", "DENIED")
        err = GovernanceDeniedError(d)
        assert err.decision is d
        assert "DENIED" in str(err)

    def test_escalated_error_carries_decision(self):
        d = Decision("d1", "ESCALATE", "review", "ESC", escalation_id="esc-9")
        err = GovernanceEscalatedError(d)
        assert err.decision is d
        assert "esc-9" in str(err)
