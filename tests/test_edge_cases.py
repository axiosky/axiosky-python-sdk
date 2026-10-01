"""Additional edge-case tests: deprecation warnings, config, lifecycle."""
import warnings

import httpx
import pytest

from axiosky import Governor, AsyncGovernor
from tests.conftest import make_governor, approve_body


class TestTenantIdDeprecation:
    def test_tenant_id_emits_deprecation_warning(self):
        gov = make_governor(lambda req: httpx.Response(200, json=approve_body()))
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            gov.evaluate("agent1", "action1", tenant_id="tenant-x")
            assert any(
                issubclass(wi.category, DeprecationWarning)
                and "tenant_id" in str(wi.message)
                for wi in w
            ), "expected DeprecationWarning for tenant_id"

    def test_no_tenant_id_no_warning(self):
        gov = make_governor(lambda req: httpx.Response(200, json=approve_body()))
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            gov.evaluate("agent1", "action1")
            # Should NOT emit a tenant_id deprecation
            assert not any(
                issubclass(wi.category, DeprecationWarning)
                and "tenant_id" in str(wi.message)
                for wi in w
            )

    def test_tenant_id_still_sent_in_body(self):
        """Despite the deprecation, tenant_id is still sent for backward compat."""
        seen = {}

        def handler(req):
            import json as _json
            body = _json.loads(req.content)
            seen["tenant_id"] = body.get("tenant_id")
            return httpx.Response(200, json=approve_body())

        gov = make_governor(handler)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            gov.evaluate("agent1", "action1", tenant_id="tenant-99")
        assert seen["tenant_id"] == "tenant-99"

    def test_no_tenant_id_omitted_from_body(self):
        seen = {}

        def handler(req):
            import json as _json
            body = _json.loads(req.content)
            seen["tenant_id"] = body.get("tenant_id")
            return httpx.Response(200, json=approve_body())

        gov = make_governor(handler)
        gov.evaluate("agent1", "action1")
        # tenant_id should NOT be in the body when not passed
        assert "tenant_id" not in seen or seen["tenant_id"] is None


class TestVerifyParameter:
    def test_verify_true_by_default(self):
        gov = Governor(api_key="k", base_url="http://test.local")
        assert gov.verify is True

    def test_verify_false(self):
        gov = Governor(api_key="k", base_url="http://test.local", verify=False)
        assert gov.verify is False

    def test_verify_string_path(self, tmp_path):
        # Use httpx's certifi bundle so this test also runs on Windows.
        import shutil
        import certifi

        ca_file = tmp_path / "ca-bundle.pem"
        shutil.copy(certifi.where(), ca_file)
        gov = Governor(
            api_key="k", base_url="http://test.local",
            verify=str(ca_file),
        )
        # The SDK stores it; httpx loads it at construction.
        assert gov.verify == str(ca_file)


class TestLimitsParameter:
    def test_default_limits(self):
        gov = Governor(api_key="k", base_url="http://test.local")
        assert gov.limits.max_connections == 100
        assert gov.limits.max_keepalive_connections == 20

    def test_custom_limits(self):
        custom = httpx.Limits(max_connections=50, max_keepalive_connections=10)
        gov = Governor(
            api_key="k", base_url="http://test.local", limits=custom,
        )
        assert gov.limits.max_connections == 50


class TestEnvironmentDefault:
    def test_default_environment_is_live(self):
        """Audit fix: environment default changed from 'shadow' to 'live'."""
        seen = {}

        def handler(req):
            import json as _json
            body = _json.loads(req.content)
            seen["environment"] = body["environment"]
            return httpx.Response(200, json=approve_body())

        gov = make_governor(handler)
        gov.evaluate("agent1", "action1")
        assert seen["environment"] == "live"

    def test_shadow_environment_passable(self):
        seen = {}

        def handler(req):
            import json as _json
            body = _json.loads(req.content)
            seen["environment"] = body["environment"]
            return httpx.Response(200, json=approve_body())

        gov = make_governor(handler)
        gov.evaluate("agent1", "action1", environment="shadow")
        assert seen["environment"] == "shadow"


class TestAllMethodsUseRetry:
    """Every method must route through _request_with_retry — verify by
    counting handler calls on a 429 (retryable)."""

    def test_get_audit_logs_retries_on_429(self, fast_sleep):
        attempts = {"n": 0}

        def handler(req):
            attempts["n"] += 1
            if attempts["n"] < 2:
                return httpx.Response(429, json={"detail": "slow"})
            return httpx.Response(200, json={"entries": []})

        gov = make_governor(handler, max_retries=2)
        gov.get_audit_logs("tenant1")
        assert attempts["n"] == 2

    def test_get_shadow_report_retries_on_429(self, fast_sleep):
        attempts = {"n": 0}

        def handler(req):
            attempts["n"] += 1
            if attempts["n"] < 2:
                return httpx.Response(429, json={"detail": "slow"})
            return httpx.Response(200, json={"summary": {}})

        gov = make_governor(handler, max_retries=2)
        gov.get_shadow_report("tenant1")
        assert attempts["n"] == 2

    def test_get_escalations_retries_on_429(self, fast_sleep):
        attempts = {"n": 0}

        def handler(req):
            attempts["n"] += 1
            if attempts["n"] < 2:
                return httpx.Response(429, json={"detail": "slow"})
            return httpx.Response(200, json={"escalations": []})

        gov = make_governor(handler, max_retries=2)
        gov.get_escalations()
        assert attempts["n"] == 2

    def test_get_policy_templates_retries_on_429(self, fast_sleep):
        attempts = {"n": 0}

        def handler(req):
            attempts["n"] += 1
            if attempts["n"] < 2:
                return httpx.Response(429, json={"detail": "slow"})
            return httpx.Response(200, json={"templates": []})

        gov = make_governor(handler, max_retries=2)
        gov.get_policy_templates(jwt="jwt.token")
        assert attempts["n"] == 2

    def test_verify_chain_retries_on_429(self, fast_sleep):
        attempts = {"n": 0}

        def handler(req):
            attempts["n"] += 1
            if attempts["n"] < 2:
                return httpx.Response(429, json={"detail": "slow"})
            return httpx.Response(200, json={"chain_intact": True})

        gov = make_governor(handler, max_retries=2)
        gov.verify_chain("tenant1")
        assert attempts["n"] == 2

    def test_resolve_escalation_retries_on_429(self, fast_sleep):
        """429 is safe to retry even for non-idempotent (request not processed)."""
        attempts = {"n": 0}

        def handler(req):
            attempts["n"] += 1
            if attempts["n"] < 2:
                return httpx.Response(429, json={"detail": "slow"})
            return httpx.Response(200, json={"status": "approved"})

        gov = make_governor(handler, max_retries=2)
        gov.resolve_escalation("esc-1", "approve", "alice", "admin")
        assert attempts["n"] == 2


class TestApiAccessLogging:
    def test_logger_name_is_axiosky(self):
        import axiosky.client as client_mod
        assert client_mod.logger.name == "axiosky"
