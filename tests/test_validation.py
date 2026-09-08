"""Tests for input validation, path injection, and URL safety."""
import httpx
import pytest

from axiosky import AxioskyError, Governor
from axiosky.client import _is_local_url, _validate_escalation_id, _validate_target_url
from tests.conftest import make_governor, approve_body


class TestInputValidation:
    def test_empty_agent_id_rejected(self):
        gov = make_governor(lambda req: httpx.Response(200, json=approve_body()))
        with pytest.raises(ValueError, match="agent_id"):
            gov.evaluate("", "action1")
        with pytest.raises(ValueError, match="agent_id"):
            gov.evaluate("   ", "action1")

    def test_empty_action_type_rejected(self):
        gov = make_governor(lambda req: httpx.Response(200, json=approve_body()))
        with pytest.raises(ValueError, match="action_type"):
            gov.evaluate("agent1", "")
        with pytest.raises(ValueError, match="action_type"):
            gov.evaluate("agent1", "   ")

    def test_non_string_agent_id_rejected(self):
        gov = make_governor(lambda req: httpx.Response(200, json=approve_body()))
        with pytest.raises(ValueError, match="agent_id"):
            gov.evaluate(None, "action1")
        with pytest.raises(ValueError, match="agent_id"):
            gov.evaluate(123, "action1")

    def test_non_string_action_type_rejected(self):
        gov = make_governor(lambda req: httpx.Response(200, json=approve_body()))
        with pytest.raises(ValueError, match="action_type"):
            gov.evaluate("agent1", None)

    def test_empty_api_key_rejected(self):
        with pytest.raises(ValueError, match="api_key"):
            Governor(api_key="")
        with pytest.raises(ValueError, match="api_key"):
            Governor(api_key=None)

    def test_empty_tenant_id_in_verify_chain(self):
        gov = make_governor(lambda req: httpx.Response(200, json={}))
        with pytest.raises(ValueError, match="tenant_id"):
            gov.verify_chain("")
        with pytest.raises(ValueError, match="tenant_id"):
            gov.verify_chain("   ")

    def test_empty_tenant_id_in_get_audit_logs(self):
        gov = make_governor(lambda req: httpx.Response(200, json={}))
        with pytest.raises(ValueError, match="tenant_id"):
            gov.get_audit_logs("")


class TestPathInjection:
    @pytest.mark.parametrize("bad_id", [
        "../etc/passwd",
        "..%2Fetc%2Fpasswd",
        "esc/../../admin",
        "esc 1",
        "esc\t1",
        "esc;rm-rf",
        "esc&other",
        "esc#frag",
        "esc?query=1",
        "esc@host",
        "",
        "   ",
        "esc.1",
        "esc_1",  # underscore not allowed
        "esc+1",
    ])
    def test_invalid_escalation_id_rejected(self, bad_id):
        with pytest.raises(AxioskyError, match="escalation_id"):
            _validate_escalation_id(bad_id)

    def test_valid_escalation_ids_accepted(self):
        _validate_escalation_id("esc-123")
        _validate_escalation_id("abc")
        _validate_escalation_id("ABC-123-XYZ")
        _validate_escalation_id("a")
        _validate_escalation_id("12345")

    def test_resolve_escalation_validates_before_request(self):
        """The handler must never be called for a bad escalation_id."""
        called = {"n": 0}

        def handler(req):
            called["n"] += 1
            return httpx.Response(200, json={})

        gov = make_governor(handler)
        with pytest.raises(AxioskyError, match="escalation_id"):
            gov.resolve_escalation("../admin", "approve", "a", "b")
        assert called["n"] == 0

    def test_resolve_escalation_rejects_non_string(self):
        gov = make_governor(lambda req: httpx.Response(200, json={}))
        with pytest.raises(AxioskyError, match="escalation_id"):
            gov.resolve_escalation(None, "approve", "a", "b")

    def test_resolve_escalation_rejects_bad_decision(self):
        gov = make_governor(lambda req: httpx.Response(200, json={}))
        with pytest.raises(ValueError, match="decision"):
            gov.resolve_escalation("esc-1", "maybe", "a", "b")


class TestTargetUrlScheme:
    @pytest.mark.parametrize("url", [
        "file:///etc/passwd",
        "ftp://example.com/file",
        "gopher://example.com/",
        "ssh://example.com/",
        "ldap://example.com/",
        "javascript:alert(1)",
        "data:text/html,<script>",
        "://no-scheme",
        "",
        "   ",
    ])
    def test_invalid_scheme_rejected(self, url):
        with pytest.raises(AxioskyError):
            _validate_target_url(url)

    def test_http_allowed(self):
        _validate_target_url("http://example.com/api")

    def test_https_allowed(self):
        _validate_target_url("https://example.com/api")

    def test_case_insensitive_scheme(self):
        _validate_target_url("HTTP://example.com/api")
        _validate_target_url("HTTPS://example.com/api")

    def test_execute_rejects_file_url(self):
        called = {"n": 0}

        def handler(req):
            called["n"] += 1
            return httpx.Response(200, json=approve_body())

        gov = make_governor(handler)
        with pytest.raises(AxioskyError, match="scheme"):
            gov.execute("agent1", "action1", "file:///etc/passwd")
        assert called["n"] == 0

    def test_execute_rejects_ftp_url(self):
        gov = make_governor(lambda req: httpx.Response(200, json=approve_body()))
        with pytest.raises(AxioskyError, match="scheme"):
            gov.execute("agent1", "action1", "ftp://example.com/file")


class TestLocalUrlDetection:
    @pytest.mark.parametrize("url", [
        "http://localhost:8000/",
        "http://localhost/",
        "http://127.0.0.1:8000/",
        "http://127.0.0.1/",
        "http://127.1.2.3/",  # 127.0.0.0/8 loopback
        "http://[::1]:8000/",
        "http://[::1]/",
        "http://10.0.0.1/",
        "http://10.255.255.255/",
        "http://172.16.0.1/",
        "http://172.31.255.255/",
        "http://192.168.1.1/",
        "http://192.168.0.0/",
        "http://169.254.1.1/",
        "http://169.254.169.254/",  # AWS metadata endpoint
        "http://[fe80::1]/",
        "http://[fe80::1234:5678:9abc:def0]/",
    ])
    def test_local_urls_detected(self, url):
        assert _is_local_url(url) is True, f"Expected {url} to be local"

    @pytest.mark.parametrize("url", [
        "http://8.8.8.8/",
        "http://1.1.1.1/",
        "http://example.com/",
        "http://api.axiosky.com/",
        "http://172.32.0.1/",  # just outside 172.16/12
        "http://11.0.0.1/",  # just outside 10/8
        "http://192.169.0.1/",  # just outside 192.168/16
        "http://170.254.1.1/",  # not link-local
    ])
    def test_public_urls_not_detected(self, url):
        assert _is_local_url(url) is False, f"Expected {url} to NOT be local"

    def test_no_hostname(self):
        assert _is_local_url("http://") is False

    def test_garbage_url(self):
        assert _is_local_url("not-a-url") is False
        assert _is_local_url("") is False
        assert _is_local_url(None) is False
