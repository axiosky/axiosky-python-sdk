"""Tests for DecisionStatus enum and Decision dataclass."""
import pytest

from axiosky import AxioskyError, Decision, DecisionStatus


class TestDecisionStatus:
    def test_case_insensitive_construction(self):
        assert DecisionStatus.from_value("APPROVE") is DecisionStatus.APPROVE
        assert DecisionStatus.from_value("approve") is DecisionStatus.APPROVE
        assert DecisionStatus.from_value("Approve") is DecisionStatus.APPROVE
        assert DecisionStatus.from_value("  approve  ") is DecisionStatus.APPROVE

    def test_block_case_insensitive(self):
        assert DecisionStatus.from_value("block") is DecisionStatus.BLOCK
        assert DecisionStatus.from_value("BLOCK") is DecisionStatus.BLOCK

    def test_escalate_case_insensitive(self):
        assert DecisionStatus.from_value("escalate") is DecisionStatus.ESCALATE
        assert DecisionStatus.from_value("ESCALATE") is DecisionStatus.ESCALATE

    def test_invalid_status_raises_axiosky_error(self):
        # The classic typo: "APRROVE" instead of "APPROVE"
        with pytest.raises(AxioskyError):
            DecisionStatus.from_value("APRROVE")

    def test_invalid_status_message_lists_valid_values(self):
        with pytest.raises(AxioskyError) as exc_info:
            DecisionStatus.from_value("MAYBE")
        msg = str(exc_info.value)
        assert "MAYBE" in msg
        assert "APPROVE" in msg
        assert "BLOCK" in msg
        assert "ESCALATE" in msg

    def test_non_string_raises(self):
        with pytest.raises(AxioskyError):
            DecisionStatus.from_value(None)
        with pytest.raises(AxioskyError):
            DecisionStatus.from_value(42)
        with pytest.raises(AxioskyError):
            DecisionStatus.from_value(["APPROVE"])

    def test_empty_string_raises(self):
        with pytest.raises(AxioskyError):
            DecisionStatus.from_value("")


class TestDecision:
    def test_approved_property(self):
        d = Decision("d1", "APPROVE", "ok", "OK")
        assert d.approved is True
        assert d.blocked is False
        assert d.escalated is False

    def test_blocked_property(self):
        d = Decision("d1", "BLOCK", "no", "DENIED")
        assert d.blocked is True
        assert d.approved is False

    def test_escalated_property(self):
        d = Decision("d1", "ESCALATE", "review", "ESC")
        assert d.escalated is True

    def test_properties_case_insensitive(self):
        d = Decision("d1", "approve", "ok", "OK")
        assert d.approved is True
        d2 = Decision("d1", "Block", "no", "DENIED")
        assert d2.blocked is True

    def test_decision_status_property(self):
        d = Decision("d1", "APPROVE", "ok", "OK")
        assert d.decision_status is DecisionStatus.APPROVE

    def test_decision_status_invalid_raises(self):
        d = Decision("d1", "MAYBE", "ok", "OK")
        with pytest.raises(AxioskyError):
            _ = d.decision_status

    def test_all_14_fields_mapped(self):
        d = Decision(
            decision_id="d1",
            status="APPROVE",
            reason="ok",
            reason_code="OK",
            timestamp="2024-01-01T00:00:00Z",
            latency_ms=42,
            shadow_result="BLOCK",
            shadow_result_reason="would-block",
            escalation_id=None,
            escalation_expires_minutes=None,
            rule_triggered="rule-1",
            policy_version="v1.2.3",
            execution_status="success",
            execution_response_code=200,
        )
        assert d.timestamp == "2024-01-01T00:00:00Z"
        assert d.latency_ms == 42
        assert d.shadow_result == "BLOCK"
        assert d.shadow_result_reason == "would-block"
        assert d.rule_triggered == "rule-1"
        assert d.policy_version == "v1.2.3"
        assert d.execution_status == "success"
        assert d.execution_response_code == 200

    def test_optional_fields_default_none(self):
        d = Decision("d1", "APPROVE", "ok", "OK")
        assert d.timestamp is None
        assert d.latency_ms is None
        assert d.escalation_id is None
        assert d.execution_status is None
