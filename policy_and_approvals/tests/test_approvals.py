from policy_and_approvals.approvals import ApprovalBroker
from policy_and_approvals.channels import WebUIChannel
from policy_and_approvals.models import (
    ApprovalState,
    Decision,
    DryRunPreview,
    PolicyDecision,
    ToolCall,
)


def _fake_request():
    call = ToolCall(tool_name="fake", args={}, actor="llm", entities={"user": "a@b.c"})
    pd = PolicyDecision(
        decision=Decision.REQUIRE_APPROVAL,
        matched_rule="test",
        reason="testing",
        approver_groups=["security"],
    )
    dr = DryRunPreview(
        tool_name="fake",
        args={},
        entities={"user": "a@b.c"},
        side_effects=["does a thing"],
        reversible=True,
    )
    return call, pd, dr


def test_request_and_get():
    broker = ApprovalBroker([WebUIChannel()])
    call, pd, dr = _fake_request()
    req = broker.request(call, pd, dr)
    assert req.state == ApprovalState.PENDING
    assert broker.get(req.approval_id) is req
    assert req in broker.pending()


def test_approve_transitions_state():
    broker = ApprovalBroker([WebUIChannel()])
    req = broker.request(*_fake_request())
    decided = broker.decide(req.approval_id, "approved", "alice")
    assert decided.state == ApprovalState.APPROVED
    assert decided.decided_by == "alice"


def test_deny_transitions_state():
    broker = ApprovalBroker([WebUIChannel()])
    req = broker.request(*_fake_request())
    decided = broker.decide(req.approval_id, "denied", "alice", reason="FP")
    assert decided.state == ApprovalState.DENIED
    assert decided.decision_reason == "FP"


def test_invalid_decision_value():
    broker = ApprovalBroker([WebUIChannel()])
    req = broker.request(*_fake_request())
    assert broker.decide(req.approval_id, "maybe", "alice") is None


def test_expired_approval_cannot_be_decided():
    broker = ApprovalBroker([WebUIChannel()], default_ttl_seconds=0)
    req = broker.request(*_fake_request())
    # TTL=0 → expired immediately on first decide attempt.
    result = broker.decide(req.approval_id, "approved", "alice")
    assert result.state == ApprovalState.EXPIRED


def test_mark_executed_and_failed():
    broker = ApprovalBroker([WebUIChannel()])
    req = broker.request(*_fake_request())
    broker.decide(req.approval_id, "approved", "alice")
    broker.mark_executed(req.approval_id, "ok")
    assert broker.get(req.approval_id).state == ApprovalState.EXECUTED
    assert broker.get(req.approval_id).result == "ok"
