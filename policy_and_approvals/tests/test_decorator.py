import json

from policy_and_approvals.approvals import ApprovalBroker
from policy_and_approvals.audit import AuditLog
from policy_and_approvals.channels import WebUIChannel
from policy_and_approvals.decorator import PolicyGate, RAW_TOOLS
from policy_and_approvals.models import Decision, DryRunPreview
from policy_and_approvals.policy import PolicyEngine, PolicyRule


def _preview(value, **_):
    return DryRunPreview(
        tool_name="fake_tool",
        args={"value": value},
        entities={"entity": value},
        side_effects=[f"Would do thing with {value}"],
        reversible=True,
        reversal_hint="undo_it()",
    )


def _entities(value, **_):
    return {"entity": value}


def _build_gate(rules, tmp_path, default=Decision.REQUIRE_APPROVAL):
    engine = PolicyEngine(rules, default_decision=default)
    audit = AuditLog(path=tmp_path / "audit.jsonl", mirror_to_cloud=False)
    broker = ApprovalBroker([WebUIChannel()])
    return PolicyGate(engine, broker, audit)


def test_allow_executes_tool(tmp_path):
    gate = _build_gate(
        [PolicyRule(name="allow", tools=["fake_tool"], decision=Decision.ALLOW, reason="ok", priority=1)],
        tmp_path,
    )

    @gate.guard(dry_run_builder=_preview, entity_extractor=_entities)
    def fake_tool(value):
        return json.dumps({"ran": True, "value": value})

    result = json.loads(fake_tool(value="x"))
    assert result["ran"] is True
    assert any(r.event_type == "tool_executed" for r in gate.audit.iter_records())


def test_deny_blocks_execution(tmp_path):
    gate = _build_gate(
        [PolicyRule(name="deny", tools=["fake_tool"], decision=Decision.DENY, reason="nope", priority=1)],
        tmp_path,
    )

    @gate.guard(dry_run_builder=_preview, entity_extractor=_entities)
    def fake_tool(value):
        raise AssertionError("should not execute")

    result = json.loads(fake_tool(value="x"))
    assert result["status"] == "denied_by_policy"


def test_require_approval_returns_pending_and_executes_after_decision(tmp_path):
    gate = _build_gate(
        [PolicyRule(name="ra", tools=["fake_tool"], decision=Decision.REQUIRE_APPROVAL, reason="think", priority=1)],
        tmp_path,
    )

    executed = {"count": 0}

    @gate.guard(dry_run_builder=_preview, entity_extractor=_entities)
    def fake_tool(value):
        executed["count"] += 1
        return json.dumps({"ran": True, "value": value})

    # First call: pending
    result = json.loads(fake_tool(value="payload"))
    assert result["status"] == "pending_approval"
    approval_id = result["approval_id"]
    assert executed["count"] == 0

    # Approver decides: approve
    gate.broker.decide(approval_id, "approved", "alice@example.com", reason="investigated")
    exec_result = gate.execute_approved(approval_id)
    assert exec_result["status"] == "executed"
    assert executed["count"] == 1

    # Audit chain stays intact across the whole flow
    ok, _ = gate.audit.verify_chain()
    assert ok


def test_raw_tools_registry_populated(tmp_path):
    gate = _build_gate([], tmp_path, default=Decision.ALLOW)

    @gate.guard(dry_run_builder=_preview, entity_extractor=_entities)
    def registered_tool(value):
        return value

    assert "registered_tool" in RAW_TOOLS
