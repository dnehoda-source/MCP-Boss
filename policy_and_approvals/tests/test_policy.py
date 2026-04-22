from datetime import datetime, timezone

import pytest

from policy_and_approvals.models import Decision, ToolCall
from policy_and_approvals.policy import PolicyEngine, PolicyRule


def _call(tool, **entities):
    return ToolCall(tool_name=tool, args={}, actor="llm:test", entities=entities)


def test_allow_rule_matches_tool():
    engine = PolicyEngine(
        [PolicyRule(name="r", tools=["get_scc_findings"], decision=Decision.ALLOW, reason="read-only")],
        default_decision=Decision.DENY,
    )
    d = engine.evaluate(_call("get_scc_findings"))
    assert d.decision == Decision.ALLOW
    assert d.matched_rule == "r"


def test_default_applied_when_no_rule_matches():
    engine = PolicyEngine([], default_decision=Decision.REQUIRE_APPROVAL)
    d = engine.evaluate(_call("purge_email_o365"))
    assert d.decision == Decision.REQUIRE_APPROVAL
    assert d.matched_rule is None


def test_priority_ordering():
    engine = PolicyEngine(
        [
            PolicyRule(name="low", tools=["*"], decision=Decision.ALLOW, reason="wildcard", priority=1),
            PolicyRule(name="high", tools=["purge_email_o365"], decision=Decision.DENY, reason="no", priority=100),
        ],
        default_decision=Decision.ALLOW,
    )
    assert engine.evaluate(_call("purge_email_o365")).matched_rule == "high"
    assert engine.evaluate(_call("get_scc_findings")).matched_rule == "low"


def test_when_entities_exact_match():
    engine = PolicyEngine(
        [
            PolicyRule(
                name="prod-deny",
                tools=["isolate_crowdstrike_host"],
                decision=Decision.DENY,
                when_entities={"environment": "prod"},
                reason="prod freeze",
                priority=10,
            )
        ]
    )
    assert engine.evaluate(_call("isolate_crowdstrike_host", environment="prod")).decision == Decision.DENY
    assert engine.evaluate(_call("isolate_crowdstrike_host", environment="dev")).decision != Decision.DENY


def test_when_entities_regex():
    engine = PolicyEngine(
        [
            PolicyRule(
                name="vip",
                tools=["suspend_okta_user"],
                decision=Decision.DENY,
                when_entities={"user_email": "re:(ceo|cfo)@"},
                reason="protected",
                priority=10,
            )
        ]
    )
    assert engine.evaluate(_call("suspend_okta_user", user_email="ceo@acme.com")).decision == Decision.DENY
    assert engine.evaluate(_call("suspend_okta_user", user_email="alice@acme.com")).decision != Decision.DENY


def test_freeze_window_forces_approval_on_allow_rule():
    engine = PolicyEngine(
        [
            PolicyRule(
                name="window",
                tools=["toggle_rule"],
                decision=Decision.ALLOW,
                freeze_windows=[{"days": ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"], "start": "00:00", "end": "23:59"}],
                reason="always-on freeze",
                priority=10,
            )
        ]
    )
    now = datetime(2026, 4, 20, 12, 0, tzinfo=timezone.utc)  # a Monday
    decision = engine.evaluate(_call("toggle_rule"), now=now)
    assert decision.decision == Decision.REQUIRE_APPROVAL
    assert decision.freeze_window == "active"


def test_default_policies_yaml_loads():
    from pathlib import Path

    yaml_path = Path(__file__).resolve().parents[1] / "policies.yaml"
    engine = PolicyEngine.from_yaml(yaml_path)
    assert len(engine.rules) > 0
    # Read-only tool should be allowed
    assert engine.evaluate(_call("get_scc_findings")).decision == Decision.ALLOW
    # Destructive tool without entities should require approval
    assert engine.evaluate(_call("isolate_crowdstrike_host")).decision == Decision.REQUIRE_APPROVAL
    # Executive match should deny
    d = engine.evaluate(_call("suspend_okta_user", user_email="ceo@acme.com"))
    assert d.decision == Decision.DENY
