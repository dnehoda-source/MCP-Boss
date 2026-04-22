"""YAML-driven policy engine.

Policy file schema (see policies.yaml for a working example):

    default_decision: require_approval    # allow | deny | require_approval
    rules:
      - name: "Block containment in production freeze"
        tools: [isolate_crowdstrike_host, revoke_aws_access_keys]
        decision: deny
        when_entities:
          environment: prod
        freeze_windows:
          - days: [Fri, Sat, Sun]
            start: "18:00"
            end:   "06:00"
        approvers: [security-leadership]
        reason: "Production freeze window — manual runbook required"
        priority: 100

Rules are evaluated in descending priority order. First match wins.
`when_entities` patterns:
  "literal"        exact match
  "*"              any non-null value
  "re:<regex>"     regex match
  [a, b, c]        any-of list
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, time, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from .models import Decision, PolicyDecision, ToolCall


@dataclass
class PolicyRule:
    name: str
    tools: List[str]
    decision: Decision
    when_entities: Dict[str, Any] = field(default_factory=dict)
    unless_entities: Dict[str, Any] = field(default_factory=dict)
    freeze_windows: List[Dict[str, Any]] = field(default_factory=list)
    approvers: List[str] = field(default_factory=list)
    reason: str = ""
    priority: int = 0

    def matches_tool(self, tool: str) -> bool:
        return "*" in self.tools or tool in self.tools

    def matches_entities(self, entities: Dict[str, Any]) -> bool:
        for key, pattern in self.when_entities.items():
            if not _match(pattern, entities.get(key)):
                return False
        for key, pattern in self.unless_entities.items():
            if _match(pattern, entities.get(key)):
                return False
        return True

    def in_freeze_window(self, now: datetime) -> bool:
        return any(_in_window(w, now) for w in self.freeze_windows)


def _match(pattern: Any, value: Any) -> bool:
    if value is None:
        return False
    if isinstance(pattern, list):
        return any(_match(p, value) for p in pattern)
    if isinstance(pattern, str):
        if pattern == "*":
            return True
        if pattern.startswith("re:"):
            return re.search(pattern[3:], str(value)) is not None
        return pattern == str(value)
    return pattern == value


def _in_window(window: Dict[str, Any], now: datetime) -> bool:
    if "from_utc" in window and "to_utc" in window:
        start = datetime.fromisoformat(window["from_utc"])
        end = datetime.fromisoformat(window["to_utc"])
        if start.tzinfo is None:
            start = start.replace(tzinfo=timezone.utc)
        if end.tzinfo is None:
            end = end.replace(tzinfo=timezone.utc)
        return start <= now <= end

    days = window.get("days")
    if days:
        day_abbr = now.strftime("%a").lower()[:3]
        allowed = [d.lower()[:3] for d in days]
        if day_abbr not in allowed:
            return False
    start_t = _parse_time(window.get("start", "00:00"))
    end_t = _parse_time(window.get("end", "23:59"))
    now_t = now.time()
    if start_t <= end_t:
        return start_t <= now_t <= end_t
    return now_t >= start_t or now_t <= end_t


def _parse_time(s: str) -> time:
    h, m = s.split(":")
    return time(int(h), int(m))


class PolicyEngine:
    def __init__(
        self,
        rules: List[PolicyRule],
        default_decision: Decision = Decision.REQUIRE_APPROVAL,
        default_approvers: Optional[List[str]] = None,
    ):
        self.rules = sorted(rules, key=lambda r: -r.priority)
        self.default = default_decision
        self.default_approvers = default_approvers or ["security-oncall"]

    @classmethod
    def from_yaml(cls, path: str | Path) -> "PolicyEngine":
        with open(path) as f:
            data = yaml.safe_load(f) or {}
        rules = [
            PolicyRule(
                name=r["name"],
                tools=r.get("tools", ["*"]),
                decision=Decision(r["decision"]),
                when_entities=r.get("when_entities", {}),
                unless_entities=r.get("unless_entities", {}),
                freeze_windows=r.get("freeze_windows", []),
                approvers=r.get("approvers", []),
                reason=r.get("reason", ""),
                priority=int(r.get("priority", 0)),
            )
            for r in data.get("rules", [])
        ]
        return cls(
            rules,
            default_decision=Decision(data.get("default_decision", "require_approval")),
            default_approvers=data.get("default_approvers", ["security-oncall"]),
        )

    def evaluate(self, call: ToolCall, now: Optional[datetime] = None) -> PolicyDecision:
        now = now or datetime.now(timezone.utc)
        for rule in self.rules:
            if not rule.matches_tool(call.tool_name):
                continue
            if not rule.matches_entities(call.entities):
                continue
            in_freeze = rule.in_freeze_window(now)
            decision = rule.decision
            reason = rule.reason
            if in_freeze and decision == Decision.ALLOW:
                decision = Decision.REQUIRE_APPROVAL
                reason = f"{rule.reason} (freeze window active, forcing approval)"
            return PolicyDecision(
                decision=decision,
                matched_rule=rule.name,
                reason=reason,
                approver_groups=rule.approvers or self.default_approvers,
                freeze_window="active" if in_freeze else None,
            )
        return PolicyDecision(
            decision=self.default,
            matched_rule=None,
            reason=f"No matching rule; using default '{self.default.value}'",
            approver_groups=self.default_approvers,
        )
