"""Data classes for the policy/approvals/audit subsystem."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid


class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class ApprovalState(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    EXECUTED = "executed"
    FAILED = "failed"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class ToolCall:
    tool_name: str
    args: Dict[str, Any]
    actor: str
    entities: Dict[str, Any] = field(default_factory=dict)
    reasoning: str = ""
    invocation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=_now_iso)


@dataclass
class PolicyDecision:
    decision: Decision
    matched_rule: Optional[str]
    reason: str
    approver_groups: List[str] = field(default_factory=list)
    freeze_window: Optional[str] = None


@dataclass
class DryRunPreview:
    """Structured preview of what the tool WILL do, shown to the approver."""
    tool_name: str
    args: Dict[str, Any]
    entities: Dict[str, Any]
    side_effects: List[str]
    reversible: bool
    reversal_hint: str = ""


@dataclass
class ApprovalRequest:
    approval_id: str
    tool_call: ToolCall
    policy_decision: PolicyDecision
    dry_run: DryRunPreview
    state: ApprovalState = ApprovalState.PENDING
    requested_at: str = field(default_factory=_now_iso)
    decided_at: Optional[str] = None
    decided_by: Optional[str] = None
    decision_reason: Optional[str] = None
    channel: Optional[str] = None
    expires_at: Optional[str] = None
    result: Optional[str] = None


@dataclass
class AuditRecord:
    """One immutable audit entry. Hash-chained to the previous via prev_hash."""
    seq: int
    timestamp: str
    event_type: str
    invocation_id: str
    actor: str
    tool_name: str
    args: Dict[str, Any]
    entities: Dict[str, Any]
    policy_decision: Optional[Dict[str, Any]] = None
    approval_id: Optional[str] = None
    approval_state: Optional[str] = None
    decided_by: Optional[str] = None
    reasoning: str = ""
    outcome: Optional[str] = None
    prev_hash: str = ""
    hash: str = ""
