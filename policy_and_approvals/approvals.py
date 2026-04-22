"""Approval broker: owns the lifecycle of pending approval requests."""

from __future__ import annotations

import threading
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from .channels.base import ApprovalChannel
from .models import (
    ApprovalRequest,
    ApprovalState,
    DryRunPreview,
    PolicyDecision,
    ToolCall,
)


class ApprovalBroker:
    def __init__(
        self,
        channels: List[ApprovalChannel],
        default_ttl_seconds: int = 3600,
    ):
        self._channels = channels
        self._by_id: Dict[str, ApprovalRequest] = {}
        self._lock = threading.Lock()
        self._ttl = default_ttl_seconds

    def request(
        self,
        tool_call: ToolCall,
        policy_decision: PolicyDecision,
        dry_run: DryRunPreview,
    ) -> ApprovalRequest:
        approval_id = str(uuid.uuid4())
        expires = datetime.now(timezone.utc) + timedelta(seconds=self._ttl)
        req = ApprovalRequest(
            approval_id=approval_id,
            tool_call=tool_call,
            policy_decision=policy_decision,
            dry_run=dry_run,
            state=ApprovalState.PENDING,
            expires_at=expires.isoformat(),
            channel=",".join(c.name for c in self._channels) or None,
        )
        with self._lock:
            self._by_id[approval_id] = req
        for ch in self._channels:
            try:
                ch.request_approval(req)
            except Exception:
                pass
        return req

    def get(self, approval_id: str) -> Optional[ApprovalRequest]:
        with self._lock:
            return self._by_id.get(approval_id)

    def pending(self) -> List[ApprovalRequest]:
        with self._lock:
            return [r for r in self._by_id.values() if r.state == ApprovalState.PENDING]

    def all(self) -> List[ApprovalRequest]:
        with self._lock:
            return list(self._by_id.values())

    def decide(
        self,
        approval_id: str,
        decision: str,
        decided_by: str,
        reason: str = "",
    ) -> Optional[ApprovalRequest]:
        with self._lock:
            req = self._by_id.get(approval_id)
            if not req:
                return None
            if req.state != ApprovalState.PENDING:
                return req
            if req.expires_at and datetime.fromisoformat(req.expires_at) < datetime.now(timezone.utc):
                req.state = ApprovalState.EXPIRED
                return req
            d = decision.lower()
            if d in ("approve", "approved", "allow"):
                req.state = ApprovalState.APPROVED
            elif d in ("deny", "denied", "reject", "rejected"):
                req.state = ApprovalState.DENIED
            else:
                return None
            req.decided_at = datetime.now(timezone.utc).isoformat()
            req.decided_by = decided_by
            req.decision_reason = reason
        for ch in self._channels:
            try:
                ch.on_decision(req)
            except Exception:
                pass
        return req

    def mark_executed(self, approval_id: str, result: str) -> None:
        with self._lock:
            req = self._by_id.get(approval_id)
            if req:
                req.state = ApprovalState.EXECUTED
                req.result = result

    def mark_failed(self, approval_id: str, err: str) -> None:
        with self._lock:
            req = self._by_id.get(approval_id)
            if req:
                req.state = ApprovalState.FAILED
                req.result = err
