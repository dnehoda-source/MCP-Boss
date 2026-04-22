"""One-line setup for the default gate used by main.py."""

from __future__ import annotations

import os
from pathlib import Path
from typing import List, Optional

from .approvals import ApprovalBroker
from .audit import AuditLog
from .channels import (
    ApprovalChannel,
    GenericWebhookChannel,
    GoogleChatChannel,
    WebUIChannel,
)
from .decorator import PolicyGate
from .policy import PolicyEngine


def _default_channels() -> List[ApprovalChannel]:
    channels: List[ApprovalChannel] = [WebUIChannel()]
    if os.environ.get("GOOGLE_CHAT_WEBHOOK_URL"):
        channels.append(GoogleChatChannel())
    if os.environ.get("APPROVAL_WEBHOOK_URL"):
        channels.append(GenericWebhookChannel())
    return channels


def build_default_gate(
    policies_path: Optional[str] = None,
    audit_path: Optional[str] = None,
    channels: Optional[List[ApprovalChannel]] = None,
    ttl_seconds: int = 3600,
) -> PolicyGate:
    pkg_dir = Path(__file__).parent
    policies = policies_path or str(pkg_dir / "policies.yaml")
    audit_p = audit_path or os.environ.get(
        "MCP_BOSS_AUDIT_PATH", "/var/log/mcp-boss/audit.jsonl"
    )

    engine = PolicyEngine.from_yaml(policies)
    audit = AuditLog(audit_p, mirror_to_cloud=True)
    broker = ApprovalBroker(channels or _default_channels(), default_ttl_seconds=ttl_seconds)
    return PolicyGate(engine, broker, audit)
