"""
MCP Boss — Policy, Approvals, and Audit.

Public API:
    PolicyEngine.from_yaml(path) -> engine
    ApprovalBroker(channels, default_ttl_seconds) -> broker
    AuditLog(path, mirror_to_cloud) -> audit
    PolicyGate(engine, broker, audit)

Usage in main.py:
    from policy_and_approvals import build_default_gate, register_http_routes, RAW_TOOLS

    gate = build_default_gate()  # loads policies.yaml, sets up broker + audit

    @app_mcp.tool()
    @gate.guard(dry_run_builder=preview_purge_email,
                entity_extractor=lambda target_mailbox, message_id, **_:
                    {"mailbox": target_mailbox, "message_id": message_id})
    def purge_email_o365(target_mailbox, message_id, purge_type="hardDelete") -> str:
        ...

    # After Starlette app is built:
    register_http_routes(_starlette_app, gate)
"""

from .models import (
    ToolCall,
    Decision,
    PolicyDecision,
    DryRunPreview,
    ApprovalRequest,
    ApprovalState,
    AuditRecord,
)
from .policy import PolicyEngine, PolicyRule
from .audit import AuditLog
from .approvals import ApprovalBroker
from .decorator import PolicyGate, RAW_TOOLS
from .api import register_http_routes
from .bootstrap import build_default_gate

__all__ = [
    "ToolCall",
    "Decision",
    "PolicyDecision",
    "DryRunPreview",
    "ApprovalRequest",
    "ApprovalState",
    "AuditRecord",
    "PolicyEngine",
    "PolicyRule",
    "AuditLog",
    "ApprovalBroker",
    "PolicyGate",
    "RAW_TOOLS",
    "register_http_routes",
    "build_default_gate",
]
