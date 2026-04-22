"""PolicyGate: the decorator that wraps destructive tools.

Usage in main.py:

    from policy_and_approvals import build_default_gate, RAW_TOOLS

    gate = build_default_gate()

    def _preview_purge_email(target_mailbox, message_id, purge_type="hardDelete", **_):
        return DryRunPreview(
            tool_name="purge_email_o365",
            args={"target_mailbox": target_mailbox, "message_id": message_id, "purge_type": purge_type},
            entities={"mailbox": target_mailbox, "message_id": message_id},
            side_effects=[f"{purge_type} email {message_id!r} from {target_mailbox}"],
            reversible=(purge_type == "softDelete"),
            reversal_hint="Item in Deleted Items folder; restorable via Graph." if purge_type == "softDelete" else "",
        )

    @app_mcp.tool()
    @gate.guard(dry_run_builder=_preview_purge_email)
    def purge_email_o365(target_mailbox, message_id, purge_type="hardDelete") -> str:
        ...
"""

from __future__ import annotations

import json
from dataclasses import asdict
from functools import wraps
from typing import Any, Callable, Dict, Optional

from .approvals import ApprovalBroker
from .audit import AuditLog
from .models import Decision, DryRunPreview, ToolCall
from .policy import PolicyEngine


# Global registry of unwrapped tool functions (needed to execute on approval).
RAW_TOOLS: Dict[str, Callable] = {}


class PolicyGate:
    def __init__(
        self,
        engine: PolicyEngine,
        broker: ApprovalBroker,
        audit: AuditLog,
    ):
        self.engine = engine
        self.broker = broker
        self.audit = audit

    def guard(
        self,
        dry_run_builder: Callable[..., DryRunPreview],
        entity_extractor: Optional[Callable[..., Dict[str, Any]]] = None,
    ):
        """Decorator factory. Applied INSIDE @app_mcp.tool()."""

        def outer(func: Callable) -> Callable:
            tool_name = func.__name__
            RAW_TOOLS[tool_name] = func

            @wraps(func)
            def wrapper(*args, **kwargs):
                # Optional metadata an LLM / orchestrator can inject:
                actor = kwargs.pop("_actor", "llm:unknown")
                reasoning = kwargs.pop("_reasoning", "")

                if entity_extractor is not None:
                    try:
                        entities = entity_extractor(*args, **kwargs) or {}
                    except Exception:
                        entities = dict(kwargs)
                else:
                    entities = {k: v for k, v in kwargs.items() if isinstance(v, (str, int, float, bool))}

                try:
                    preview = dry_run_builder(*args, **kwargs)
                except Exception as e:
                    preview = DryRunPreview(
                        tool_name=tool_name,
                        args=dict(kwargs),
                        entities=entities,
                        side_effects=[f"(preview unavailable: {e})"],
                        reversible=False,
                    )

                call = ToolCall(
                    tool_name=tool_name,
                    args={**{f"_arg{i}": a for i, a in enumerate(args)}, **kwargs},
                    actor=actor,
                    entities=entities,
                    reasoning=reasoning,
                )

                decision = self.engine.evaluate(call)
                self.audit.append(
                    "policy_decision",
                    invocation_id=call.invocation_id,
                    actor=actor,
                    tool_name=tool_name,
                    args=call.args,
                    entities=entities,
                    policy_decision={
                        "decision": decision.decision.value,
                        "rule": decision.matched_rule,
                        "reason": decision.reason,
                        "freeze_window": decision.freeze_window,
                    },
                    reasoning=reasoning,
                )

                if decision.decision == Decision.DENY:
                    return json.dumps(
                        {
                            "status": "denied_by_policy",
                            "tool": tool_name,
                            "rule": decision.matched_rule,
                            "reason": decision.reason,
                            "approvers_to_contact": decision.approver_groups,
                        }
                    )

                if decision.decision == Decision.REQUIRE_APPROVAL:
                    req = self.broker.request(call, decision, preview)
                    self.audit.append(
                        "approval_requested",
                        invocation_id=call.invocation_id,
                        actor=actor,
                        tool_name=tool_name,
                        args=call.args,
                        entities=entities,
                        approval_id=req.approval_id,
                        approval_state=req.state.value,
                    )
                    return json.dumps(
                        {
                            "status": "pending_approval",
                            "approval_id": req.approval_id,
                            "tool": tool_name,
                            "required_approvers": decision.approver_groups,
                            "reason": decision.reason,
                            "dry_run": asdict(preview),
                            "message": (
                                f"Action requires approval. Pending ID: {req.approval_id}. "
                                "Check the approvals panel or Google Chat."
                            ),
                        },
                        default=str,
                    )

                # Decision.ALLOW
                try:
                    result = func(*args, **kwargs)
                    self.audit.append(
                        "tool_executed",
                        invocation_id=call.invocation_id,
                        actor=actor,
                        tool_name=tool_name,
                        args=call.args,
                        entities=entities,
                        outcome="success",
                    )
                    return result
                except Exception as e:
                    self.audit.append(
                        "tool_failed",
                        invocation_id=call.invocation_id,
                        actor=actor,
                        tool_name=tool_name,
                        args=call.args,
                        entities=entities,
                        outcome=f"error: {e}",
                    )
                    raise

            wrapper.__wrapped_raw__ = func  # type: ignore[attr-defined]
            return wrapper

        return outer

    def execute_approved(self, approval_id: str) -> Dict[str, Any]:
        """Invoked by the HTTP approval endpoint after a human approves."""
        req = self.broker.get(approval_id)
        if not req:
            return {"error": "unknown approval_id"}
        if req.state.value != "approved":
            return {"error": f"approval state is {req.state.value}, not approved"}

        fn = RAW_TOOLS.get(req.tool_call.tool_name)
        if fn is None:
            return {"error": f"tool {req.tool_call.tool_name} not registered"}

        kwargs = {k: v for k, v in req.tool_call.args.items() if not k.startswith("_arg")}
        try:
            result = fn(**kwargs)
            self.broker.mark_executed(approval_id, str(result)[:4000])
            self.audit.append(
                "tool_executed",
                invocation_id=req.tool_call.invocation_id,
                actor=req.tool_call.actor,
                tool_name=req.tool_call.tool_name,
                args=req.tool_call.args,
                entities=req.tool_call.entities,
                approval_id=approval_id,
                approval_state="approved",
                decided_by=req.decided_by,
                outcome="success",
            )
            return {"status": "executed", "approval_id": approval_id, "result": result}
        except Exception as e:
            self.broker.mark_failed(approval_id, str(e))
            self.audit.append(
                "tool_failed",
                invocation_id=req.tool_call.invocation_id,
                actor=req.tool_call.actor,
                tool_name=req.tool_call.tool_name,
                args=req.tool_call.args,
                entities=req.tool_call.entities,
                approval_id=approval_id,
                outcome=f"error: {e}",
            )
            return {"status": "error", "approval_id": approval_id, "error": str(e)}
