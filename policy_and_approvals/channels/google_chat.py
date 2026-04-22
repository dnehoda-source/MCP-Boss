"""Google Chat adapter — posts an interactive card with Approve/Deny buttons.

Config:
    GOOGLE_CHAT_WEBHOOK_URL   Incoming-webhook URL for the target space.
    PUBLIC_BASE_URL           Public base URL of this MCP Boss instance
                              (e.g. https://mcp-boss.example.com). The Approve/Deny
                              buttons link back to /api/approvals/<id>/decide here.
"""

from __future__ import annotations

import json
import os
from typing import Optional

import requests

from ..models import ApprovalRequest
from .base import ApprovalChannel


class GoogleChatChannel(ApprovalChannel):
    name = "google_chat"

    def __init__(
        self,
        webhook_url: Optional[str] = None,
        base_callback_url: Optional[str] = None,
    ):
        self.webhook_url = webhook_url or os.environ.get("GOOGLE_CHAT_WEBHOOK_URL", "")
        self.callback = (base_callback_url or os.environ.get("PUBLIC_BASE_URL", "")).rstrip("/")

    def request_approval(self, req: ApprovalRequest) -> None:
        if not self.webhook_url:
            return
        try:
            requests.post(self.webhook_url, json=self._build_card(req), timeout=10)
        except Exception:
            pass

    def _build_card(self, req: ApprovalRequest) -> dict:
        preview = req.dry_run
        side_effects = "\n".join(f"• {s}" for s in preview.side_effects) or "(none listed)"
        approve_url = f"{self.callback}/api/approvals/{req.approval_id}/decide?decision=approved&by=gchat"
        deny_url = f"{self.callback}/api/approvals/{req.approval_id}/decide?decision=denied&by=gchat"
        reversal = (
            f"yes — {preview.reversal_hint}" if preview.reversible else "NO — irreversible action"
        )
        return {
            "cardsV2": [
                {
                    "cardId": f"approval-{req.approval_id}",
                    "card": {
                        "header": {
                            "title": f"Approval required: {preview.tool_name}",
                            "subtitle": f"Requested by {req.tool_call.actor}",
                        },
                        "sections": [
                            {
                                "widgets": [
                                    {
                                        "textParagraph": {
                                            "text": f"<b>Reason:</b> {req.policy_decision.reason}"
                                        }
                                    },
                                    {
                                        "textParagraph": {
                                            "text": f"<b>Entities:</b> <code>{json.dumps(req.tool_call.entities)}</code>"
                                        }
                                    },
                                    {
                                        "textParagraph": {
                                            "text": f"<b>Side effects:</b><br>{side_effects}"
                                        }
                                    },
                                    {
                                        "textParagraph": {
                                            "text": f"<b>Reversible:</b> {reversal}"
                                        }
                                    },
                                    {
                                        "textParagraph": {
                                            "text": f"<b>Approvers:</b> {', '.join(req.policy_decision.approver_groups) or 'default'}"
                                        }
                                    },
                                    {
                                        "buttonList": {
                                            "buttons": [
                                                {
                                                    "text": "Approve",
                                                    "onClick": {"openLink": {"url": approve_url}},
                                                },
                                                {
                                                    "text": "Deny",
                                                    "onClick": {"openLink": {"url": deny_url}},
                                                },
                                            ]
                                        }
                                    },
                                ]
                            }
                        ],
                    },
                }
            ]
        }
