"""Generic webhook adapter.

POSTs the approval request as signed JSON to a customer-configured URL.
The receiver (PagerDuty, Opsgenie, ServiceNow, a home-grown system) is expected
to surface it to a human and call back:

    POST <PUBLIC_BASE_URL>/api/approvals/<approval_id>/decide
    {"decision": "approved" | "denied", "decided_by": "...", "reason": "..."}

Config:
    APPROVAL_WEBHOOK_URL     Where to POST.
    APPROVAL_WEBHOOK_SECRET  HMAC-SHA256 signing key (header: X-MCP-Boss-Signature).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import asdict
from typing import Optional

import requests

from ..models import ApprovalRequest
from .base import ApprovalChannel


class GenericWebhookChannel(ApprovalChannel):
    name = "generic_webhook"

    def __init__(self, url: Optional[str] = None, secret: Optional[str] = None):
        self.url = url or os.environ.get("APPROVAL_WEBHOOK_URL", "")
        secret_raw = secret or os.environ.get("APPROVAL_WEBHOOK_SECRET", "")
        self.secret = secret_raw.encode() if secret_raw else b""

    def request_approval(self, req: ApprovalRequest) -> None:
        if not self.url:
            return
        payload = json.dumps(asdict(req), default=str).encode()
        headers = {"Content-Type": "application/json"}
        if self.secret:
            sig = hmac.new(self.secret, payload, hashlib.sha256).hexdigest()
            headers["X-MCP-Boss-Signature"] = f"sha256={sig}"
        try:
            requests.post(self.url, data=payload, headers=headers, timeout=10)
        except Exception:
            pass
