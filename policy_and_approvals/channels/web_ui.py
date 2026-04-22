"""Web UI approval queue adapter.

No external dependency. The ApprovalBroker already stores every pending request
in its in-memory dict; the web UI simply GETs /api/approvals and renders them.
"""

from ..models import ApprovalRequest
from .base import ApprovalChannel


class WebUIChannel(ApprovalChannel):
    name = "web_ui"

    def request_approval(self, req: ApprovalRequest) -> None:
        return None
