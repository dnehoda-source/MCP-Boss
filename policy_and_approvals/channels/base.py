"""Abstract approval channel interface."""

from abc import ABC, abstractmethod

from ..models import ApprovalRequest


class ApprovalChannel(ABC):
    name: str = "base"

    @abstractmethod
    def request_approval(self, req: ApprovalRequest) -> None:
        """Deliver the approval request (post card, POST webhook, no-op for in-proc queues, etc)."""

    def on_decision(self, req: ApprovalRequest) -> None:
        """Hook called after the approval is decided. Default: no-op."""
        return None
