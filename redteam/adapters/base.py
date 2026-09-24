from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional


class TargetAdapter(ABC):
    """Uniform interface the harness uses to talk to whatever it's attacking.

    A single `send` call is one conversational turn. `session_id` lets
    multi-turn attacks keep state on the target side; adapters that are
    stateless on their own end (e.g. a raw model API with no server-side
    memory) are responsible for replaying prior turns themselves.
    """

    name: str = "target"

    @abstractmethod
    def send(self, message: str, session_id: Optional[str] = None) -> str:
        """Send one message to the target and return its text response."""
        raise NotImplementedError
