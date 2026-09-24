from __future__ import annotations

from typing import Optional

import httpx

from redteam.adapters.base import TargetAdapter


class HTTPTargetAdapter(TargetAdapter):
    """Adapter for any target exposed as a JSON chat endpoint, including the
    bundled demo vulnerable app (see vulnapp/app.py).

    `send` talks to POST /chat. `send_html` talks to GET /chat-ui — used only
    by attacks whose `channel` is `chat_ui` (the LLM05 output-handling corpus),
    since that's the surface that renders the model's response as raw HTML.

    `get_debug_state`/`reset_debug_state` call vulnapp's /debug/state and
    /debug/reset. Those only exist because vulnapp is a demo app built
    specifically to be instrumented — a real black-box target won't have
    them, so the execution engine checks for these methods with `hasattr`
    rather than assuming every target supports them.
    """

    def __init__(
        self,
        base_url: str,
        name: str = "http-target",
        timeout: float = 30.0,
    ) -> None:
        self.name = name
        self._base_url = base_url.rstrip("/")
        self._client = httpx.Client(timeout=timeout)

    def send(self, message: str, session_id: Optional[str] = None) -> str:
        response = self._client.post(
            self._base_url + "/chat",
            json={"message": message, "session_id": session_id},
        )
        response.raise_for_status()
        return response.json()["response"]

    def send_html(self, message: str, session_id: Optional[str] = None) -> str:
        response = self._client.get(
            self._base_url + "/chat-ui",
            params={"message": message, "session_id": session_id},
        )
        response.raise_for_status()
        return response.text

    def get_debug_state(self) -> dict:
        response = self._client.get(self._base_url + "/debug/state")
        response.raise_for_status()
        return response.json()

    def reset_debug_state(self) -> None:
        response = self._client.post(self._base_url + "/debug/reset")
        response.raise_for_status()

    def close(self) -> None:
        self._client.close()
