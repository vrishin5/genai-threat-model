from __future__ import annotations

from typing import Optional

import httpx

from redteam.adapters.base import TargetAdapter


class HTTPTargetAdapter(TargetAdapter):
    """Adapter for any target exposed as a JSON chat endpoint, including the
    bundled demo vulnerable app (see vulnapp/app.py, POST /chat).
    """

    def __init__(
        self,
        base_url: str,
        path: str = "/chat",
        name: str = "http-target",
        timeout: float = 30.0,
    ) -> None:
        self.name = name
        self._url = base_url.rstrip("/") + path
        self._client = httpx.Client(timeout=timeout)

    def send(self, message: str, session_id: Optional[str] = None) -> str:
        response = self._client.post(
            self._url,
            json={"message": message, "session_id": session_id},
        )
        response.raise_for_status()
        return response.json()["response"]

    def close(self) -> None:
        self._client.close()
