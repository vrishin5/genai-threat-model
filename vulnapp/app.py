from __future__ import annotations

from typing import Optional

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from vulnapp.agent import chat
from vulnapp.tools import refund_ledger, reset_state, sent_emails, tool_call_counts

app = FastAPI(title="Acme Support Bot (intentionally vulnerable demo)")


class ChatRequest(BaseModel):
    message: str
    session_id: Optional[str] = None


class ChatResponse(BaseModel):
    response: str
    session_id: str


@app.post("/chat", response_model=ChatResponse)
def chat_endpoint(req: ChatRequest) -> ChatResponse:
    text, session_id = chat(req.message, req.session_id)
    return ChatResponse(response=text, session_id=session_id)


@app.get("/chat-ui", response_class=HTMLResponse)
def chat_ui(message: str, session_id: Optional[str] = None) -> str:
    """VULN (LLM05, improper output handling): the model's response is
    interpolated straight into an HTML page with no escaping. If a prompt
    (direct or injected via a retrieved doc) gets the model to emit markup,
    it renders/executes in whatever consumes this page — a classic stored/
    reflected XSS pattern rooted in trusting LLM output as safe HTML.
    """
    text, session_id = chat(message, session_id)
    return f"""
    <html>
      <body>
        <p><b>You:</b> {message}</p>
        <p><b>Acme Support:</b> {text}</p>
        <p style="color:#888">session_id: {session_id}</p>
      </body>
    </html>
    """


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/debug/state")
def debug_state() -> dict:
    """Test instrumentation for the red-team harness's judges — a real
    black-box target wouldn't expose this. It gives ground truth on what
    tools actually ran, instead of trusting the model's own summary of its
    actions.
    """
    return {
        "refunds": refund_ledger,
        "emails": sent_emails,
        "tool_call_counts": tool_call_counts,
    }


@app.post("/debug/reset")
def debug_reset() -> dict:
    reset_state()
    return {"status": "reset"}
