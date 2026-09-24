from __future__ import annotations

import uuid
from typing import Optional

from redteam.adapters.base import TargetAdapter
from redteam.judges import evaluate
from redteam.llm_judge import llm_evaluate
from redteam.schema import Attack, Channel, Finding, RunResult


def run_attack(adapter: TargetAdapter, attack: Attack, llm_judge_client: Optional[object] = None) -> Finding:
    """Replay one attack's turns against the target and score the result.

    Each attack gets a fresh session id and, when the target supports it, a
    fresh debug-state reset — so findings are independent of run order and
    of whatever a previous attack left behind.
    """
    if hasattr(adapter, "reset_debug_state"):
        adapter.reset_debug_state()

    session_id = str(uuid.uuid4())
    transcript: list[dict] = []
    final_response = ""

    for turn in attack.payload:
        if attack.channel == Channel.CHAT_UI:
            if not hasattr(adapter, "send_html"):
                raise NotImplementedError(
                    f"Attack {attack.id!r} needs channel=chat_ui but adapter "
                    f"{adapter.name!r} doesn't implement send_html()."
                )
            response = adapter.send_html(turn, session_id=session_id)
        else:
            response = adapter.send(turn, session_id=session_id)
        transcript.append({"role": "user", "content": turn})
        transcript.append({"role": "target", "content": response})
        final_response = response

    # An attack with no rule-based judge falls back to the LLM-as-judge when
    # one's enabled; otherwise `evaluate` itself returns a manual-review
    # Finding (see redteam/judges.py) — either way this call is exhaustive.
    if attack.judge is None and llm_judge_client is not None:
        return llm_evaluate(attack, transcript, llm_judge_client)

    debug_state = adapter.get_debug_state() if hasattr(adapter, "get_debug_state") else None
    return evaluate(attack, transcript, final_response, debug_state)


def run_corpus(
    adapter: TargetAdapter,
    attacks: list[Attack],
    target_name: str,
    llm_judge_client: Optional[object] = None,
) -> RunResult:
    result = RunResult(target_name=target_name)
    for attack in attacks:
        result.findings.append(run_attack(adapter, attack, llm_judge_client=llm_judge_client))
    return result
