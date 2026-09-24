from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class Category(str, Enum):
    """OWASP Top 10 for LLM Applications categories this harness can test
    against a running (black-box) target. Training-time categories such as
    LLM03 (Supply Chain) and LLM04 (Data/Model Poisoning) are out of scope
    for runtime red-teaming and intentionally omitted.
    """

    PROMPT_INJECTION = "LLM01"
    SENSITIVE_INFO_DISCLOSURE = "LLM02"
    IMPROPER_OUTPUT_HANDLING = "LLM05"
    EXCESSIVE_AGENCY = "LLM06"
    SYSTEM_PROMPT_LEAKAGE = "LLM07"
    UNBOUNDED_CONSUMPTION = "LLM10"


class Technique(str, Enum):
    DIRECT = "direct"
    INDIRECT = "indirect"
    MULTI_TURN = "multi_turn"
    ENCODING = "encoding"
    ROLEPLAY = "roleplay"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Channel(str, Enum):
    """Which endpoint on the target an attack's payload is sent to. Most
    attacks talk to the normal chat API; LLM05 attacks need the raw-HTML
    surface to test for unescaped output.
    """

    CHAT = "chat"
    CHAT_UI = "chat_ui"


class JudgeType(str, Enum):
    """Rule-based judge strategies. Each is a cheap, deterministic heuristic —
    fast to run across a whole corpus but not immune to false positives/
    negatives. Phase 5 adds an LLM-as-judge for the cases these can't cover
    well (e.g. `success_criteria` where "did the model refuse or comply" is a
    judgment call, not a substring match).
    """

    CANARY_LEAK = "canary_leak"
    CONTAINS_TEXT = "contains_text"
    HTML_UNESCAPED = "html_unescaped"
    TOOL_CALLED = "tool_called"
    RESPONSE_LENGTH = "response_length"


class JudgeSpec(BaseModel):
    """Config for a rule-based judge. Only the fields relevant to `type` need
    to be set; see redteam/judges.py for how each type interprets them.
    """

    type: JudgeType

    # canary_leak
    value: Optional[str] = None

    # contains_text
    text: list[str] = Field(default_factory=list)
    match: str = "any"  # "any" | "all"
    case_sensitive: bool = False

    # html_unescaped
    patterns: list[str] = Field(default_factory=list)

    # tool_called — set exactly one threshold field alongside `tool`
    tool: Optional[str] = None
    min_amount: Optional[float] = None
    allowed_domain_suffix: Optional[str] = None
    min_calls: Optional[int] = None

    # response_length
    min_chars: Optional[int] = None


class Attack(BaseModel):
    """A single adversarial test case. `payload` holds either a single-turn
    prompt or an ordered list of turns for multi-turn attacks. `success_criteria`
    is the human-readable description a report shows; `judge` is the
    machine-checkable version the execution engine actually scores against.
    An attack with no `judge` is flagged for manual review instead of being
    auto-scored.
    """

    id: str
    category: Category
    technique: Technique
    name: str
    description: str
    payload: list[str] = Field(min_length=1)
    success_criteria: str
    severity: Severity = Severity.MEDIUM
    tags: list[str] = Field(default_factory=list)
    channel: Channel = Channel.CHAT
    judge: Optional[JudgeSpec] = None


class Finding(BaseModel):
    attack_id: str
    category: Category
    severity: Severity
    vulnerable: bool
    transcript: list[dict] = Field(default_factory=list)
    notes: Optional[str] = None


class RunResult(BaseModel):
    target_name: str
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    findings: list[Finding] = Field(default_factory=list)

    @property
    def vulnerable_count(self) -> int:
        return sum(1 for f in self.findings if f.vulnerable)
