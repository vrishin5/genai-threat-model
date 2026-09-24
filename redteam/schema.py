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


class Attack(BaseModel):
    """A single adversarial test case. `payload` holds either a single-turn
    prompt or an ordered list of turns for multi-turn attacks. `success_criteria`
    is a human-readable description now; Phase 3+ judges consume the same
    field plus attack-specific config to decide pass/fail automatically.
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
