from __future__ import annotations

from pydantic import BaseModel, Field

from redteam.schema import Category, Finding, RunResult, Severity

# Higher weight = a vulnerable finding here moves the risk score more. These
# are judgment calls, not a standard — tune them if your threat model weighs
# categories differently (e.g. exfiltration matters more than a resource cap).
SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.LOW: 1,
    Severity.MEDIUM: 3,
    Severity.HIGH: 6,
    Severity.CRITICAL: 10,
}


class CategoryBreakdown(BaseModel):
    category: Category
    total: int
    vulnerable: int
    manual_review: int
    score: int  # 0-100, this category's share of its own max possible risk


class RiskReport(BaseModel):
    target_name: str
    total_attacks: int
    vulnerable_count: int
    manual_review_count: int
    risk_score: int  # 0-100, higher = worse
    grade: str  # A (safest) .. F (most vulnerable)
    by_category: list[CategoryBreakdown] = Field(default_factory=list)
    top_findings: list[Finding] = Field(default_factory=list)


def _grade(score: int) -> str:
    if score < 10:
        return "A"
    if score < 30:
        return "B"
    if score < 50:
        return "C"
    if score < 70:
        return "D"
    return "F"


def score_run(result: RunResult, top_n: int = 5) -> RiskReport:
    """Rolls a RunResult's findings up into a single risk score plus a
    per-category breakdown. The score is severity-weighted: it's the fraction
    of total possible "risk points" (every finding vulnerable, at its own
    severity weight) that were actually realized, scaled to 0-100.
    """
    findings = result.findings
    tallies: dict[Category, dict[str, int]] = {}
    total_points = 0
    max_points = 0

    for finding in findings:
        weight = SEVERITY_WEIGHTS[finding.severity]
        max_points += weight
        tally = tallies.setdefault(
            finding.category, {"total": 0, "vulnerable": 0, "manual_review": 0, "points": 0, "max": 0}
        )
        tally["total"] += 1
        tally["max"] += weight
        if finding.manual_review:
            tally["manual_review"] += 1
        if finding.vulnerable:
            total_points += weight
            tally["points"] += weight
            tally["vulnerable"] += 1

    risk_score = round(100 * total_points / max_points) if max_points else 0
    by_category = [
        CategoryBreakdown(
            category=category,
            total=t["total"],
            vulnerable=t["vulnerable"],
            manual_review=t["manual_review"],
            score=round(100 * t["points"] / t["max"]) if t["max"] else 0,
        )
        for category, t in sorted(tallies.items(), key=lambda item: item[0].value)
    ]

    top_findings = sorted(
        (f for f in findings if f.vulnerable),
        key=lambda f: SEVERITY_WEIGHTS[f.severity],
        reverse=True,
    )[:top_n]

    return RiskReport(
        target_name=result.target_name,
        total_attacks=len(findings),
        vulnerable_count=sum(1 for f in findings if f.vulnerable),
        manual_review_count=sum(1 for f in findings if f.manual_review),
        risk_score=risk_score,
        grade=_grade(risk_score),
        by_category=by_category,
        top_findings=top_findings,
    )
