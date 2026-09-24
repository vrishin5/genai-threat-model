from redteam.schema import Category, Finding, RunResult, Severity
from redteam.scoring import score_run


def _finding(category, severity, vulnerable, manual_review=False):
    return Finding(
        attack_id=f"{category.value}-{severity.value}-{vulnerable}",
        category=category,
        severity=severity,
        vulnerable=vulnerable,
        manual_review=manual_review,
    )


def test_all_safe_scores_zero():
    result = RunResult(
        target_name="t",
        findings=[
            _finding(Category.EXCESSIVE_AGENCY, Severity.CRITICAL, vulnerable=False),
            _finding(Category.PROMPT_INJECTION, Severity.LOW, vulnerable=False),
        ],
    )
    report = score_run(result)
    assert report.risk_score == 0
    assert report.grade == "A"
    assert report.vulnerable_count == 0


def test_all_vulnerable_scores_hundred():
    result = RunResult(
        target_name="t",
        findings=[
            _finding(Category.EXCESSIVE_AGENCY, Severity.CRITICAL, vulnerable=True),
            _finding(Category.PROMPT_INJECTION, Severity.LOW, vulnerable=True),
        ],
    )
    report = score_run(result)
    assert report.risk_score == 100
    assert report.grade == "F"
    assert report.vulnerable_count == 2


def test_mixed_severities_weight_critical_more_than_low():
    # One critical vulnerable + one low safe should score much higher than
    # one low vulnerable + one critical safe, even though vulnerable_count
    # is the same in both cases.
    high_risk = RunResult(
        target_name="t",
        findings=[
            _finding(Category.EXCESSIVE_AGENCY, Severity.CRITICAL, vulnerable=True),
            _finding(Category.PROMPT_INJECTION, Severity.LOW, vulnerable=False),
        ],
    )
    low_risk = RunResult(
        target_name="t",
        findings=[
            _finding(Category.EXCESSIVE_AGENCY, Severity.CRITICAL, vulnerable=False),
            _finding(Category.PROMPT_INJECTION, Severity.LOW, vulnerable=True),
        ],
    )
    assert score_run(high_risk).risk_score > score_run(low_risk).risk_score


def test_manual_review_counted_separately_from_vulnerable():
    result = RunResult(
        target_name="t",
        findings=[
            _finding(Category.SYSTEM_PROMPT_LEAKAGE, Severity.MEDIUM, vulnerable=False, manual_review=True),
        ],
    )
    report = score_run(result)
    assert report.manual_review_count == 1
    assert report.vulnerable_count == 0
    assert report.by_category[0].manual_review == 1


def test_top_findings_sorted_by_severity_desc():
    result = RunResult(
        target_name="t",
        findings=[
            _finding(Category.PROMPT_INJECTION, Severity.LOW, vulnerable=True),
            _finding(Category.EXCESSIVE_AGENCY, Severity.CRITICAL, vulnerable=True),
            _finding(Category.SENSITIVE_INFO_DISCLOSURE, Severity.HIGH, vulnerable=True),
        ],
    )
    report = score_run(result, top_n=2)
    assert len(report.top_findings) == 2
    assert report.top_findings[0].severity == Severity.CRITICAL
    assert report.top_findings[1].severity == Severity.HIGH


def test_empty_result_scores_zero_without_error():
    report = score_run(RunResult(target_name="t", findings=[]))
    assert report.risk_score == 0
    assert report.grade == "A"
    assert report.by_category == []
