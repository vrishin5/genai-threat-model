from __future__ import annotations

import html as html_lib

from redteam.schema import Finding, RunResult, Severity
from redteam.scoring import RiskReport

# General OWASP-aligned remediation guidance per category. Deliberately not
# tied to vulnapp's specific fixes — this harness is meant to run against
# other targets too, so the advice has to generalize.
REMEDIATIONS: dict[str, str] = {
    "LLM01": (
        "Treat all retrieved or tool-returned content as untrusted data, never as "
        "instructions. Don't let text from documents, web pages, or other users "
        "silently change the assistant's behavior or trigger tool calls — "
        "independently verify high-impact actions instead of trusting what appears "
        "in retrieved content."
    ),
    "LLM02": (
        "Never put secrets, credentials, or PII in a system prompt or any context "
        "the model can be induced to repeat. Add output-side scanning for known "
        "secret formats, and treat any credential that ever entered a model's "
        "context as compromised."
    ),
    "LLM05": (
        "Treat model output as untrusted input for every downstream sink — escape "
        "it for HTML, parameterize it for SQL, sandbox it before executing it as "
        "code — exactly as you would unsanitized user input, because that's what "
        "it functionally is."
    ),
    "LLM06": (
        "Apply least privilege to every tool: hard caps on financial or destructive "
        "actions, independent verification (e.g. look up the real order instead of "
        "trusting the number in the prompt), and human-in-the-loop confirmation "
        "before anything irreversible."
    ),
    "LLM07": (
        "Assume the system prompt will eventually leak and design so that leaking "
        "it causes no harm — keep secrets and authorization logic out of the "
        "prompt entirely rather than relying on an instruction not to repeat them."
    ),
    "LLM10": (
        "Enforce hard limits on output length, tool-call count per turn, and "
        "conversation length/cost server-side, independent of the model's own "
        "judgment about what's reasonable."
    ),
}

SEVERITY_ORDER = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}


def _sorted_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (not f.vulnerable, SEVERITY_ORDER[f.severity], f.attack_id))


def _esc(value: object) -> str:
    return html_lib.escape(str(value))


def _status_badge(f: Finding) -> str:
    if f.vulnerable:
        return '<span class="badge badge-vuln">VULNERABLE</span>'
    if f.manual_review:
        return '<span class="badge badge-review">MANUAL REVIEW</span>'
    return '<span class="badge badge-safe">safe</span>'


def _transcript_html(transcript: list[dict]) -> str:
    # Every value here is attacker- or model-controlled text (some of it is
    # literally an XSS payload the harness sent on purpose) — it MUST be
    # escaped, or the report itself becomes exploitable the moment someone
    # opens it. Never interpolate transcript content unescaped.
    turns = []
    for turn in transcript:
        role = "Attacker" if turn.get("role") == "user" else "Target"
        content = _esc(turn.get("content", ""))
        turns.append(f'<div class="turn"><strong>{_esc(role)}:</strong><pre>{content}</pre></div>')
    return "\n".join(turns) if turns else "<p><em>No transcript recorded.</em></p>"


def _finding_row(f: Finding) -> str:
    return (
        f"<tr class=\"sev-{f.severity.value}\">"
        f"<td>{_esc(f.attack_id)}</td>"
        f"<td>{_esc(f.category.value)}</td>"
        f"<td>{_esc(f.severity.value)}</td>"
        f"<td>{_status_badge(f)}</td>"
        f"<td>{_esc(f.notes or '')}</td>"
        "</tr>"
    )


def _finding_detail(f: Finding) -> str:
    remediation = REMEDIATIONS.get(f.category.value, "")
    return f"""
<div class="finding-detail sev-{f.severity.value}">
  <h3>{_esc(f.attack_id)} — {_esc(f.category.value)} ({_esc(f.severity.value)})</h3>
  <p>{_esc(f.notes or '')}</p>
  <details><summary>Transcript</summary>{_transcript_html(f.transcript)}</details>
  <p class="remediation"><strong>Remediation:</strong> {_esc(remediation)}</p>
</div>"""


_CSS = """
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
       max-width: 960px; margin: 2rem auto; padding: 0 1rem; color: #1a1a1a; line-height: 1.5; }
header { border-bottom: 2px solid #eee; margin-bottom: 1.5rem; padding-bottom: 1rem; }
h1 { margin-bottom: 0.25rem; }
.meta { color: #666; font-size: 0.9rem; }
.summary { display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 2rem; }
.card { border: 1px solid #ddd; border-radius: 8px; padding: 1rem 1.5rem; min-width: 120px; text-align: center; }
.card-label { display: block; font-size: 0.8rem; color: #666; text-transform: uppercase; letter-spacing: 0.03em; }
.card-value { display: block; font-size: 1.8rem; font-weight: 700; margin-top: 0.25rem; }
.grade-a, .grade-b { color: #1a7f37; }
.grade-c { color: #9a6700; }
.grade-d, .grade-f { color: #cf222e; }
table { border-collapse: collapse; width: 100%; margin-bottom: 1.5rem; font-size: 0.9rem; }
th, td { border: 1px solid #ddd; padding: 0.5rem 0.75rem; text-align: left; }
th { background: #f6f8fa; }
tr.sev-critical { background: #fff0f0; }
tr.sev-high { background: #fff8f0; }
.badge { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }
.badge-vuln { background: #cf222e; color: white; }
.badge-review { background: #9a6700; color: white; }
.badge-safe { background: #1a7f37; color: white; }
.finding-detail { border-left: 4px solid #ddd; padding: 0.5rem 1rem; margin-bottom: 1rem; }
.finding-detail.sev-critical { border-left-color: #cf222e; }
.finding-detail.sev-high { border-left-color: #bc4c00; }
.finding-detail.sev-medium { border-left-color: #9a6700; }
.finding-detail.sev-low { border-left-color: #57606a; }
.turn { margin: 0.5rem 0; }
.turn pre { white-space: pre-wrap; word-break: break-word; background: #f6f8fa; padding: 0.5rem; border-radius: 4px; margin: 0.25rem 0 0; }
.remediation { color: #333; }
section { margin-bottom: 2rem; }
"""


def render_html(result: RunResult, report: RiskReport) -> str:
    grade_class = f"grade-{report.grade.lower()}"
    category_rows = "\n".join(
        f"<tr><td>{_esc(cb.category.value)}</td><td>{cb.vulnerable}/{cb.total}</td>"
        f"<td>{cb.manual_review}</td><td>{cb.score}/100</td></tr>"
        for cb in report.by_category
    )
    findings_rows = "\n".join(_finding_row(f) for f in _sorted_findings(result.findings))
    top_details = "\n".join(_finding_detail(f) for f in report.top_findings)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>GenAI Red-Team Report — {_esc(report.target_name)}</title>
<style>{_CSS}</style>
</head>
<body>
<header>
  <h1>GenAI Red-Team Report</h1>
  <p class="meta">Target: <code>{_esc(report.target_name)}</code> &middot; Generated {_esc(result.started_at.isoformat())}</p>
</header>

<section class="summary">
  <div class="card"><span class="card-label">Risk score</span><span class="card-value {grade_class}">{report.risk_score}/100</span></div>
  <div class="card"><span class="card-label">Grade</span><span class="card-value {grade_class}">{_esc(report.grade)}</span></div>
  <div class="card"><span class="card-label">Vulnerable</span><span class="card-value">{report.vulnerable_count}/{report.total_attacks}</span></div>
  <div class="card"><span class="card-label">Manual review</span><span class="card-value">{report.manual_review_count}</span></div>
</section>

<section>
  <h2>By OWASP category</h2>
  <table>
    <thead><tr><th>Category</th><th>Vulnerable / Total</th><th>Manual review</th><th>Category score</th></tr></thead>
    <tbody>{category_rows}</tbody>
  </table>
</section>

<section>
  <h2>Top findings</h2>
  {top_details or "<p>No vulnerable findings.</p>"}
</section>

<section>
  <h2>All findings</h2>
  <table>
    <thead><tr><th>Attack</th><th>Category</th><th>Severity</th><th>Status</th><th>Notes</th></tr></thead>
    <tbody>{findings_rows}</tbody>
  </table>
</section>
</body>
</html>
"""


def render_markdown(result: RunResult, report: RiskReport) -> str:
    lines = [
        f"# GenAI Red-Team Report — {report.target_name}",
        "",
        f"Generated: {result.started_at.isoformat()}",
        "",
        f"**Risk score:** {report.risk_score}/100 (grade {report.grade})",
        f"**Vulnerable:** {report.vulnerable_count}/{report.total_attacks}",
        f"**Manual review needed:** {report.manual_review_count}",
        "",
        "## By OWASP category",
        "",
        "| Category | Vulnerable / Total | Manual review | Score |",
        "|---|---|---|---|",
    ]
    for cb in report.by_category:
        lines.append(f"| {cb.category.value} | {cb.vulnerable}/{cb.total} | {cb.manual_review} | {cb.score}/100 |")

    lines += ["", "## Top findings", ""]
    if not report.top_findings:
        lines.append("No vulnerable findings.")
    for f in report.top_findings:
        remediation = REMEDIATIONS.get(f.category.value, "")
        lines += [
            f"### {f.attack_id} — {f.category.value} ({f.severity.value})",
            "",
            f.notes or "",
            "",
            f"**Remediation:** {remediation}",
            "",
        ]

    lines += ["## All findings", "", "| Attack | Category | Severity | Status | Notes |", "|---|---|---|---|---|"]
    for f in _sorted_findings(result.findings):
        status = "VULNERABLE" if f.vulnerable else ("manual review" if f.manual_review else "safe")
        notes = (f.notes or "").replace("|", "\\|").replace("\n", " ")
        lines.append(f"| {f.attack_id} | {f.category.value} | {f.severity.value} | {status} | {notes} |")

    return "\n".join(lines) + "\n"
