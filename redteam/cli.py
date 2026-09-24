from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
import yaml
from rich.console import Console
from rich.table import Table

from redteam.adapters.http_adapter import HTTPTargetAdapter
from redteam.engine import run_corpus
from redteam.mutators import generate_mutations
from redteam.report import render_html, render_markdown
from redteam.schema import Attack, RunResult
from redteam.scoring import RiskReport, score_run

app = typer.Typer(help="Automated red-teaming harness for GenAI applications.")
console = Console()

ATTACKS_DIR = Path(__file__).resolve().parent.parent / "data" / "attacks"
GENERATED_DIR = ATTACKS_DIR / "generated"
RUNS_DIR = Path(__file__).resolve().parent.parent / "data" / "runs"


def _load_attacks() -> list[Attack]:
    """Loads both hand-written attacks (data/attacks/*.yaml) and any
    mutator-generated ones (data/attacks/generated/*.yaml, from `redteam
    mutate`) — they're both just Attack YAML, so the runner doesn't care
    which produced them.
    """
    attacks: list[Attack] = []
    for path in sorted(ATTACKS_DIR.rglob("*.yaml")):
        raw = yaml.safe_load(path.read_text())
        for entry in (raw or {}).get("attacks", []):
            attacks.append(Attack.model_validate(entry))
    return attacks


@app.command()
def version() -> None:
    """Print the harness version."""
    console.print("genai-threat-model redteam harness — v0.1.0 (through Phase 4: mutation/fuzzing)")


@app.command("list-attacks")
def list_attacks() -> None:
    """List attacks currently defined under data/attacks/ (empty until Phase 2)."""
    attacks = _load_attacks()
    if not attacks:
        console.print(
            f"No attacks found in {ATTACKS_DIR}. The attack corpus is built in Phase 2."
        )
        raise typer.Exit()

    table = Table(title="Attack corpus")
    table.add_column("ID")
    table.add_column("Category")
    table.add_column("Technique")
    table.add_column("Severity")
    table.add_column("Name")
    for attack in attacks:
        table.add_row(
            attack.id,
            attack.category.value,
            attack.technique.value,
            attack.severity.value,
            attack.name,
        )
    console.print(table)


@app.command()
def run(
    target_url: str = typer.Option(
        "http://127.0.0.1:8000", help="Base URL of the target chat app."
    ),
    category: Optional[str] = typer.Option(
        None, help="Only run attacks in this OWASP category, e.g. LLM06."
    ),
    save: bool = typer.Option(
        True, help="Save the full run (with transcripts) as JSON under data/runs/."
    ),
    llm_judge: bool = typer.Option(
        False,
        "--llm-judge/--no-llm-judge",
        help="Score attacks with no rule-based judge using an LLM-as-judge (needs ANTHROPIC_API_KEY).",
    ),
) -> None:
    """Run the attack corpus against a target and report vulnerable findings."""
    attacks = _load_attacks()
    if category:
        attacks = [a for a in attacks if a.category.value.lower() == category.lower()]
    if not attacks:
        console.print("No attacks match — nothing to run.")
        raise typer.Exit()

    judge_client = None
    if llm_judge:
        import anthropic

        judge_client = anthropic.Anthropic()

    adapter = HTTPTargetAdapter(base_url=target_url)
    with console.status(f"Running {len(attacks)} attacks against {target_url}..."):
        result = run_corpus(adapter, attacks, target_name=target_url, llm_judge_client=judge_client)
    adapter.close()

    table = Table(
        title=f"Findings — {result.vulnerable_count}/{len(result.findings)} vulnerable"
    )
    table.add_column("ID")
    table.add_column("Category")
    table.add_column("Severity")
    table.add_column("Vulnerable")
    table.add_column("Notes")
    for finding in sorted(result.findings, key=lambda f: (not f.vulnerable, f.attack_id)):
        style = "bold red" if finding.vulnerable else "green"
        table.add_row(
            finding.attack_id,
            finding.category.value,
            finding.severity.value,
            "[bold red]YES[/bold red]" if finding.vulnerable else "no",
            finding.notes or "",
            style=style if finding.vulnerable else None,
        )
    console.print(table)

    report = score_run(result)
    risk_table = Table(title=f"Risk score: {report.risk_score}/100 (grade {report.grade})")
    risk_table.add_column("Category")
    risk_table.add_column("Vulnerable / Total")
    risk_table.add_column("Manual review")
    risk_table.add_column("Category score")
    for cb in report.by_category:
        risk_table.add_row(
            cb.category.value,
            f"{cb.vulnerable}/{cb.total}",
            str(cb.manual_review),
            f"{cb.score}/100",
        )
    console.print(risk_table)

    if save:
        RUNS_DIR.mkdir(parents=True, exist_ok=True)
        out_path = RUNS_DIR / f"{result.started_at.strftime('%Y%m%dT%H%M%SZ')}.json"
        out_path.write_text(
            json.dumps(
                {"result": result.model_dump(mode="json"), "risk_report": report.model_dump(mode="json")},
                indent=2,
            )
        )
        console.print(f"Full run (with transcripts) and risk report saved to {out_path}")


@app.command()
def mutate(
    techniques: str = typer.Option(
        "b64,homoglyph,leetspeak,split",
        help="Comma-separated mutators to run: b64, homoglyph, leetspeak, split, paraphrase.",
    ),
    category: Optional[str] = typer.Option(
        None, help="Only mutate seed attacks in this OWASP category, e.g. LLM06."
    ),
    out: Path = typer.Option(
        GENERATED_DIR / "mutated.yaml", help="Where to write the generated attacks."
    ),
    llm: bool = typer.Option(
        False,
        "--llm/--no-llm",
        help="Enable the 'paraphrase' mutator, which calls Claude (needs ANTHROPIC_API_KEY).",
    ),
) -> None:
    """Generate obfuscated/rephrased variants of the seed attack corpus.

    The deterministic mutators (b64, homoglyph, leetspeak, split) are free
    and always available. 'paraphrase' additionally rewrites the payload
    with an LLM call and is skipped unless --llm is passed.
    """
    seeds = [a for a in _load_attacks() if "mutated" not in a.tags]
    if category:
        seeds = [a for a in seeds if a.category.value.lower() == category.lower()]
    if not seeds:
        console.print("No seed attacks match — nothing to mutate.")
        raise typer.Exit()

    names = [t.strip() for t in techniques.split(",") if t.strip()]
    client = None
    if "paraphrase" in names:
        if not llm:
            console.print(
                "[yellow]Skipping 'paraphrase' — pass --llm to enable it.[/yellow]"
            )
            names = [n for n in names if n != "paraphrase"]
        else:
            import anthropic

            client = anthropic.Anthropic()

    mutated = generate_mutations(seeds, names, client=client)
    if not mutated:
        console.print("No mutations were generated.")
        raise typer.Exit()

    out.parent.mkdir(parents=True, exist_ok=True)
    payload = {"attacks": [attack.model_dump(mode="json") for attack in mutated]}
    out.write_text(yaml.safe_dump(payload, sort_keys=False, allow_unicode=True))
    console.print(f"Wrote {len(mutated)} mutated attacks (from {len(seeds)} seeds) to {out}")


def _find_latest_run() -> Optional[Path]:
    if not RUNS_DIR.exists():
        return None
    candidates = sorted(RUNS_DIR.glob("*.json"))
    return candidates[-1] if candidates else None


@app.command()
def report(
    run_file: Optional[Path] = typer.Argument(
        None,
        help="Path to a saved run JSON from `redteam run` (data/runs/*.json). "
        "Defaults to the most recent one.",
    ),
    out: Optional[Path] = typer.Option(
        None, help="Output path. Defaults to the run file's name with .html/.md."
    ),
    fmt: str = typer.Option("html", help="Output format: html or md."),
) -> None:
    """Render a saved run into a shareable HTML or Markdown report."""
    path = run_file or _find_latest_run()
    if path is None or not path.exists():
        console.print(
            "No run file found. Run `redteam run` first, or pass a path explicitly."
        )
        raise typer.Exit(code=1)

    raw = json.loads(path.read_text())
    result = RunResult.model_validate(raw["result"])
    risk_report = RiskReport.model_validate(raw["risk_report"])

    if fmt == "html":
        content = render_html(result, risk_report)
        default_suffix = ".html"
    elif fmt == "md":
        content = render_markdown(result, risk_report)
        default_suffix = ".md"
    else:
        console.print(f"Unknown format {fmt!r} — use 'html' or 'md'.")
        raise typer.Exit(code=1)

    out_path = out or path.with_suffix(default_suffix)
    out_path.write_text(content)
    console.print(f"Wrote report to {out_path}")


if __name__ == "__main__":
    app()
