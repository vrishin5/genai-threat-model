from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
import yaml
from rich.console import Console
from rich.table import Table

from redteam.adapters.http_adapter import HTTPTargetAdapter
from redteam.engine import run_corpus
from redteam.schema import Attack

app = typer.Typer(help="Automated red-teaming harness for GenAI applications.")
console = Console()

ATTACKS_DIR = Path(__file__).resolve().parent.parent / "data" / "attacks"
RUNS_DIR = Path(__file__).resolve().parent.parent / "data" / "runs"


def _load_attacks() -> list[Attack]:
    attacks: list[Attack] = []
    for path in sorted(ATTACKS_DIR.glob("*.yaml")):
        raw = yaml.safe_load(path.read_text())
        for entry in raw.get("attacks", []):
            attacks.append(Attack.model_validate(entry))
    return attacks


@app.command()
def version() -> None:
    """Print the harness version."""
    console.print("genai-threat-model redteam harness — v0.1.0 (Phase 0/1 scaffold)")


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
) -> None:
    """Run the attack corpus against a target and report vulnerable findings."""
    attacks = _load_attacks()
    if category:
        attacks = [a for a in attacks if a.category.value.lower() == category.lower()]
    if not attacks:
        console.print("No attacks match — nothing to run.")
        raise typer.Exit()

    adapter = HTTPTargetAdapter(base_url=target_url)
    with console.status(f"Running {len(attacks)} attacks against {target_url}..."):
        result = run_corpus(adapter, attacks, target_name=target_url)
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

    if save:
        RUNS_DIR.mkdir(parents=True, exist_ok=True)
        out_path = RUNS_DIR / f"{result.started_at.strftime('%Y%m%dT%H%M%SZ')}.json"
        out_path.write_text(result.model_dump_json(indent=2))
        console.print(f"Full run (with transcripts) saved to {out_path}")


if __name__ == "__main__":
    app()
