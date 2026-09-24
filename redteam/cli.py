from __future__ import annotations

from pathlib import Path

import typer
import yaml
from rich.console import Console
from rich.table import Table

from redteam.schema import Attack

app = typer.Typer(help="Automated red-teaming harness for GenAI applications.")
console = Console()

ATTACKS_DIR = Path(__file__).resolve().parent.parent / "data" / "attacks"


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
) -> None:
    """Run the attack corpus against a target. Wired up fully in Phase 3."""
    console.print(
        "[yellow]Execution engine lands in Phase 3.[/yellow] "
        f"For now: target={target_url}, attacks loaded={len(_load_attacks())}"
    )


if __name__ == "__main__":
    app()
