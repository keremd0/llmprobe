"""Command line interface."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

import typer
import yaml
from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, TextColumn, TimeElapsedColumn

from llmprobe import __version__
from llmprobe.attacks import AttackDefinitionError, load_attacks
from llmprobe.engine import Engine
from llmprobe.models import Severity
from llmprobe.mutators import MUTATORS
from llmprobe.reporting import WRITERS, print_summary
from llmprobe.targets import build_target

app = typer.Typer(help="Security testing framework for LLM-powered applications.", no_args_is_help=True,
                  add_completion=False)
console = Console()

BANNER = f"[bold cyan]llmprobe[/] v{__version__} - LLM application security scanner"
DISCLAIMER = "[dim]Only scan systems you own or are explicitly authorised to test.[/]"

EXAMPLE_CONFIG = """\
# llmprobe scan configuration
target:
  type: http                       # http | openai
  name: my-chatbot
  url: http://127.0.0.1:8765/chat
  method: POST
  headers:
    Content-Type: application/json
    # Authorization: "Bearer ${API_TOKEN}"   # env vars are expanded
  body:
    message: "{{prompt}}"
    document: "{{document}}"       # remove if the app has no document/RAG input
  response_path: reply             # dotted path to the answer text in the JSON response
  tool_calls_path: tool_calls      # optional: where tool calls appear in the response
  canaries:                        # secrets you planted in the system prompt / context
    - CANARY-7f3a91

scan:
  attacks: []                      # empty = all built-in attacks
  mutators: [identity, base64, payload_split, roleplay]
  payload_dirs: []                 # extra folders with your own attack YAML files
  concurrency: 4
  delay: 0                         # seconds between requests per worker (rate limiting)
"""


def _version(value: bool):
    if value:
        console.print(__version__)
        raise typer.Exit()


@app.callback()
def main(version: Optional[bool] = typer.Option(None, "--version", callback=_version, is_eager=True)):
    pass


@app.command()
def scan(
    config: Path = typer.Option(..., "--config", "-c", exists=True, readable=True, help="Scan config YAML."),
    output: Path = typer.Option(Path("reports"), "--output", "-o", help="Output directory."),
    formats: str = typer.Option("html,json,sarif", "--format", "-f", help="Comma separated: html,json,sarif"),
    attack: list[str] = typer.Option([], "--attack", "-a", help="Run only these attack ids (repeatable)."),
    mutators: Optional[str] = typer.Option(None, "--mutators", "-m", help="Comma separated mutator names."),
    concurrency: Optional[int] = typer.Option(None, "--concurrency", "-j"),
    fail_on: str = typer.Option("none", "--fail-on",
                                help="Exit with code 1 if a finding at/above this severity exists (CI). "
                                     "none|low|medium|high|critical"),
):
    """Run a scan against the target described in CONFIG."""
    console.print(BANNER)
    console.print(DISCLAIMER)

    cfg = yaml.safe_load(config.read_text(encoding="utf-8")) or {}
    scan_cfg = cfg.get("scan", {}) or {}
    try:
        attacks = load_attacks(scan_cfg.get("payload_dirs", []), only=attack or scan_cfg.get("attacks") or None)
    except AttackDefinitionError as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(2)

    mutator_names = mutators.split(",") if mutators else scan_cfg.get("mutators")
    target = build_target(cfg["target"])

    async def _run():
        async with target:
            with Progress(TextColumn("[cyan]scanning"), BarColumn(), MofNCompleteColumn(),
                          TextColumn("[red]{task.fields[hits]} hits"), TimeElapsedColumn(),
                          console=console) as progress:
                engine = Engine(target, attacks, mutator_names,
                                concurrency=concurrency or scan_cfg.get("concurrency", 4),
                                delay=scan_cfg.get("delay", 0.0))
                task = progress.add_task("scan", total=len(engine.probes), hits=0)
                hits = 0

                def on_result(r):
                    nonlocal hits
                    hits += r.success
                    progress.update(task, advance=1, hits=hits)

                engine.on_result = on_result
                return await engine.run()

    try:
        report = asyncio.run(_run())
    except ValueError as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(2)

    print_summary(report, console)

    output.mkdir(parents=True, exist_ok=True)
    stamp = report.started.replace(":", "").replace("-", "")[:15]
    for fmt in [f.strip() for f in formats.split(",") if f.strip()]:
        if fmt not in WRITERS:
            console.print(f"[yellow]Unknown format '{fmt}', skipped.[/]")
            continue
        path = WRITERS[fmt](report, output / f"llmprobe-{stamp}.{fmt}")
        console.print(f"[green]✓[/] {fmt.upper()} report: {path}")

    if fail_on != "none":
        threshold = Severity(fail_on).rank
        if any(f.attack.severity.rank >= threshold for f in report.vulnerable_findings):
            raise typer.Exit(1)


@app.command("list-attacks")
def list_attacks(payload_dir: list[Path] = typer.Option([], "--payload-dir", "-p")):
    """Show available attacks."""
    from rich.table import Table

    table = Table(title="Attacks")
    for col in ("ID", "OWASP", "Severity", "Payloads", "Mutated"):
        table.add_column(col)
    for a in load_attacks(payload_dir):
        table.add_row(a.id, f"{a.owasp} {a.owasp_name}", a.severity.value,
                      str(len(a.payloads) * max(1, len(a.documents))), "yes" if a.mutate else "no")
    console.print(table)
    console.print(f"Mutators: {', '.join(MUTATORS)}")


@app.command()
def init(path: Path = typer.Argument(Path("llmprobe.yaml"))):
    """Write an example config file."""
    if path.exists():
        console.print(f"[red]{path} already exists.[/]")
        raise typer.Exit(1)
    path.write_text(EXAMPLE_CONFIG, encoding="utf-8")
    console.print(f"[green]✓[/] wrote {path}")


if __name__ == "__main__":
    app()
