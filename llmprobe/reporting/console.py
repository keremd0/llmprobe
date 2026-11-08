from __future__ import annotations

from rich.console import Console
from rich.table import Table

from llmprobe.models import ScanReport, Severity

SEV_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def print_summary(report: ScanReport, console: Console | None = None) -> None:
    console = console or Console()
    table = Table(title=f"llmprobe results - {report.target}", show_lines=False)
    table.add_column("Severity")
    table.add_column("OWASP")
    table.add_column("Attack")
    table.add_column("Hit rate", justify="right")
    table.add_column("Bypassing mutators")
    table.add_column("Status")

    for f in sorted(report.findings, key=lambda f: (-f.attack.severity.rank, -f.success_rate)):
        sev = f.attack.severity
        status = "[bold red]VULNERABLE[/]" if f.vulnerable else "[green]passed[/]"
        if f.errors == f.total:
            status = "[magenta]errors[/]"
        table.add_row(
            f"[{SEV_STYLE[sev]}]{sev.value.upper()}[/]",
            f.attack.owasp,
            f.attack.name,
            f"{f.successes}/{f.total} ({f.success_rate:.0%})",
            ", ".join(f.successful_mutators) or "-",
            status,
        )
    console.print(table)

    failed = [r for r in report.results if r.response.error]
    if failed:
        console.print(f"[magenta]{len(failed)} probe(s) returned errors. First error: {failed[0].response.error}[/]")
        if len(failed) == len(report.results):
            console.print("[magenta]Every probe failed - is the target running, and is the URL/port in the "
                          "config correct? Results above are NOT meaningful.[/]")
