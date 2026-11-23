import httpx
import typer
from rich.console import Console
from rich.table import Table

from catchit.fetch import fetch_files, parse_repo
from catchit.models import Report
from catchit.rules import run_rules

app = typer.Typer(help="Scan a GitHub repo before you clone or run it.")
console = Console()


@app.callback()
def main() -> None:
    pass


@app.command()
def scan(repo: str = typer.Argument(..., help="owner/repo or a GitHub URL")) -> None:
    """Fetch a repo through the GitHub API (no clone, no execution) and scan it."""
    slug = parse_repo(repo)

    try:
        with console.status(f"Fetching {slug}..."):
            files = fetch_files(slug)
    except httpx.HTTPStatusError as e:
        code = e.response.status_code
        hint = {403: "rate limit hit - set GITHUB_TOKEN", 404: "repo not found or private"}
        console.print(f"[red]GitHub API error {code}[/]: {hint.get(code, e.response.reason_phrase)}")
        raise typer.Exit(1)

    report = Report(repo=slug, findings=run_rules(files))
    color = "green" if report.score < 20 else "yellow" if report.score < 50 else "red"
    console.print(f"\n[bold]{slug}[/] - scanned {len(files)} files - "
                  f"risk score [bold {color}]{report.score}/100[/]\n")

    if not report.findings:
        console.print("[green]No findings.[/] (Not a guarantee - the rules are still basic.)")
        return

    table = Table("Severity", "Rule", "File", "Message")
    for f in sorted(report.findings, key=lambda f: f.severity.value):
        loc = f"{f.path}:{f.line}" if f.line else f.path
        table.add_row(f.severity.value, f.rule_id, loc, f.message)
    console.print(table)