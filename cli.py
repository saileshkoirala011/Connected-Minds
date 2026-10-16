"""cli.py — terminal runner for GraphSentinel."""

from __future__ import annotations

import sys
from typing import Optional

import typer
from rich import print as rprint
from rich.console import Console
from rich.table import Table

app = typer.Typer(help="GraphSentinel CLI")
console = Console()


@app.command("health")
def health() -> None:
    """Check FalkorDB connectivity."""
    from db import health_check

    try:
        ok = health_check()
        if ok:
            rprint("ok")
        else:
            rprint("error: health_check returned False")
            raise typer.Exit(code=1)
    except Exception as exc:
        rprint(f"error: {exc}")
        raise typer.Exit(code=1)


@app.command("ingest")
def ingest(url: str) -> None:
    """Clone and ingest a GitHub repository into the graph."""
    from ingest.pipeline import ingest_repo

    try:
        rprint(f"[bold]Ingesting[/bold] {url} …")
        result = ingest_repo(url)
        rprint(
            f"[green]Done.[/green]  "
            f"files={result['file_count']}  "
            f"functions={result['function_count']}  "
            f"import_edges={result['import_edges']}  "
            f"packages={result['packages_written']}"
        )
    except ValueError as exc:
        rprint(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1)


@app.command("summary")
def summary(repo: str) -> None:
    """Show high-level statistics for a repo."""
    from queries import get_entry_point_count, get_repo_summary

    data = get_repo_summary(repo)
    ep_count = get_entry_point_count(repo)

    if not data:
        rprint(f"[yellow]No data found for repo:[/yellow] {repo}")
        raise typer.Exit(code=1)

    table = Table(title=f"Summary — {repo}", show_header=False)
    table.add_column("Metric", style="bold")
    table.add_column("Value")

    table.add_row("Ingested at", str(data.get("ingested_at", "—")))
    table.add_row("Files", str(data.get("file_count", 0)))
    table.add_row("Functions", str(data.get("function_count", 0)))
    table.add_row("Entry points", str(ep_count))
    table.add_row("Packages", str(data.get("package_count", 0)))
    table.add_row("Vulns", str(data.get("vuln_count", 0)))

    console.print(table)


@app.command("top")
def top(
    repo: Optional[str] = typer.Option(None, "--repo", help="owner/name"),
    n: int = typer.Option(10, "--n", help="Number of results"),
) -> None:
    """List the most-imported files in a repo."""
    if repo is None:
        rprint("[red]Error:[/red] --repo is required")
        raise typer.Exit(code=1)

    from queries import most_imported_files

    rows = most_imported_files(repo, n)

    table = Table(title=f"Most imported — {repo}")
    table.add_column("Path", style="cyan")
    table.add_column("Importers", justify="right")

    for row in rows:
        table.add_row(str(row.get("path", "")), str(row.get("importers", 0)))

    console.print(table)


@app.command("blast")
def blast(
    path: str,
    repo: Optional[str] = typer.Option(None, "--repo", help="owner/name"),
) -> None:
    """Show all files that transitively import a given file (blast radius)."""
    if repo is None:
        rprint("[red]Error:[/red] --repo is required")
        raise typer.Exit(code=1)

    from queries import find_file_dependents

    rows = find_file_dependents(repo, path)

    if not rows:
        rprint(f"No dependents found for [cyan]{path}[/cyan] in [bold]{repo}[/bold]")
        return

    rprint(f"\n[bold]Dependents of[/bold] [cyan]{path}[/cyan] ([bold]{repo}[/bold]):\n")
    for row in rows:
        rprint(f"  {row.get('path', '')}")


@app.command("cycles")
def cycles(
    repo: Optional[str] = typer.Option(None, "--repo", help="owner/name"),
) -> None:
    """Find files involved in circular import chains."""
    if repo is None:
        rprint("[red]Error:[/red] --repo is required")
        raise typer.Exit(code=1)

    from queries import find_circular_imports

    rows = find_circular_imports(repo)

    if not rows:
        rprint(f"[green]No circular imports found in[/green] [bold]{repo}[/bold]")
        return

    rprint(f"\n[bold]Files in circular imports — {repo}:[/bold]\n")
    for row in rows:
        rprint(f"  {row.get('path', '')}")


@app.command("repos")
def repos() -> None:
    """List all ingested repositories."""
    from queries import list_repos

    rows = list_repos()

    if not rows:
        rprint("[yellow]No repositories ingested yet.[/yellow]")
        return

    table = Table(title="Ingested Repositories")
    table.add_column("Repo", style="bold cyan")
    table.add_column("URL")
    table.add_column("Ingested at")
    table.add_column("Files", justify="right")
    table.add_column("Functions", justify="right")

    for row in rows:
        table.add_row(
            str(row.get("repo", "")),
            str(row.get("url", "")),
            str(row.get("ingested_at", "")),
            str(row.get("file_count", "")),
            str(row.get("function_count", "")),
        )

    console.print(table)


if __name__ == "__main__":
    app()
