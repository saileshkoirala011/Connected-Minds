"""tools.py — 8 read-only agent tools backed by queries.py."""

from __future__ import annotations

from queries import (
    get_repo_summary,
    get_entry_point_count,
    most_imported_files,
    find_file_dependents,
    find_file_dependencies,
    find_circular_imports,
    list_vulnerabilities,
    reachable_vulns,
    import_only_vulns,
    shortest_path_between,
    list_repos,
)
from config import settings


class ToolError(Exception):
    """Raised when a tool cannot complete its query."""


def _wrap(result, description: str) -> dict:
    """Wrap a query result in the standard tool response envelope."""
    if isinstance(result, list):
        return {
            "result": result,
            "cypher": description,
            "nodes": len(result),
            "edges": 0,
        }
    elif isinstance(result, dict):
        return {
            "result": result,
            "cypher": description,
            "nodes": 1,
            "edges": 0,
        }
    return {"result": result, "cypher": description, "nodes": 0, "edges": 0}


def get_repo_summary_tool(repo: str) -> dict:
    """Return file, function, package, and CVE counts for a repo."""
    try:
        summary = get_repo_summary(repo)
        entry_pts = get_entry_point_count(repo)
        if summary:
            summary["entry_point_count"] = entry_pts
        return _wrap(summary, "get_repo_summary: counts for Repo node and related nodes")
    except Exception as e:
        raise ToolError(str(e)) from e


def most_imported_tool(repo: str, n: int = 10) -> dict:
    """Return the N most-imported files by inbound IMPORTS edge count."""
    try:
        rows = most_imported_files(repo, limit=min(n, settings.agent_tool_max_rows))
        return _wrap(rows, "most_imported_files: count inbound IMPORTS edges per File")
    except Exception as e:
        raise ToolError(str(e)) from e


def find_dependents_tool(repo: str, path: str) -> dict:
    """Return all files that transitively import the given file (blast radius)."""
    try:
        rows = find_file_dependents(repo, path)
        return _wrap(rows, "find_file_dependents: variable-length IMPORTS*1..6 traversal")
    except Exception as e:
        raise ToolError(str(e)) from e


def find_dependencies_tool(repo: str, path: str) -> dict:
    """Return all files that the given file transitively imports."""
    try:
        rows = find_file_dependencies(repo, path)
        return _wrap(rows, "find_file_dependencies: variable-length IMPORTS*1..6 outgoing traversal")
    except Exception as e:
        raise ToolError(str(e)) from e


def find_cycles_tool(repo: str) -> dict:
    """Return files that participate in circular import chains."""
    try:
        rows = find_circular_imports(repo)
        return _wrap(rows, "find_circular_imports: IMPORTS*2..6 cycle detection")
    except Exception as e:
        raise ToolError(str(e)) from e


def list_vulns_tool(repo: str) -> dict:
    """Return all CVEs affecting packages used by the repo."""
    try:
        rows = list_vulnerabilities(repo, limit=settings.agent_tool_max_rows)
        return _wrap(rows, "list_vulnerabilities: (Vuln)-[:AFFECTS]->(Package)<-[:DEPENDS_ON]-(Repo)")
    except Exception as e:
        raise ToolError(str(e)) from e


def reachable_vulns_tool(repo: str) -> dict:
    """Return CVEs reachable from entry-point functions via the call graph."""
    try:
        call_rows = reachable_vulns(repo, limit=settings.agent_tool_max_rows)
        import_rows = import_only_vulns(repo, limit=settings.agent_tool_max_rows)
        return {
            "result": {
                "reachable_via_calls": call_rows,
                "import_only": import_rows,
            },
            "cypher": "reachable_vulns: CALLS*0..8 chain; import_only_vulns: USES edges",
            "nodes": len(call_rows) + len(import_rows),
            "edges": len(call_rows),
        }
    except Exception as e:
        raise ToolError(str(e)) from e


def explain_path_tool(repo: str, from_path: str, to_path: str) -> dict:
    """Return the shortest relationship path between two files."""
    try:
        path_nodes = shortest_path_between(repo, from_path, to_path)
        return _wrap(
            path_nodes,
            "shortest_path_between: shortestPath(*..10) between two File nodes",
        )
    except Exception as e:
        raise ToolError(str(e)) from e


# Tool registry for agent
TOOLS: dict[str, callable] = {
    "get_repo_summary": get_repo_summary_tool,
    "most_imported": most_imported_tool,
    "find_dependents": find_dependents_tool,
    "find_dependencies": find_dependencies_tool,
    "find_cycles": find_cycles_tool,
    "list_vulns": list_vulns_tool,
    "reachable_vulns": reachable_vulns_tool,
    "explain_path": explain_path_tool,
}
