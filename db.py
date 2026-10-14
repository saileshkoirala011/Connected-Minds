"""
db.py — FalkorDB connection singleton.

Usage anywhere in the codebase:

    from db import get_graph, run_query

    rows = run_query(SOME_CYPHER, {"repo": "owner/name"})

The graph handle is created once and reused for the lifetime of the process.
Never import FalkorDB directly outside this module.
"""

from __future__ import annotations

import logging
from typing import Any

from falkordb import FalkorDB

from config import settings

logger = logging.getLogger(__name__)

_graph = None  # module-level singleton


def get_graph():
    """
    Return the cached FalkorDB Graph handle for FALKORDB_GRAPH.

    Creates the connection on first call using settings from config.py.
    Subsequent calls return the same object.

    Raises:
        GraphError: if the connection cannot be established.
    """
    global _graph
    if _graph is None:
        try:
            db = FalkorDB(
                host=settings.falkordb_host,
                port=settings.falkordb_port,
                password=settings.falkordb_password or None,
            )
            _graph = db.select_graph(settings.falkordb_graph)
            logger.info(
                "Connected to FalkorDB at %s:%s graph=%s",
                settings.falkordb_host,
                settings.falkordb_port,
                settings.falkordb_graph,
            )
        except Exception as exc:
            raise GraphError(f"Cannot connect to FalkorDB: {exc}") from exc
    return _graph


def run_query(cypher: str, params: dict | None = None) -> list[dict]:
    """
    Execute a Cypher query and return rows as plain dicts.

    Node and edge objects are unwrapped to their .properties dict so
    callers never need to import FalkorDB node/edge types.

    Args:
        cypher: Parameterised Cypher string (use $param placeholders).
        params: Dict of parameter values. Pass None for queries with no params.

    Returns:
        List of row dicts keyed by the column aliases in the RETURN clause.

    Raises:
        GraphError: on query execution failure.
    """
    graph = get_graph()
    try:
        result = graph.query(cypher, params or {})
    except Exception as exc:
        raise GraphError(f"Query failed: {exc}\nCypher: {cypher}") from exc

    rows: list[dict] = []
    for record in result.result_set:
        row: dict[str, Any] = {}
        for i, header in enumerate(result.header):
            val = record[i]
            # Unwrap FalkorDB Node / Edge / Path objects to plain Python types
            if hasattr(val, "properties"):
                val = dict(val.properties)
            elif hasattr(val, "nodes"):
                # Path — return list of property dicts
                val = [dict(n.properties) for n in val.nodes]
            row[header] = val
        rows.append(row)
    return rows


def health_check() -> bool:
    """
    Run RETURN 1 against FalkorDB and return True on success.

    Used by the /health endpoint and startup checks.
    """
    try:
        rows = run_query("RETURN 1 AS ok")
        return bool(rows and rows[0].get("ok") == 1)
    except GraphError:
        return False


# ---------------------------------------------------------------------------
# Custom exception
# ---------------------------------------------------------------------------


class GraphError(Exception):
    """Raised when a FalkorDB connection or query fails."""
