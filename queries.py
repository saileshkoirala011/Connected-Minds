"""
queries.py — Every Cypher query GraphSentinel depends on.

Rules (from rules.md §3):
  - All Cypher lives here; never in tools.py, agent.py, or ingest/.
  - Always parameterised ($param), never f-string or %-formatted.
  - Read queries are in this file; write queries used only by ingest/.

Each function signature mirrors the tool that calls it, so the mapping
between tool name and Cypher is explicit and auditable (rule 12).

All queries follow the backend-schema.md node model:
  Repo, File, Function, Package, Vuln, IngestJob, Analysis
"""

from __future__ import annotations

from db import run_query

# ============================================================
# 1. SCHEMA — Indexes
# (run once at startup via create_indexes())
# ============================================================

_INDEX_STATEMENTS = [
    "CREATE INDEX FOR (n:File)       ON (n.repo, n.path)",
    "CREATE INDEX FOR (n:Function)   ON (n.repo, n.qualname)",
    "CREATE INDEX FOR (n:Package)    ON (n.repo, n.name)",
    "CREATE INDEX FOR (n:Vuln)       ON (n.id)",
    "CREATE INDEX FOR (n:IngestJob)  ON (n.id)",
    "CREATE INDEX FOR (n:Repo)       ON (n.repo)",
]


def create_indexes() -> None:
    """
    Create all property indexes.  Safe to call on every startup —
    FalkorDB silently ignores duplicate index creation.
    """
    for stmt in _INDEX_STATEMENTS:
        try:
            run_query(stmt)
        except Exception:  # noqa: BLE001 — already exists
            pass


# ============================================================
# 2. HEALTH
# ============================================================


def ping() -> bool:
    """Return True if FalkorDB responds to RETURN 1."""
    rows = run_query("RETURN 1 AS ok")
    return bool(rows and rows[0].get("ok") == 1)


# ============================================================
# 3. REPO STATS
# (tool: get_repo_summary)
# ============================================================


def get_repo_summary(repo: str) -> dict:
    """
    Return high-level counts for a repo.

    Cypher: count File, Function, Package, Vuln nodes scoped to $repo.

    Args:
        repo: "owner/name" string.

    Returns:
        dict: {file_count, function_count, package_count, vuln_count,
               entry_point_count, ingested_at}
    """
    cypher = """
        MATCH (r:Repo {repo: $repo})
        OPTIONAL MATCH (r)-[:CONTAINS]->(f:File)
        OPTIONAL MATCH (f)-[:DEFINES]->(fn:Function)
        OPTIONAL MATCH (r)-[:DEPENDS_ON]->(pkg:Package)
        OPTIONAL MATCH (pkg)<-[:AFFECTS]-(v:Vuln)
        RETURN
            r.ingested_at                    AS ingested_at,
            count(DISTINCT f)                AS file_count,
            count(DISTINCT fn)               AS function_count,
            count(DISTINCT pkg)              AS package_count,
            count(DISTINCT v)                AS vuln_count
    """
    rows = run_query(cypher, {"repo": repo})
    return rows[0] if rows else {}


def get_entry_point_count(repo: str) -> int:
    """Count functions marked as entry points."""
    cypher = """
        MATCH (fn:Function {repo: $repo, is_entry: true})
        RETURN count(fn) AS n
    """
    rows = run_query(cypher, {"repo": repo})
    return int(rows[0]["n"]) if rows else 0


# ============================================================
# 4. MOST-IMPORTED FILES
# (tool: most_imported)
# ============================================================


def most_imported_files(repo: str, limit: int = 10) -> list[dict]:
    """
    Files that are imported most often — structural hotspots.

    Cypher: count inbound IMPORTS edges per File.

    Args:
        repo:  "owner/name"
        limit: Number of results.

    Returns:
        List of {path, importers} sorted by importers DESC.
    """
    cypher = """
        MATCH (a:File {repo: $repo})-[:IMPORTS]->(b:File {repo: $repo})
        RETURN b.path AS path, count(a) AS importers
        ORDER BY importers DESC
        LIMIT $limit
    """
    return run_query(cypher, {"repo": repo, "limit": limit})


# ============================================================
# 5. BLAST RADIUS — file dependents
# (tool: find_dependents)
# ============================================================


def find_file_dependents(repo: str, path: str) -> list[dict]:
    """
    All files that (transitively) import a given file — its blast radius.

    Cypher: variable-length IMPORTS path, depth 1..6.

    Args:
        repo: "owner/name"
        path: Relative file path, e.g. "src/core.py"

    Returns:
        List of {path} — distinct files that depend on the target.
    """
    cypher = """
        MATCH (f:File {repo: $repo, path: $path})<-[:IMPORTS*1..6]-(d:File {repo: $repo})
        RETURN DISTINCT d.path AS path
        ORDER BY path
    """
    return run_query(cypher, {"repo": repo, "path": path})


# ============================================================
# 6. TRANSITIVE DEPENDENCIES — file deps
# (tool: find_dependencies)
# ============================================================


def find_file_dependencies(repo: str, path: str) -> list[dict]:
    """
    All files that a given file (transitively) imports.

    Args:
        repo: "owner/name"
        path: Source file path.

    Returns:
        List of {path, depth} ordered by depth then path.
    """
    cypher = """
        MATCH p = (f:File {repo: $repo, path: $path})-[:IMPORTS*1..6]->(dep:File {repo: $repo})
        RETURN DISTINCT dep.path AS path, min(length(p)) AS depth
        ORDER BY depth, path
    """
    return run_query(cypher, {"repo": repo, "path": path})


# ============================================================
# 7. CIRCULAR IMPORTS
# (tool: find_cycles)
# ============================================================


def find_circular_imports(repo: str, limit: int = 50) -> list[dict]:
    """
    Files involved in circular import chains.

    Cypher: variable-length path from a node back to itself (length 2..6).
    Depth cap keeps the query fast; exact cycle enumeration is O(n!).

    Args:
        repo:  "owner/name"
        limit: Max number of files to return.

    Returns:
        List of {path} — files that are part of at least one cycle.
    """
    cypher = """
        MATCH p = (a:File {repo: $repo})-[:IMPORTS*2..6]->(a)
        RETURN DISTINCT a.path AS path
        LIMIT $limit
    """
    return run_query(cypher, {"repo": repo, "limit": limit})


# ============================================================
# 8. VULNERABILITY LIST
# (tool: list_vulns)
# ============================================================


def list_vulnerabilities(repo: str, limit: int = 100) -> list[dict]:
    """
    All CVEs that affect packages used by a repo.

    Cypher: (Vuln)-[:AFFECTS]->(Package)<-[:DEPENDS_ON]-(Repo)

    Args:
        repo:  "owner/name"
        limit: Max rows (agent cap is 100 per rules.md §5).

    Returns:
        List of {vuln_id, severity, summary, package, version}
        ordered by severity (critical first).
    """
    cypher = """
        MATCH (r:Repo {repo: $repo})-[:DEPENDS_ON]->(pkg:Package)
        MATCH (v:Vuln)-[:AFFECTS]->(pkg)
        RETURN v.id       AS vuln_id,
               v.severity AS severity,
               v.summary  AS summary,
               pkg.name   AS package,
               pkg.version AS version
        ORDER BY
            CASE v.severity
                WHEN 'critical' THEN 0
                WHEN 'high'     THEN 1
                WHEN 'medium'   THEN 2
                WHEN 'low'      THEN 3
                ELSE                 4
            END,
            pkg.name
        LIMIT $limit
    """
    return run_query(cypher, {"repo": repo, "limit": limit})


# ============================================================
# 9. REACHABLE VULNERABILITIES (via call graph)
# (tool: reachable_vulns)
# ============================================================


def reachable_vulns(repo: str, limit: int = 25) -> list[dict]:
    """
    Vulnerabilities reachable from entry-point functions via CALLS edges.

    This is the core query that demonstrates why the graph exists:
    it chains Function-level call resolution through File-level package
    usage to vulnerability data.

    Cypher:
        (entry Function)-[:CALLS*0..8]->(Function)
            <-[:DEFINES]-(File)-[:USES]->(Package)
            <-[:AFFECTS]-(Vuln)

    Args:
        repo:  "owner/name"
        limit: Max rows returned.

    Returns:
        List of {vuln_id, severity, package, file_path, entry_qualname}
        ordered by severity then vuln_id.
    """
    cypher = """
        MATCH (e:Function {repo: $repo, is_entry: true})
        MATCH p = (e)-[:CALLS*0..8]->(fn:Function {repo: $repo})
        MATCH (f:File {repo: $repo, path: fn.file})-[:USES]->(pkg:Package {repo: $repo})
        MATCH (v:Vuln)-[:AFFECTS]->(pkg)
        RETURN DISTINCT
               v.id           AS vuln_id,
               v.severity     AS severity,
               v.summary      AS summary,
               pkg.name       AS package,
               f.path         AS file_path,
               e.qualname     AS entry_qualname,
               length(p)      AS call_depth
        ORDER BY
            CASE v.severity
                WHEN 'critical' THEN 0
                WHEN 'high'     THEN 1
                WHEN 'medium'   THEN 2
                WHEN 'low'      THEN 3
                ELSE                 4
            END,
            call_depth
        LIMIT $limit
    """
    return run_query(cypher, {"repo": repo, "limit": limit})


def import_only_vulns(repo: str, limit: int = 100) -> list[dict]:
    """
    Import-level exposure fallback when call edges are unresolved.

    Cypher: (File)-[:USES]->(Package)<-[:AFFECTS]-(Vuln)
    No call-graph traversal — every file that imports a vulnerable
    package is considered exposed.

    Args:
        repo:  "owner/name"
        limit: Max rows.

    Returns:
        List of {vuln_id, severity, package, file_path}
    """
    cypher = """
        MATCH (f:File {repo: $repo})-[:USES]->(pkg:Package {repo: $repo})
        MATCH (v:Vuln)-[:AFFECTS]->(pkg)
        RETURN DISTINCT
               v.id       AS vuln_id,
               v.severity AS severity,
               pkg.name   AS package,
               f.path     AS file_path
        ORDER BY
            CASE v.severity
                WHEN 'critical' THEN 0
                WHEN 'high'     THEN 1
                WHEN 'medium'   THEN 2
                WHEN 'low'      THEN 3
                ELSE                 4
            END
        LIMIT $limit
    """
    return run_query(cypher, {"repo": repo, "limit": limit})


# ============================================================
# 10. SHORTEST PATH between two nodes
# (tool: explain_path)
# ============================================================


def shortest_path_between(repo: str, from_path: str, to_path: str) -> list[dict]:
    """
    Shortest relationship path between two files (any relationship type).

    Cypher: shortestPath with depth cap 10.

    Args:
        repo:      "owner/name"
        from_path: Source file path.
        to_path:   Target file path.

    Returns:
        List of node property dicts along the path, or [] if none exists.
    """
    cypher = """
        MATCH (a:File {repo: $repo, path: $from_path}),
              (b:File {repo: $repo, path: $to_path})
        MATCH p = shortestPath((a)-[*..10]-(b))
        RETURN [n IN nodes(p) | {label: labels(n)[0], path: n.path, qualname: n.qualname}]
               AS path_nodes
    """
    rows = run_query(cypher, {"repo": repo, "from_path": from_path, "to_path": to_path})
    return rows[0]["path_nodes"] if rows else []


# ============================================================
# 11. RISK SCORING — graph-derived factors
# (used by ingest/risk_scorer.py — NOT plain-Python scoring)
# ============================================================


def package_blast_radius(repo: str, package_name: str) -> int:
    """
    Count files that use a package (directly or via transitive imports).

    This is the graph-query input to the risk scorer, not a Python calculation.
    Rule 3: the graph must be load-bearing — scoring from parsed data alone
    would make the graph decorative.

    Args:
        repo:         "owner/name"
        package_name: Package name (lowercase).

    Returns:
        Integer count of exposed files.
    """
    cypher = """
        MATCH (pkg:Package {repo: $repo, name: $package_name})
        MATCH (f:File {repo: $repo})-[:USES]->(pkg)
        RETURN count(DISTINCT f) AS blast_radius
    """
    rows = run_query(cypher, {"repo": repo, "package_name": package_name})
    return int(rows[0]["blast_radius"]) if rows else 0


def package_reachability_count(repo: str, package_name: str) -> int:
    """
    Count functions that can reach this package via the call graph.

    Higher reachability = more code paths that could be exploited.

    Args:
        repo:         "owner/name"
        package_name: Package name.

    Returns:
        Integer count of reachable functions.
    """
    cypher = """
        MATCH (pkg:Package {repo: $repo, name: $package_name})
        MATCH (f:File {repo: $repo})-[:USES]->(pkg)
        MATCH (fn:Function {repo: $repo, file: f.path})
        MATCH (caller:Function {repo: $repo})-[:CALLS*0..8]->(fn)
        RETURN count(DISTINCT caller) AS reachable_fns
    """
    rows = run_query(cypher, {"repo": repo, "package_name": package_name})
    return int(rows[0]["reachable_fns"]) if rows else 0


def package_import_count(repo: str, package_name: str) -> int:
    """
    Count files that directly import this package (shallow exposure metric).

    Args:
        repo:         "owner/name"
        package_name: Package name.

    Returns:
        Integer direct import count.
    """
    cypher = """
        MATCH (f:File {repo: $repo})-[:USES]->(pkg:Package {repo: $repo, name: $package_name})
        RETURN count(f) AS import_count
    """
    rows = run_query(cypher, {"repo": repo, "package_name": package_name})
    return int(rows[0]["import_count"]) if rows else 0


# ============================================================
# 12. INGEST JOB STATUS
# ============================================================


def get_ingest_job(job_id: str) -> dict:
    """
    Fetch the current status of an ingest job.

    Args:
        job_id: UUID string.

    Returns:
        dict with keys: id, repo, status, step, error, started_at, finished_at
    """
    cypher = """
        MATCH (j:IngestJob {id: $job_id})
        RETURN j.id          AS id,
               j.repo        AS repo,
               j.status      AS status,
               j.step        AS step,
               j.error       AS error,
               j.started_at  AS started_at,
               j.finished_at AS finished_at
    """
    rows = run_query(cypher, {"job_id": job_id})
    return rows[0] if rows else {}


def list_repos() -> list[dict]:
    """
    List all repos that have been ingested.

    Returns:
        List of {repo, url, ingested_at, file_count, function_count}
    """
    cypher = """
        MATCH (r:Repo)
        RETURN r.repo           AS repo,
               r.url            AS url,
               r.ingested_at    AS ingested_at,
               r.file_count     AS file_count,
               r.function_count AS function_count
        ORDER BY r.ingested_at DESC
    """
    return run_query(cypher)
