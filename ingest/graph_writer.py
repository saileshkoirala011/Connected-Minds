"""ingest/graph_writer.py — MERGE writes to FalkorDB; idempotent via UNWIND+MERGE."""

from __future__ import annotations

import sys
import os

# Ensure project root is on sys.path so `from db import run_query` works
_project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from db import run_query

BATCH_SIZE = 500


def _batched(items: list, size: int):
    """Yield successive batches of `size` from items."""
    for i in range(0, len(items), size):
        yield items[i : i + size]


class GraphWriter:
    """Write graph nodes and edges to FalkorDB using parameterized Cypher."""

    # ── Repo lifecycle ─────────────────────────────────────────────────────

    def delete_repo(self, repo: str) -> None:
        """Delete all non-Vuln nodes belonging to this repo."""
        run_query(
            "MATCH (n {repo: $repo}) WHERE NOT n:Vuln DETACH DELETE n",
            {"repo": repo},
        )

    def write_repo(
        self,
        repo: str,
        url: str,
        ingested_at: str,
        file_count: int,
        function_count: int,
    ) -> None:
        """MERGE a Repo node and set its properties."""
        run_query(
            "MERGE (r:Repo {repo: $repo}) "
            "SET r.url=$url, r.ingested_at=$ingested_at, "
            "r.file_count=$file_count, r.function_count=$function_count",
            {
                "repo": repo,
                "url": url,
                "ingested_at": ingested_at,
                "file_count": file_count,
                "function_count": function_count,
            },
        )

    # ── Files ──────────────────────────────────────────────────────────────

    def write_files(self, repo: str, files: list[dict]) -> None:
        """MERGE File nodes and link them to their Repo with CONTAINS edges."""
        for batch in _batched(files, BATCH_SIZE):
            run_query(
                "UNWIND $files AS f "
                "MERGE (n:File {repo: $repo, path: f.path}) "
                "SET n.loc=f.loc, n.parse_ok=f.parse_ok "
                "WITH n, f "
                "MATCH (r:Repo {repo: $repo}) "
                "MERGE (r)-[:CONTAINS]->(n)",
                {"repo": repo, "files": batch},
            )

    # ── Functions ──────────────────────────────────────────────────────────

    def write_functions(self, repo: str, functions: list[dict]) -> None:
        """MERGE Function nodes and link them to their File with DEFINES edges."""
        for batch in _batched(functions, BATCH_SIZE):
            run_query(
                "UNWIND $fns AS f "
                "MERGE (fn:Function {repo: $repo, qualname: f.qualname}) "
                "SET fn.file=f.path, fn.lineno=f.lineno, fn.is_entry=f.is_entry "
                "WITH fn, f "
                "MATCH (fi:File {repo: $repo, path: f.path}) "
                "MERGE (fi)-[:DEFINES]->(fn)",
                {"repo": repo, "fns": batch},
            )

    # ── Import edges ───────────────────────────────────────────────────────

    def write_import_edges(self, repo: str, edges: list[dict]) -> None:
        """MERGE IMPORTS edges between File nodes."""
        for batch in _batched(edges, BATCH_SIZE):
            run_query(
                "UNWIND $edges AS e "
                "MATCH (a:File {repo: $repo, path: e.src}) "
                "MATCH (b:File {repo: $repo, path: e.dst}) "
                "MERGE (a)-[:IMPORTS]->(b)",
                {"repo": repo, "edges": batch},
            )

    # ── Package nodes ──────────────────────────────────────────────────────

    def write_package_nodes(self, repo: str, packages: list[dict]) -> None:
        """MERGE Package nodes and link them to importing Files with USES edges."""
        for batch in _batched(packages, BATCH_SIZE):
            run_query(
                "UNWIND $pkgs AS p "
                "MERGE (pkg:Package {repo: $repo, name: p.name}) "
                "SET pkg.version=p.version, pkg.ecosystem=p.ecosystem "
                "WITH pkg, p "
                "MATCH (f:File {repo: $repo, path: p.file_path}) "
                "MERGE (f)-[:USES]->(pkg)",
                {"repo": repo, "pkgs": batch},
            )

    # ── Ingest job ─────────────────────────────────────────────────────────

    def write_ingest_job(self, job: dict) -> None:
        """MERGE an IngestJob node and set all its status fields."""
        run_query(
            "MERGE (j:IngestJob {id: $id}) "
            "SET j.repo=$repo, j.status=$status, j.step=$step, "
            "j.error=$error, j.started_at=$started_at, j.finished_at=$finished_at",
            {
                "id": job["id"],
                "repo": job["repo"],
                "status": job["status"],
                "step": job["step"],
                "error": job["error"],
                "started_at": job["started_at"],
                "finished_at": job["finished_at"],
            },
        )

    # ── Vuln nodes ─────────────────────────────────────────────────────────

    def write_vuln_nodes(self, repo: str, vulns: list[dict]) -> None:
        """MERGE global Vuln nodes and AFFECTS edges to Package scoped to $repo."""
        for batch in _batched(vulns, BATCH_SIZE):
            run_query(
                "UNWIND $vulns AS v "
                "MERGE (vn:Vuln {id: v.id}) "
                "SET vn.summary=v.summary, vn.severity=v.severity, "
                "    vn.aliases=v.aliases, vn.fixed_in=v.fixed_in "
                "WITH vn, v "
                "MATCH (pkg:Package {repo: $repo, name: v.package_name}) "
                "MERGE (vn)-[:AFFECTS]->(pkg)",
                {"repo": repo, "vulns": batch},
            )

    def write_depends_on_edges(self, repo: str, packages: list[dict]) -> None:
        """MERGE DEPENDS_ON edges from Repo to Package for manifest-declared deps."""
        for batch in _batched(packages, BATCH_SIZE):
            run_query(
                "UNWIND $pkgs AS p "
                "MATCH (r:Repo {repo: $repo}) "
                "MATCH (pkg:Package {repo: $repo, name: p.name}) "
                "MERGE (r)-[:DEPENDS_ON]->(pkg)",
                {"repo": repo, "pkgs": batch},
            )

    def write_calls_edges(self, repo: str, calls: list[dict]) -> None:
        """MERGE CALLS edges between Function nodes (best-effort, resolved flag)."""
        for batch in _batched(calls, BATCH_SIZE):
            run_query(
                "UNWIND $calls AS c "
                "MATCH (caller:Function {repo: $repo, qualname: c.caller_qualname}) "
                "MATCH (callee:Function {repo: $repo, qualname: c.callee_qualname}) "
                "MERGE (caller)-[:CALLS {resolved: c.resolved}]->(callee)",
                {"repo": repo, "calls": batch},
            )
