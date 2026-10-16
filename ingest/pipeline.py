"""ingest/pipeline.py — orchestrates clone → parse → write → OSV → score."""

from __future__ import annotations

import shutil
import tempfile
import uuid
from datetime import datetime
from pathlib import Path

from ingest.dependency_parser import ManifestInfo, parse_manifest
from ingest.graph_writer import GraphWriter
from ingest.repo_parser import RepoParser, clone_repo, validate_github_url, walk_python_files


# ── IngestPipeline (async, for tests) ─────────────────────────────────────


class IngestPipeline:
    """
    Async pipeline used by tests (with mocked I/O).

    run() parses manifests from a local directory, calls _enrich_vulnerabilities
    and _score_all, then returns a summary dict.
    """

    async def run(
        self,
        repo_path: str,
        root_package: str = "",
        root_version: str = "1.0.0",
    ) -> dict:
        """
        Run the ingest pipeline on a local repo directory.

        Args:
            repo_path:     Absolute path to the repo root.
            root_package:  Package name (unused in step 2).
            root_version:  Package version (unused in step 2).

        Returns:
            dict with: packages_written, vulnerabilities_found, high_risk_packages

        Raises:
            FileNotFoundError: if repo_path does not exist.
        """
        root = Path(repo_path)
        if not root.exists():
            raise FileNotFoundError(f"repo_path does not exist: {repo_path}")

        # Parse manifests
        parser = RepoParser(root)
        packages: list[dict] = []
        for manifest_info in parser.find_manifests():
            try:
                deps = parse_manifest(root / manifest_info.path)
                for dep in deps:
                    packages.append(
                        {
                            "name": dep.name,
                            "version": dep.version,
                            "ecosystem": dep.ecosystem,
                            "file_path": str(manifest_info.path),
                        }
                    )
            except (ValueError, OSError):
                pass

        # GraphWriter is patched in tests; instantiate for real usage
        writer = GraphWriter()

        # Enrich and score (stubs in this step)
        vulnerabilities_found = await self._enrich_vulnerabilities(packages)
        high_risk_packages = await self._score_all(packages)

        return {
            "packages_written": len(packages),
            "vulnerabilities_found": vulnerabilities_found,
            "high_risk_packages": high_risk_packages,
        }

    async def _enrich_vulnerabilities(self, packages: list) -> int:
        """Stub — real OSV enrichment in Step 4."""
        return 0

    async def _score_all(self, packages: list) -> list:
        """Stub — real risk scoring in Step 4."""
        return []


# ── ingest_repo (sync, called by cli.py) ──────────────────────────────────


def ingest_repo(url: str) -> dict:
    """
    Full synchronous ingest pipeline for a GitHub repository URL.

    Steps:
      1. Validate URL → (owner, name)
      2. Create IngestJob record (status='running')
      3. Clone repo to a temp directory
      4. Walk .py files
      5. Resolve internal imports → IMPORTS edges
      6. Collect external package references
      7. Parse manifest files (requirements.txt, package.json)
      8. Write everything to FalkorDB via GraphWriter
      9. Mark job done; clean up temp dir
     10. Return summary dict

    Raises:
        ValueError: on invalid GitHub URL.
        Any other exception: job is marked failed; temp dir cleaned up; re-raised.
    """
    owner, name = validate_github_url(url)
    repo = f"{owner}/{name}"
    job_id = str(uuid.uuid4())
    started_at = datetime.utcnow().isoformat()
    temp_dir: str | None = None
    current_step = "init"
    writer = GraphWriter()

    def _update_job(status: str, step: str, error: str = "", finished_at: str = "") -> None:
        try:
            writer.write_ingest_job(
                {
                    "id": job_id,
                    "repo": repo,
                    "status": status,
                    "step": step,
                    "error": error,
                    "started_at": started_at,
                    "finished_at": finished_at,
                }
            )
        except Exception:
            pass  # Don't mask the original error

    try:
        # Create initial job record
        current_step = "clone"
        _update_job("running", current_step)

        # Clone
        temp_dir = tempfile.mkdtemp()
        clone_repo(url, Path(temp_dir))
        root = Path(temp_dir)

        # Walk Python files
        current_step = "parse"
        _update_job("running", current_step)
        py_files = walk_python_files(root)

        # Build a lookup: normalized_module → relative_file_path
        # e.g. "click/core.py" → "click.core"
        module_to_path: dict[str, str] = {}
        for f in py_files:
            file_path = f["path"]  # already forward-slash
            # strip .py
            without_ext = file_path[:-3] if file_path.endswith(".py") else file_path
            # __init__ → package name
            if without_ext.endswith("/__init__"):
                without_ext = without_ext[: -len("/__init__")]
            normalized = without_ext.replace("/", ".")
            module_to_path[normalized] = file_path

        # Resolve imports to edges
        current_step = "edges"
        _update_job("running", current_step)
        import_edges: list[dict] = []
        external_packages: list[dict] = []

        for f in py_files:
            src_path = f["path"]
            for module in f.get("imports", []):
                # Try exact match, then progressively shorten (for `from a.b import c`)
                resolved = False
                parts = module.split(".")
                for length in range(len(parts), 0, -1):
                    candidate = ".".join(parts[:length])
                    if candidate in module_to_path:
                        dst_path = module_to_path[candidate]
                        if dst_path != src_path:
                            import_edges.append({"src": src_path, "dst": dst_path})
                        resolved = True
                        break
                if not resolved:
                    # External package — use top-level module name
                    top_name = parts[0]
                    external_packages.append(
                        {
                            "name": top_name,
                            "version": "",
                            "ecosystem": "PyPI",
                            "file_path": src_path,
                        }
                    )

        # Also parse manifest files for declared deps
        current_step = "manifests"
        _update_job("running", current_step)
        manifest_packages: list[dict] = []
        for manifest_info in RepoParser(root).find_manifests():
            try:
                deps = parse_manifest(root / manifest_info.path)
                rel_manifest = str(manifest_info.path).replace("\\", "/")
                for dep in deps:
                    manifest_packages.append(
                        {
                            "name": dep.name,
                            "version": dep.version,
                            "ecosystem": dep.ecosystem,
                            "file_path": rel_manifest,
                        }
                    )
            except (ValueError, OSError):
                pass

        # Collect all functions for writing
        all_functions: list[dict] = []
        for f in py_files:
            for fn in f.get("functions", []):
                all_functions.append(
                    {
                        "path": f["path"],
                        "qualname": fn["qualname"],
                        "lineno": fn["lineno"],
                        "is_entry": fn["is_entry"],
                    }
                )

        file_count = len(py_files)
        function_count = len(all_functions)

        # Write to graph
        current_step = "write"
        _update_job("running", current_step)
        writer.delete_repo(repo)
        writer.write_repo(
            repo=repo,
            url=url,
            ingested_at=started_at,
            file_count=file_count,
            function_count=function_count,
        )

        # File dicts for graph_writer expect path, loc, parse_ok
        file_records = [
            {"path": f["path"], "loc": f["loc"], "parse_ok": f["parse_ok"]}
            for f in py_files
        ]
        writer.write_files(repo, file_records)
        writer.write_functions(repo, all_functions)

        # Deduplicate import edges
        seen_edges: set[tuple[str, str]] = set()
        unique_edges: list[dict] = []
        for e in import_edges:
            key = (e["src"], e["dst"])
            if key not in seen_edges:
                seen_edges.add(key)
                unique_edges.append(e)

        writer.write_import_edges(repo, unique_edges)

        # Combine external + manifest packages, deduplicate by (name, file_path)
        all_packages = external_packages + manifest_packages
        seen_pkgs: set[tuple[str, str]] = set()
        unique_pkgs: list[dict] = []
        for p in all_packages:
            key = (p["name"], p["file_path"])
            if key not in seen_pkgs:
                seen_pkgs.add(key)
                unique_pkgs.append(p)

        writer.write_package_nodes(repo, unique_pkgs)

        # Mark done
        finished_at = datetime.utcnow().isoformat()
        current_step = "complete"
        _update_job("done", current_step, finished_at=finished_at)

        return {
            "file_count": file_count,
            "function_count": function_count,
            "import_edges": len(unique_edges),
            "packages_written": len(unique_pkgs),
            "job_id": job_id,
        }

    except Exception as exc:
        finished_at = datetime.utcnow().isoformat()
        _update_job("failed", current_step, error=str(exc), finished_at=finished_at)
        raise

    finally:
        if temp_dir:
            shutil.rmtree(temp_dir, ignore_errors=True)
