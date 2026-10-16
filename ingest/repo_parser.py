"""ingest/repo_parser.py — validate URL, shallow-clone repo, walk .py files."""

from __future__ import annotations

import ast
import re
import subprocess
from pathlib import Path
from typing import Iterator

from ingest.dependency_parser import ManifestInfo

# Directories to skip when walking Python files
_SKIP_DIRS = {
    "tests", "docs", "build", "dist", ".git", "venv", ".venv", "node_modules",
}

# Directories to skip when looking for manifests
_SKIP_MANIFEST_DIRS = {"node_modules", ".git", ".venv", "venv"}


class RepoParser:
    """Walk a cloned repository to discover manifest files and Python source."""

    def __init__(self, root_path: Path) -> None:
        self.root_path = root_path

    def find_manifests(self) -> Iterator[ManifestInfo]:
        """
        Recursively walk root_path and yield ManifestInfo for every
        requirements.txt or package.json, skipping node_modules/.git/.venv/venv.

        ``manifest_info.path`` is relative to ``self.root_path``.
        """
        for current_dir, dirs, files in self.root_path.walk() if hasattr(Path, "walk") else _os_walk(self.root_path):
            # Prune skipped directories in-place so walk doesn't descend into them
            dirs[:] = [d for d in dirs if d not in _SKIP_MANIFEST_DIRS]
            for filename in files:
                if filename in ("requirements.txt", "package.json"):
                    full_path = Path(current_dir) / filename
                    rel_path = full_path.relative_to(self.root_path)
                    yield ManifestInfo(filename=filename, path=rel_path)


def _os_walk(root: Path):
    """Fallback walk using os.walk for Python < 3.12."""
    import os
    for dirpath, dirnames, filenames in os.walk(root):
        yield dirpath, dirnames, filenames


def validate_github_url(url: str) -> tuple[str, str]:
    """
    Validate a GitHub repository URL.

    Accepts: https://github.com/<owner>/<name>
    Strips trailing slashes and optional .git suffix.

    Returns:
        (owner, name) tuple.

    Raises:
        ValueError: if the URL does not match the expected format.
    """
    url = url.rstrip("/")
    if url.endswith(".git"):
        url = url[:-4]
    pattern = r"^https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)$"
    match = re.match(pattern, url)
    if not match:
        raise ValueError(
            f"Invalid GitHub URL: {url!r}. Expected https://github.com/<owner>/<name>"
        )
    return match.group(1), match.group(2)


def clone_repo(url: str, dest: Path) -> None:
    """
    Shallow-clone a repository into dest.

    Args:
        url:  Clone URL (https://github.com/...).
        dest: Destination directory (must not yet exist).

    Raises:
        RuntimeError: if git clone exits non-zero.
    """
    result = subprocess.run(
        ["git", "clone", "--depth", "1", url, str(dest)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"git clone failed (exit {result.returncode}):\n{result.stderr}"
        )


def walk_python_files(root: Path) -> list[dict]:
    """
    Walk root recursively, parse every .py file, and return structured data.

    Skips directories: tests, docs, build, dist, .git, venv, .venv, node_modules.

    Each returned dict has:
        path       (str)  — relative to root
        loc        (int)  — line count
        parse_ok   (bool) — False if ast.parse raised
        functions  (list) — {qualname, lineno, is_entry}
        imports    (list) — module name strings
        calls      (list) — {caller_qualname, callee_name}

    Entry-point detection (is_entry=True):
        - function name is 'main'
        - any decorator is named 'command', 'get', 'post', 'route', or 'task'
        - function appears in an `if __name__ == '__main__'` block at module level
    """
    import os

    results: list[dict] = []
    root_str = str(root)

    for dirpath, dirnames, filenames in os.walk(root):
        # Prune skip directories in-place
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]

        for filename in filenames:
            if not filename.endswith(".py"):
                continue

            abs_path = Path(dirpath) / filename
            rel_path = str(abs_path.relative_to(root)).replace("\\", "/")

            try:
                source = abs_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                results.append(
                    dict(
                        path=rel_path,
                        loc=0,
                        parse_ok=False,
                        functions=[],
                        imports=[],
                        calls=[],
                    )
                )
                continue

            loc = len(source.splitlines())

            try:
                tree = ast.parse(source, filename=rel_path)
            except SyntaxError:
                results.append(
                    dict(
                        path=rel_path,
                        loc=loc,
                        parse_ok=False,
                        functions=[],
                        imports=[],
                        calls=[],
                    )
                )
                continue

            # ── Collect names in __main__ blocks ──────────────────────────
            main_block_names: set[str] = set()
            for node in ast.iter_child_nodes(tree):
                if isinstance(node, ast.If):
                    test = node.test
                    # if __name__ == '__main__' or '__main__' == __name__
                    is_main_guard = False
                    if isinstance(test, ast.Compare):
                        left = test.left
                        ops = test.ops
                        comps = test.comparators
                        if (
                            len(ops) == 1
                            and isinstance(ops[0], ast.Eq)
                            and len(comps) == 1
                        ):
                            lname = isinstance(left, ast.Name) and left.id == "__name__"
                            rconst = isinstance(comps[0], ast.Constant) and comps[0].value == "__main__"
                            rname = isinstance(comps[0], ast.Name) and comps[0].id == "__name__"
                            lconst = isinstance(left, ast.Constant) and left.value == "__main__"
                            if (lname and rconst) or (rname and lconst):
                                is_main_guard = True
                    if is_main_guard:
                        for child in ast.walk(node):
                            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                                main_block_names.add(child.name)
                            # also capture direct Call of a name, e.g. main()
                            if isinstance(child, ast.Call):
                                if isinstance(child.func, ast.Name):
                                    main_block_names.add(child.func.id)

            # ── Collect imports ────────────────────────────────────────────
            imports: list[str] = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.append(alias.name)
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imports.append(node.module)

            # ── Collect functions and calls ────────────────────────────────
            _ENTRY_DECORATORS = {"command", "get", "post", "route", "task"}

            functions: list[dict] = []
            calls: list[dict] = []

            def _collect_functions(
                nodes: list[ast.stmt],
                prefix: str = "",
            ) -> None:
                for node in nodes:
                    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        continue
                    qualname = f"{prefix}{node.name}" if prefix else node.name

                    # Determine is_entry
                    is_entry = False
                    if node.name == "main":
                        is_entry = True
                    if node.name in main_block_names:
                        is_entry = True
                    for dec in node.decorator_list:
                        dec_name = None
                        if isinstance(dec, ast.Name):
                            dec_name = dec.id
                        elif isinstance(dec, ast.Attribute):
                            dec_name = dec.attr
                        elif isinstance(dec, ast.Call):
                            inner = dec.func
                            if isinstance(inner, ast.Name):
                                dec_name = inner.id
                            elif isinstance(inner, ast.Attribute):
                                dec_name = inner.attr
                        if dec_name and dec_name in _ENTRY_DECORATORS:
                            is_entry = True

                    functions.append(
                        dict(qualname=qualname, lineno=node.lineno, is_entry=is_entry)
                    )

                    # Collect calls within this function
                    for child in ast.walk(node):
                        if isinstance(child, ast.Call):
                            callee: str | None = None
                            if isinstance(child.func, ast.Name):
                                callee = child.func.id
                            elif isinstance(child.func, ast.Attribute):
                                callee = child.func.attr
                            if callee:
                                calls.append(
                                    dict(caller_qualname=qualname, callee_name=callee)
                                )

                    # Recurse into nested functions with dotted qualname
                    _collect_functions(node.body, prefix=f"{qualname}.")

            _collect_functions(list(ast.iter_child_nodes(tree)))

            results.append(
                dict(
                    path=rel_path,
                    loc=loc,
                    parse_ok=True,
                    functions=functions,
                    imports=imports,
                    calls=calls,
                )
            )

    return results
