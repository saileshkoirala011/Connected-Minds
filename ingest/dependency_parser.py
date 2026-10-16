"""ingest/dependency_parser.py — parse requirements.txt / package.json → Dependency list."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Dependency:
    """A single declared dependency from a manifest file."""

    name: str
    version: str
    ecosystem: str


class ManifestInfo:
    """Lightweight record of a discovered manifest file.

    ``path`` stores the path **relative** to the repo root so callers can
    do simple string checks (e.g. "node_modules" not in str(m.path)) without
    the absolute directory prefix polluting the comparison.

    When reading the file, combine with the root path::

        deps = parse_manifest(root / manifest_info.path)
    """

    def __init__(self, filename: str, path: Path) -> None:
        self.filename = filename
        self.path = path


# ── Parsers ────────────────────────────────────────────────────────────────


def parse_requirements_txt(path: Path) -> list[Dependency]:
    """
    Parse a requirements.txt file into a list of Dependency objects.

    Strips version specifiers, extras, and environment markers.
    Skips blank lines and comment lines.
    ecosystem is always 'PyPI'.
    """
    deps: list[Dependency] = []
    text = path.read_text(encoding="utf-8", errors="replace")
    for raw_line in text.splitlines():
        line = raw_line.strip()
        # Skip blank lines, comments, -r / -c / --index-url style options
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Strip environment markers:  pkg; python_version >= "3.8"
        line = line.split(";")[0].strip()
        # Strip extras:  pkg[extra1,extra2]
        line = re.sub(r"\[.*?\]", "", line)
        # Strip version specifiers (==, >=, <=, !=, ~=, >, <)
        name = re.split(r"[=<>!~\s]", line)[0].strip()
        if name:
            deps.append(Dependency(name=name, version="", ecosystem="PyPI"))
    return deps


def parse_package_json(path: Path) -> list[Dependency]:
    """
    Parse a package.json file into a list of Dependency objects.

    Reads both 'dependencies' and 'devDependencies'.
    ecosystem is always 'npm'; version is the raw value string.
    """
    data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    deps: list[Dependency] = []
    for section in ("dependencies", "devDependencies"):
        for name, version in data.get(section, {}).items():
            deps.append(Dependency(name=name, version=str(version), ecosystem="npm"))
    return deps


# ── Dispatcher ─────────────────────────────────────────────────────────────

_PARSERS = {
    "requirements.txt": parse_requirements_txt,
    "package.json": parse_package_json,
}


def parse_manifest(path: Path) -> list[Dependency]:
    """
    Dispatch to the correct parser based on the file's name.

    Raises:
        ValueError: if no parser is registered for the filename.
    """
    filename = path.name
    parser = _PARSERS.get(filename)
    if parser is None:
        raise ValueError(f"No parser registered for {filename}")
    return parser(path)
