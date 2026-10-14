"""
tests/test_pipeline.py — Integration-style tests for the ingest pipeline.

Uses mocks to avoid requiring a live FalkorDB instance or network access.
Verifies that the pipeline correctly orchestrates its dependencies.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ingest.dependency_parser import Dependency


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_deps(*names: str) -> list[Dependency]:
    return [Dependency(name=n, version="1.0.0", ecosystem="PyPI") for n in names]


# ---------------------------------------------------------------------------
# RiskScorer unit tests
# ---------------------------------------------------------------------------


class TestRiskScorer:
    def test_zero_factors_gives_zero_score(self):
        from ingest.risk_scorer import RiskScorer, RiskFactors

        scorer = RiskScorer()
        assert scorer.score(RiskFactors()) == 0.0

    def test_max_cvss_dominates_score(self):
        from ingest.risk_scorer import RiskScorer, RiskFactors

        scorer = RiskScorer()
        score = scorer.score(RiskFactors(max_cvss=10.0))
        # Weight is 0.50, so 10 * 0.50 = 5.0 minimum
        assert score >= 5.0

    def test_full_factors_caps_at_ten(self):
        from ingest.risk_scorer import RiskScorer, RiskFactors

        scorer = RiskScorer()
        score = scorer.score(
            RiskFactors(max_cvss=10.0, vuln_count=100, blast_radius=500, max_depth=20)
        )
        assert score <= 10.0

    def test_critical_cvss_maps_to_critical_label(self):
        from ingest.risk_scorer import severity_label

        assert severity_label(9.5) == "CRITICAL"
        assert severity_label(7.5) == "HIGH"
        assert severity_label(5.0) == "MEDIUM"
        assert severity_label(2.0) == "LOW"
        assert severity_label(0.0) == "NONE"

    def test_score_from_vulns(self):
        from ingest.risk_scorer import RiskScorer

        scorer = RiskScorer()
        vulns = [
            {"severity": [{"score": "9.8"}], "database_specific": {"cvss": 9.8}},
            {"severity": [], "database_specific": {"severity": "HIGH"}},
        ]
        score, factors = scorer.score_from_vulns(vulns, blast_radius=10)
        assert factors.vuln_count == 2
        assert factors.max_cvss >= 8.0
        assert 0.0 <= score <= 10.0


# ---------------------------------------------------------------------------
# OSVClient CVSS extraction
# ---------------------------------------------------------------------------


class TestOSVClientEnrichment:
    def test_extract_cvss_from_database_specific(self):
        from ingest.osv_client import extract_cvss

        vuln = {"database_specific": {"cvss": 7.5}}
        assert extract_cvss(vuln) == 7.5

    def test_extract_cvss_from_severity_label(self):
        from ingest.osv_client import extract_cvss

        vuln = {"database_specific": {"severity": "CRITICAL"}}
        score = extract_cvss(vuln)
        assert score >= 9.0

    def test_extract_cvss_no_data(self):
        from ingest.osv_client import extract_cvss

        assert extract_cvss({}) == 0.0

    def test_enrich_adds_cvss_keys(self):
        from ingest.osv_client import OSVClient

        client = OSVClient()
        vulns = [
            {"id": "CVE-2024-0001", "database_specific": {"cvss": 8.1}},
        ]
        enriched = client._enrich(vulns)
        assert enriched[0]["_cvss_score"] == 8.1
        assert enriched[0]["_severity"] == "HIGH"

    def test_cvss_to_severity_boundaries(self):
        from ingest.osv_client import cvss_to_severity

        assert cvss_to_severity(9.0) == "CRITICAL"
        assert cvss_to_severity(8.9) == "HIGH"
        assert cvss_to_severity(7.0) == "HIGH"
        assert cvss_to_severity(4.0) == "MEDIUM"
        assert cvss_to_severity(3.9) == "LOW"
        assert cvss_to_severity(0.0) == "NONE"


# ---------------------------------------------------------------------------
# DependencyParser
# ---------------------------------------------------------------------------


class TestDependencyParser:
    def test_parse_requirements_txt(self, tmp_path: Path):
        from ingest.dependency_parser import parse_requirements_txt

        req = tmp_path / "requirements.txt"
        req.write_text(
            "requests>=2.0\n"
            "flask==3.0.0\n"
            "# comment\n"
            "pytest[testing]>=7.0; python_version>='3.8'\n"
        )
        deps = parse_requirements_txt(req)
        names = [d.name for d in deps]
        assert "requests" in names
        assert "flask" in names
        assert "pytest" in names

    def test_parse_package_json(self, tmp_path: Path):
        import json

        from ingest.dependency_parser import parse_package_json

        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "dependencies": {"lodash": "^4.17.21"},
            "devDependencies": {"jest": "^29.0.0"},
        }))
        deps = parse_package_json(pkg)
        names = [d.name for d in deps]
        assert "lodash" in names
        assert "jest" in names
        assert all(d.ecosystem == "npm" for d in deps)

    def test_unsupported_manifest_raises(self, tmp_path: Path):
        from ingest.dependency_parser import parse_manifest

        unknown = tmp_path / "Cargo.toml"
        unknown.write_text("")
        with pytest.raises(ValueError, match="No parser registered"):
            parse_manifest(unknown)


# ---------------------------------------------------------------------------
# RepoParser
# ---------------------------------------------------------------------------


class TestRepoParser:
    def test_finds_requirements_txt(self, tmp_path: Path):
        from ingest.repo_parser import RepoParser

        req = tmp_path / "requirements.txt"
        req.write_text("requests>=2.0\n")

        manifests = list(RepoParser(tmp_path).find_manifests())
        assert any(m.filename == "requirements.txt" for m in manifests)

    def test_skips_node_modules(self, tmp_path: Path):
        from ingest.repo_parser import RepoParser

        (tmp_path / "node_modules").mkdir()
        (tmp_path / "node_modules" / "package.json").write_text("{}")
        (tmp_path / "package.json").write_text('{"dependencies": {}}')

        manifests = list(RepoParser(tmp_path).find_manifests())
        paths = [str(m.path) for m in manifests]
        assert not any("node_modules" in p for p in paths)


# ---------------------------------------------------------------------------
# IngestPipeline (mocked)
# ---------------------------------------------------------------------------


class TestIngestPipeline:
    @pytest.mark.asyncio
    async def test_run_returns_summary(self, tmp_path: Path, mocker):
        from ingest.pipeline import IngestPipeline

        # Create a minimal repo with one manifest
        (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")

        # Patch all external I/O
        mocker.patch("ingest.pipeline.GraphWriter")
        mocker.patch(
            "ingest.pipeline.IngestPipeline._enrich_vulnerabilities",
            new=AsyncMock(return_value=2),
        )
        mocker.patch(
            "ingest.pipeline.IngestPipeline._score_all",
            new=AsyncMock(return_value=["requests@2.31.0"]),
        )

        pipeline = IngestPipeline()
        summary = await pipeline.run(
            repo_path=str(tmp_path),
            root_package="myapp",
            root_version="1.0.0",
        )

        assert "packages_written" in summary
        assert summary["vulnerabilities_found"] == 2
        assert "requests@2.31.0" in summary["high_risk_packages"]

    @pytest.mark.asyncio
    async def test_run_raises_on_missing_path(self):
        from ingest.pipeline import IngestPipeline

        pipeline = IngestPipeline()
        with pytest.raises(FileNotFoundError):
            await pipeline.run(
                repo_path="/nonexistent/path",
                root_package="test",
            )
