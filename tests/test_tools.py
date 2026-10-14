"""
tests/test_tools.py — Unit tests for tools.py graph functions.

Uses pytest-mock to stub out FalkorDB queries so tests run without a
live database instance.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_query_result(headers: list[str], rows: list[list]):
    """Build a fake FalkorDB QueryResult-like object."""
    result = MagicMock()
    result.header = headers
    result.result_set = [
        [
            cell.properties if hasattr(cell, "properties") else cell
            for cell in row
        ]
        for row in rows
    ]
    # Make cells that have .properties behave correctly in _query()
    fake_rows = []
    for row in rows:
        fake_row = []
        for cell in row:
            if isinstance(cell, dict):
                node = MagicMock()
                node.properties = cell
                fake_row.append(node)
            else:
                fake_row.append(cell)
        fake_rows.append(fake_row)
    result.result_set = fake_rows
    return result


@pytest.fixture()
def mock_graph(mocker):
    """Patch tools._get_graph to return a controllable mock."""
    graph = MagicMock()
    mocker.patch("tools._get_graph", return_value=graph)
    return graph


# ---------------------------------------------------------------------------
# get_transitive_dependencies
# ---------------------------------------------------------------------------


def test_get_transitive_dependencies_returns_list(mock_graph):
    """Happy path: query returns two transitive deps."""
    from tools import get_transitive_dependencies

    mock_graph.query.return_value = _make_query_result(
        headers=["name", "version", "ecosystem", "depth"],
        rows=[
            ["requests", "2.31.0", "PyPI", 1],
            ["urllib3", "2.0.7", "PyPI", 2],
        ],
    )

    result = get_transitive_dependencies("myapp")

    assert len(result) == 2
    assert result[0]["name"] == "requests"
    assert result[1]["name"] == "urllib3"
    assert result[1]["depth"] == 2


def test_get_transitive_dependencies_empty(mock_graph):
    """No dependencies returns empty list."""
    from tools import get_transitive_dependencies

    mock_graph.query.return_value = _make_query_result(
        headers=["name", "version", "ecosystem", "depth"],
        rows=[],
    )

    result = get_transitive_dependencies("isolated-pkg")
    assert result == []


# ---------------------------------------------------------------------------
# get_high_risk_packages
# ---------------------------------------------------------------------------


def test_get_high_risk_packages_filters_by_score(mock_graph):
    from tools import get_high_risk_packages

    mock_graph.query.return_value = _make_query_result(
        headers=["package", "version", "ecosystem", "risk_score", "vuln_count"],
        rows=[
            ["requests", "2.28.0", "PyPI", 8.5, 3],
            ["lodash", "4.17.15", "npm", 9.2, 5],
        ],
    )

    result = get_high_risk_packages(min_score=7.0)

    assert len(result) == 2
    # Both should have risk_score property
    scores = [r["risk_score"] for r in result]
    assert all(s >= 7.0 for s in scores)


# ---------------------------------------------------------------------------
# get_blast_radius
# ---------------------------------------------------------------------------


def test_get_blast_radius_returns_upstream(mock_graph):
    from tools import get_blast_radius

    mock_graph.query.return_value = _make_query_result(
        headers=["name", "version", "ecosystem", "depth"],
        rows=[
            ["myapp", "1.0.0", "PyPI", 1],
            ["other-app", "2.0.0", "PyPI", 2],
        ],
    )

    result = get_blast_radius("requests")

    assert len(result) == 2
    assert result[0]["name"] == "myapp"


def test_get_blast_radius_no_upstreams(mock_graph):
    from tools import get_blast_radius

    mock_graph.query.return_value = _make_query_result(
        headers=["name", "version", "ecosystem", "depth"],
        rows=[],
    )

    result = get_blast_radius("leaf-package")
    assert result == []


# ---------------------------------------------------------------------------
# shortest_path
# ---------------------------------------------------------------------------


def test_shortest_path_found(mock_graph):
    from tools import shortest_path

    mock_graph.query.return_value = _make_query_result(
        headers=["path"],
        rows=[
            [["myapp", "requests", "urllib3"]],
        ],
    )

    result = shortest_path("myapp", "urllib3")
    assert result == ["myapp", "requests", "urllib3"]


def test_shortest_path_not_found(mock_graph):
    from tools import shortest_path

    mock_graph.query.return_value = _make_query_result(
        headers=["path"],
        rows=[],
    )

    result = shortest_path("a", "z")
    assert result == []


# ---------------------------------------------------------------------------
# get_dependency_graph
# ---------------------------------------------------------------------------


def test_get_dependency_graph_structure(mock_graph):
    from tools import get_dependency_graph

    mock_graph.query.return_value = _make_query_result(
        headers=["source", "source_risk", "target"],
        rows=[
            ["myapp", 3.0, "requests"],
            ["requests", 8.5, "urllib3"],
        ],
    )

    result = get_dependency_graph("myapp")

    assert "nodes" in result
    assert "edges" in result
    node_ids = {n["id"] for n in result["nodes"]}
    assert "myapp" in node_ids
    assert "requests" in node_ids
    assert "urllib3" in node_ids
    assert len(result["edges"]) == 2
