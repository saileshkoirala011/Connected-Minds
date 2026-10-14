# 🛡 GraphSentinel

**AI-powered codebase risk & vulnerability agent**

GraphSentinel models your project's entire dependency tree as a property graph in [FalkorDB](https://falkordb.com), enriches every package with live CVE data from the [OSV database](https://osv.dev), computes a composite risk score for each node, and lets you interrogate the graph through an LLM agent or MCP tools — all in under a minute.

---

## Why it matters

Every production codebase carries hundreds of transitive dependencies. Most vulnerability scanners output a flat list of CVEs and leave you to figure out the blast radius, the shortest exploit path, or which 3 packages to upgrade to fix 80% of your exposure. GraphSentinel answers those questions directly.

```
"Which packages in my repo have CRITICAL CVEs?"
"What is the blast radius if lodash@4.17.15 is compromised?"
"Show me the shortest path from my app to urllib3."
"Rank my top 10 riskiest dependencies."
```

---

## Features

| Feature | Description |
|---|---|
| **Multi-ecosystem ingestion** | Parses `requirements.txt`, `pyproject.toml`, `package.json`, `pom.xml` |
| **FalkorDB graph storage** | Idempotent MERGE writes; GraphBLAS-accelerated traversal |
| **Live CVE enrichment** | Batch-queries OSV API; writes `HAS_VULNERABILITY` edges |
| **Composite risk scoring** | CVSS + vuln count + blast radius + depth → 0–10 score |
| **LLM agent** | OpenAI function-calling ReAct loop; heuristic fallback (no key needed) |
| **MCP server** | 7 tools discoverable by any MCP-aware IDE or LLM host |
| **REST API** | FastAPI with `/scan`, `/query`, `/report/{pkg}` endpoints |
| **Rich CLI** | Typer + Rich terminal tables for offline analysis |

---

## Quick Start

### Prerequisites

- Docker & Docker Compose
- Python 3.11+

### 1. Configure

```bash
cp .env.example .env
# Set OPENAI_API_KEY if you want full LLM analysis (optional)
```

### 2. Start FalkorDB + API server

```bash
docker compose up --build
```

- FalkorDB Browser: `http://localhost:3000`
- GraphSentinel API + Swagger UI: `http://localhost:8000/docs`

### 3. Scan a repository

```bash
# Via REST
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"repo_path": "/path/to/repo", "root_package": "myapp", "root_version": "1.0.0"}'

# Via CLI (after pip install -r requirements.txt)
python cli.py scan /path/to/repo --package myapp --version 1.0.0
```

### 4. Ask questions

```bash
# Natural-language agent query
curl -X POST http://localhost:8000/query \
  -H "Content-Type: application/json" \
  -d '{"prompt": "Which packages have critical CVEs?"}'

# CLI
python cli.py query "What is the blast radius for requests?"
python cli.py top-risks --min-score 7.0
python cli.py report requests
python cli.py blast-radius requests --version 2.28.0
python cli.py path myapp urllib3
```

### 5. Use as an MCP tool source

Point any MCP-aware host at `http://localhost:8000/mcp/manifest` to discover all 7 tools.

---

## Project Structure

```
graphhacks/
├── app.py                      # FastAPI entry point
├── agent.py                    # LLM ReAct agent (OpenAI + heuristic fallback)
├── tools.py                    # 7 FalkorDB-backed agent tools
├── mcp_server.py               # MCP manifest + call endpoints
├── cli.py                      # Typer CLI (scan, report, query, top-risks, …)
│
├── ingest/
│   ├── pipeline.py             # Full ingest orchestrator
│   ├── repo_parser.py          # Locate manifests in a repository
│   ├── dependency_parser.py    # Parse manifests → Dependency objects
│   ├── osv_client.py           # OSV API client (sync + async, CVSS enrichment)
│   ├── graph_writer.py         # Idempotent FalkorDB writer
│   └── risk_scorer.py          # Composite risk scoring (CVSS-weighted)
│
├── queries.cypher              # Reference Cypher queries
├── tests/
│   ├── test_tools.py           # Graph tool unit tests (mocked FalkorDB)
│   └── test_pipeline.py        # Pipeline + scorer unit tests
│
├── docs/
│   ├── architecture.md         # System design & component overview
│   └── graph-schema.md         # Node/edge schema + risk score formula
│
├── docker-compose.yml          # FalkorDB + app (one-command local stack)
├── .env.example                # Environment variable template
├── requirements.txt            # Pinned Python dependencies
└── README.md
```

---

## API Reference

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Liveness probe |
| `POST` | `/scan` | Trigger full ingest + vulnerability + scoring pass |
| `POST` | `/query` | Natural-language agent query |
| `GET` | `/report/{package}` | Risk report: deps, CVEs, score, blast radius |
| `GET` | `/mcp/manifest` | MCP tool discovery manifest |
| `POST` | `/mcp/call` | Invoke a named MCP tool |

Full interactive docs at `http://localhost:8000/docs`.

---

## CLI Reference

```
python cli.py scan PATH --package NAME --version VER   Ingest a repository
python cli.py report PACKAGE [--version VER]           Risk report for a package
python cli.py query "PROMPT"                           Ask the agent
python cli.py top-risks [--min-score N] [--limit N]   List riskiest packages
python cli.py blast-radius PACKAGE [--version VER]    Upstream exposure
python cli.py path SOURCE TARGET                       Shortest dependency path
```

---

## Risk Score

```
score = 0.50 × CVSS_norm
      + 0.20 × log_scale(vuln_count,  cap=20)
      + 0.20 × blast_radius_norm(     cap=100)
      + 0.10 × depth_norm(            cap=10)
```

| Score | Label |
|---|---|
| 9.0 – 10.0 | CRITICAL |
| 7.0 – 8.9 | HIGH |
| 4.0 – 6.9 | MEDIUM |
| 0.1 – 3.9 | LOW |
| 0.0 | NONE |

---

## Development

```bash
# Install dependencies
pip install -r requirements.txt

# Run tests (no live DB required — all graph calls are mocked)
pytest tests/ -v

# Lint
ruff check .
ruff format --check .
```

---

## Docs

- [Architecture](docs/architecture.md)
- [Graph Schema](docs/graph-schema.md)
- [Cypher Query Reference](queries.cypher)
- [FalkorDB Docs](https://docs.falkordb.com)
- [OSV API](https://google.github.io/osv.dev/api/)
