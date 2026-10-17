# 🛡️ GraphSentinel

**AI-powered code security agent — answers "Which CVEs are reachable?" by traversing a FalkorDB code graph**

GraphSentinel ingests a public Python GitHub repository, builds a property graph of files, functions, imports, calls, packages, and known vulnerabilities, then lets you ask security questions in plain English. The agent chains graph queries and answers only from what it finds — showing you the exact path as proof.

**Hackathon:** GraphHacks 2026 · **Track 1:** Agents That Act on Connected Data · **Bonus Track 2:** Agent Memory

---

## Why the graph matters

A flat CVE scanner tells you *what* is vulnerable. GraphSentinel tells you *whether* it is reachable from your code, *what* would break if you changed a file, and *which* packages to upgrade to fix the most exposure. Remove FalkorDB and the product stops working — the graph is the product.

---

## Graph data model

```
Repo ─CONTAINS─► File ─DEFINES─► Function ─CALLS─► Function
  │                │ ▲  IMPORTS (File→File)
  │                └─USES─► Package ◄─AFFECTS─ Vuln
  └──────DEPENDS_ON────────► Package
IngestJob (status per repo)
```

### Node labels

| Label | Key properties |
|---|---|
| `Repo` | `repo` (owner/name), `url`, `ingested_at`, `file_count`, `function_count` |
| `File` | `repo`, `path`, `loc`, `parse_ok` |
| `Function` | `repo`, `qualname`, `file`, `lineno`, `is_entry` |
| `Package` | `repo`, `name`, `version`, `ecosystem` |
| `Vuln` | `id` (CVE/GHSA), `summary`, `severity`, `aliases`, `fixed_in` |
| `IngestJob` | `id`, `repo`, `status`, `step`, `error`, `started_at`, `finished_at` |

### Edge types

| Edge | From → To | Meaning |
|---|---|---|
| `CONTAINS` | Repo → File | repo owns file |
| `DEFINES` | File → Function | function defined in file |
| `IMPORTS` | File → File | internal import |
| `USES` | File → Package | file imports external package |
| `CALLS` | Function → Function | call edge (best-effort, `resolved` flag) |
| `DEPENDS_ON` | Repo → Package | listed in manifest |
| `AFFECTS` | Vuln → Package | vulnerable version range |

---

## Quick start

### Option A: Local with Docker Compose

```bash
cp .env.example .env
# Fill in ANTHROPIC_API_KEY (required for chat)
docker compose up --build
```

- Streamlit UI: `http://localhost:8501`
- FalkorDB Browser: `http://localhost:3000`

### Option B: Cloud (FalkorDB Cloud + Streamlit Cloud)

1. Create a free cluster at [app.falkordb.cloud](https://app.falkordb.cloud). Copy the host, port, username, and password.
2. Fork this repo and deploy to [Streamlit Community Cloud](https://streamlit.io/cloud).
3. In Streamlit Cloud → Settings → Secrets, paste:

```toml
FALKORDB_HOST = "your-cluster.falkordb.cloud"
FALKORDB_PORT = "6379"
FALKORDB_USERNAME = "your-username"
FALKORDB_PASSWORD = "your-password"
FALKORDB_SSL = "true"
FALKORDB_GRAPH = "graphsentinel"
ANTHROPIC_API_KEY = "sk-ant-..."
ANTHROPIC_MODEL = "claude-sonnet-4-5"
```

---

## CLI reference

```
# Check database connection
python cli.py health

# Ingest a public repo
python cli.py ingest https://github.com/pallets/click

# Repo summary (files, functions, packages, CVEs)
python cli.py summary pallets/click

# Most-imported files (structural hotspots)
python cli.py top pallets/click

# Blast radius of a file
python cli.py blast pallets/click src/click/core.py

# Files in circular import chains
python cli.py cycles pallets/click
```

---

## Ingest pipeline

1. Validate URL (`https://github.com/<owner>/<repo>`)
2. `git clone --depth 1` into a temp dir; enforce size and time limits
3. Walk `.py` files, parse with `ast`: defs, imports, calls
4. Resolve internal imports to IMPORTS edges; external to Package nodes
5. Parse `requirements.txt` / `pyproject.toml` for declared deps
6. Write Repo, File, Function, Package nodes and CONTAINS/DEFINES/IMPORTS/USES edges
7. Resolve intra-repo function calls → CALLS edges
8. Write DEPENDS_ON edges from Repo to manifest packages
9. Query [OSV API](https://google.github.io/osv.dev/api/) in batches → write Vuln nodes + AFFECTS edges
10. Mark `IngestJob` done; delete temp dir

---

## AI-use disclosure

This project was built with AI coding assistance (Kiro/Claude). All Cypher queries, architecture decisions, and graph schema were designed by the team; AI assisted with implementation.

---

## Docs

- [Architecture](docs/architecture.md)
- [Backend schema](docs/backend-schema.md)
- [Cypher query reference](queries.cypher)
- [FalkorDB docs](https://docs.falkordb.com)
- [OSV API](https://google.github.io/osv.dev/api/)
