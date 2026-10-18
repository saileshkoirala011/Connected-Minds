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

See [`queries.cypher`](queries.cypher) for every Cypher query the product depends on.

---

## Quick start

### Option A: Local with Docker Compose

```bash
cp .env.example .env
# Fill in GEMINI_API_KEY and FalkorDB credentials
docker compose up --build
```

- Streamlit UI: `http://localhost:8501`
- FalkorDB Browser: `http://localhost:3000`

### Option B: Local without Docker

```bash
cp .env.example .env
# Fill in credentials (see .env.example)
pip install -r requirements.txt
python cli.py health          # confirm DB connection
python cli.py ingest https://github.com/pallets/click
python -m streamlit run app.py
```

### Option C: Streamlit Cloud

1. Fork this repo
2. Deploy at [share.streamlit.io](https://share.streamlit.io) → point to `app.py`
3. In **Settings → Secrets**, paste:

```toml
FALKORDB_HOST = "your-cloud-host"
FALKORDB_PORT = "65405"
FALKORDB_USERNAME = "your-username"
FALKORDB_PASSWORD = "your-password"
FALKORDB_SSL = "false"
FALKORDB_GRAPH = "graphsentinel"
GEMINI_API_KEY = "your-gemini-key"
GEMINI_MODEL = "gemini-flash-latest"
```

---

## CLI reference

```bash
python cli.py health                                    # check DB connection
python cli.py ingest https://github.com/pallets/click  # ingest a repo
python cli.py summary pallets/click                    # file/function/CVE counts
python cli.py top --repo pallets/click                 # most-imported files
python cli.py blast src/click/core.py --repo pallets/click  # blast radius
python cli.py cycles --repo pallets/click              # circular imports
python cli.py repos                                    # list all ingested repos
```

---

## Ingest pipeline

1. Validate URL (`https://github.com/<owner>/<repo>`)
2. `git clone --depth 1` into a temp dir; enforce size and time limits
3. Walk `.py` files, parse with `ast`: defs, imports, calls
4. Resolve internal imports → IMPORTS edges; external → Package nodes
5. Parse `requirements.txt` / `package.json` for declared deps
6. Write Repo, File, Function, Package nodes and CONTAINS/DEFINES/IMPORTS/USES edges
7. Resolve intra-repo function calls → CALLS edges (best-effort)
8. Write DEPENDS_ON edges from Repo to manifest packages
9. Query [OSV API](https://google.github.io/osv.dev/api/) in batches → write Vuln nodes + AFFECTS edges
10. Mark `IngestJob` done; delete temp dir

---

## Stack

| Concern | Choice |
|---|---|
| Graph database | FalkorDB (primary and only datastore) |
| UI | Streamlit |
| LLM | Google Gemini via `gemini_client.py` adapter |
| Vulnerability data | OSV.dev API |
| Parsing | Python stdlib `ast` |
| HTTP | `httpx` with retries |
| Config | `python-dotenv` |

---

## AI-use disclosure

This project was built with AI coding assistance (Kiro IDE, powered by Claude/Anthropic). All Cypher queries, the graph schema, and architectural decisions were designed by the team. AI assisted with implementation, debugging, and code generation. The Gemini adapter (`gemini_client.py`) was provided as part of the development process. All generated code was reviewed and tested before use.

---

## Known limitations

- Python call resolution is approximate (dynamic dispatch, decorators, reflection not supported)
- Reachability via CALLS edges is labelled "best-effort" — not proof of exploitability
- CVE enrichment requires versioned dependencies in `requirements.txt`; libraries without version pins show 0 CVEs

---

## Docs

- [Architecture](docs/architecture.md)
- [Backend schema](docs/backend-schema.md)
- [Cypher query reference](queries.cypher)
- [FalkorDB docs](https://docs.falkordb.com)
- [OSV API](https://google.github.io/osv.dev/api/)
