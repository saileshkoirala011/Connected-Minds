# GraphSentinel: Technical Requirements Document (TRD)

This is the blueprint for every technical choice. Do not substitute tools without updating this file.

## 1. Stack
| Concern | Decision | Version policy |
|---|---|---|
| Language | Python | 3.12 for deploy; 3.14 works locally |
| Graph DB | FalkorDB (primary and only data store) | FalkorDB Cloud for dev + demo; local Docker optional |
| DB client | `falkordb` | pinned |
| UI | Streamlit | pinned |
| Graph rendering | `pyvis` (HTML component) | pinned |
| API | FastAPI + uvicorn | pinned |
| Validation | pydantic v2 | pinned |
| LLM | Anthropic API via `anthropic` SDK, tool use | model name in env `ANTHROPIC_MODEL` |
| HTTP | `httpx` with timeouts | |
| Retries | `tenacity` | |
| Parsing | stdlib `ast` (MVP); tree-sitter only for S4 | |
| Config | `python-dotenv` + Streamlit secrets in deploy | |
| Tests / lint | pytest, ruff | |
| Hosting | Streamlit Community Cloud (UI) + FalkorDB Cloud (DB) | |

## 2. External APIs
| API | Use | Auth | Limits / handling |
|---|---|---|---|
| FalkorDB Cloud | graph storage and queries | host, port, username, password | timeouts; surface "database unavailable" |
| OSV.dev (`api.osv.dev/v1/querybatch`) | CVE lookup per package+version | none | batch requests, timeout 15 s, 3 retries, cache results in graph |
| Anthropic Messages API | agent reasoning with tools | `ANTHROPIC_API_KEY` | max 8 tool calls per question, timeout 60 s, retry on 429/5xx |
| GitHub (git clone over HTTPS) | fetch public repos | none | public repos only |

## 3. Environment variables
```
ANTHROPIC_API_KEY=
ANTHROPIC_MODEL=
FALKOR_HOST=
FALKOR_PORT=
FALKOR_USERNAME=
FALKOR_PASSWORD=
GRAPH_NAME=graphsentinel
APP_PASSWORD=            # optional demo gate
MAX_REPO_MB=50
MAX_PY_FILES=3000
INGEST_TIMEOUT_S=120
```
`.env` is never committed. Deploy secrets live in Streamlit Cloud settings.

## 4. Architecture decisions
1. **One graph** named `graphsentinel`. Every node has a `repo` property (`owner/name`); every query filters by it. Re-ingesting a repo deletes its nodes first, then rewrites (idempotent).
2. **Agent calls fixed tools only.** It never writes Cypher; tools run parameterized, read-only queries. The ingestion writer is a separate module the agent cannot reach.
3. **No second datastore.** Ingest job status is stored as an `IngestJob` node in FalkorDB.
4. **Tools return** `{result, cypher, nodes, edges}` so the UI can draw evidence.
5. **Streamlit calls the Python modules directly** (no HTTP hop) for speed of development. FastAPI exposes the same functions for the API/MCP/stretch work and for the README.
6. **Entry points** are functions that are module-level `main`, `if __name__ == "__main__"` targets, framework route decorators (`@app.get`, `@app.route`, `@click.command`), or public functions with no callers in the repo.

## 5. Agent specification
- Loop: send question + tool schemas → execute tool calls → feed results back → stop on final text or 8 calls.
- System prompt rules: answer only from tool results; cite files and CVE IDs; say "not found" when data is missing; label reachability confidence.
- Tools (all read-only):
  `get_repo_summary()`, `most_imported(n)`, `find_dependents(path)`, `find_dependencies(path)`, `find_cycles()`, `list_vulns()`, `reachable_vulns()`, `explain_path(from, to)`.
- Max 100 rows per tool result; truncate and say so.

## 6. Ingestion pipeline
1. Validate URL (`https://github.com/<owner>/<repo>`).
2. `git clone --depth 1` into a temp dir; enforce size and time limits.
3. Walk `.py` files, skipping `node_modules`, `tests`, `docs`, `build`, `dist`, `.git`, `venv`, `.venv`.
4. Parse each file with `ast`: defs, imports, calls. Skip and count unparseable files.
5. Resolve internal imports to files; mark others as packages.
6. Parse dependency manifests; query OSV in batches.
7. Write to FalkorDB in `UNWIND` batches of 500 with `MERGE`.
8. Mark entry points; update `IngestJob` status; delete temp dir.
Never execute cloned code.

## 7. Error handling
Custom exceptions `IngestError`, `GraphError`, `ToolError`, `AgentError`. Catch at boundaries (UI action, API route, tool dispatch). Tool errors go back to the agent as `{error}`. User messages are plain sentences; stack traces go to `logging` only.

## 8. Security and compliance
Parameterized Cypher only; read-only agent; input validation (URL pattern, question under 500 chars); no private or personal data (rule 6); secrets via env; AI-assistant use disclosed in README (rule 11).

## 9. Libraries to avoid
LangChain/LlamaIndex, Neo4j drivers, SQLite/Postgres/MongoDB for app data, NetworkX as source of truth, unpinned dependencies.

## 10. Testing
pytest for: URL validation, parser on a fixture file, import resolution, each tool against a tiny fixture graph. Manual end-to-end run on the demo repo before submission.

## 11. Deployment
Streamlit Cloud (Python 3.12) with secrets set; FalkorDB Cloud instance; test the deployed app on Oct 17, not Oct 18.
