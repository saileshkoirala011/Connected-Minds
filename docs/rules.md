# GraphSentinel: Rules

## 1. Use
| Need | Library |
|---|---|
| Graph DB client | `falkordb` |
| API | `fastapi`, `uvicorn`, `pydantic` |
| UI | `streamlit`, `pyvis` |
| LLM | `anthropic` |
| HTTP | `httpx` (timeouts always set) |
| Config | `python-dotenv` |
| Retries | `tenacity` |
| Parsing | stdlib `ast`; `tree-sitter` only as stretch |
| Tests / lint | `pytest`, `ruff` |
| Git | `subprocess` calling `git clone --depth 1` |

## 2. Avoid
- **Any other primary datastore** (SQLite, Postgres, MongoDB) for graph data. FalkorDB must be the thing the product runs on.
- **NetworkX as the source of truth.** Fine for a quick local experiment, not for the product.
- **LangChain / LlamaIndex.** Too heavy and hides the graph logic you must explain.
- **LLM-written Cypher run directly.** The agent calls fixed tools; no free-form query execution.
- **Neo4j drivers**, and unpinned dependencies.
- **Hard-coded secrets** or committing `.env`.
- **Copying large generated blocks you can't explain** (rule 12/13: you must understand and defend the code).

## 3. Coding standards
- Type hints on public functions; docstrings for tools.
- All Cypher lives in `graph/queries.py`; always **parameterized** (`$param`), never string-formatted.
- Idempotent writes: `MERGE`, not `CREATE`, for ingestion.
- Batch writes with `UNWIND` (500-1000 rows per batch).
- Small functions; no module over ~300 lines.

## 4. Error handling
- Define custom exceptions: `IngestError`, `GraphError`, `ToolError`, `AgentError`.
- Catch at boundaries (API route, tool dispatch, UI), not deep inside helpers.
- Tool errors return `{error: "..."}` to the agent so it can recover; never crash the loop.
- OSV and LLM calls: timeout 10-30 s, retry up to 3 times with backoff, then degrade gracefully ("vulnerability data unavailable").
- Unparseable files: skip, count them, report in the ingest summary.
- User-facing errors are plain sentences; stack traces go to logs only.
- Use `logging`, not `print`.

## 5. Boundaries
**Ingestion**
- Only public `https://github.com/<owner>/<repo>` URLs; reject everything else.
- Shallow clone, repo size cap (~50 MB), file cap (~3,000 `.py` files), ingest timeout (~120 s).
- Skip: `node_modules`, `tests`, `docs`, `build`, `dist`, `.git`, `venv`.
- Never execute cloned code.

**Agent**
- Tools are **read-only**; the graph writer is a separate module the agent cannot call.
- Max 8 tool calls per question; max result size per tool (e.g. 100 rows).
- System prompt: answer only from tool results; if data is missing, say so.

**API**
| Endpoint | Method | Purpose |
|---|---|---|
| `/health` | GET | DB connectivity |
| `/ingest` | POST | start ingestion `{url}` |
| `/ingest/{id}` | GET | status |
| `/ask` | POST | agent question `{question}` |
| `/graph` | GET | nodes/edges for the view |
- Validate all input with pydantic; limit question length (~500 chars); basic rate limiting.
- CORS restricted to the app origin.

## 6. Data and compliance
- Only public repos and public vulnerability data; no personal or restricted data (rule 6).
- Disclose AI coding assistant use in the README (rule 11).
- Record all third-party libraries in `requirements.txt`; credit OSV.dev.

## 7. Git hygiene
- Public repo created **after** Oct 15, 12:01 AM IST; commit regularly so history shows work done during the event.
- Conventional commit messages; `.gitignore` for `.env`, `data/`, `.venv/`.
