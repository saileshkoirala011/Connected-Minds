# GraphSentinel: Architecture

## 1. Tech stack
| Layer | Choice |
|---|---|
| Language | Python 3.11+ (frontend and backend) |
| Graph DB | FalkorDB (Docker locally, FalkorDB Cloud for the demo) |
| UI | Streamlit + pyvis (or streamlit-agraph) |
| API | FastAPI |
| Agent | Anthropic Python SDK, tool use |
| Tool protocol | `mcp` Python SDK (stretch) |
| Parsing | `ast` (MVP), tree-sitter (stretch) |
| Vulnerability data | OSV.dev public API |
| Tests / lint | pytest, ruff |
| Deploy | Streamlit Community Cloud + FalkorDB Cloud |

## 2. App flow
```
GitHub URL
   │
   ▼
[Ingest] clone (depth 1) → walk .py files → parse AST
   │          → files, functions, imports, calls
   │          → parse requirements/pyproject → packages
   │          → OSV.dev lookup → vulnerabilities
   ▼
[FalkorDB graph]  ◄──────────────┐
   ▲                              │ read-only Cypher
   │                              │
[Tools layer] find_dependents, reachable_vulns, find_cycles, ...
   ▲
   │ tool calls
[Agent loop] Claude decides which tools to call, multi-hop
   │
   ▼
[Streamlit UI] chat answer + highlighted graph + Cypher/evidence panel
```

## 3. Graph data model
**Nodes**
| Label | Properties |
|---|---|
| `Repo` | name, url, ingested_at |
| `File` | path, loc |
| `Function` | qualname, file, lineno, is_entry |
| `Package` | name, version, ecosystem |
| `Vuln` | id, summary, severity, aliases |
| `Analysis` | id, question, created_at (agent memory, stretch) |

**Relationships**
| Edge | Meaning |
|---|---|
| `(Repo)-[:CONTAINS]->(File)` | repo owns file |
| `(File)-[:DEFINES]->(Function)` | function defined in file |
| `(File)-[:IMPORTS]->(File)` | internal import |
| `(File)-[:USES]->(Package)` | external import |
| `(Function)-[:CALLS]->(Function)` | resolved call |
| `(Repo)-[:DEPENDS_ON]->(Package)` | declared dependency |
| `(Vuln)-[:AFFECTS]->(Package)` | vulnerability affects package version |
| `(Analysis)-[:MENTIONED]->(node)` | memory link (stretch) |

**Reachability query (core)**
```cypher
MATCH p = (e:Function {is_entry:true})-[:CALLS*0..8]->(:Function)<-[:DEFINES]-(f:File)-[:USES]->(pkg:Package)<-[:AFFECTS]-(v:Vuln)
RETURN v.id, pkg.name, f.path, p LIMIT 25
```

## 4. Agent tools (all read-only Cypher)
| Tool | Purpose |
|---|---|
| `get_repo_summary` | counts, top-level stats |
| `find_dependents(file)` | blast radius via `IMPORTS*` |
| `find_dependencies(file)` | transitive deps |
| `find_cycles()` | circular imports |
| `most_imported(n)` | critical files |
| `list_vulns()` | all CVEs and their packages |
| `reachable_vulns()` | CVEs reachable from entry points, with path |
| `explain_path(a, b)` | shortest path between two nodes |

Each tool returns `{result, cypher, nodes, edges}` so the UI can render evidence.

## 5. Folder structure
```
graphsentinel/
├── app.py                 # Streamlit entry
├── api/
│   ├── main.py            # FastAPI app
│   └── routes.py
├── agent/
│   ├── loop.py            # tool-use loop
│   ├── tools.py           # tool schemas + dispatch
│   └── prompts.py
├── graph/
│   ├── client.py          # FalkorDB connection
│   ├── schema.py          # indexes, constraints
│   └── queries.py         # all Cypher in one place
├── ingest/
│   ├── clone.py
│   ├── parse_python.py
│   ├── deps.py            # requirements / pyproject
│   ├── osv.py             # vulnerability lookup
│   └── pipeline.py
├── mcp_server.py          # stretch
├── ui/
│   ├── graph_view.py
│   └── theme.py
├── tests/
├── queries.cypher         # submission artifact
├── docker-compose.yml
├── .streamlit/config.toml
├── .env.example
├── requirements.txt
└── README.md
```

## 6. Deployment
- Local: `docker compose up -d` (FalkorDB), then `streamlit run app.py`.
- Live: Streamlit Community Cloud connected to FalkorDB Cloud; secrets via platform settings.
