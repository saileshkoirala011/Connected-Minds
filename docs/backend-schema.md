# GraphSentinel: Backend Schema

FalkorDB is the only datastore, so the "tables" are node labels and the "relationships" are edge types. One graph: `graphsentinel`. Every node carries `repo` (`owner/name`) so queries and deletes can be scoped.

## 1. Node labels
### Repo
| Property | Type | Notes |
|---|---|---|
| repo | string | `owner/name`, unique |
| url | string | |
| ingested_at | datetime (ISO string) | |
| file_count, function_count | int | |

### File
| Property | Type | Notes |
|---|---|---|
| repo | string | |
| path | string | relative path; unique per repo |
| loc | int | |
| parse_ok | bool | false if skipped |

### Function
| Property | Type | Notes |
|---|---|---|
| repo | string | |
| qualname | string | `module.Class.func`; unique per repo |
| file | string | path |
| lineno | int | |
| is_entry | bool | entry-point flag |

### Package
| Property | Type | Notes |
|---|---|---|
| repo | string | |
| name | string | lowercase |
| version | string | from manifest, may be empty |
| ecosystem | string | `PyPI` |

### Vuln
| Property | Type | Notes |
|---|---|---|
| id | string | e.g. `GHSA-…` or `CVE-…`; unique |
| summary | string | |
| severity | string | critical/high/medium/low/unknown |
| aliases | list | |
| fixed_in | string | optional |

### IngestJob
| Property | Type | Notes |
|---|---|---|
| id | string | uuid |
| repo | string | |
| status | string | queued/running/done/failed |
| step | string | current pipeline step |
| error | string | plain message if failed |
| started_at, finished_at | string | |

### Analysis (stretch S1, agent memory)
| Property | Type |
|---|---|
| id, repo, question | string |
| answer_summary | string |
| created_at | string |

## 2. Relationships
| Edge | From → To | Properties | Meaning |
|---|---|---|---|
| `CONTAINS` | Repo → File | | repo owns file |
| `DEFINES` | File → Function | | function defined in file |
| `IMPORTS` | File → File | | internal import |
| `USES` | File → Package | | file imports external package |
| `CALLS` | Function → Function | `resolved` (bool) | call edge, best effort |
| `DEPENDS_ON` | Repo → Package | `declared_in` | listed in manifest |
| `AFFECTS` | Vuln → Package | `versions` | vulnerable version range |
| `MENTIONED` | Analysis → any node | | memory link (stretch) |

## 3. Indexes
```cypher
CREATE INDEX FOR (n:File) ON (n.repo, n.path)
CREATE INDEX FOR (n:Function) ON (n.repo, n.qualname)
CREATE INDEX FOR (n:Package) ON (n.repo, n.name)
CREATE INDEX FOR (n:Vuln) ON (n.id)
CREATE INDEX FOR (n:IngestJob) ON (n.id)
```

## 4. Write patterns (ingestion only)
```cypher
UNWIND $files AS f
MERGE (n:File {repo:$repo, path:f.path})
SET n.loc = f.loc, n.parse_ok = f.parse_ok
```
```cypher
UNWIND $edges AS e
MATCH (a:File {repo:$repo, path:e.src}), (b:File {repo:$repo, path:e.dst})
MERGE (a)-[:IMPORTS]->(b)
```
Re-ingest: delete first.
```cypher
MATCH (n {repo:$repo}) DETACH DELETE n
```
`Vuln` nodes are shared across repos (keyed by `id`); do not delete them on re-ingest.

## 5. Core read queries (all go in `queries.cypher` for submission)
```cypher
// Most imported files
MATCH (a:File {repo:$repo})-[:IMPORTS]->(b:File)
RETURN b.path AS path, count(a) AS importers ORDER BY importers DESC LIMIT $n

// Blast radius of a file
MATCH (f:File {repo:$repo, path:$path})<-[:IMPORTS*1..6]-(d:File)
RETURN DISTINCT d.path

// Circular imports
MATCH p=(a:File {repo:$repo})-[:IMPORTS*2..6]->(a) RETURN DISTINCT a.path LIMIT 50

// Reachable vulnerabilities
MATCH p=(e:Function {repo:$repo, is_entry:true})-[:CALLS*0..8]->(fn:Function)
MATCH (f:File {repo:$repo, path:fn.file})-[:USES]->(pkg:Package)<-[:AFFECTS]-(v:Vuln)
RETURN v.id, v.severity, pkg.name, f.path, p LIMIT 25

// Import-only exposure (fallback when calls unresolved)
MATCH (f:File {repo:$repo})-[:USES]->(pkg:Package)<-[:AFFECTS]-(v:Vuln)
RETURN v.id, pkg.name, f.path

// Shortest path between two nodes
MATCH (a {repo:$repo, path:$from}), (b {repo:$repo, path:$to})
MATCH p=shortestPath((a)-[*..10]-(b)) RETURN p
```

## 6. Relationship diagram
```
Repo ─CONTAINS─► File ─DEFINES─► Function ─CALLS─► Function
  │                │ ▲ IMPORTS (File→File)
  │                └─USES─► Package ◄─AFFECTS─ Vuln
  └──────DEPENDS_ON────────► Package
IngestJob (status per repo)        Analysis ─MENTIONED─► any node (stretch)
```

## 7. Authentication and access
- **No user accounts** (non-goal), so there are no user tables.
- **Demo gate (optional):** if `APP_PASSWORD` is set, Streamlit shows a password prompt and stores the "unlocked" flag in `st.session_state`. Compare with `hmac.compare_digest`.
- **Secrets:** Anthropic key and FalkorDB credentials come only from env / Streamlit secrets, never from the browser.
- **API (FastAPI):** if exposed publicly, require header `X-API-Key` matching `API_KEY` env; reject otherwise with 401. Rate limit per IP.
- **Agent permissions:** read-only tool functions; the ingestion writer is not importable from the agent module.
- **Data scope:** public repos and public vulnerability data only.

## 8. Data lifecycle
Repos persist until re-ingested or deleted. Add a "Delete repo" action that runs the delete query above. Clone directories are removed after each ingest.
