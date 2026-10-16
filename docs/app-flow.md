# GraphSentinel: App Flow

## 1. Pages
Single Streamlit app, one main screen with a sidebar and tabs. No login (optional shared-password gate).

| Page / area | Purpose |
|---|---|
| **Gate** (optional) | Password prompt when `APP_PASSWORD` is set |
| **Sidebar** | Repo URL input, Ingest button, repo selector, repo stats |
| **Chat panel** (left) | Ask questions, see answers, example questions |
| **Graph panel** (right) | Interactive graph view |
| **Detail tabs** (below graph) | Evidence, Cypher, Ingest log |

## 2. User journey
1. **Open app** → (if gated) enter password → empty state with 3 example questions and a prompt to ingest a repo.
2. **Ingest** → paste URL → click **Ingest repo**.
3. **Wait** → progress steps: Cloning → Parsing → Resolving imports → Checking vulnerabilities → Writing graph. On success, a summary card appears and chat unlocks.
4. **Ask** → type a question or click an example → agent runs.
5. **Read answer** → answer card with confidence label; graph highlights the path; Evidence tab lists tool calls.
6. **Explore** → click a node to see its details; ask a follow-up.
7. **Switch or re-ingest** → pick another ingested repo or ingest again.

## 3. Button and action behavior
| Action | What happens | Result / next state |
|---|---|---|
| Ingest repo (valid URL) | Disable button, run pipeline, stream progress | Success: summary card, chat enabled, graph shows overview. Failure: error message, button re-enabled |
| Ingest repo (invalid URL) | Inline validation message | No pipeline started |
| Re-ingest | Confirm, delete repo's nodes, run pipeline | Fresh graph, chat history cleared |
| Example question | Fills input and submits | Same as Ask |
| Send question | Spinner "Querying the graph…", agent loop | Answer card, highlighted path, evidence filled |
| Clear highlight | Resets graph styling | Full graph view |
| Click graph node | Show properties in a side box | No agent call |
| Evidence tab | Lists each tool call: name, args, row count, time | Read-only |
| Cypher tab | Shows executed Cypher with params | Copy button |
| Repo selector change | Load that repo's graph and summary | Chat history cleared |

## 4. States
| State | UI |
|---|---|
| Empty (no repo) | Chat disabled, helper text |
| Ingesting | Progress steps, controls disabled |
| Ready | Chat enabled, overview graph |
| Thinking | Spinner in chat, input disabled |
| Error | Red banner with plain-language message and a retry action |
| Limits hit | "Repo too large" or "Too many files" with the limit shown |

## 5. Flow diagram
```
Open ─► [Gate?] ─► Empty state
                      │ paste URL + Ingest
                      ▼
                 Ingesting ──error──► Error banner ─► Empty state
                      │ success
                      ▼
                    Ready ◄────────────┐
                      │ question        │
                      ▼                 │
                   Thinking ──► Answer + highlighted path + evidence
                                        │ follow-up / new repo
                                        └────────────────────────┘
```

## 6. Demo script (video)
1. Ingest the demo repo.
2. "Give me a summary of this repo."
3. "Which files are most critical?"
4. "What breaks if I change core.py?"
5. "Which vulnerabilities are reachable from our entry points?" → highlighted path.
6. "Are there circular imports?"
Close on the "why the graph matters" line: the answer is a path query, not a text search.
