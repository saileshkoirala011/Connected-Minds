# GraphSentinel: Product Requirements

**Tagline:** Ask your codebase what's risky, and see the proof as a graph.
**Hackathon:** GraphHacks 2026 (FalkorDB). **Track:** 1, Agents That Act on Connected Data (bonus: Track 2, Agent Memory).

## 1. Problem
Dependency scanners list CVEs but can't say which ones actually matter. Developers get hundreds of alerts and can't tell what is reachable from their own code, what a change will break, or why a finding was flagged.

## 2. What we build
An AI agent that ingests a public Python repository into a FalkorDB graph (files, functions, imports, calls, packages, vulnerabilities) and answers risk questions by running graph queries. Every answer shows the graph path that produced it.

## 3. Target users
| User | Need |
|---|---|
| Developer / maintainer | "What breaks if I change this file?" |
| Security engineer | "Which of these CVEs are reachable from our code?" |
| Code reviewer | "How risky is this change?" |
| Student / newcomer | "How is this codebase structured?" |

## 4. Core features (MVP)
1. **Repo ingestion**: paste a public GitHub URL; the system clones it and builds the code graph.
2. **Dependency + CVE layer**: parse requirements, link packages to known vulnerabilities (OSV.dev).
3. **Agent chat**: natural-language questions answered through graph tools.
4. **Reachability analysis**: show which vulnerabilities are reachable from entry points, with the exact path.
5. **Blast radius**: all files and functions affected by changing a given file.
6. **Structural risks**: circular imports, most-imported (critical) files.
7. **Graph view**: interactive visualization with the answer path highlighted.
8. **Explainability panel**: for every answer, the Cypher run and the nodes and edges used.

## 5. Stretch features
- Agent memory: past analyses stored in the graph and reused (Track 2).
- MCP server exposing the same tools to other agents.
- PR / diff risk score.
- Second language via tree-sitter.

## 6. Non-goals
Private repos, auto-fixing code, full static analysis precision, user accounts.

## 7. Success criteria (demo)
- Ingest a real public repo in under 2 minutes.
- Demo question: "Which vulnerabilities are reachable from our entry points?" returns a result with a highlighted path.
- The product stops working if FalkorDB is removed (rule 3).

## 8. Constraints (hackathon rules)
- FalkorDB is the primary database; public, synthetic, or own data only.
- Main coding begins after Oct 15, 12:01 AM IST; submission closes Oct 18, 11:59 PM IST.
- Submission: public repo, README with graph data model, Cypher queries, demo video, deployment or local setup, track named, AI assistant use disclosed.
- The author must be able to explain every part of the code and the graph model.

## 9. Known limitations (state them in the README)
Call resolution in Python is approximate (dynamic dispatch, decorators). Reachability is therefore "likely reachable", with a confidence label.
