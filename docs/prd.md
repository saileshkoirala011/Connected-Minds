# GraphSentinel: Product Requirements Document (PRD)

## 1. Overview
GraphSentinel is an AI agent that answers codebase risk questions by querying a FalkorDB graph. The user pastes a public Python repository URL; the app builds a graph of files, functions, imports, calls, packages, and known vulnerabilities (CVEs). The user then asks questions in plain English ("Which vulnerabilities are reachable from our code?"). The agent runs graph queries, answers, and shows the exact graph path as proof.

**Hackathon:** GraphHacks 2026. **Track:** 1, Agents That Act on Connected Data. **Bonus:** Track 2 (agent memory of past analyses).

## 2. Problem
Dependency scanners list hundreds of CVEs but cannot say which ones are reachable from the project's own code, what a change will break, or why something was flagged. Developers waste time on alerts that don't matter.

## 3. Target users
| User | Question they ask |
|---|---|
| Developer / maintainer | "What breaks if I change this file?" |
| Security engineer | "Which CVEs are actually reachable?" |
| Code reviewer | "How risky is this change?" |
| Student / newcomer | "How is this codebase structured?" |

## 4. Features (exact build list)

### MVP (must ship)
| ID | Feature | Description |
|---|---|---|
| F1 | Repo ingestion | Paste a public GitHub URL; the app clones it (depth 1) and builds the code graph. Shows progress and a summary (files, functions, edges, skipped files). |
| F2 | Code graph | Files, functions, internal imports, external package usage, and function calls (best-effort). |
| F3 | Dependency + CVE layer | Parse `requirements.txt` / `pyproject.toml`, look up vulnerabilities on OSV.dev, link `Package` to `Vuln`. |
| F4 | Agent chat | Natural-language questions; the agent picks graph tools, can chain several calls (multi-hop), and answers only from tool results. |
| F5 | Reachability | Show which CVEs are reachable from entry points, with a confidence label ("likely reachable" or "import only"). |
| F6 | Blast radius | All files and functions affected by changing a given file. |
| F7 | Structural risks | Circular imports, most-imported (critical) files, orphan files. |
| F8 | Graph view | Interactive graph with the answer path highlighted. |
| F9 | Evidence panel | For every answer: tool calls made, the Cypher run, nodes and edges used. |
| F10 | Example questions | Clickable starter questions for the demo. |

### Stretch (only if time)
| ID | Feature |
|---|---|
| S1 | Agent memory: save past analyses to the graph and reuse them (Track 2) |
| S2 | MCP server exposing the same tools to other agents |
| S3 | PR / diff risk score |
| S4 | Second language via tree-sitter |

## 5. Non-goals
Private repos, automatic code fixes, user accounts, full static-analysis precision, languages other than Python (MVP).

## 6. Success criteria
- A repo ingests in under 2 minutes.
- The demo question "Which vulnerabilities are reachable?" returns a result with a highlighted path.
- Remove FalkorDB and the product stops working (rule 3).
- Deployed at a live URL; demo video recorded.

## 7. Constraints
Hackathon rules: FalkorDB is the primary graph DB; public/synthetic/own data only; main coding starts after Oct 15, 12:01 AM IST; submit by Oct 18, 11:59 PM IST; disclose AI assistant use; explain all code and the graph model.

## 8. Known limitations (publish in README)
Python call resolution is approximate (dynamic dispatch, decorators, reflection), so reachability is labelled "likely".
