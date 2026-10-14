# GraphSentinel: Phases

Window: **Oct 15, 12:01 AM IST → Oct 18, 11:59 PM IST**. Solo build. Times below are targets.

## Phase 0: Planning (now → before start)
Docs only: PRD, architecture, rules, design. Pick the demo repo. Create accounts (FalkorDB Cloud, Anthropic API, Streamlit Cloud). **No main code before the start (rule 8).**
**Done when:** docs reviewed, demo repo chosen, API keys ready.

## Phase 1: Foundation (Oct 15)
- Create the public repo; docker-compose for FalkorDB; `.env`.
- `graph/client.py`, `/health`, indexes.
- Clone + parse imports → `File`, `IMPORTS`, `USES`.
- Three proof queries (most-imported, transitive deps, cycles).
**Done when:** one command ingests the demo repo and the graph shows in the FalkorDB browser.

## Phase 2: Code + vulnerability graph (Oct 15-16)
- `Function`, `DEFINES`, `CALLS` (best-effort resolution), entry-point detection.
- Parse requirements, `Package`, `DEPENDS_ON`.
- OSV lookup → `Vuln`, `AFFECTS`.
- Reachability query working.
**Done when:** `reachable_vulns` returns a path for the demo repo.

## Phase 3: Agent (Oct 16)
- Tool functions in `agent/tools.py` returning result + cypher + nodes/edges.
- Tool-use loop with call limit and error recovery.
- System prompt that forbids unsupported claims.
**Done when:** 5 demo questions answered correctly from the terminal.

## Phase 4: UI (Oct 17)
- Streamlit: repo input, ingest progress, chat, graph view with highlighted path, evidence panel.
- Apply `design.md` theme.
**Done when:** the full demo flow works end to end in the browser.

## Phase 5: Polish + deploy (Oct 17-18)
- FalkorDB Cloud + Streamlit Cloud deployment.
- Tests for parser and tools; fix edge cases on the demo repo.
- Stretch only if time: memory of past analyses, MCP server, PR risk score.
**Done when:** a live URL works from a clean browser.

## Phase 6: Submission (Oct 18, before 6 PM IST)
- README: setup, **graph data model**, limitations, AI-use disclosure, track named.
- `queries.cypher` with every query the product depends on.
- Demo video (2-3 min): problem → ingest → question → highlighted path → why the graph matters.
- Submit with buffer; do not wait for the last hour.

## Cut list (drop in this order if behind)
1. MCP server  2. Agent memory  3. PR risk score  4. Function-level calls (fall back to file-level reachability)  5. Fancy graph styling.
**Never cut:** ingestion, vulnerability link, agent tools, evidence panel, README, demo video.

## Demo script questions
1. "Give me a summary of this repo."
2. "Which files are most critical?"
3. "What breaks if I change `core.py`?"
4. "Which vulnerabilities are reachable from our entry points?"
5. "Are there circular imports?"
