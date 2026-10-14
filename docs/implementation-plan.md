# GraphSentinel: Implementation Plan

Build in this exact order. Do not start a step until the previous step's check passes. **Main coding begins after Oct 15, 12:01 AM IST.** Before that, only setup and planning.

## Step 0: Before the start (allowed)
- [ ] Anthropic API key in `.env`
- [ ] FalkorDB Cloud instance; connection test returns `[[1]]`
- [ ] Python venv works; `requirements.txt` ready
- [ ] Demo repo chosen (small Python project with a few known vulnerable dependencies)
- [ ] Re-read full text of rule 8

## Step 1: Repo and config (Oct 15)
1. Create the public GitHub repo (after the start). Add `.gitignore`, `README.md`, `.env.example`, `requirements.txt`.
2. `graph/client.py`: connection from env; `graph/schema.py`: create indexes.
3. `api/main.py`: `/health` runs `RETURN 1`.
**Check:** `/health` returns ok against FalkorDB Cloud.

## Step 2: Ingest the code graph (Oct 15)
1. `ingest/clone.py`: validate URL, shallow clone, size/time limits, cleanup.
2. `ingest/parse_python.py`: files, functions, imports, calls using `ast`.
3. Import resolution; `Repo`, `File`, `Function`, `DEFINES`, `IMPORTS`, `USES` writes via `UNWIND`/`MERGE`.
4. Re-ingest delete query; `IngestJob` status updates.
**Check:** one command ingests the demo repo; nodes and edges visible in the FalkorDB browser; three proof queries return sensible results.

## Step 3: Calls, entry points, packages (Oct 15-16)
1. `CALLS` edges (best effort, `resolved` flag).
2. Entry-point detection (`is_entry`).
3. `ingest/deps.py`: parse `requirements.txt` / `pyproject.toml` → `Package`, `DEPENDS_ON`.
**Check:** entry points listed; packages linked to files that import them.

## Step 4: Vulnerabilities (Oct 16)
1. `ingest/osv.py`: batch query, retries, severity mapping.
2. Write `Vuln`, `AFFECTS`.
3. Reachable and import-only queries working.
**Check:** `reachable_vulns` returns at least one path on the demo repo (pick or adjust the demo repo until it does).

## Step 5: Tools layer (Oct 16)
1. `graph/queries.py`: all Cypher, parameterized, read-only.
2. `agent/tools.py`: the 8 tools, each returning `{result, cypher, nodes, edges}`.
3. pytest: tools against a tiny fixture graph.
**Check:** each tool called from a Python shell returns correct data.

## Step 6: Agent loop (Oct 16)
1. `agent/prompts.py`: system prompt (answer only from tool results, label confidence).
2. `agent/loop.py`: tool-use loop, 8-call cap, error recovery, timeouts.
**Check:** the 5 demo questions answered correctly from the terminal; the agent chains two or more tools for the reachability question.

## Step 7: UI (Oct 17)
1. `.streamlit/config.toml` theme; layout from `ui-ux-design.md`.
2. Sidebar: URL input, Ingest button, progress steps, repo selector, stats.
3. Chat panel with example chips and answer cards.
4. `ui/graph_view.py`: pyvis graph, path highlight, node details.
5. Evidence, Cypher, and Log tabs.
6. Optional password gate.
**Check:** the full demo script runs end to end in the browser.

## Step 8: Deploy (Oct 17)
1. Set secrets in Streamlit Cloud; choose Python 3.12.
2. Deploy; run the full demo on the live URL from a clean browser.
**Check:** live URL works with no local services.

## Step 9: Stretch (only if Steps 1-8 are done)
In order: agent memory (`Analysis` nodes), MCP server, PR risk score, tree-sitter second language.

## Step 10: Submission (Oct 18, finish by 6 PM IST)
- [ ] README: overview, setup, **graph data model**, limitations, AI-use disclosure, track named, demo link
- [ ] `queries.cypher` containing every query the product depends on
- [ ] Demo video (2-3 minutes) following the demo script in `app-flow.md`
- [ ] Public repo, live URL or local setup steps, final test on a fresh clone
- [ ] Submit with buffer before 11:59 PM IST

## Cut list (drop in this order if behind)
1. MCP server  2. Agent memory  3. PR risk score  4. Function-level calls (fall back to import-only reachability)  5. Graph styling polish.
**Never cut:** ingestion, vulnerability link, agent tools, evidence panel, README, demo video.

## Working agreement for the AI agent
- Follow `trd.md` for all technical choices; ask before deviating.
- Complete one step at a time; stop at each **Check**.
- Never write Cypher with string formatting; parameters only.
- Keep `memory.md` updated: current step, last completed file, open issues.
