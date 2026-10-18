"""app.py — GraphSentinel Streamlit UI."""

from __future__ import annotations

import hmac
import hashlib
import time

import streamlit as st

from config import settings

# ── Page config (must be first Streamlit call) ─────────────────────────────
st.set_page_config(
    page_title="GraphSentinel",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Optional password gate ────────────────────────────────────────────────
if settings.app_password:
    def _check_password() -> bool:
        def _submit():
            entered = st.session_state.get("password_input", "")
            if hmac.compare_digest(
                hashlib.sha256(entered.encode()).digest(),
                hashlib.sha256(settings.app_password.encode()).digest(),
            ):
                st.session_state["authenticated"] = True
            else:
                st.session_state["auth_failed"] = True

        if st.session_state.get("authenticated"):
            return True
        st.title("🛡️ GraphSentinel")
        st.text_input("Password", type="password", key="password_input")
        st.button("Enter", on_click=_submit)
        if st.session_state.get("auth_failed"):
            st.error("Incorrect password.")
        return False

    if not _check_password():
        st.stop()

# ── Session state defaults ────────────────────────────────────────────────
defaults = {
    "selected_repo": None,
    "chat_history": [],  # list of {role, content, evidence}
    "ingest_result": None,
    "last_evidence": None,
}
for k, v in defaults.items():
    if k not in st.session_state:
        st.session_state[k] = v

# 4f. Create indexes at startup
try:
    from queries import create_indexes
    create_indexes()
except Exception:
    pass

# ── Custom CSS ────────────────────────────────────────────────────────────
st.markdown("""
<style>
  .risk-critical { color: #FF5C6C; font-weight: 700; }
  .risk-high     { color: #F5B544; font-weight: 700; }
  .risk-medium   { color: #F5B544; }
  .risk-low      { color: #4DA3FF; }
  .risk-none     { color: #8B93A7; }
  .conf-reach    { color: #2DD4A0; font-weight: 600; }
  .conf-import   { color: #8B93A7; }
  code { font-family: 'JetBrains Mono', monospace; font-size: 13px; }
</style>
""", unsafe_allow_html=True)

EXAMPLE_QUESTIONS = [
    "Which vulnerabilities are reachable from entry points?",
    "What are the most critical (most imported) files?",
    "Are there circular import cycles?",
    "What would break if I changed this file?",
]

# ── Sidebar ────────────────────────────────────────────────────────────────
with st.sidebar:
    st.title("🛡️ GraphSentinel")
    st.caption("Code security via graph analysis")
    st.divider()

    # Ingest section
    st.subheader("Ingest Repository")
    repo_url = st.text_input(
        "GitHub URL",
        placeholder="https://github.com/owner/repo",
        label_visibility="collapsed",
    )
    ingest_btn = st.button("🔍 Ingest Repo", use_container_width=True, type="primary")

    # 4a. Replace spinner with st.status() progress during ingest
    if ingest_btn and repo_url:
        result = None
        with st.status("Ingesting repository...", expanded=True) as status:
            st.write("Cloning and parsing repository...")
            try:
                from ingest.pipeline import ingest_repo
                result = ingest_repo(repo_url)
                st.write(f"✅ {result['file_count']} files · {result['function_count']} functions · {result['import_edges']} import edges · {result.get('vuln_count', 0)} CVEs")
                status.update(label="Ingest complete!", state="complete")
            except ValueError as e:
                status.update(label=f"Ingest failed: {e}", state="error")
            except Exception as e:
                status.update(label=f"Ingest error: {e}", state="error")
        if result is not None:
            st.session_state["ingest_result"] = result
            st.session_state["selected_repo"] = None
    elif ingest_btn:
        st.warning("Please enter a GitHub URL.")

    st.divider()

    # Repo selector
    st.subheader("Select Repository")
    try:
        from queries import list_repos
        repos_data = list_repos()
        repo_names = [r["repo"] for r in repos_data]
    except Exception:
        repos_data = []
        repo_names = []

    if repo_names:
        idx = 0
        if st.session_state["selected_repo"] in repo_names:
            idx = repo_names.index(st.session_state["selected_repo"])
        selected = st.selectbox(
            "Repository",
            repo_names,
            index=idx,
            label_visibility="collapsed",
        )
        st.session_state["selected_repo"] = selected

        # Stats panel for selected repo
        if selected:
            try:
                from queries import get_repo_summary, get_entry_point_count
                stats = get_repo_summary(selected)
                ep = get_entry_point_count(selected)
                col1, col2 = st.columns(2)
                col1.metric("Files", stats.get("file_count", 0))
                col2.metric("Functions", stats.get("function_count", 0))
                col1.metric("Packages", stats.get("package_count", 0))
                col2.metric("CVEs", stats.get("vuln_count", 0))
                st.caption(f"Entry points: {ep}")
                # 4b. Show ingested_at date
                st.caption(f"Ingested: {stats.get('ingested_at','')[:10]}")
            except Exception:
                pass
    else:
        st.info("No repositories ingested yet.")

# ── Main area ─────────────────────────────────────────────────────────────
col_chat, col_graph = st.columns([4, 6])

with col_chat:
    current_repo = st.session_state.get("selected_repo")

    if not current_repo:
        # 4d. Better empty state
        st.markdown("## 🛡️ GraphSentinel")
        st.markdown("**Paste a public GitHub Python repo URL in the sidebar to begin.**")
        st.markdown("---")
        cols = st.columns(2)
        for i, q in enumerate(EXAMPLE_QUESTIONS):
            cols[i % 2].info(q)
    else:
        st.markdown(f"### 💬 Chat — `{current_repo}`")

        # Example question chips (shown when chat is empty)
        if not st.session_state["chat_history"]:
            st.markdown("**Try an example question:**")
            cols = st.columns(len(EXAMPLE_QUESTIONS))
            for i, q in enumerate(EXAMPLE_QUESTIONS):
                if cols[i].button(q, key=f"chip_{i}", use_container_width=True):
                    st.session_state["_pending_question"] = q

        # Render chat history
        for entry in st.session_state["chat_history"]:
            if entry["role"] == "user":
                with st.chat_message("user"):
                    st.markdown(entry["content"])
            else:
                with st.chat_message("assistant"):
                    st.markdown(entry["content"])
                    if entry.get("evidence"):
                        # 4e. Evidence expander — show tool calls
                        with st.expander("🔍 How I got this"):
                            ev = entry["evidence"]
                            if ev.get("tool_calls"):
                                st.markdown("**Tools called:**")
                                for tc in ev["tool_calls"]:
                                    args = ", ".join(f"{k}={v!r}" for k, v in tc.get("inputs", {}).items() if k != "repo")
                                    st.code(f"{tc['tool']}({args})", language="python")
                            st.caption(f"Nodes touched: {ev.get('nodes', 0)} · Edges: {ev.get('edges', 0)}")

        # Chat input
        pending = st.session_state.pop("_pending_question", None)
        question = st.chat_input("Ask a question about this repo…") or pending

        if question:
            st.session_state["chat_history"].append(
                {"role": "user", "content": question, "evidence": None}
            )
            with st.spinner("Thinking…"):
                try:
                    from agent import ask, AgentError
                    answer, evidence = ask(question, current_repo)
                except AgentError as e:
                    answer = f"⚠️ Agent error: {e}"
                    evidence = None
                except Exception as e:
                    answer = f"⚠️ Error: {e}"
                    evidence = None
            st.session_state["chat_history"].append(
                {"role": "assistant", "content": answer, "evidence": evidence}
            )
            st.rerun()

with col_graph:
    st.markdown("### 📊 Graph View")
    current_repo = st.session_state.get("selected_repo")
    if not current_repo:
        st.info("Select a repository to see graph data.")
    else:
        tab_graph, tab_evidence, tab_cypher = st.tabs(["Graph", "Evidence", "Cypher"])

        with tab_graph:
            # Show top files and packages as a text graph summary
            try:
                from db import run_query
                from queries import most_imported_files, list_vulnerabilities, find_circular_imports

                # ── All files in the graph ──────────────────────────────
                all_files = run_query(
                    "MATCH (f:File {repo: $repo}) RETURN f.path AS path ORDER BY path",
                    {"repo": current_repo},
                )
                st.markdown(f"**📁 Files in graph ({len(all_files)}):**")
                if all_files:
                    paths = [r["path"] for r in all_files]
                    st.code("\n".join(paths), language=None)
                else:
                    st.info("No files ingested yet.")

                top_files = most_imported_files(current_repo, limit=10)

                # 4c. Interactive pyvis graph (capped at 60 nodes)
                try:
                    from pyvis.network import Network
                    import streamlit.components.v1 as components

                    edge_rows = run_query(
                        "MATCH (a:File {repo: $repo})-[:IMPORTS]->(b:File {repo: $repo}) RETURN a.path AS src, b.path AS dst",
                        {"repo": current_repo},
                    )
                    if edge_rows:
                        # Collect unique nodes, cap at 60
                        node_set: set[str] = set()
                        capped_edges = []
                        for er in edge_rows:
                            if len(node_set) >= 60 and er["src"] not in node_set and er["dst"] not in node_set:
                                continue
                            node_set.add(er["src"])
                            node_set.add(er["dst"])
                            capped_edges.append(er)

                        # Top 3 hotspots are red; others are purple
                        hotspot_paths = {r["path"] for r in (top_files or [])[:3]}

                        net = Network(height="380px", width="100%", bgcolor="#141822", font_color="#E6E9F2", directed=True)
                        net.set_options('{"edges": {"arrows": {"to": {"enabled": true}}}, "physics": {"stabilization": {"iterations": 100}}}')
                        for node in node_set:
                            color = "#FF5C6C" if node in hotspot_paths else "#7C6CFF"
                            label = node.split("/")[-1]  # show just filename
                            net.add_node(node, label=label, title=node, color=color, shape="dot", size=12)
                        for er in capped_edges:
                            net.add_edge(er["src"], er["dst"], color="#4DA3FF", width=1)

                        html_str = net.generate_html()
                        components.html(html_str, height=400, scrolling=False)
                        if len(all_files) > 60:
                            st.caption(f"Showing 60 of {len(all_files)} nodes. Purple = file node, Red = top hotspot.")
                        else:
                            st.caption("Purple = file node, Red = top hotspot (most imported).")
                except Exception as pyvis_err:
                    st.caption(f"Interactive graph unavailable: {pyvis_err}")

                cycles = find_circular_imports(current_repo, limit=10)
                vulns = list_vulnerabilities(current_repo, limit=10)

                if top_files:
                    st.markdown("**Most imported files (hotspots):**")
                    for row in top_files:
                        bar = "█" * min(row.get("importers", 0), 20)
                        st.code(f"{row['path']:50s}  {bar} ({row['importers']})", language=None)
                else:
                    st.info("No import data yet.")

                if cycles:
                    st.markdown("**⚠️ Files in circular imports:**")
                    for row in cycles:
                        st.code(row["path"], language=None)

                if vulns:
                    st.markdown("**🔴 CVEs in this repo:**")
                    for v in vulns[:5]:
                        sev = v.get("severity", "NONE").upper()
                        css_class = f"risk-{sev.lower()}"
                        st.markdown(
                            f'<span class="{css_class}">{sev}</span> '
                            f'**{v.get("vuln_id", "")}** — {v.get("package", "")} '
                            f'({v.get("summary", "")[:80]})',
                            unsafe_allow_html=True,
                        )
            except Exception as e:
                st.error(f"Could not load graph data: {e}")

        with tab_evidence:
            # Show evidence from the most recent assistant message
            last_ev = None
            for entry in reversed(st.session_state.get("chat_history", [])):
                if entry["role"] == "assistant" and entry.get("evidence"):
                    last_ev = entry["evidence"]
                    break
            if last_ev:
                st.json(last_ev)
            else:
                st.info("Evidence will appear here after the agent answers a question.")

        with tab_cypher:
            st.markdown("**Key Cypher queries used by the agent:**")
            st.code("""
-- Repo summary
MATCH (r:Repo {repo: $repo})
OPTIONAL MATCH (r)-[:CONTAINS]->(f:File)
OPTIONAL MATCH (f)-[:DEFINES]->(fn:Function)
RETURN count(DISTINCT f) AS file_count, count(DISTINCT fn) AS function_count

-- Reachable CVEs
MATCH (e:Function {repo: $repo, is_entry: true})
MATCH p = (e)-[:CALLS*0..8]->(fn:Function {repo: $repo})
MATCH (f:File)-[:USES]->(pkg:Package)
MATCH (v:Vuln)-[:AFFECTS]->(pkg)
RETURN v.id, v.severity, pkg.name, f.path
""", language="cypher")
