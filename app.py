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

    if ingest_btn and repo_url:
        with st.spinner("Cloning and analysing repository…"):
            try:
                from ingest.pipeline import ingest_repo
                result = ingest_repo(repo_url)
                st.session_state["ingest_result"] = result
                st.session_state["selected_repo"] = None  # reset so dropdown reloads
                st.success(
                    f"✅ Done: {result['file_count']} files, "
                    f"{result['function_count']} functions, "
                    f"{result['import_edges']} imports, "
                    f"{result.get('vuln_count', 0)} CVEs"
                )
            except ValueError as e:
                st.error(f"Ingest failed: {e}")
            except Exception as e:
                st.error(f"Ingest error: {e}")
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
            except Exception:
                pass
    else:
        st.info("No repositories ingested yet.")

# ── Main area ─────────────────────────────────────────────────────────────
col_chat, col_graph = st.columns([4, 6])

with col_chat:
    current_repo = st.session_state.get("selected_repo")

    if not current_repo:
        # Empty state
        st.markdown("## 🛡️ GraphSentinel")
        st.markdown("Paste a public Python repository URL in the sidebar to begin.")
        st.markdown("**Example questions** (available after ingesting a repo):")
        for q in EXAMPLE_QUESTIONS:
            st.markdown(f"- *{q}*")
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
                        with st.expander("🔍 How I got this"):
                            ev = entry["evidence"]
                            st.caption(f"Cypher: `{ev.get('cypher', '')}` | Nodes: {ev.get('nodes', 0)} | Edges: {ev.get('edges', 0)}")

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
                from queries import most_imported_files, list_vulnerabilities, find_circular_imports
                top_files = most_imported_files(current_repo, limit=10)
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
