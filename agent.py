"""agent.py — Anthropic tool-use loop for GraphSentinel."""

from __future__ import annotations

import json
import os

import anthropic

from config import settings
from tools import TOOLS, ToolError
from gemini_client import GeminiClient


class AgentError(Exception):
    """Raised when the LLM call fails."""


SYSTEM_PROMPT = """You are GraphSentinel, a code security analyst powered by a FalkorDB graph database.

Rules:
- Answer ONLY from tool results. Never invent data.
- Cite file paths (e.g. src/utils.py) and CVE IDs (e.g. CVE-2023-1234) from tool output.
- When vulnerability data is missing, say 'not found in graph'.
- Label reachability confidence: say 'LIKELY REACHABLE (call graph)' for call-graph paths,
  or 'IMPORT ONLY (not confirmed via call graph)' for import-level exposure.
- Be concise. Use bullet points for lists of files or CVEs.
- Never reveal internal tool call details or raw JSON unless asked."""


TOOL_SCHEMAS = [
    {
        "name": "get_repo_summary",
        "description": "Get file count, function count, package count, CVE count, and entry point count for a repo.",
        "input_schema": {
            "type": "object",
            "properties": {
                "repo": {"type": "string", "description": "Repository in 'owner/name' format"}
            },
            "required": ["repo"],
        },
    },
    {
        "name": "most_imported",
        "description": "Return the N most-imported files by inbound import count (structural hotspots).",
        "input_schema": {
            "type": "object",
            "properties": {
                "repo": {"type": "string"},
                "n": {"type": "integer", "description": "Number of results (default 10)"},
            },
            "required": ["repo"],
        },
    },
    {
        "name": "find_dependents",
        "description": "Find all files that transitively import a given file (blast radius).",
        "input_schema": {
            "type": "object",
            "properties": {
                "repo": {"type": "string"},
                "path": {"type": "string", "description": "Relative file path, e.g. 'src/core.py'"},
            },
            "required": ["repo", "path"],
        },
    },
    {
        "name": "find_dependencies",
        "description": "Find all files that a given file transitively imports.",
        "input_schema": {
            "type": "object",
            "properties": {
                "repo": {"type": "string"},
                "path": {"type": "string"},
            },
            "required": ["repo", "path"],
        },
    },
    {
        "name": "find_cycles",
        "description": "Find files involved in circular import chains.",
        "input_schema": {
            "type": "object",
            "properties": {
                "repo": {"type": "string"}
            },
            "required": ["repo"],
        },
    },
    {
        "name": "list_vulns",
        "description": "List all CVEs affecting packages used by a repo.",
        "input_schema": {
            "type": "object",
            "properties": {
                "repo": {"type": "string"}
            },
            "required": ["repo"],
        },
    },
    {
        "name": "reachable_vulns",
        "description": "Find CVEs reachable from entry points via the call graph, plus import-only exposure.",
        "input_schema": {
            "type": "object",
            "properties": {
                "repo": {"type": "string"}
            },
            "required": ["repo"],
        },
    },
    {
        "name": "explain_path",
        "description": "Find the shortest relationship path between two files in the graph.",
        "input_schema": {
            "type": "object",
            "properties": {
                "repo": {"type": "string"},
                "from_path": {"type": "string"},
                "to_path": {"type": "string"},
            },
            "required": ["repo", "from_path", "to_path"],
        },
    },
]


def ask(question: str, repo: str) -> tuple[str, dict]:
    """
    Run the agent loop for one question.

    Args:
        question: Natural-language question from the user.
        repo:     Repository slug (owner/name) to scope tool calls.

    Returns:
        (answer_text, evidence_dict) where evidence_dict contains:
            tool_calls: list of {tool, inputs}
            nodes: total nodes across all tool results
            edges: total edges across all tool results

    Raises:
        AgentError: If the Anthropic API call fails.
    """
    if not settings.anthropic_api_key and not os.getenv("GEMINI_API_KEY"):
        raise AgentError("No LLM API key configured. Set ANTHROPIC_API_KEY or GEMINI_API_KEY in .env")

    try:
        client = GeminiClient()
    except Exception as e:
        raise AgentError(f"Failed to create client: {e}") from e

    messages: list[dict] = [
        {"role": "user", "content": question}
    ]

    tool_calls_made = 0
    max_calls = settings.agent_max_tool_calls
    evidence_tool_calls: list[dict] = []
    evidence_nodes = 0
    evidence_edges = 0

    while True:
        try:
            response = client.messages.create(
                model=settings.anthropic_model,
                max_tokens=2048,
                system=SYSTEM_PROMPT,
                tools=TOOL_SCHEMAS,
                messages=messages,
            )
        except Exception as e:
            raise AgentError(f"Anthropic API error: {e}") from e

        # Collect text and tool use blocks
        text_parts: list[str] = []
        tool_use_blocks: list = []
        for block in response.content:
            if block.type == "text":
                text_parts.append(block.text)
            elif block.type == "tool_use":
                tool_use_blocks.append(block)

        # If no tool calls, return the text
        if not tool_use_blocks or response.stop_reason == "end_turn":
            text = "\n".join(text_parts) if text_parts else "I could not find relevant data for that question."
            return text, {"tool_calls": evidence_tool_calls, "nodes": evidence_nodes, "edges": evidence_edges}

        # Append assistant message
        messages.append({"role": "assistant", "content": response.content})

        # Process tool calls
        tool_results: list[dict] = []
        for tool_block in tool_use_blocks:
            if tool_calls_made >= max_calls:
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": tool_block.id,
                    "content": json.dumps({"error": "Tool call limit reached"}),
                })
                continue

            tool_fn = TOOLS.get(tool_block.name)
            if tool_fn is None:
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": tool_block.id,
                    "content": json.dumps({"error": f"Unknown tool: {tool_block.name}"}),
                })
                continue

            # Inject repo into inputs if the tool expects it
            inputs = dict(tool_block.input)
            if "repo" not in inputs:
                inputs["repo"] = repo

            try:
                result = tool_fn(**inputs)
                content = json.dumps(result, default=str)
                # Accumulate evidence
                evidence_tool_calls.append({"tool": tool_block.name, "inputs": inputs})
                evidence_nodes += result.get("nodes", 0) if isinstance(result, dict) else 0
                evidence_edges += result.get("edges", 0) if isinstance(result, dict) else 0
            except ToolError as e:
                content = json.dumps({"error": str(e)})
            except Exception as e:
                content = json.dumps({"error": f"Tool error: {e}"})

            tool_calls_made += 1
            tool_results.append({
                "type": "tool_result",
                "tool_use_id": tool_block.id,
                "content": content,
            })

        messages.append({"role": "user", "content": tool_results})

        # If we hit the tool call limit, add a final instruction
        if tool_calls_made >= max_calls:
            messages.append({
                "role": "user",
                "content": "Please provide your final answer based on the tool results so far.",
            })
            try:
                final = client.messages.create(
                    model=settings.anthropic_model,
                    max_tokens=2048,
                    system=SYSTEM_PROMPT,
                    messages=messages,
                )
                text = " ".join(
                    b.text for b in final.content if b.type == "text"
                ) or "Tool call limit reached."
                return text, {"tool_calls": evidence_tool_calls, "nodes": evidence_nodes, "edges": evidence_edges}
            except Exception as e:
                raise AgentError(f"API error on final call: {e}") from e
