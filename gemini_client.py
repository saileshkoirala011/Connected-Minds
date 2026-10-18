"""gemini_client.py — Gemini adapter that matches the Anthropic client interface."""

import json, os, time, uuid
import httpx
from dotenv import load_dotenv

load_dotenv()
BASE = "https://generativelanguage.googleapis.com/v1beta/models"


class _Block:
    def __init__(self, type, **kw):
        self.type = type
        self.__dict__.update(kw)


class _Usage:
    def __init__(self, i=0, o=0):
        self.input_tokens, self.output_tokens = i, o


class _Response:
    def __init__(self, content, stop_reason, usage):
        self.content, self.stop_reason, self.usage = content, stop_reason, usage


def _get(b, k, d=None):
    return b.get(k, d) if isinstance(b, dict) else getattr(b, k, d)


def _clean(s):
    if not isinstance(s, dict):
        return s
    out = {}
    for k, v in s.items():
        if k == "properties":
            out[k] = {n: _clean(p) for n, p in v.items()}
        elif k == "items":
            out[k] = _clean(v)
        elif k in ("type", "required", "description", "enum"):
            out[k] = v
    return out


def _to_contents(messages):
    names, out = {}, []
    for m in messages:
        role = "model" if m["role"] == "assistant" else "user"
        c = m["content"]
        if isinstance(c, str):
            out.append({"role": role, "parts": [{"text": c}]})
            continue
        parts = []
        for b in c:
            t = _get(b, "type")
            if t == "text":
                if _get(b, "text"):
                    parts.append({"text": _get(b, "text")})
            elif t == "tool_use":
                names[_get(b, "id")] = _get(b, "name")
                p = {"functionCall": {"name": _get(b, "name"), "args": _get(b, "input") or {}}}
                if _get(b, "sig"):
                    p["thoughtSignature"] = _get(b, "sig")
                parts.append(p)
            elif t == "tool_result":
                content = _get(b, "content")
                if isinstance(content, list):
                    content = "".join(_get(x, "text", "") for x in content)
                try:
                    data = json.loads(content)
                except Exception:
                    data = content
                resp = data if isinstance(data, dict) else {"result": data}
                parts.append({"functionResponse": {
                    "name": names.get(_get(b, "tool_use_id"), "tool"), "response": resp}})
        if parts:
            out.append({"role": role, "parts": parts})
    return out


class _Messages:
    def create(self, max_tokens=2048, system=None, tools=None, messages=None, **_):
        key = os.getenv("GEMINI_API_KEY")
        if not key:
            raise RuntimeError("GEMINI_API_KEY is not set")
        model = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
        body = {"contents": _to_contents(messages or []),
                "generationConfig": {"maxOutputTokens": max(max_tokens, 8192)}}
        if system:
            body["systemInstruction"] = {"parts": [{"text": system}]}
        if tools:
            decls = []
            for t in tools:
                d = {"name": t["name"], "description": t.get("description", "")}
                params = _clean(t.get("input_schema") or {})
                if params.get("properties"):
                    d["parameters"] = params
                decls.append(d)
            body["tools"] = [{"functionDeclarations": decls}]
        url = f"{BASE}/{model}:generateContent"
        for attempt in range(5):
            r = httpx.post(url, json=body, headers={"x-goog-api-key": key}, timeout=90)
            if r.status_code in (429, 503) and attempt < 4:
                time.sleep(6 * (attempt + 1))
                continue
            break
        if r.status_code != 200:
            raise RuntimeError(f"Gemini API error {r.status_code}: {r.text[:300]}")
        data = r.json()
        parts = (data.get("candidates") or [{}])[0].get("content", {}).get("parts", [])
        blocks = []
        for p in parts:
            if p.get("text") and not p.get("thought"):
                blocks.append(_Block("text", text=p["text"]))
            elif "functionCall" in p:
                fc = p["functionCall"]
                blocks.append(_Block("tool_use", id=f"call_{uuid.uuid4().hex[:12]}",
                                     name=fc["name"], input=fc.get("args") or {},
                                     sig=p.get("thoughtSignature")))
        if not blocks:
            blocks.append(_Block("text", text="(no response from model)"))
        u = data.get("usageMetadata", {})
        stop = "tool_use" if any(b.type == "tool_use" for b in blocks) else "end_turn"
        return _Response(blocks, stop, _Usage(u.get("promptTokenCount", 0),
                                              u.get("candidatesTokenCount", 0)))


class GeminiClient:
    def __init__(self):
        self.messages = _Messages()
