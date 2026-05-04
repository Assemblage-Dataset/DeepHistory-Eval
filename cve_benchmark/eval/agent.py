"""Minimal tool-calling agent for binary analysis benchmarking."""

import hashlib
import json
import os
import re
import shutil
import sys
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))
from binaryapi import BinaryAPI


STRIPPED_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "stripped_binaries")


def prepare_binary(original_path):
    """Copy binary to an isolated directory without PDB/debug companions; cached by file hash."""
    os.makedirs(STRIPPED_DIR, exist_ok=True)

    sha = hashlib.sha256()
    with open(original_path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            sha.update(chunk)
    file_hash = sha.hexdigest()[:16]

    base_name = os.path.basename(original_path)
    stripped_path = os.path.join(STRIPPED_DIR, f"{file_hash}_{base_name}")

    if os.path.exists(stripped_path):
        return stripped_path

    shutil.copy2(original_path, stripped_path)

    with open(stripped_path, "rb") as f:
        magic = f.read(4)
    if magic == b"\x7fELF":
        import subprocess
        stripped_ok = False
        for tool in ("llvm-strip", "strip"):
            try:
                subprocess.run([tool, stripped_path],
                               capture_output=True, timeout=30, check=True)
                stripped_ok = True
                break
            except (subprocess.CalledProcessError, FileNotFoundError):
                continue
        if not stripped_ok:
            try:
                os.remove(stripped_path)
            except OSError:
                pass
            raise RuntimeError(
                f"Failed to strip ELF {base_name}: "
                f"neither llvm-strip nor strip succeeded")

    return stripped_path


PAGE_LIMIT_DEFAULT = 100

TOOLS = [
    {"type": "function", "function": {
        "name": "list_functions",
        "description": ("List all internal functions (name, address, size_bytes, "
                        "num_blocks), paginated. Response includes total count "
                        "and the next offset so you can iterate until exhausted."),
        "parameters": {"type": "object", "properties": {
            "offset": {"type": "integer",
                       "description": "0-based offset. Default 0."},
            "limit":  {"type": "integer",
                       "description": f"Page size. Default {PAGE_LIMIT_DEFAULT}."},
        }}}},
    {"type": "function", "function": {
        "name": "get_imports",
        "description": ("List all imported library function names, paginated "
                        "(offset/limit). Response includes total + next offset."),
        "parameters": {"type": "object", "properties": {
            "offset": {"type": "integer"},
            "limit":  {"type": "integer"},
        }}}},
    {"type": "function", "function": {
        "name": "get_strings",
        "description": ("List all string literals (>= 4 chars), paginated "
                        "(offset/limit). Response includes total + next offset."),
        "parameters": {"type": "object", "properties": {
            "offset": {"type": "integer"},
            "limit":  {"type": "integer"},
        }}}},
    {"type": "function", "function": {
        "name": "find_callers_of_import",
        "description": "Return internal functions that directly call the given import.",
        "parameters": {"type": "object", "properties": {
            "import_name": {"type": "string"}}, "required": ["import_name"]}}},
    {"type": "function", "function": {
        "name": "find_functions_referencing_string",
        "description": ("Return functions referencing a string containing s "
                        "(substring match, case-insensitive by default). "
                        "Pass case_sensitive=true for exact-case matching."),
        "parameters": {"type": "object", "properties": {
            "s": {"type": "string"},
            "case_sensitive": {"type": "boolean",
                               "description": "Default false (case-insensitive)."},
        }, "required": ["s"]}}},
    {"type": "function", "function": {
        "name": "get_callees",
        "description": "Return all functions directly called by func.",
        "parameters": {"type": "object", "properties": {
            "func": {"type": "string"}}, "required": ["func"]}}},
    {"type": "function", "function": {
        "name": "get_callers",
        "description": "Return all functions that call func.",
        "parameters": {"type": "object", "properties": {
            "func": {"type": "string"}}, "required": ["func"]}}},
    {"type": "function", "function": {
        "name": "get_cfg",
        "description": "Return the control-flow graph of func.",
        "parameters": {"type": "object", "properties": {
            "func": {"type": "string"}}, "required": ["func"]}}},
    {"type": "function", "function": {
        "name": "decompile",
        "description": "Return decompiled C pseudocode for func.",
        "parameters": {"type": "object", "properties": {
            "func": {"type": "string"}}, "required": ["func"]}}},
    {"type": "function", "function": {
        "name": "get_pcode",
        "description": "Return high p-code (post-SSA) for func, grouped by basic block.",
        "parameters": {"type": "object", "properties": {
            "func": {"type": "string"}}, "required": ["func"]}}},
    {"type": "function", "function": {
        "name": "get_assembly",
        "description": ("Return raw disassembly (one instruction per line) "
                        "for func. Use this when decompiled C looks correct "
                        "but the bug is architecturally low-level -- timing "
                        "side-channels, constant-time violations, emitted "
                        "branch layout, register/calling-convention issues."),
        "parameters": {"type": "object", "properties": {
            "func": {"type": "string"}}, "required": ["func"]}}},
    {"type": "function", "function": {
        "name": "search_decompiled",
        "description": ("Search all decompiled output with a Python regex "
                        "pattern. Returns {results, total_match_count, "
                        "truncated, limit}. If truncated=true, refine the "
                        "pattern or raise limit (default 200)."),
        "parameters": {"type": "object", "properties": {
            "pattern": {"type": "string"},
            "limit": {"type": "integer",
                      "description": "Max total matches. Default 200."},
        }, "required": ["pattern"]}}},
    {"type": "function", "function": {
        "name": "search_pcode",
        "description": ("Search all p-code output with a Python regex "
                        "pattern. Same return shape and truncation contract "
                        "as search_decompiled."),
        "parameters": {"type": "object", "properties": {
            "pattern": {"type": "string"},
            "limit": {"type": "integer",
                      "description": "Max total matches. Default 200."},
        }, "required": ["pattern"]}}},
    {"type": "function", "function": {
        "name": "search_assembly",
        "description": ("Search all disassembly with a Python regex pattern. "
                        "Same return shape and truncation contract as "
                        "search_decompiled."),
        "parameters": {"type": "object", "properties": {
            "pattern": {"type": "string"},
            "limit": {"type": "integer",
                      "description": "Max total matches. Default 200."},
        }, "required": ["pattern"]}}},
    {"type": "function", "function": {
        "name": "discard_tool_result",
        "description": ("Drop a past tool result from context to free memory. "
                        "Every tool result is prefixed with [tag=tN]; pass that "
                        "tag here to replace the stored content with a short "
                        "placeholder. The message slot stays so ordering is "
                        "preserved. Use this when a result has served its "
                        "purpose (e.g., a large decompile listing you have "
                        "already digested)."),
        "parameters": {"type": "object", "properties": {
            "tag": {"type": "string",
                    "description": "Result tag from the [tag=tN] prefix."},
        }, "required": ["tag"]}}},
]


_PSEUDO_CALL_RE = re.compile(
    r'(?:call\s*:\s*)?(?:api\s*\.\s*)?(\w+)\s*\(([^()]*)\)',
    re.DOTALL)


def _strip_template_tags(s):
    """Strip gemma's leaked template tags like ``<|"|>``."""
    return re.sub(r'<\|[^|]*\|>', '', s)


def _parse_pseudo_tool_calls(content, tool_schemas):
    """Convert gemma's pseudo-Python tool calls in ``content`` into ollama-style tool_call dicts."""
    if not content:
        return []

    name_to_params = {}
    for t in tool_schemas:
        f = t.get("function", {}) if isinstance(t, dict) else {}
        n = f.get("name", "")
        params = f.get("parameters", {}) or {}
        name_to_params[n] = {
            "required": params.get("required", []) or [],
            "all": list((params.get("properties", {}) or {}).keys()),
        }

    out = []
    seen = set()
    for m in _PSEUDO_CALL_RE.finditer(content):
        name = m.group(1)
        if name not in name_to_params:
            continue
        args_text = _strip_template_tags(m.group(2)).strip()

        info = name_to_params[name]
        args = {}
        if not args_text:
            pass
        elif re.search(r'^\s*\w+\s*[:=]', args_text):
            for kv in re.split(r',\s*(?=\w+\s*[:=])', args_text):
                kv = kv.strip()
                mm = re.match(r'(\w+)\s*[:=]\s*(.*)', kv, re.DOTALL)
                if not mm:
                    continue
                key = mm.group(1).strip()
                val = mm.group(2).strip().strip('"').strip("'")
                args[key] = val
        else:
            val = args_text.strip().strip('"').strip("'")
            target = (info["required"][0] if info["required"]
                      else (info["all"][0] if info["all"] else None))
            if target:
                args[target] = val

        key = (name, tuple(sorted(args.items())))
        if key in seen:
            continue
        seen.add(key)
        out.append({"function": {"name": name, "arguments": args}})
    return out


_CANDIDATES_PATTERNS = [
    re.compile(
        r'[`*_]*candidates[`*_]*\s*(?:[:=]|\bare\b)?\s*[`*_]*\s*\[([^\]]*)\]',
        re.IGNORECASE),
]


def parse_candidates(content):
    """Extract a candidate list from model content; takes the LAST match."""
    if not content:
        return None
    best_text = None
    best_pos = -1
    for pat in _CANDIDATES_PATTERNS:
        for m in pat.finditer(content):
            if m.start() > best_pos:
                best_text = m.group(1)
                best_pos = m.start()
    if best_text is None:
        return None
    cands = []
    for c in best_text.split(','):
        c = c.strip().strip('"').strip("'").strip('`').strip('*').strip('_').strip()
        if c:
            cands.append(c)
    return cands or None


class AgentResult:
    """Complete record of one agent run."""
    __slots__ = ("candidates", "conversation", "api_log", "turns",
                 "finished", "reason", "elapsed_seconds")

    def __init__(self):
        self.candidates = []
        self.conversation = []
        self.api_log = []
        self.turns = 0
        self.finished = False
        self.reason = ""
        self.elapsed_seconds = 0.0


class OllamaBackend:
    """Ollama /api/chat backend."""

    def __init__(self, model="gemma4:26b",
                 url=os.environ.get("OLLAMA_CHAT_URL",
                                    "http://localhost:11434/api/chat"),
                 temperature=0, max_tokens=None, timeout=600, think=False):
        self.model = model
        self.url = url
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.timeout = timeout
        self.think = think

    def chat(self, messages, tools=None):
        options = {"temperature": self.temperature}
        if self.max_tokens is not None:
            options["num_predict"] = self.max_tokens
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": options,
        }
        if self.think is not None:
            payload["think"] = self.think
        if tools:
            payload["tools"] = tools
        data = json.dumps(payload).encode()
        req = urllib.request.Request(self.url, data=data,
                                    headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return json.loads(resp.read())

    @property
    def name(self):
        return self.model


class VLLMBackend:
    """vLLM OpenAI-compatible /v1/chat/completions backend."""

    def __init__(self, model, url="http://localhost:8000/v1",
                 temperature=0, max_tokens=None, timeout=600,
                 extra_body=None):
        from openai import OpenAI
        self.model = model
        self.url = url.rstrip("/")
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.timeout = timeout
        self.extra_body = extra_body or {
            "chat_template_kwargs": {"enable_thinking": False},
        }
        self.client = OpenAI(base_url=self.url, api_key="EMPTY",
                             timeout=self.timeout)

    def _prep_messages(self, messages):
        """Synthesize tool_call ids + tool_call_id back-references for OpenAI strict mode."""
        out = []
        last_tc_ids = []
        next_tc_idx = 0
        synthetic_counter = 0
        for m in messages:
            role = m.get("role")
            if role == "assistant" and m.get("tool_calls"):
                fixed_calls = []
                last_tc_ids = []
                for tc in m["tool_calls"]:
                    tc_id = tc.get("id")
                    if not tc_id:
                        synthetic_counter += 1
                        tc_id = f"call_{synthetic_counter}"
                    fn = tc.get("function", {}) or {}
                    args = fn.get("arguments", "")
                    if not isinstance(args, str):
                        args = json.dumps(args)
                    fixed_calls.append({
                        "id": tc_id,
                        "type": "function",
                        "function": {
                            "name": fn.get("name", ""),
                            "arguments": args,
                        },
                    })
                    last_tc_ids.append(tc_id)
                out.append({
                    "role": "assistant",
                    "content": m.get("content", "") or "",
                    "tool_calls": fixed_calls,
                })
                next_tc_idx = 0
            elif role == "tool":
                tc_id = m.get("tool_call_id")
                if not tc_id:
                    if next_tc_idx < len(last_tc_ids):
                        tc_id = last_tc_ids[next_tc_idx]
                        next_tc_idx += 1
                    else:
                        synthetic_counter += 1
                        tc_id = f"call_{synthetic_counter}"
                out.append({
                    "role": "tool",
                    "tool_call_id": tc_id,
                    "content": m.get("content", "") or "",
                })
            else:
                out.append({
                    k: v for k, v in m.items()
                    if k in ("role", "content", "name")
                })
        return out

    def chat(self, messages, tools=None):
        prepped = self._prep_messages(messages)
        kwargs = {
            "model": self.model,
            "messages": prepped,
            "temperature": self.temperature,
            "stream": False,
            "extra_body": self.extra_body,
        }
        if self.max_tokens is not None:
            kwargs["max_tokens"] = self.max_tokens
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"
        completion = self.client.chat.completions.create(**kwargs)
        choice = completion.choices[0]
        msg = choice.message
        out_msg = {"role": msg.role, "content": msg.content or ""}
        tcs = getattr(msg, "tool_calls", None) or []
        if tcs:
            out_msg["tool_calls"] = [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {
                        "name": tc.function.name,
                        "arguments": tc.function.arguments,
                    },
                }
                for tc in tcs
            ]
        return {"message": out_msg, "done_reason": choice.finish_reason}

    @property
    def name(self):
        return self.model


NUDGE_CONTINUE = ("Continue your analysis. When ready, output: "
                  "CANDIDATES: [func1, func2, ...]")
NUDGE_EMPTY = ("You returned no content and no tool call. If you have an "
               "answer, output CANDIDATES: [func1, func2, ...]. Otherwise, "
               "call a tool to continue investigating.")
NUDGE_EMPTY_WITH_CONTEXT = (
    "You returned no content and no tool call. Your last tool call was "
    "{desc} -> {summary}. If this is enough to name suspects, output "
    "CANDIDATES: [func1, func2, ...]. Otherwise try a different approach: "
    "a broader search term, a different tool (list_functions, "
    "find_callers_of_import, search_decompiled), or decompile one of the "
    "matches.")
EMPTY_STREAK_LIMIT = 10
RESULT_PREVIEW_CHARS = 220
TOOL_CALLS_PER_RESPONSE_CAP = 10
TOOL_CALL_CAP_NOTICE = (
    "[notice] Your previous response contained {total} tool calls. "
    "Only the first {cap} were executed. Please make at most {cap} tool "
    "calls per response -- make your next call and wait for the result "
    "before issuing further calls.")


def _is_empty_result(result_str):
    """True if a tool result payload is 'empty' (errors are NOT treated as empty)."""
    if not result_str:
        return True
    try:
        data = json.loads(result_str)
    except (json.JSONDecodeError, TypeError):
        return False
    if data is None:
        return True
    if isinstance(data, list):
        return len(data) == 0
    if isinstance(data, str):
        return len(data.strip()) == 0
    if isinstance(data, dict):
        if "items" in data and isinstance(data["items"], list):
            return len(data["items"]) == 0
        if "results" in data and isinstance(data["results"], list):
            return len(data["results"]) == 0
        if "error" in data:
            return False
        return not data
    return False


def _format_tool_desc(name, args):
    """Short, readable rendering of a tool call for agent feedback."""
    if not args:
        return f"{name}()"
    try:
        return f"{name}({json.dumps(args, default=str)})"
    except (TypeError, ValueError):
        return f"{name}({args})"


def _summarize_result(result_str):
    """One-line summary of a tool result for nudge context."""
    if not result_str:
        return "no response"
    s = result_str
    try:
        data = json.loads(s)
    except (json.JSONDecodeError, TypeError):
        body = s.strip()
        preview = body[:RESULT_PREVIEW_CHARS]
        if len(body) > RESULT_PREVIEW_CHARS:
            preview += "..."
        return f"{len(body)} chars: {preview}"

    if data is None:
        return "null"
    if isinstance(data, list):
        n = len(data)
        if n == 0:
            return "no results (empty list)"
        preview = json.dumps(data[:5])
        if len(preview) > RESULT_PREVIEW_CHARS:
            preview = preview[:RESULT_PREVIEW_CHARS] + "..."
        return f"{n} item{'s' if n != 1 else ''}: {preview}"
    if isinstance(data, str):
        body = data.strip()
        if not body:
            return "empty string"
        preview = body[:RESULT_PREVIEW_CHARS]
        if len(body) > RESULT_PREVIEW_CHARS:
            preview += "..."
        return f"{len(body)} chars: {preview}"
    if isinstance(data, dict):
        if "error" in data:
            return f"error: {str(data['error'])[:RESULT_PREVIEW_CHARS]}"
        if "items" in data and isinstance(data["items"], list):
            total = data.get("total")
            offset = data.get("offset", 0)
            n = len(data["items"])
            preview = json.dumps(data["items"][:5])
            if len(preview) > RESULT_PREVIEW_CHARS:
                preview = preview[:RESULT_PREVIEW_CHARS] + "..."
            total_str = f" of {total}" if total is not None else ""
            return (f"{n} item{'s' if n != 1 else ''}{total_str} "
                    f"(offset {offset}): {preview}")
        if "results" in data and isinstance(data["results"], list):
            n_funcs = len(data["results"])
            total = data.get("total_match_count", 0)
            trunc = " (truncated)" if data.get("truncated") else ""
            preview = json.dumps(data["results"][:3])
            if len(preview) > RESULT_PREVIEW_CHARS:
                preview = preview[:RESULT_PREVIEW_CHARS] + "..."
            return (f"{total} match{'es' if total != 1 else ''} across "
                    f"{n_funcs} function{'s' if n_funcs != 1 else ''}"
                    f"{trunc}: {preview}")
        preview = json.dumps(data)
        if len(preview) > RESULT_PREVIEW_CHARS:
            preview = preview[:RESULT_PREVIEW_CHARS] + "..."
        return preview
    preview = json.dumps(data)
    if len(preview) > RESULT_PREVIEW_CHARS:
        preview = preview[:RESULT_PREVIEW_CHARS] + "..."
    return preview


class Agent:
    """Minimal tool-calling agent for binary vulnerability search."""

    def __init__(self, backend, binary_path, max_wall_seconds=1800,
                 strip=True, response_dir=None, max_turns=1000):
        self.backend = backend
        self.max_wall_seconds = max_wall_seconds
        self.max_turns = max_turns
        self.response_dir = response_dir
        if strip:
            self.binary_path = prepare_binary(binary_path)
        else:
            self.binary_path = binary_path
        self.api = BinaryAPI(self.binary_path)

    def _save_response(self, filename, data):
        """Save raw response to response_dir if set."""
        if not self.response_dir:
            return
        os.makedirs(self.response_dir, exist_ok=True)
        with open(os.path.join(self.response_dir, filename), "w") as f:
            json.dump(data, f, indent=2)

    def run(self, prompt, condition=""):
        """Run the agent loop. Returns AgentResult."""
        result = AgentResult()
        messages = [{"role": "user", "content": prompt}]

        tool_tag_to_idx = {}
        tag_counter = 0

        consecutive_empty = 0
        last_tool_desc = ""
        last_tool_summary = ""
        start_time = time.time()

        while True:
            elapsed = time.time() - start_time

            if self.max_wall_seconds and elapsed >= self.max_wall_seconds:
                result.reason = "time_limit"
                break

            if self.max_turns and result.turns >= self.max_turns:
                result.reason = "turn_limit"
                break

            if consecutive_empty >= EMPTY_STREAK_LIMIT:
                result.reason = "stalled"
                break

            try:
                response = self.backend.chat(messages, tools=TOOLS)
            except Exception as e:
                err = str(e)
                result.conversation.append({
                    "turn": result.turns, "type": "error", "error": err,
                })
                self._save_response(
                    f"{condition}_turn_{result.turns:02d}_error.json",
                    {"turn": result.turns, "error": err})
                result.reason = f"backend_error: {err[:200]}"
                break

            msg = response.get("message", {})
            content = msg.get("content", "") or ""
            thinking = msg.get("thinking", "") or ""
            tool_calls = msg.get("tool_calls") or []

            recovered_via_retry = False
            if (not content and not tool_calls
                    and "gemma" in self.backend.name.lower()):
                try:
                    retry = self.backend.chat(messages, tools=None)
                    retry_msg = retry.get("message", {}) or {}
                    retry_content = retry_msg.get("content", "") or ""
                    recovered = _parse_pseudo_tool_calls(retry_content, TOOLS)
                    if recovered:
                        tool_calls = recovered
                        recovered_via_retry = True
                    elif retry_content:
                        content = retry_content
                except Exception:
                    pass

            self._save_response(
                f"{condition}_turn_{result.turns:02d}.json",
                {
                    "turn": result.turns,
                    "model": self.backend.name,
                    "elapsed_seconds": round(elapsed, 2),
                    "raw_response": response,
                    "recovered_via_retry": recovered_via_retry,
                })

            result.conversation.append({
                "turn": result.turns,
                "type": "model_response",
                "role": msg.get("role", "assistant"),
                "content": content,
                "thinking": thinking,
                "tool_calls_raw": tool_calls,
                "elapsed_seconds": round(elapsed, 2),
            })

            result.turns += 1

            if content:
                cands = parse_candidates(content)
                if cands:
                    result.candidates = cands
                    result.finished = True
                    result.reason = "candidates"
                    break

            if not content and not tool_calls:
                consecutive_empty += 1
                if last_tool_desc:
                    nudge = NUDGE_EMPTY_WITH_CONTEXT.format(
                        desc=last_tool_desc,
                        summary=last_tool_summary)
                else:
                    nudge = NUDGE_EMPTY
                messages.append({"role": "assistant", "content": content})
                messages.append({"role": "user", "content": nudge})
                result.conversation.append({
                    "turn": result.turns - 1,
                    "type": "nudge",
                    "nudge_message": nudge,
                    "consecutive_empty": consecutive_empty,
                    "last_tool_desc": last_tool_desc or None,
                })
                continue

            consecutive_empty = 0

            if tool_calls:
                total_tc = len(tool_calls)
                capped = total_tc > TOOL_CALLS_PER_RESPONSE_CAP
                if capped:
                    tool_calls = tool_calls[:TOOL_CALLS_PER_RESPONSE_CAP]
                    if isinstance(msg, dict):
                        msg["tool_calls"] = tool_calls
                    result.conversation.append({
                        "turn": result.turns - 1,
                        "type": "tool_call_cap",
                        "received": total_tc,
                        "executed": TOOL_CALLS_PER_RESPONSE_CAP,
                    })
                messages.append(msg)
                for tc in tool_calls:
                    fn = tc.get("function", {})
                    tool_name = fn.get("name", "")
                    tool_args = fn.get("arguments", {})
                    if isinstance(tool_args, str):
                        try:
                            tool_args = json.loads(tool_args)
                        except json.JSONDecodeError:
                            tool_args = {}

                    if tool_name == "discard_tool_result":
                        tag = tool_args.get("tag", "") if isinstance(
                            tool_args, dict) else ""
                        idx = tool_tag_to_idx.get(tag)
                        if idx is not None and idx < len(messages):
                            old = messages[idx].get("content", "") or ""
                            placeholder = (
                                f"[discarded by agent: was tag={tag}, "
                                f"{len(old)} chars]")
                            messages[idx] = {"role": "tool",
                                             "content": placeholder}
                            reply = f"discarded tag={tag}"
                        else:
                            reply = f"no such tag: {tag}"
                        messages.append({"role": "tool", "content": reply})
                        result.api_log.append({
                            "method": tool_name,
                            "args": tool_args,
                            "result": reply,
                        })
                        result.conversation.append({
                            "turn": result.turns - 1,
                            "type": "tool_call",
                            "tool_name": tool_name,
                            "tool_args": tool_args,
                            "tool_result": reply,
                        })
                        continue

                    tag = f"t{tag_counter}"
                    tag_counter += 1
                    tool_result = self._call_tool(tool_name, tool_args,
                                                  result.api_log, tag=tag)
                    empty = _is_empty_result(tool_result)
                    last_tool_desc = _format_tool_desc(tool_name, tool_args)
                    last_tool_summary = _summarize_result(tool_result)

                    note = " (empty result)" if empty else ""
                    tagged = f"[tag={tag}]{note} {tool_result}"

                    msg_idx = len(messages)
                    messages.append({"role": "tool", "content": tagged})
                    tool_tag_to_idx[tag] = msg_idx

                    result.conversation.append({
                        "turn": result.turns - 1,
                        "type": "tool_call",
                        "tag": tag,
                        "tool_name": tool_name,
                        "tool_args": tool_args,
                        "tool_result_length": len(tool_result),
                        "empty_result": empty,
                    })

                if capped:
                    notice = TOOL_CALL_CAP_NOTICE.format(
                        total=total_tc, cap=TOOL_CALLS_PER_RESPONSE_CAP)
                    messages.append({"role": "user", "content": notice})

            else:
                messages.append({"role": "assistant", "content": content})
                messages.append({"role": "user", "content": NUDGE_CONTINUE})
                result.conversation.append({
                    "turn": result.turns - 1,
                    "type": "nudge",
                    "nudge_message": NUDGE_CONTINUE,
                })

        result.elapsed_seconds = round(time.time() - start_time, 2)
        if not result.reason:
            result.reason = "unknown"
        return result

    ALLOWED_TOOLS = frozenset(t["function"]["name"] for t in TOOLS)

    def _call_tool(self, tool_name, args, api_log, tag=""):
        """Execute one BinaryAPI method (with paging wrappers for enum tools)."""
        if tool_name not in self.ALLOWED_TOOLS:
            api_log.append({
                "method": tool_name, "args": args, "tag": tag,
                "error": "blocked: not in allowlist",
            })
            return json.dumps({"error": f"Unknown tool: {tool_name}"})

        t0 = time.time()
        try:
            if tool_name in ("list_functions", "get_imports", "get_strings"):
                page, total, offset, end = self._paged_enum(tool_name, args)
                elapsed = time.time() - t0
                result_str = json.dumps({
                    "total": total,
                    "offset": offset,
                    "returned": end - offset,
                    "next_offset": end if end < total else None,
                    "items": page,
                })
                api_log.append({
                    "method": tool_name, "args": args, "tag": tag,
                    "total": total, "offset": offset, "returned": end - offset,
                    "elapsed_seconds": round(elapsed, 4),
                })
                return result_str

            method = getattr(self.api, tool_name)
            raw = method(**args) if args else method()
            elapsed = time.time() - t0
            result_str = json.dumps(raw) if not isinstance(raw, str) else raw
            api_log.append({
                "method": tool_name, "args": args, "tag": tag,
                "result_length": len(result_str),
                "elapsed_seconds": round(elapsed, 4),
            })
            return result_str
        except Exception as e:
            elapsed = time.time() - t0
            api_log.append({
                "method": tool_name, "args": args, "tag": tag,
                "error": str(e),
                "elapsed_seconds": round(elapsed, 4),
            })
            return json.dumps({"error": str(e)})

    def _paged_enum(self, tool_name, args):
        """Fetch the full list from BinaryAPI, return (page, total, offset, end)."""
        method = getattr(self.api, tool_name)
        full = method()
        total = len(full)
        offset = int(args.get("offset", 0) or 0)
        limit = int(args.get("limit", PAGE_LIMIT_DEFAULT)
                    or PAGE_LIMIT_DEFAULT)
        if offset < 0:
            offset = 0
        if limit <= 0:
            limit = PAGE_LIMIT_DEFAULT
        end = min(offset + limit, total)
        if offset >= total:
            return [], total, offset, offset
        return full[offset:end], total, offset, end
