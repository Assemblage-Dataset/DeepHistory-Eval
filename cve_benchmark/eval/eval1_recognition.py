"""Eval 1: CVE Recognition (source vs binary x zero-shot vs with-description)."""

import json
import os
import re
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _paths  # noqa: E402

FILLED_DIR = _paths.FILLED_DIR
RESULTS_DIR = _paths.RESULTS_DIR
RESPONSES_DIR = _paths.RESPONSE_DIR
SELECTED = _paths.SELECTED_JSON
DECOYS_PATH = _paths.DECOYS_JSON
SKIP_CVES_PATH = os.path.join(_paths.DATA_OUT, "skip_cves.json")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from backends import call_openrouter, BackendError, RateLimitError  # noqa: E402

OLLAMA_GENERATE_URL = "http://localhost:11434/api/generate"
OLLAMA_CHAT_URL = "http://localhost:11434/api/chat"

THINKING_MODELS = {"qwen3.6:latest", "qwen3.6", "gemma4:26b", "gemma4"}

MODELS = {
    "gemma4":          {"backend": "ollama", "model_id": "gemma4:26b",
                        "think": True},
    "gemma4-nothink":  {"backend": "ollama", "model_id": "gemma4:26b",
                        "think": False},
    "qwen3.6":         {"backend": "ollama", "model_id": "qwen3.6:latest",
                        "think": True},
    "qwen3.6-nothink": {"backend": "ollama", "model_id": "qwen3.6:latest",
                        "think": False},
    "gemini3.1":       {"backend": "openrouter",
                        "model_id": "google/gemini-3.1-pro-preview",
                        "think": False,
                        "reasoning": {"max_tokens": 4096}},
    "opus4.7":         {"backend": "openrouter",
                        "model_id": "anthropic/claude-opus-4.7",
                        "think": False,
                        "reasoning": {"enabled": False}},
    "gpt5.4":          {"backend": "openrouter",
                        "model_id": "openai/gpt-5.4",
                        "think": False,
                        "reasoning": {"enabled": False}},
}

CONDITIONS = {
    "binary_zeroshot":   ("00_zeroshot_cve",     "binary"),
    "binary_with_desc":  ("01_withdesc_cve",     "binary"),
    "source_zeroshot":   ("02_source_zeroshot",  "source"),
    "source_with_desc":  ("03_source_withdesc",  "source"),
}

PLATFORMS = ("linux", "windows")


def log(msg):
    print(msg, flush=True)


def call_ollama(model_id, prompt, think):
    """Call Ollama and return (content, raw_api_response, think)."""
    if think or model_id in THINKING_MODELS:
        payload = json.dumps({
            "model": model_id,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
            "think": think,
            "options": {"temperature": 0},
        }).encode()
        req = urllib.request.Request(OLLAMA_CHAT_URL, data=payload,
                                    headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=600) as resp:
            raw = json.loads(resp.read())
        content = raw.get("message", {}).get("content", "")
        return content, raw, think
    else:
        payload = json.dumps({
            "model": model_id,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0},
        }).encode()
        req = urllib.request.Request(OLLAMA_GENERATE_URL, data=payload,
                                    headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=600) as resp:
            raw = json.loads(resp.read())
        content = raw.get("response", "")
        return content, raw, False


def call_model(model_name, prompt):
    """Returns (content, raw_api_response_dict, think)."""
    cfg = MODELS[model_name]
    backend = cfg["backend"]
    if backend == "ollama":
        return call_ollama(cfg["model_id"], prompt, cfg["think"])
    content, raw = call_openrouter(
        cfg["model_id"], prompt,
        reasoning=cfg.get("reasoning"),
        verbosity=cfg.get("verbosity"),
        temperature=0,
        max_tokens=16384,
        timeout=1800,
    )
    return content, raw, cfg["think"]


_ANSWER_DIGIT = r'(\d+)'
_WRAP = r'[`*_\s\[\]]*(?:function|func|#)?[`*_\s\[\]]*'
_ANSWER_PATTERNS = [
    re.compile(
        r'[`*_]*answer[`*_]*\s*(?:[:=]|\bis\b)\s*' + _WRAP + _ANSWER_DIGIT,
        re.IGNORECASE),
    re.compile(
        r'final\s+answer\s*(?:[:=]|\bis\b)?\s*' + _WRAP + _ANSWER_DIGIT,
        re.IGNORECASE),
    re.compile(
        r'vulnerable\s+function\s+is\s+' + _WRAP + _ANSWER_DIGIT,
        re.IGNORECASE),
    re.compile(
        r'(?:choose|pick|select)\s+' + _WRAP + _ANSWER_DIGIT,
        re.IGNORECASE),
]
_LEADING_DIGIT_RE = re.compile(r'^\s*(\d)\s*(?:$|[^\w])', re.MULTILINE)


def parse_answer(response):
    """Extract numeric answer (0-4) from a (possibly verbose) model response."""
    if not response:
        return None
    best = None
    best_pos = -1
    for pat in _ANSWER_PATTERNS:
        for m in pat.finditer(response):
            val = int(m.group(1))
            if 0 <= val <= 4 and m.start() > best_pos:
                best = val
                best_pos = m.start()
    if best is not None:
        return best
    m = _LEADING_DIGIT_RE.search(response.strip())
    if m:
        val = int(m.group(1))
        if 0 <= val <= 4:
            return val
    return None


def run_condition(selected, decoys_data, model_name, condition_name,
                  prompt_stem, representation):
    """Score one (model, condition) pair across every OS rep of every CVE."""
    log(f"\n=== Recognition: {model_name} / {condition_name} "
        f"({representation}) ===")
    correct = 0
    total = 0

    for i, entry in enumerate(selected):
        cve_id = entry["cve_id"]
        if cve_id not in decoys_data:
            continue

        cve_decoys = decoys_data[cve_id]
        for bpath, decoy_entry in cve_decoys.items():
            plat = decoy_entry.get("platform")
            if plat not in PLATFORMS:
                continue

            prompt_path = os.path.join(
                FILLED_DIR, cve_id, f"{prompt_stem}_{plat}.txt")
            if not os.path.exists(prompt_path):
                continue

            bid = _bid_for_path(entry, bpath)
            if bid is None:
                continue
            bid = str(bid)

            result_path = os.path.join(
                RESULTS_DIR,
                f"{cve_id}_recognition_{condition_name}_{model_name}_{bid}.json")
            existing = None
            if os.path.exists(result_path) and os.path.getsize(result_path) > 0:
                try:
                    with open(result_path) as _f:
                        existing = json.load(_f)
                except json.JSONDecodeError as e:
                    log(f"  SKIP CORRUPT {os.path.basename(result_path)}: {e} -- will re-run")
            if existing is not None:
                total += 1
                if existing.get("correct"):
                    correct += 1
                continue

            expected = decoy_entry["ground_truth_label"]
            prompt = open(prompt_path).read()

            response_path = os.path.join(
                RESPONSES_DIR,
                f"{cve_id}_recognition_{condition_name}_{model_name}_{bid}.json")
            os.makedirs(RESULTS_DIR, exist_ok=True)
            os.makedirs(RESPONSES_DIR, exist_ok=True)

            think_enabled = MODELS[model_name]["think"]

            try:
                response, raw, think_enabled = call_model(model_name, prompt)
            except RateLimitError as e:
                err_msg = str(e)
                log(f"  RATE_LIMIT {cve_id}/{plat}/{bid}: {err_msg[:160]}")
                err_result = {
                    "cve_id": cve_id,
                    "task": "recognition",
                    "condition": condition_name,
                    "representation": representation,
                    "platform": plat,
                    "model": model_name,
                    "binary_id": bid,
                    "difficulty": "reference",
                    "expected": expected,
                    "predicted": None,
                    "correct": False,
                    "think": think_enabled,
                    "error_kind": "rate_limit",
                    "error": err_msg,
                    "raw_response": "",
                }
                with open(result_path, "w") as f:
                    json.dump(err_result, f, indent=2)
                total += 1
                continue
            except Exception as e:
                err_msg = str(e)
                log(f"  ERROR {cve_id}/{plat}/{bid}: {err_msg}")
                err_result = {
                    "cve_id": cve_id,
                    "task": "recognition",
                    "condition": condition_name,
                    "representation": representation,
                    "platform": plat,
                    "model": model_name,
                    "binary_id": bid,
                    "difficulty": "reference",
                    "expected": expected,
                    "predicted": None,
                    "correct": False,
                    "think": think_enabled,
                    "error_kind": "error",
                    "error": err_msg,
                    "raw_response": "",
                }
                with open(result_path, "w") as f:
                    json.dump(err_result, f, indent=2)
                total += 1
                continue

            predicted = parse_answer(response)
            is_correct = predicted == expected

            total += 1
            if is_correct:
                correct += 1

            result = {
                "cve_id": cve_id,
                "task": "recognition",
                "condition": condition_name,
                "representation": representation,
                "platform": plat,
                "model": model_name,
                "binary_id": bid,
                "difficulty": "reference",
                "expected": expected,
                "predicted": predicted,
                "correct": is_correct,
                "think": think_enabled,
                "raw_response": response,
            }

            with open(result_path, "w") as f:
                json.dump(result, f, indent=2)

            with open(response_path, "w") as f:
                json.dump(raw, f, indent=2)

        if (i + 1) % 20 == 0 or i == 0:
            acc = correct / total * 100 if total else 0
            log(f"  [{i+1}/{len(selected)}] {cve_id} "
                f"running_acc={acc:.1f}% ({correct}/{total})")

    if total:
        log(f"  Final {model_name}/{condition_name}: "
            f"{correct}/{total} = {correct/total*100:.1f}%")
    else:
        log(f"  No results for {model_name}/{condition_name}.")
    return correct, total


def _bid_for_path(entry, bpath):
    """Resolve bid for a full_path within an entry's reference + variants."""
    ref = entry.get("reference") or {}
    if ref.get("full_path") == bpath:
        return ref.get("binary_id")
    for v in entry.get("variants", []):
        if v.get("full_path") == bpath:
            return v.get("binary_id")
    return None


def _load_skip_cves():
    """Load skip_cves.json -> set of CVE IDs (empty set if missing)."""
    if not os.path.exists(SKIP_CVES_PATH):
        return set()
    try:
        data = json.load(open(SKIP_CVES_PATH))
    except Exception as e:
        log(f"WARN: failed to parse {SKIP_CVES_PATH}: {e}")
        return set()
    return {row["cve_id"] for row in data.get("cves", []) if "cve_id" in row}


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--models", nargs="+",
                        default=["gemma4", "qwen3.6"],
                        help="Models to evaluate")
    parser.add_argument("--conditions", nargs="+",
                        default=list(CONDITIONS.keys()),
                        choices=list(CONDITIONS.keys()),
                        help="Which recognition conditions to run "
                             "(binary/source x zeroshot/with_desc)")
    parser.add_argument("--max-cves", type=int, default=None)
    parser.add_argument("--include-skipped", action="store_true",
                        help="Include CVEs listed in "
                             "benchmark/data/skip_cves.json (which by "
                             "default are dropped for having oversized "
                             "prompts). Use this to force a run on the "
                             "long-tail CVEs.")
    args = parser.parse_args()

    selected = json.load(open(SELECTED))
    decoys_data = json.load(open(DECOYS_PATH))

    skip = set() if args.include_skipped else _load_skip_cves()
    if skip:
        before = len(selected)
        selected = [e for e in selected if e["cve_id"] not in skip]
        log(f"Skipping {before - len(selected)} CVEs per "
            f"benchmark/data/skip_cves.json (use --include-skipped to "
            f"override).")

    if args.max_cves:
        selected = selected[:args.max_cves]

    for model_name in args.models:
        for condition_name in args.conditions:
            prompt_stem, representation = CONDITIONS[condition_name]
            run_condition(
                selected, decoys_data, model_name,
                condition_name, prompt_stem, representation)


if __name__ == "__main__":
    main()
