"""Eval 2: CVE Hunting -- solo agent + strategy-guided agent."""

import json
import os
import random
import sys
import urllib.request

_PKG_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _PKG_DIR)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _paths  # noqa: E402

from agent import Agent, OllamaBackend  # noqa: E402
from backends import call_openrouter, BackendError  # noqa: E402

FILLED_DIR = _paths.FILLED_DIR
OUTPUT_DIR = _paths.OUTPUTS_DIR
RESPONSE_DIR = _paths.RESPONSE_DIR
RESULTS_DIR = _paths.RESULTS_DIR
SELECTED = _paths.SELECTED_JSON
GROUND_TRUTH = _paths.GROUND_TRUTH_JSON

OLLAMA_GEN_URL = "http://localhost:11434/api/generate"

STRATEGY_BACKENDS = {
    "gemma4":    {"backend": "ollama",     "model_id": "gemma4:26b"},
    "qwen3.6":   {"backend": "ollama",     "model_id": "qwen3.6:latest"},
    "gemini3.1": {"backend": "openrouter", "model_id": "google/gemini-3.1-pro-preview",
                  "reasoning": {"max_tokens": 16384, "exclude": False},
                  "max_tokens": 48000},
    "opus4.7":   {"backend": "openrouter", "model_id": "anthropic/claude-opus-4.7",
                  "reasoning": {"enabled": True, "exclude": False},
                  "verbosity": "max",
                  "max_tokens": 48000,
                  "provider": {"order": ["Anthropic"], "allow_fallbacks": False}},
    "gpt5.4":    {"backend": "openrouter", "model_id": "openai/gpt-5.4",
                  "reasoning": {"effort": "high", "exclude": False},
                  "max_tokens": 48000},
}

FRONTIER_STRATEGY_MODELS = ["gemini3.1", "opus4.7", "gpt5.4"]

BASE_AGENTS = ["gemma4", "qwen3.6"]

OLLAMA_MODELS = {
    "gemma4":  "gemma4:26b",
    "qwen3.6": "qwen3.6:latest",
}


def log(msg):
    print(msg, flush=True)


def generate_strategy(cve_id, model_name):
    """Generate (or load cached) strategy document. Returns the text."""
    strat_dir = os.path.join(OUTPUT_DIR, cve_id, "strategies")
    strat_path = os.path.join(strat_dir, f"{model_name}.md")

    if os.path.exists(strat_path):
        return open(strat_path).read()

    prompt_path = os.path.join(FILLED_DIR, cve_id, "10_strategy_gen.txt")
    if not os.path.exists(prompt_path):
        return None

    prompt = open(prompt_path).read()

    if model_name not in STRATEGY_BACKENDS:
        log(f"  Unknown strategy model: {model_name}")
        return None

    cfg = STRATEGY_BACKENDS[model_name]
    backend = cfg["backend"]
    model_id = cfg["model_id"]
    raw = None
    try:
        if backend == "ollama":
            payload = json.dumps({
                "model": model_id,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0},
            }).encode()
            req = urllib.request.Request(
                OLLAMA_GEN_URL, data=payload,
                headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=600) as resp:
                result = json.loads(resp.read())
            strategy = result.get("response", "")
            raw = result
        else:
            strategy, raw = call_openrouter(
                model_id, prompt,
                reasoning=cfg.get("reasoning"),
                verbosity=cfg.get("verbosity"),
                temperature=None,
                max_tokens=cfg.get("max_tokens", 32000),
                provider=cfg.get("provider"),
                timeout=1800,
            )
    except Exception as e:
        log(f"  Strategy generation failed for {cve_id} via {model_name}: {e}")
        return None

    os.makedirs(strat_dir, exist_ok=True)
    with open(strat_path, "w") as f:
        f.write(strategy)

    resp_dir = os.path.join(RESPONSE_DIR, model_name, cve_id)
    os.makedirs(resp_dir, exist_ok=True)
    with open(os.path.join(resp_dir, "strategy_gen.json"), "w") as rf:
        json.dump({
            "cve_id": cve_id,
            "model": model_name,
            "task": "strategy_gen",
            "prompt_length": len(prompt),
            "raw_response": raw,
        }, rf, indent=2)

    return strategy


def run_phase_strategy(selected, strategy_models):
    """Phase 2: generate strategies for (CVE x strategy_model)."""
    log("\n=== Phase 2: Strategy generation ===")
    for model in strategy_models:
        log(f"\nStrategy model: {model}")
        ok = skipped = failed = 0
        for i, entry in enumerate(selected):
            cve_id = entry["cve_id"]
            strat_path = os.path.join(
                OUTPUT_DIR, cve_id, "strategies", f"{model}.md")
            if os.path.exists(strat_path):
                ok += 1
                continue
            prompt_path = os.path.join(FILLED_DIR, cve_id, "10_strategy_gen.txt")
            if not os.path.exists(prompt_path):
                skipped += 1
                continue
            text = generate_strategy(cve_id, model)
            if text:
                ok += 1
            else:
                failed += 1
            if (i + 1) % 10 == 0:
                log(f"  [{i+1}/{len(selected)}] "
                    f"ok={ok} failed={failed} skipped={skipped}")
        log(f"  {model}: ok={ok} failed={failed} skipped={skipped}")


def _binary_loadable(full_path):
    """Quick magic-byte check so non-binary files are skipped rather than crashing Ghidra."""
    if not full_path or not os.path.exists(full_path):
        return False
    fname = os.path.basename(full_path).lower()
    if any(fname.endswith(ext) for ext in (".exe", ".dll", ".so")):
        return True
    try:
        with open(full_path, "rb") as bf:
            magic = bf.read(4)
    except OSError:
        return False
    return magic[:4] == b"\x7fELF" or magic[:2] == b"MZ"


def _binary_iter(entry, max_variants=None):
    """Yield (binary_dict, bid_str) for reference + sample_variant binaries."""
    ref = entry["reference"]
    bins = [{
        "binary_id": ref["binary_id"],
        "full_path": ref["full_path"],
        "difficulty": "reference",
        "has_vulnerability": True,
    }]
    sv = entry.get("sample_variant")
    if sv:
        def _os(b):
            return "linux" if (b.get("platform") or "").lower() == "linux" else "windows"
        ref_os = _os(ref)
        has_cross_os = any(_os(v) != ref_os for v in entry.get("variants", []))
        if has_cross_os:
            bins.append(sv)
    if max_variants:
        bins = bins[:max_variants]
    for b in bins:
        yield b, str(b["binary_id"])


def _normalize_stripped_name(name):
    if not name:
        return ""
    name = name.strip()
    for prefix in ("FUN_", "sub_"):
        if name.startswith(prefix):
            addr = name[len(prefix):].lstrip("0") or "0"
            return "sub_" + addr.lower()
    return name.lower()


def _candidate_matches(candidate, targets):
    if not candidate:
        return False
    c = candidate.strip().split("(", 1)[0].strip()
    c_norm = _normalize_stripped_name(c)
    for tgt in targets:
        if not tgt:
            continue
        if c == tgt or c_norm == _normalize_stripped_name(tgt):
            return True
    return False


def _rank_candidates(given, expected):
    """Return (rank, matched_source_func) or (None, None)."""
    if not expected:
        return None, None
    for i, cand in enumerate(given):
        if _candidate_matches(cand, expected):
            c_norm = _normalize_stripped_name(
                str(cand).split("(", 1)[0].strip())
            return i + 1, c_norm
    return None, None


def _save_agent_result(agent_result, cve_id, phase, agent_model,
                      strategy_model, binary_info, result_path,
                      log_filename, ground_truth):
    """Persist agent output (full log to response/, scored summary to results/raw/)."""
    response_log_dir = os.path.join(
        RESPONSE_DIR, agent_model, cve_id)
    os.makedirs(response_log_dir, exist_ok=True)
    log_path = os.path.join(response_log_dir, log_filename)
    with open(log_path, "w") as f:
        json.dump({
            "cve_id": cve_id,
            "phase": phase,
            "binary_id": binary_info["binary_id"],
            "binary_path": binary_info["full_path"],
            "agent_model": agent_model,
            "strategy_model": strategy_model,
            "turns": agent_result.turns,
            "elapsed_seconds": agent_result.elapsed_seconds,
            "finished": agent_result.finished,
            "reason": agent_result.reason,
            "candidates": agent_result.candidates,
            "conversation": agent_result.conversation,
            "api_log": agent_result.api_log,
        }, f, indent=2)

    bid = str(binary_info["binary_id"])
    gt_entry = (ground_truth.get(cve_id, {})
                .get("binaries", {}).get(bid, {}))
    func_map = gt_entry.get("functions", {})
    expected_stripped = list(func_map.values())
    given = agent_result.candidates[:20]
    rank, matched_norm = _rank_candidates(given, expected_stripped)

    matched_source = None
    if matched_norm is not None:
        for src, stripped in func_map.items():
            if _normalize_stripped_name(stripped) == matched_norm:
                matched_source = src
                break

    result = {
        "cve_id": cve_id,
        "task": "hunting",
        "phase": phase,
        "agent_model": agent_model,
        "model_id": agent_model,
        "strategy_model": strategy_model,
        "binary_id": binary_info["binary_id"],
        "difficulty": binary_info.get("difficulty"),
        "has_vulnerability": binary_info.get("has_vulnerability", True),
        "expected_funcs": expected_stripped,
        "expected_source_funcs": list(func_map.keys()),
        "given_answer": given,
        "rank": rank,
        "hit_at_1": rank == 1 if rank else False,
        "hit_at_5": rank is not None and rank <= 5,
        "correct": rank == 1 if rank else False,
        "matched_source_func": matched_source,
        "turns": agent_result.turns,
        "elapsed_seconds": agent_result.elapsed_seconds,
        "finished": agent_result.finished,
        "reason": agent_result.reason,
        "terminated_reason": agent_result.reason,
        "api_call_count": len(agent_result.api_log),
        "log_path": log_path,
    }
    os.makedirs(os.path.dirname(result_path), exist_ok=True)
    with open(result_path, "w") as f:
        json.dump(result, f, indent=2)


def _run_agent(prompt, agent_model, binary_info, response_dir_parts,
               condition_tag, max_wall_seconds=1800, max_turns=1000):
    """Spin up an Ollama agent against one binary; returns AgentResult or None."""
    if not _binary_loadable(binary_info["full_path"]):
        return None

    model_id = OLLAMA_MODELS.get(agent_model, agent_model)
    response_dir = os.path.join(RESPONSE_DIR, *response_dir_parts)
    backend = OllamaBackend(model=model_id, think=False, max_tokens=4096)
    try:
        agent = Agent(backend, binary_info["full_path"],
                      max_wall_seconds=max_wall_seconds,
                      max_turns=max_turns,
                      response_dir=response_dir)
    except (ValueError, FileNotFoundError) as e:
        log(f"    Skipping {binary_info['full_path']}: {e}")
        return None
    return agent.run(prompt, condition=condition_tag)


def run_phase_solo(selected, agents, max_variants=None,
                   max_wall_seconds=1800, max_turns=1000, ground_truth=None):
    """Phase 1: each base agent runs the solo prompt on every binary."""
    log("\n=== Phase 1: Solo baseline ===")
    ground_truth = ground_truth or {}
    for agent_model in agents:
        log(f"\nAgent: {agent_model}")
        for i, entry in enumerate(selected):
            cve_id = entry["cve_id"]
            prompt_path = os.path.join(FILLED_DIR, cve_id, "20_agent_zeroshot.txt")
            if not os.path.exists(prompt_path):
                continue
            prompt = open(prompt_path).read()

            for b, bid in _binary_iter(entry, max_variants):
                result_path = os.path.join(
                    RESULTS_DIR,
                    f"{cve_id}_hunting_solo_{agent_model}_{bid}.json")
                if os.path.exists(result_path):
                    continue

                ar = _run_agent(
                    prompt, agent_model, b,
                    response_dir_parts=(agent_model, cve_id),
                    condition_tag=f"solo_{agent_model}",
                    max_wall_seconds=max_wall_seconds,
                    max_turns=max_turns)
                if ar is None:
                    continue

                _save_agent_result(
                    ar, cve_id, phase="solo",
                    agent_model=agent_model,
                    strategy_model=None,
                    binary_info=b,
                    result_path=result_path,
                    log_filename=f"solo_{agent_model}_{bid}.json",
                    ground_truth=ground_truth)

            if (i + 1) % 5 == 0:
                log(f"  [{i+1}/{len(selected)}] {cve_id}")


def run_phase_guided(selected, strategy_models, agents, max_variants=None,
                     max_wall_seconds=1800, max_turns=1000, ground_truth=None,
                     cached_only=False, shuffle_seed=42):
    """Phase 3: each agent follows each strategy on every binary."""
    log("\n=== Phase 3: Strategy-guided execution (random walk) ===")
    ground_truth = ground_truth or {}

    tasks = []
    missing_per_strategy = {sm: 0 for sm in strategy_models}
    for strategy_model in strategy_models:
        for agent_model in agents:
            for entry in selected:
                cve_id = entry["cve_id"]
                strat_path = os.path.join(
                    OUTPUT_DIR, cve_id, "strategies",
                    f"{strategy_model}.md")
                if cached_only and not os.path.exists(strat_path):
                    missing_per_strategy[strategy_model] += 1
                    continue
                tmpl_path = os.path.join(
                    FILLED_DIR, cve_id, "21_agent_follow_template.txt")
                if not os.path.exists(tmpl_path):
                    continue
                for b, bid in _binary_iter(entry, max_variants):
                    result_path = os.path.join(
                        RESULTS_DIR,
                        f"{cve_id}_hunting_guided_{strategy_model}_"
                        f"{agent_model}_{bid}.json")
                    if os.path.exists(result_path):
                        continue
                    tasks.append((strategy_model, agent_model, entry,
                                  b, bid, tmpl_path, strat_path,
                                  result_path))

    rng = random.Random(shuffle_seed)
    rng.shuffle(tasks)
    total = len(tasks)
    log(f"  Random walk over {total} pending tasks (seed={shuffle_seed})")
    for sm, c in missing_per_strategy.items():
        if c:
            log(f"  (skipping {c} CVEs without {sm} strategy)")

    strategy_cache = {}
    completed = 0
    for (strategy_model, agent_model, entry, b, bid,
         tmpl_path, strat_path, result_path) in tasks:
        cve_id = entry["cve_id"]

        if os.path.exists(result_path):
            continue

        key = (cve_id, strategy_model)
        if key not in strategy_cache:
            if cached_only:
                strategy_cache[key] = open(strat_path).read()
            else:
                strategy_cache[key] = generate_strategy(cve_id, strategy_model)
        strategy = strategy_cache[key]
        if not strategy:
            continue

        prompt = open(tmpl_path).read().replace(
            "{strategy_document}", strategy)

        tag = f"guided_{strategy_model}_{agent_model}"
        ar = _run_agent(
            prompt, agent_model, b,
            response_dir_parts=(agent_model, cve_id),
            condition_tag=tag,
            max_wall_seconds=max_wall_seconds,
            max_turns=max_turns)
        if ar is None:
            continue

        _save_agent_result(
            ar, cve_id, phase="guided",
            agent_model=agent_model,
            strategy_model=strategy_model,
            binary_info=b,
            result_path=result_path,
            log_filename=f"{tag}_{bid}.json",
            ground_truth=ground_truth)
        completed += 1
        if completed % 5 == 0:
            log(f"  [{completed}/{total}] {strategy_model} -> "
                f"{agent_model} -> {cve_id}/{bid}")


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--phases", nargs="+",
                        default=["solo", "strategy", "guided"],
                        choices=["solo", "strategy", "guided"],
                        help="Which phases to run")
    parser.add_argument("--agents", nargs="+", default=BASE_AGENTS,
                        choices=BASE_AGENTS,
                        help="Base-model agents (Phase 1 and 3)")
    parser.add_argument("--strategy-models", nargs="+",
                        default=FRONTIER_STRATEGY_MODELS,
                        choices=list(STRATEGY_BACKENDS.keys()),
                        help="Models that produce strategies. "
                             "Defaults to the three frontier models. "
                             "Adding gemma4/qwen3.6 populates the "
                             "base-strategy columns of Table 3.")
    parser.add_argument("--max-cves", type=int, default=None)
    parser.add_argument("--cve-id", nargs="+", default=None,
                        help="Restrict to specific CVE IDs (overrides --max-cves "
                             "ordering). Useful for targeted test runs.")
    parser.add_argument("--max-variants", type=int, default=None,
                        help="Cap binaries per CVE (1 = reference only)")
    parser.add_argument("--max-wall-seconds", type=int, default=1800,
                        help="Per-binary wall-clock budget for the agent. "
                             "Default 1800 (30 min). Set 0 to disable. The "
                             "agent also has a separate per-HTTP-call "
                             "backend timeout (default 600 s / 10 min on "
                             "OllamaBackend). Any cap expiring aborts the "
                             "run -- no retries.")
    parser.add_argument("--max-turns", type=int, default=1000,
                        help="Per-binary turn cap for the agent. Default "
                             "1000. Set 0 to disable. Exits with "
                             "reason='turn_limit' when reached.")
    parser.add_argument("--cached-strategies-only", action="store_true",
                        help="Skip Phase 2 strategy generation; in Phase 3, "
                             "skip CVEs whose strategy file is missing "
                             "instead of calling the API to generate it. "
                             "Use when running guided execution against a "
                             "subset of strategy models without paying for "
                             "API calls on missing strategies.")
    args = parser.parse_args()

    selected = json.load(open(SELECTED))
    ground_truth = (json.load(open(GROUND_TRUTH))
                    if os.path.exists(GROUND_TRUTH) else {})
    if args.cve_id:
        wanted = set(args.cve_id)
        selected = [e for e in selected if e["cve_id"] in wanted]
        missing = wanted - {e["cve_id"] for e in selected}
        if missing:
            log(f"Warning: CVE IDs not found in selected.json: {sorted(missing)}")
    elif args.max_cves:
        selected = selected[:args.max_cves]

    if "solo" in args.phases:
        run_phase_solo(selected, args.agents, args.max_variants,
                       max_wall_seconds=args.max_wall_seconds,
                       max_turns=args.max_turns,
                       ground_truth=ground_truth)

    if ("strategy" in args.phases or "guided" in args.phases) \
            and not args.cached_strategies_only:
        run_phase_strategy(selected, args.strategy_models)

    if "guided" in args.phases:
        run_phase_guided(
            selected, args.strategy_models, args.agents, args.max_variants,
            max_wall_seconds=args.max_wall_seconds,
            max_turns=args.max_turns,
            ground_truth=ground_truth,
            cached_only=args.cached_strategies_only)


if __name__ == "__main__":
    main()
