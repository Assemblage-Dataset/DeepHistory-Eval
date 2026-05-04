"""Eval 3: Cross-Build Transfer -- reuse Eval 2 strategies on cross-build variants."""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from eval2_hunting import (
    BASE_AGENTS,
    FRONTIER_STRATEGY_MODELS,
    STRATEGY_BACKENDS,
    FILLED_DIR,
    OUTPUT_DIR,
    RESULTS_DIR,
    SELECTED,
    GROUND_TRUTH,
    _run_agent,
    _save_agent_result,
    log,
)

DIFFICULTY_PREFIXES = ("D1_", "D2_", "D3_", "D4_", "D5_")


def _matches_difficulty(diff, allowed_prefixes):
    if not diff:
        return False
    return any(diff.startswith(p) for p in allowed_prefixes)


def _variant_iter(entry, allowed_prefixes, max_variants=None):
    """Yield (binary_dict, bid_str) for cross-build variants + fixed binaries."""
    sv = entry.get("sample_variant") or {}
    sv_bid = sv.get("binary_id")

    bins = []
    for v in entry.get("variants", []):
        if sv_bid is not None and v.get("binary_id") == sv_bid:
            continue
        if not _matches_difficulty(v.get("difficulty"), allowed_prefixes):
            continue
        bins.append(v)

    for fb in entry.get("fixed_binaries", []) or []:
        if _matches_difficulty(fb.get("difficulty"), allowed_prefixes):
            bins.append(fb)

    if max_variants:
        bins = bins[:max_variants]
    for b in bins:
        yield b, str(b["binary_id"])


def _load_strategy(cve_id, strategy_model):
    """Return the strategy text from Eval 2 Phase 2, or None if missing."""
    path = os.path.join(
        OUTPUT_DIR, cve_id, "strategies", f"{strategy_model}.md")
    if not os.path.exists(path):
        return None
    return open(path).read()


def run_phase_solo(selected, agents, allowed_prefixes,
                   max_variants=None, max_wall_seconds=1800,
                   ground_truth=None):
    log("\n=== Eval 3 Phase 1: Solo transfer ===")
    ground_truth = ground_truth or {}
    for agent_model in agents:
        log(f"\nAgent: {agent_model}")
        for i, entry in enumerate(selected):
            cve_id = entry["cve_id"]
            prompt_path = os.path.join(
                FILLED_DIR, cve_id, "20_agent_zeroshot.txt")
            if not os.path.exists(prompt_path):
                continue
            prompt = open(prompt_path).read()

            for b, bid in _variant_iter(entry, allowed_prefixes, max_variants):
                result_path = os.path.join(
                    RESULTS_DIR,
                    f"{cve_id}_transfer_solo_{agent_model}_{bid}.json")
                if os.path.exists(result_path):
                    continue

                ar = _run_agent(
                    prompt, agent_model, b,
                    response_dir_parts=(agent_model, cve_id),
                    condition_tag=f"transfer_solo_{agent_model}",
                    max_wall_seconds=max_wall_seconds)
                if ar is None:
                    continue

                _save_agent_result(
                    ar, cve_id, phase="transfer_solo",
                    agent_model=agent_model,
                    strategy_model=None,
                    binary_info=b,
                    result_path=result_path,
                    log_filename=f"transfer_solo_{agent_model}_{bid}.json",
                    ground_truth=ground_truth)

            if (i + 1) % 5 == 0:
                log(f"  [{i+1}/{len(selected)}] {cve_id}")


def run_phase_guided(selected, strategy_models, agents, allowed_prefixes,
                     max_variants=None, max_wall_seconds=1800,
                     ground_truth=None):
    log("\n=== Eval 3 Phase 2: Guided transfer ===")
    ground_truth = ground_truth or {}
    for strategy_model in strategy_models:
        for agent_model in agents:
            log(f"\nStrategy: {strategy_model} -> Agent: {agent_model}")
            missing_strategies = 0
            for i, entry in enumerate(selected):
                cve_id = entry["cve_id"]

                strategy = _load_strategy(cve_id, strategy_model)
                if strategy is None:
                    missing_strategies += 1
                    continue

                tmpl_path = os.path.join(
                    FILLED_DIR, cve_id, "21_agent_follow_template.txt")
                if not os.path.exists(tmpl_path):
                    continue

                prompt = open(tmpl_path).read().replace(
                    "{strategy_document}", strategy)

                for b, bid in _variant_iter(entry, allowed_prefixes, max_variants):
                    result_path = os.path.join(
                        RESULTS_DIR,
                        f"{cve_id}_transfer_guided_{strategy_model}_"
                        f"{agent_model}_{bid}.json")
                    if os.path.exists(result_path):
                        continue

                    tag = f"transfer_guided_{strategy_model}_{agent_model}"
                    ar = _run_agent(
                        prompt, agent_model, b,
                        response_dir_parts=(agent_model, cve_id),
                        condition_tag=tag,
                        max_wall_seconds=max_wall_seconds)
                    if ar is None:
                        continue

                    _save_agent_result(
                        ar, cve_id, phase="transfer_guided",
                        agent_model=agent_model,
                        strategy_model=strategy_model,
                        binary_info=b,
                        result_path=result_path,
                        log_filename=f"{tag}_{bid}.json",
                        ground_truth=ground_truth)

                if (i + 1) % 5 == 0:
                    log(f"  [{i+1}/{len(selected)}] {cve_id}")

            if missing_strategies:
                log(f"  (skipped {missing_strategies} CVEs with no "
                    f"{strategy_model} strategy -- run eval2_hunting.py "
                    f"--phases strategy first)")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--phases", nargs="+",
                        default=["solo", "guided"],
                        choices=["solo", "guided"],
                        help="Which phases to run")
    parser.add_argument("--agents", nargs="+", default=BASE_AGENTS,
                        choices=BASE_AGENTS,
                        help="Base-model agents (Phase 1 and 2)")
    parser.add_argument("--strategy-models", nargs="+",
                        default=FRONTIER_STRATEGY_MODELS,
                        choices=list(STRATEGY_BACKENDS.keys()),
                        help="Strategies to execute (must already exist "
                             "in outputs/{cve}/strategies/). Defaults to "
                             "the three frontier models.")
    parser.add_argument("--difficulties", nargs="+",
                        default=["D1", "D2", "D3", "D4", "D5"],
                        choices=["D1", "D2", "D3", "D4", "D5"],
                        help="Difficulty buckets to include. Matched by "
                             "prefix against variant.difficulty "
                             "(e.g. D1 matches D1_cross_opt).")
    parser.add_argument("--max-cves", type=int, default=None)
    parser.add_argument("--cve-id", nargs="+", default=None,
                        help="Restrict to specific CVE IDs (overrides "
                             "--max-cves ordering).")
    parser.add_argument("--max-variants", type=int, default=None,
                        help="Cap variants per CVE (pilot runs)")
    parser.add_argument("--max-wall-seconds", type=int, default=1800,
                        help="Per-binary wall-clock budget for the agent "
                             "(default 1800 = 30 min). Matches eval2.")
    args = parser.parse_args()

    selected = json.load(open(SELECTED))
    ground_truth = (json.load(open(GROUND_TRUTH))
                    if os.path.exists(GROUND_TRUTH) else {})
    if args.cve_id:
        wanted = set(args.cve_id)
        selected = [e for e in selected if e["cve_id"] in wanted]
        missing = wanted - {e["cve_id"] for e in selected}
        if missing:
            log(f"Warning: CVE IDs not found in selected.json: "
                f"{sorted(missing)}")
    elif args.max_cves:
        selected = selected[:args.max_cves]

    allowed_prefixes = tuple(f"{d}_" for d in args.difficulties)

    if "solo" in args.phases:
        run_phase_solo(
            selected, args.agents, allowed_prefixes,
            max_variants=args.max_variants,
            max_wall_seconds=args.max_wall_seconds,
            ground_truth=ground_truth)

    if "guided" in args.phases:
        run_phase_guided(
            selected, args.strategy_models, args.agents, allowed_prefixes,
            max_variants=args.max_variants,
            max_wall_seconds=args.max_wall_seconds,
            ground_truth=ground_truth)


if __name__ == "__main__":
    main()
