"""Scoring + table generation for the benchmark."""

import csv
import json
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _paths  # noqa: E402

RESULTS_DIR = _paths.RESULTS_DIR
GT_PATH = _paths.GROUND_TRUTH_JSON
SELECTED_PATH = _paths.SELECTED_JSON
TABLES_DIR = _paths.TABLES_DIR

MODEL_DISPLAY = {
    "gemma4": "Gemma 4 26B",
    "qwen3.6": "Qwen 3.6",
    "gemini3.1": "Gemini 3.1 Pro",
    "gpt5.4": "GPT-5.4",
    "opus4.7": "Opus 4.7",
}

ALL_MODELS = ["gemma4", "qwen3.6", "gemini3.1", "opus4.7", "gpt5.4"]
BASE_AGENTS = ["gemma4", "qwen3.6"]
FRONTIER_STRATEGIES = ["gemini3.1", "opus4.7"]
BASE_STRATEGIES = ["gemma4", "qwen3.6"]

DIFFICULTIES = [
    "reference", "D1_cross_opt", "D2_cross_compiler",
    "D4_cross_version", "D5_cross_everything",
]

DIFF_SHORT = {
    "reference": "Ref",
    "D1_cross_opt": "D1 Cross-Opt",
    "D2_cross_compiler": "D2 Cross-Compiler",
    "D4_cross_version": "D4 Cross-Version",
    "D5_cross_everything": "D5 Cross-All",
}


def log(msg):
    print(msg, flush=True)


def load_ground_truth():
    return json.load(open(GT_PATH)) if os.path.exists(GT_PATH) else {}


def load_results():
    results = []
    if not os.path.exists(RESULTS_DIR):
        return results
    for f in sorted(os.listdir(RESULTS_DIR)):
        if not f.endswith(".json"):
            continue
        if f.startswith("broken_"):
            continue
        try:
            data = json.load(open(os.path.join(RESULTS_DIR, f)))
        except (json.JSONDecodeError, OSError):
            continue
        results.append(data)
    return results


def _normalize_stripped_name(name):
    """Normalize FUN_00401234 / sub_401234 -> 'sub_401234'."""
    if not name:
        return ""
    name = name.strip()
    for prefix in ("FUN_", "sub_"):
        if name.startswith(prefix):
            addr = name[len(prefix):].lstrip("0") or "0"
            return "sub_" + addr.lower()
    return name.lower()


def _candidate_matches(candidate, targets):
    """Check whether a candidate name matches any ground-truth stripped name."""
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


def score_hunting(result, gt):
    """Score a hunting (solo or guided) result against per-binary GT."""
    cve_id = result["cve_id"]
    binary_id = str(result.get("binary_id", ""))
    candidates = result.get("candidates", [])
    has_vuln = result.get("has_vulnerability", True)

    if cve_id not in gt:
        return None

    gt_entry = gt[cve_id]

    if not has_vuln:
        return {
            "cve_id": cve_id,
            "binary_id": binary_id,
            "has_vulnerability": False,
            "false_positive": len(candidates) > 0,
            "candidate_count": len(candidates),
        }

    bin_entry = gt_entry.get("binaries", {}).get(binary_id, {})
    func_map = bin_entry.get("functions", {})
    targets = list(func_map.values())

    if not targets:
        return {
            "cve_id": cve_id,
            "binary_id": binary_id,
            "has_vulnerability": True,
            "rank": None,
            "hit_at_1": False,
            "hit_at_5": False,
            "candidate_count": len(candidates),
            "matched_func": None,
            "ground_truth_missing": True,
        }

    rank = None
    matched_func = None
    for i, cand in enumerate(candidates):
        if _candidate_matches(cand, targets):
            rank = i + 1
            c_norm = _normalize_stripped_name(
                str(cand).split("(", 1)[0].strip())
            for src, stripped in func_map.items():
                if _normalize_stripped_name(stripped) == c_norm:
                    matched_func = src
                    break
            break

    return {
        "cve_id": cve_id,
        "binary_id": binary_id,
        "has_vulnerability": True,
        "rank": rank,
        "hit_at_1": rank == 1 if rank else False,
        "hit_at_5": rank is not None and rank <= 5,
        "candidate_count": len(candidates),
        "matched_func": matched_func,
    }


RECOG_CONDITIONS = {
    "binary_zeroshot":  ("binary", "zeroshot"),
    "binary_with_desc": ("binary", "with_desc"),
    "source_zeroshot":  ("source", "zeroshot"),
    "source_with_desc": ("source", "with_desc"),
    "zeroshot":         ("binary", "zeroshot"),
    "with_desc":        ("binary", "with_desc"),
}


def _canonical_recog_cond(result):
    """Derive (representation, cond_short) from a recognition result row."""
    cond = result.get("condition", "")
    rep = result.get("representation")
    if rep in ("source", "binary") and cond in ("zeroshot", "with_desc"):
        return rep, cond
    return RECOG_CONDITIONS.get(cond, (None, None))


def _canonical_model(name):
    """Strip backend-specific suffixes (e.g. '-nothink')."""
    if not name:
        return ""
    for suffix in ("-nothink", "-think"):
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def _load_no_real_diff_cves():
    """CVEs whose YAML hunks field is prose placeholder rather than a real unified diff."""
    try:
        with open(SELECTED_PATH) as f:
            sel = json.load(f)
    except FileNotFoundError:
        return set()
    return {c["cve_id"] for c in sel if not c.get("has_real_diff", True)}


def generate_table1(recognition_results):
    """Source vs Binary recognition accuracy per model."""
    no_diff_cves = _load_no_real_diff_cves()
    by_mrc = defaultdict(lambda: {"correct": 0, "total": 0})
    for r in recognition_results:
        model = _canonical_model(r.get("model", ""))
        rep, cond_short = _canonical_recog_cond(r)
        if not model or rep is None:
            continue
        if cond_short == "with_desc" and r.get("cve_id") in no_diff_cves:
            continue
        by_mrc[(model, rep, cond_short)]["total"] += 1
        if r.get("correct"):
            by_mrc[(model, rep, cond_short)]["correct"] += 1

    def acc(model, rep, cond_short):
        stats = by_mrc.get((model, rep, cond_short))
        if not stats or stats["total"] == 0:
            return None
        return stats["correct"] / stats["total"] * 100

    def fmt(v):
        return f"{v:.1f}" if v is not None else "-"

    headers = ["Model",
               "Source zero-shot", "Source with-desc",
               "Binary zero-shot", "Binary with-desc",
               "\u0394 decomp (with-desc)"]
    rows = []
    for model in ALL_MODELS:
        s_z = acc(model, "source", "zeroshot")
        s_d = acc(model, "source", "with_desc")
        b_z = acc(model, "binary", "zeroshot")
        b_d = acc(model, "binary", "with_desc")
        delta = (s_d - b_d) if (s_d is not None and b_d is not None) else None
        row = {
            "Model": MODEL_DISPLAY.get(model, model),
            "Source zero-shot": fmt(s_z),
            "Source with-desc": fmt(s_d),
            "Binary zero-shot": fmt(b_z),
            "Binary with-desc": fmt(b_d),
            "\u0394 decomp (with-desc)":
                f"{delta:+.1f}" if delta is not None else "-",
        }
        rows.append(row)

    rows.append({
        "Model": "*Random baseline*",
        "Source zero-shot": "20.0",
        "Source with-desc": "20.0",
        "Binary zero-shot": "20.0",
        "Binary with-desc": "20.0",
        "\u0394 decomp (with-desc)": "0.0",
    })
    return rows, headers


def _hit_rates(scored):
    """(hit1_pct, hit5_pct, n) over scorable affected-binary results."""
    vuln = [s for s in scored
            if s.get("has_vulnerability")
            and not s.get("ground_truth_missing")]
    if not vuln:
        return None, None, 0
    n = len(vuln)
    h1 = sum(1 for s in vuln if s.get("hit_at_1")) / n * 100
    h5 = sum(1 for s in vuln if s.get("hit_at_5")) / n * 100
    return h1, h5, n


def generate_table2(scored_solo):
    """Hit@1 per base agent, averaged across all binaries."""
    headers = ["Agent", "Hit@1", "Hit@5", "n"]
    rows = []
    for agent in BASE_AGENTS:
        agent_scored = [s for s in scored_solo if s.get("agent_model") == agent]
        h1, h5, n = _hit_rates(agent_scored)
        rows.append({
            "Agent": MODEL_DISPLAY.get(agent, agent),
            "Hit@1": f"{h1:.1f}" if h1 is not None else "-",
            "Hit@5": f"{h5:.1f}" if h5 is not None else "-",
            "n": str(n),
        })
    return rows, headers


def generate_table3(scored_guided, strategies):
    """Hit@1 per (strategy_model x base_agent)."""
    headers = ["Agent"] + [MODEL_DISPLAY.get(s, s) for s in strategies]
    rows = []
    for agent in BASE_AGENTS:
        row = {"Agent": MODEL_DISPLAY.get(agent, agent)}
        for strat in strategies:
            scored = [s for s in scored_guided
                      if s.get("agent_model") == agent
                      and s.get("strategy_model") == strat]
            h1, _h5, _n = _hit_rates(scored)
            col = MODEL_DISPLAY.get(strat, strat)
            row[col] = f"{h1:.1f}" if h1 is not None else "-"
        rows.append(row)
    return rows, headers


def generate_table4(scored_solo, scored_guided, strategies):
    """Delta Hit@1 = guided - solo, per (strategy, agent)."""
    solo_by_agent = {}
    for agent in BASE_AGENTS:
        subset = [s for s in scored_solo if s.get("agent_model") == agent]
        h1, _h5, _n = _hit_rates(subset)
        solo_by_agent[agent] = h1

    headers = ["Agent"] + [MODEL_DISPLAY.get(s, s) for s in strategies]
    rows = []
    for agent in BASE_AGENTS:
        row = {"Agent": MODEL_DISPLAY.get(agent, agent)}
        solo_h1 = solo_by_agent.get(agent)
        for strat in strategies:
            scored = [s for s in scored_guided
                      if s.get("agent_model") == agent
                      and s.get("strategy_model") == strat]
            guided_h1, _, _ = _hit_rates(scored)
            col = MODEL_DISPLAY.get(strat, strat)
            if guided_h1 is not None and solo_h1 is not None:
                row[col] = f"{guided_h1 - solo_h1:+.1f}"
            else:
                row[col] = "-"
        rows.append(row)
    return rows, headers


EVAL3_PATH = os.path.join(RESULTS_DIR, "eval3_transfer.json")


def generate_table5():
    """Cross-Build Transfer table; reads eval3_transfer.json."""
    if not os.path.exists(EVAL3_PATH):
        return None, None, None, None

    data = json.load(open(EVAL3_PATH))
    conditions = data.get("conditions", {})
    if not conditions:
        return None, None, None, None

    diff_cols = [DIFF_SHORT[d] for d in DIFFICULTIES]
    headers = ["Condition"] + diff_cols + ["\u0394 Ref\u2192D5"]

    rows = []
    caption_parts = []
    fp_lines = ["_False positive rate on fixed binaries_\n"]

    def _format(condition_label, cond):
        buckets = cond.get("buckets", {})
        row = {"Condition": condition_label}
        for diff, col in zip(DIFFICULTIES, diff_cols):
            b = buckets.get(diff, {})
            h1 = b.get("hit_at_1_pct")
            h5 = b.get("hit_at_5_pct")
            if h1 is None and h5 is None:
                row[col] = "-"
            else:
                h1s = f"{h1:.0f}" if h1 is not None else "-"
                h5s = f"{h5:.0f}" if h5 is not None else "-"
                row[col] = f"{h1s}/{h5s}"
        delta = cond.get("delta_ref_to_d5_pp")
        row["\u0394 Ref\u2192D5"] = (
            f"{delta:+.1f}" if delta is not None else "-")
        return row

    if "solo_best" in conditions:
        cond = conditions["solo_best"]
        agent = cond.get("agent_model", "?")
        label = f"Solo: {MODEL_DISPLAY.get(agent, agent)}"
        rows.append(_format(label, cond))
        caption_parts.append(f"Solo baseline = {MODEL_DISPLAY.get(agent, agent)}")
        for diff in DIFFICULTIES:
            b = cond.get("buckets", {}).get(diff, {})
            fp = b.get("fp_rate_pct")
            fp_n = b.get("fp_n", 0)
            if fp is not None and fp_n:
                fp_lines.append(
                    f"- {label} / {DIFF_SHORT[diff]}: "
                    f"{fp:.1f}% (n={fp_n})")

    if "guided_best" in conditions:
        cond = conditions["guided_best"]
        strat = cond.get("strategy_model", "?")
        agent = cond.get("agent_model", "?")
        label = (f"{MODEL_DISPLAY.get(strat, strat)} \u2192 "
                 f"{MODEL_DISPLAY.get(agent, agent)}")
        rows.append(_format(label, cond))
        caption_parts.append(f"Best guided = {label}")
        for diff in DIFFICULTIES:
            b = cond.get("buckets", {}).get(diff, {})
            fp = b.get("fp_rate_pct")
            fp_n = b.get("fp_n", 0)
            if fp is not None and fp_n:
                fp_lines.append(
                    f"- {label} / {DIFF_SHORT[diff]}: "
                    f"{fp:.1f}% (n={fp_n})")

    caption = "; ".join(caption_parts) if caption_parts else None
    fp_footer = "\n".join(fp_lines) if len(fp_lines) > 1 else None
    return rows, headers, caption, fp_footer


def _load_cwe_for_cve(cve_id):
    path = os.path.join(_paths.DATASET_DIR, f"{cve_id}.json")
    if not os.path.exists(path):
        return None
    try:
        data = json.load(open(path))
    except (json.JSONDecodeError, OSError):
        return None
    containers = data.get("containers", {})
    sources = [containers.get("cna", {})]
    for adp in containers.get("adp", []):
        sources.append(adp)
    for src in sources:
        for pt in src.get("problemTypes", []):
            for d in pt.get("descriptions", []):
                if d.get("cweId"):
                    return d["cweId"]
    return None


def generate_table6():
    if not os.path.exists(SELECTED_PATH):
        return [], []

    selected = json.load(open(SELECTED_PATH))
    gt = load_ground_truth()

    cve_count = len(selected)
    packages = set()
    cwe_cats = set()
    total_variants = 0
    fixed_count = 0
    affected_count = 0
    versions_per_cve = []
    binary_func_counts = []
    per_difficulty = defaultdict(int)
    per_difficulty["reference"] = cve_count

    for entry in selected:
        cve_id = entry["cve_id"]
        packages.add(entry.get("package", ""))
        variants = entry.get("variants", [])
        total_variants += len(variants)
        for v in variants:
            if v.get("has_vulnerability"):
                affected_count += 1
                diff = v.get("difficulty")
                if diff:
                    per_difficulty[diff] += 1
            else:
                fixed_count += 1

        versions = {entry.get("reference", {}).get("version", "")}
        for v in variants:
            versions.add(v.get("version", ""))
        versions.discard("")
        versions_per_cve.append(len(versions))

        cwe = _load_cwe_for_cve(cve_id)
        if cwe:
            cwe_cats.add(cwe)

        gt_bins = gt.get(cve_id, {}).get("binaries", {})
        for b in gt_bins.values():
            n = b.get("function_count")
            if isinstance(n, int) and n > 0:
                binary_func_counts.append(n)

    avg_versions = (sum(versions_per_cve) / len(versions_per_cve)
                    if versions_per_cve else 0)
    avg_funcs_per_bin = (sum(binary_func_counts) / len(binary_func_counts)
                         if binary_func_counts else None)

    affected_count += cve_count

    rows = [
        {"Measurement": "CVEs", "Value": str(cve_count)},
        {"Measurement": "Open-source libraries", "Value": str(len(packages))},
        {"Measurement": "CWE categories",
         "Value": str(len(cwe_cats)) if cwe_cats else "-"},
        {"Measurement": "Versions per CVE (avg)",
         "Value": f"{avg_versions:.1f}"},
        {"Measurement": "Compilers",
         "Value": "GCC, Clang, MSVC (vc140-vc143)"},
        {"Measurement": "Optimization levels",
         "Value": "O0-O3 (Linux), Od/O1/O2 (Windows)"},
        {"Measurement": "Platforms", "Value": "Linux, Windows"},
        {"Measurement": "Affected binaries",
         "Value": str(affected_count)},
        {"Measurement": "Fixed (patched) binaries",
         "Value": str(fixed_count)},
        {"Measurement": "Total variant binaries",
         "Value": str(total_variants)},
        {"Measurement": "Avg functions per binary",
         "Value": f"{avg_funcs_per_bin:.0f}"
                  if avg_funcs_per_bin is not None else "-"},
    ]

    for diff in DIFFICULTIES:
        count = per_difficulty.get(diff, 0)
        rows.append({
            "Measurement": f"(CVE, binary) pairs -- {DIFF_SHORT[diff]}",
            "Value": str(count),
        })

    return rows, ["Measurement", "Value"]


def compute_fp(scored, group_keys):
    """Aggregate FP rate grouped by a tuple of keys (e.g. ('agent_model',))."""
    out = defaultdict(lambda: {"fp": 0, "total": 0})
    for s in scored:
        if s.get("has_vulnerability"):
            continue
        key = tuple(s.get(k, "") for k in group_keys)
        if not all(key):
            continue
        out[key]["total"] += 1
        if s.get("false_positive"):
            out[key]["fp"] += 1
    return {
        k: {"fp": v["fp"], "total": v["total"],
            "rate": (v["fp"] / v["total"] * 100) if v["total"] else None}
        for k, v in out.items()
    }


def write_table(rows, headers, name, footer_text=None):
    """Write a table as CSV + Markdown."""
    os.makedirs(TABLES_DIR, exist_ok=True)

    with open(os.path.join(TABLES_DIR, f"{name}.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=headers)
        w.writeheader()
        for row in rows:
            w.writerow(row)

    with open(os.path.join(TABLES_DIR, f"{name}.md"), "w") as f:
        f.write("| " + " | ".join(headers) + " |\n")
        f.write("| " + " | ".join("---" for _ in headers) + " |\n")
        for row in rows:
            f.write("| " + " | ".join(
                str(row.get(h, "")) for h in headers) + " |\n")
        if footer_text:
            f.write("\n" + footer_text.rstrip() + "\n")


def main():
    gt = load_ground_truth()
    results = load_results()
    log(f"Loaded {len(results)} results, {len(gt)} ground truth entries")

    if not results:
        log("No results to score.")
        return

    recognition_results = [r for r in results if r.get("task") == "recognition"]
    hunting_results = [r for r in results if r.get("task") == "hunting"]

    recog_counts = defaultdict(int)
    for r in recognition_results:
        rep, cond_short = _canonical_recog_cond(r)
        if rep and cond_short:
            recog_counts[f"{rep}_{cond_short}"] += 1
    log(f"  Recognition: {len(recognition_results)} "
        + "(" + ", ".join(f"{k}={v}" for k, v in sorted(recog_counts.items()))
        + ")")
    log(f"  Hunting: {len(hunting_results)} "
        f"(solo={sum(1 for r in hunting_results if r.get('phase') == 'solo')}, "
        f"guided={sum(1 for r in hunting_results if r.get('phase') == 'guided')})")

    if recognition_results:
        rows, headers = generate_table1(recognition_results)
        write_table(rows, headers, "table1_recognition")
        log(f"Table 1 written to {TABLES_DIR}/table1_recognition.*")
        delta_key = "\u0394 decomp (with-desc)"
        for row in rows:
            log(f"  {row['Model']}: "
                f"src_z={row['Source zero-shot']}  "
                f"src_d={row['Source with-desc']}  "
                f"bin_z={row['Binary zero-shot']}  "
                f"bin_d={row['Binary with-desc']}  "
                f"\u0394decomp={row[delta_key]}")

    scored_solo = []
    scored_guided = []
    for r in hunting_results:
        s = score_hunting(r, gt)
        if not s:
            continue
        s["agent_model"] = r.get("agent_model", "")
        s["strategy_model"] = r.get("strategy_model")
        s["difficulty"] = r.get("difficulty")
        s["phase"] = r.get("phase", "")
        if s["phase"] == "solo":
            scored_solo.append(s)
        elif s["phase"] == "guided":
            scored_guided.append(s)

    strategy_set = sorted({
        s.get("strategy_model") for s in scored_guided
        if s.get("strategy_model")})
    strategies = ([s for s in FRONTIER_STRATEGIES if s in strategy_set]
                  + [s for s in BASE_STRATEGIES if s in strategy_set])
    if not strategies:
        strategies = FRONTIER_STRATEGIES

    fp_solo = compute_fp(scored_solo, ("agent_model",))
    if scored_solo:
        rows, headers = generate_table2(scored_solo)
        fp_lines = ["_False positive rate on fixed binaries_\n"]
        for agent in BASE_AGENTS:
            stats = fp_solo.get((agent,))
            if stats and stats["total"]:
                fp_lines.append(
                    f"- {MODEL_DISPLAY.get(agent, agent)}: "
                    f"{stats['rate']:.1f}% ({stats['fp']}/{stats['total']})")
        footer = "\n".join(fp_lines) if len(fp_lines) > 1 else None
        write_table(rows, headers, "table2_solo_baseline", footer_text=footer)
        log(f"Table 2 written to {TABLES_DIR}/table2_solo_baseline.*")

    fp_guided = compute_fp(scored_guided, ("strategy_model", "agent_model"))
    if scored_guided:
        rows, headers = generate_table3(scored_guided, strategies)
        fp_lines = ["_False positive rate on fixed binaries (strategy -> agent)_\n"]
        for strat in strategies:
            for agent in BASE_AGENTS:
                stats = fp_guided.get((strat, agent))
                if stats and stats["total"]:
                    fp_lines.append(
                        f"- {MODEL_DISPLAY.get(strat, strat)} \u2192 "
                        f"{MODEL_DISPLAY.get(agent, agent)}: "
                        f"{stats['rate']:.1f}% ({stats['fp']}/{stats['total']})")
        footer = "\n".join(fp_lines) if len(fp_lines) > 1 else None
        write_table(rows, headers, "table3_strategy_guided", footer_text=footer)
        log(f"Table 3 written to {TABLES_DIR}/table3_strategy_guided.*")

    if scored_solo and scored_guided:
        rows, headers = generate_table4(scored_solo, scored_guided, strategies)
        write_table(rows, headers, "table4_uplift")
        log(f"Table 4 written to {TABLES_DIR}/table4_uplift.*")

    t5 = generate_table5()
    if t5[0] is not None:
        rows, headers, caption, fp_footer = t5
        footer_parts = []
        if caption:
            footer_parts.append(f"_{caption}_")
        if fp_footer:
            footer_parts.append(fp_footer)
        footer = "\n\n".join(footer_parts) if footer_parts else None
        write_table(rows, headers, "table5_cross_build", footer_text=footer)
        log(f"Table 5 written to {TABLES_DIR}/table5_cross_build.*")
    else:
        log("Table 5 skipped: eval3_transfer.json not found. "
            "Run eval3_transfer.py first.")

    rows, headers = generate_table6()
    if rows:
        write_table(rows, headers, "table6_dataset_stats")
        log(f"Table 6 written to {TABLES_DIR}/table6_dataset_stats.*")

    summary = {
        "total_results": len(results),
        "recognition_count": len(recognition_results),
        "hunting_count": len(hunting_results),
    }

    if recognition_results:
        by_cond = defaultdict(lambda: {"correct": 0, "total": 0})
        for r in recognition_results:
            rep, cond_short = _canonical_recog_cond(r)
            if not rep or not cond_short:
                continue
            key = f"{rep}_{cond_short}"
            by_cond[key]["total"] += 1
            if r.get("correct"):
                by_cond[key]["correct"] += 1
        summary["recognition_accuracy"] = {
            cond: round(v["correct"] / v["total"] * 100, 1)
            for cond, v in by_cond.items() if v["total"]
        }

    solo_h1, solo_h5, solo_n = _hit_rates(scored_solo)
    if solo_h1 is not None:
        summary["solo_hit1"] = round(solo_h1, 1)
        summary["solo_hit5"] = round(solo_h5, 1)
        summary["solo_n"] = solo_n

    guided_h1, guided_h5, guided_n = _hit_rates(scored_guided)
    if guided_h1 is not None:
        summary["guided_hit1"] = round(guided_h1, 1)
        summary["guided_hit5"] = round(guided_h5, 1)
        summary["guided_n"] = guided_n

    if fp_solo:
        summary["solo_fp_rate"] = {
            k[0]: {"rate": round(v["rate"], 1) if v["rate"] is not None else None,
                   "fp": v["fp"], "total": v["total"]}
            for k, v in fp_solo.items()
        }
    if fp_guided:
        summary["guided_fp_rate"] = {
            f"{k[0]}__{k[1]}":
                {"rate": round(v["rate"], 1) if v["rate"] is not None else None,
                 "fp": v["fp"], "total": v["total"]}
            for k, v in fp_guided.items()
        }

    os.makedirs(TABLES_DIR, exist_ok=True)
    with open(os.path.join(TABLES_DIR, "summary.json"), "w") as f:
        json.dump(summary, f, indent=2)
    log(f"\nSummary written to {TABLES_DIR}/summary.json")


if __name__ == "__main__":
    main()
