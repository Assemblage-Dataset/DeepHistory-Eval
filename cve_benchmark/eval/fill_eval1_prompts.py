"""Eval 1 prompt filler -- reads directly from `_prepare_shards/`."""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _paths  # noqa: E402

SHARD_DIR = _paths.SHARD_DIR
DECOYS_JSON = _paths.DECOYS_JSON
PROMPTS_DIR = _paths.PROMPTS_DIR
FILLED_DIR = _paths.FILLED_DIR
PATCH_DIR = _paths.PATCH_DIR
CVE_JSON_DIR = _paths.DATASET_DIR

SHARD_SCHEMA_VERSION = 4

PLATFORMS = ("linux", "windows")


def log(msg):
    print(msg, flush=True)


def _valid_shard(path):
    """Return the shard dict if valid (schema match, no error), else None."""
    try:
        data = json.load(open(path))
    except Exception:
        return None
    if "error" in data:
        return None
    if data.get("schema") != SHARD_SCHEMA_VERSION:
        return None
    return data


def _read_description(cve_id):
    """Extract description line from the CVE's YAML, or empty string."""
    yaml_path = os.path.join(PATCH_DIR, f"{cve_id}.yaml")
    if not os.path.exists(yaml_path):
        return ""
    for line in open(yaml_path):
        if line.startswith("description:"):
            return line.split(":", 1)[1].strip().strip('"')
    return ""


def extract_hunks(patch_content):
    """Extract code_changes hunks from patch YAML content."""
    code_changes = []
    lines = patch_content.split("\n")
    i = 0
    cf = cfn = ca = ""
    while i < len(lines):
        s = lines[i].strip()
        if s.startswith("- commit:"):
            pass
        elif s.startswith("file:"):
            cf = s.split(":", 1)[1].strip().strip('"')
        elif s.startswith("function:"):
            cfn = s.split(":", 1)[1].strip().strip('"')
        elif s.startswith("fix_function:"):
            cfn = s.split(":", 1)[1].strip().strip('"')
        elif s.startswith("affected_function:"):
            ca = s.split(":", 1)[1].strip().strip('"')
        elif s == "hunks: |":
            hl = []
            i += 1
            while i < len(lines):
                line = lines[i]
                if line.startswith("      ") or line.strip() == "":
                    hl.append(line.rstrip())
                elif line.startswith("    ") and line.strip()[:1] in "@+-":
                    hl.append(line.rstrip())
                else:
                    break
                i += 1
            if hl:
                mi = min((len(l) - len(l.lstrip()) for l in hl if l.strip()),
                        default=0)
                cleaned = "\n".join(l[mi:] for l in hl)
                header = f"--- {cf} :: {cfn}"
                if ca and ca != cfn:
                    header += f" (affects: {ca})"
                code_changes.append(f"{header}\n{cleaned}")
            continue
        i += 1
    return "\n\n".join(code_changes) if code_changes else "(no code diff available)"


def extract_cwe(cve_id):
    """Extract (cwe_id, cwe_name) from the CVE JSON, or ('N/A', 'N/A')."""
    path = os.path.join(CVE_JSON_DIR, f"{cve_id}.json")
    if not os.path.exists(path):
        return "N/A", "N/A"
    try:
        data = json.load(open(path))
    except Exception:
        return "N/A", "N/A"
    containers = data.get("containers", {})
    sources = [containers.get("cna", {})]
    for adp in containers.get("adp", []):
        sources.append(adp)
    for src in sources:
        for pt in src.get("problemTypes", []):
            for d in pt.get("descriptions", []):
                if d.get("cweId"):
                    return d["cweId"], d.get("description", "N/A")
    return "N/A", "N/A"


def build_functions_text(decoy_entry):
    """Decompiled-function block shared by the two binary templates."""
    vulnerable = decoy_entry["vulnerable"]
    decoys = decoy_entry["decoys"]
    label_order = decoy_entry["label_order"]
    gt_label = decoy_entry["ground_truth_label"]
    decompiled = decoy_entry["decompiled"]
    stripped_names = decoy_entry["stripped_names"]

    all_funcs = [vulnerable] + decoys
    ordered = [all_funcs[idx] for idx in label_order]

    parts = []
    for i, func_name in enumerate(ordered):
        label = i
        decomp = decompiled.get(func_name, "(decompilation not available)")
        sname = stripped_names.get(func_name)
        if sname:
            decomp = decomp.replace(sname, f"Function_{label}")
        line_count = len(decomp.split("\n"))
        parts.append(
            f"**Function {label}** ({line_count} lines)\n"
            f"```c\n{decomp}\n```\n"
        )
    return "\n".join(parts), gt_label


def build_source_functions_text(decoy_entry):
    """Source-code function block for Eval 1 source conditions."""
    vulnerable = decoy_entry["vulnerable"]
    decoys = decoy_entry["decoys"]
    label_order = decoy_entry["label_order"]
    gt_label = decoy_entry["ground_truth_label"]
    snippets = decoy_entry.get("source_snippets", {})

    all_funcs = [vulnerable] + decoys
    ordered = [all_funcs[idx] for idx in label_order]

    parts = []
    for i, func_name in enumerate(ordered):
        label = i
        src = snippets.get(func_name)
        if not src:
            src = "(source not available for this function)"
        else:
            pattern = re.compile(r"\b" + re.escape(func_name) + r"\b")
            src = pattern.sub(f"Function_{label}", src)
        line_count = len(src.split("\n"))
        parts.append(
            f"**Function {label}** ({line_count} lines)\n"
            f"```c\n{src}\n```\n"
        )
    return "\n".join(parts), gt_label

def fill_one_cve(shard, templates, overwrite=False, decoys_override=None):
    """Emit all available Eval 1 files for one CVE's shard."""
    counts = {"binary_zero": 0, "binary_desc": 0,
              "source_zero": 0, "source_desc": 0,
              "skipped_no_platform": 0, "skipped_no_decomp": 0,
              "skipped_no_source": 0}

    cve_id = shard["cve_id"]
    decoys = decoys_override if decoys_override is not None else (shard.get("decoys") or {})
    if not decoys:
        return counts

    cve_dir = os.path.join(FILLED_DIR, cve_id)
    os.makedirs(cve_dir, exist_ok=True)

    description = _read_description(cve_id)
    cwe_id, cwe_name = extract_cwe(cve_id)
    yaml_path = os.path.join(PATCH_DIR, f"{cve_id}.yaml")
    patch_diff = extract_hunks(open(yaml_path).read()) if os.path.exists(yaml_path) else ""

    zero_tmpl = templates["zero"]
    desc_tmpl = templates["desc"]
    src_zero_tmpl = templates["src_zero"]
    src_desc_tmpl = templates["src_desc"]

    for bpath, entry in decoys.items():
        plat = entry.get("platform")
        if plat not in PLATFORMS:
            counts["skipped_no_platform"] += 1
            continue
        if "decompiled" not in entry:
            counts["skipped_no_decomp"] += 1
            continue

        functions_text, _ = build_functions_text(entry)

        zero_path = os.path.join(cve_dir, f"00_zeroshot_cve_{plat}.txt")
        if overwrite or not os.path.exists(zero_path):
            open(zero_path, "w").write(
                zero_tmpl.replace("{functions_text}", functions_text))
        counts["binary_zero"] += 1

        desc_path = os.path.join(cve_dir, f"01_withdesc_cve_{plat}.txt")
        if overwrite or not os.path.exists(desc_path):
            content = (desc_tmpl
                       .replace("{cve_id}", cve_id)
                       .replace("{cwe_id}", cwe_id)
                       .replace("{cwe_name}", cwe_name)
                       .replace("{cve_description}",
                                description or "(no description available)")
                       .replace("{patch_diff}", patch_diff)
                       .replace("{functions_text}", functions_text))
            open(desc_path, "w").write(content)
        counts["binary_desc"] += 1

        snippets = entry.get("source_snippets") or {}
        vuln = entry.get("vulnerable")
        if not (vuln and snippets.get(vuln)):
            counts["skipped_no_source"] += 1
            continue

        src_functions_text, _ = build_source_functions_text(entry)

        src_zero_path = os.path.join(cve_dir, f"02_source_zeroshot_{plat}.txt")
        if overwrite or not os.path.exists(src_zero_path):
            open(src_zero_path, "w").write(
                src_zero_tmpl.replace("{functions_text}", src_functions_text))
        counts["source_zero"] += 1

        src_desc_path = os.path.join(cve_dir, f"03_source_withdesc_{plat}.txt")
        if overwrite or not os.path.exists(src_desc_path):
            content = (src_desc_tmpl
                       .replace("{cve_id}", cve_id)
                       .replace("{cwe_id}", cwe_id)
                       .replace("{cwe_name}", cwe_name)
                       .replace("{cve_description}",
                                description or "(no description available)")
                       .replace("{patch_diff}", patch_diff)
                       .replace("{functions_text}", src_functions_text))
            open(src_desc_path, "w").write(content)
        counts["source_desc"] += 1

    return counts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--overwrite", action="store_true",
                    help="Overwrite existing per-OS prompt files "
                         "(default: skip when present).")
    ap.add_argument("--cves", nargs="+",
                    help="Restrict to these CVE IDs.")
    ap.add_argument("--max-cves", type=int,
                    help="Process only the first N shards (alphabetical).")
    args = ap.parse_args()

    templates = {
        "zero":     open(os.path.join(PROMPTS_DIR, "00_zeroshot_cve.md")).read(),
        "desc":     open(os.path.join(PROMPTS_DIR, "01_withdesc_cve.md")).read(),
        "src_zero": open(os.path.join(PROMPTS_DIR, "02_source_zeroshot.md")).read(),
        "src_desc": open(os.path.join(PROMPTS_DIR, "03_source_withdesc.md")).read(),
    }

    shard_paths = sorted(glob.glob(os.path.join(SHARD_DIR, "*.json")))
    if args.cves:
        want = set(args.cves)
        shard_paths = [p for p in shard_paths
                       if os.path.basename(p)[:-5] in want]
    if args.max_cves:
        shard_paths = shard_paths[:args.max_cves]

    decoys_override_map = {}
    if os.path.exists(DECOYS_JSON):
        decoys_override_map = json.load(open(DECOYS_JSON))
        log(f"Overlay decoys.json loaded: {len(decoys_override_map)} CVEs")

    log(f"Scanning {len(shard_paths)} shards in {SHARD_DIR}")
    totals = {"binary_zero": 0, "binary_desc": 0,
              "source_zero": 0, "source_desc": 0,
              "skipped_no_platform": 0, "skipped_no_decomp": 0,
              "skipped_no_source": 0,
              "cves_done": 0, "cves_no_decoys": 0, "cves_invalid": 0}
    os.makedirs(FILLED_DIR, exist_ok=True)

    for i, sp in enumerate(shard_paths):
        shard = _valid_shard(sp)
        if shard is None:
            totals["cves_invalid"] += 1
            continue
        cve_id = shard.get("cve_id")
        override = decoys_override_map.get(cve_id) if cve_id else None
        effective = override if override is not None else (shard.get("decoys") or {})
        if not effective:
            totals["cves_no_decoys"] += 1
            continue
        counts = fill_one_cve(shard, templates, overwrite=args.overwrite,
                              decoys_override=override)
        for k, v in counts.items():
            totals[k] = totals.get(k, 0) + v
        totals["cves_done"] += 1
        if (i + 1) % 50 == 0 or i == 0:
            log(f"  [{i+1}/{len(shard_paths)}] "
                f"bin_z={totals['binary_zero']} "
                f"bin_d={totals['binary_desc']} "
                f"src_z={totals['source_zero']} "
                f"src_d={totals['source_desc']}")

    log("")
    log(f"Done. CVEs processed: {totals['cves_done']} "
        f"(no decoys: {totals['cves_no_decoys']}, "
        f"invalid shards: {totals['cves_invalid']})")
    log(f"  binary_zeroshot:  {totals['binary_zero']}")
    log(f"  binary_with_desc: {totals['binary_desc']}")
    log(f"  source_zeroshot:  {totals['source_zero']}")
    log(f"  source_with_desc: {totals['source_desc']}")
    log(f"  (skipped: no-platform={totals['skipped_no_platform']}, "
        f"no-decomp={totals['skipped_no_decomp']}, "
        f"no-source={totals['skipped_no_source']})")
    log(f"Output under: {FILLED_DIR}")


if __name__ == "__main__":
    main()
