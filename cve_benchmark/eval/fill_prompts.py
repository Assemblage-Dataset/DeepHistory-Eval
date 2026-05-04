"""B1: Fill prompt templates + generate Eval 1 recognition prompts."""

import json
import multiprocessing as mp
import os
import random
import re
import shutil
import sys
import tempfile
import traceback

import yaml

_PKG_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _PKG_DIR)
import _paths  # noqa: E402

import binaryapi as _bapi  # noqa: E402
_bapi._CACHE_DIR = os.path.expanduser("~/.cache/binaryapi_debug")

from binaryapi import BinaryAPI  # noqa: E402

sys.path.insert(0, os.path.join(_PKG_DIR, "data"))
import query  # noqa: E402

PROMPTS_DIR = _paths.PROMPTS_DIR
SELECTED = _paths.SELECTED_JSON
DECOYS_PATH = _paths.DECOYS_JSON
FILLED_DIR = _paths.FILLED_DIR
DH_DIR = _paths.BINARY_BASE_DIR
PATCH_DIR = _paths.PATCH_DIR
DATASET_DIR = _paths.DATASET_DIR

RANDOM_SEED = 0xDEEF
random.seed(RANDOM_SEED)


def log(msg):
    print(msg, flush=True)


def get_pdb_paths(binary_id):
    """Return list of existing PDB file paths for a binary."""
    return query.get_pdb_paths(binary_id)


def load_with_debug(binary_path, binary_id):
    """Load binary via BinaryAPI with PDB debug symbols."""
    pdb_paths = get_pdb_paths(binary_id)
    tmpdir = tempfile.mkdtemp(prefix="bapi_dbg_")
    try:
        bin_name = os.path.basename(binary_path)
        tmp_bin = os.path.join(tmpdir, bin_name)
        os.symlink(os.path.abspath(binary_path), tmp_bin)

        for pdb_path in pdb_paths:
            pdb_name = os.path.basename(pdb_path)
            original = pdb_name.split("_", 1)[1] if "_" in pdb_name else pdb_name
            tmp_pdb = os.path.join(tmpdir, original)
            if not os.path.exists(tmp_pdb):
                os.symlink(os.path.abspath(pdb_path), tmp_pdb)

        api = BinaryAPI(tmp_bin)
        return api
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def get_function_strings(api, func_name):
    """Get strings referenced by a specific function."""
    result = []
    for text, funcs in api._string_refs.items():
        if func_name in funcs:
            result.append(text)
    return sorted(result)


def resolve_function_name(api, func_name):
    """Resolve a source function name to what Ghidra actually has."""
    if func_name in api._functions:
        return func_name
    if "::" in func_name:
        short = func_name.rsplit("::", 1)[1]
        if short in api._functions:
            return short
    return None


def format_function_analysis(api, func_name, build_label):
    """Format binary analysis for one function (decompiled + assembly + callees + strings)."""
    resolved = resolve_function_name(api, func_name)
    if resolved is None:
        return None
    func_name = resolved

    parts = [f"#### {build_label}\n"]

    decomp = api.decompile(func_name)
    parts.append("**Decompiled C:**")
    parts.append(f"```c\n{decomp}\n```\n")

    try:
        asm = api.get_assembly(func_name)
    except Exception:
        asm = ""
    if asm and not asm.startswith("; Assembly unavailable"):
        parts.append("**Disassembly:**")
        parts.append(f"```asm\n{asm}\n```\n")

    callees = api.get_callees(func_name)
    imports = sorted(c for c in callees if c in api._import_set)
    internals = sorted(c for c in callees if c not in api._import_set)
    if imports:
        parts.append(f"**Import calls:** {', '.join(imports)}")
    if internals:
        parts.append(f"**Internal calls:** {', '.join(internals)}")

    callers = api.get_callers(func_name)
    if callers:
        parts.append(f"**Called by:** {', '.join(callers[:15])}")

    strings = get_function_strings(api, func_name)
    if strings:
        displayed = []
        for s in strings[:10]:
            s_esc = s.replace('"', '\\"')
            displayed.append(f'"{s_esc[:80]}"' if len(s) <= 80 else f'"{s_esc[:77]}..."')
        parts.append(f"**Referenced strings:** {', '.join(displayed)}")

    return "\n".join(parts)


def format_build_analysis(api, bin_info, affected_fns, label_prefix):
    """Format analysis for all affected functions on a single binary."""
    sections = []
    build_label = (
        f"{bin_info.get('file_name', '?')} "
        f"({bin_info.get('build_key', '?')}, v{bin_info.get('version', '?')})"
    )

    for fn in affected_fns:
        sections.append(f"### Function: `{fn}` -- {label_prefix}\n")
        if api is None:
            sections.append(f"({label_prefix} binary failed to load)\n")
            continue
        analysis = format_function_analysis(api, fn, build_label)
        if analysis:
            sections.append(analysis)
        else:
            partial = [f["name"] for f in api.list_functions()
                       if fn.lower() in f["name"].lower()][:5]
            hint = f"  Partial matches: {partial}" if partial else ""
            sections.append(
                f"(function `{fn}` not found in {label_prefix} binary){hint}\n")

    return "\n".join(sections) if sections else f"(no {label_prefix} analysis available)"


def _as_bin_info(entry):
    """Normalise a reference or sample_variant dict to the keys used by format_build_analysis."""
    if not entry:
        return None
    return {
        "binary_id": entry.get("binary_id"),
        "full_path": entry.get("full_path", ""),
        "file_name": entry.get("file_name", ""),
        "build_key": entry.get("build_key", ""),
        "version": entry.get("version", ""),
    }


def build_functions_text(decoy_entry):
    """Assemble the decompiled-function block shared by both binary recognition templates."""
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


_IDENT_RE = re.compile(r"\b{name}\b")


def build_source_functions_text(decoy_entry):
    """Assemble the source-code function block for Eval 1 source conditions."""
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


def _read_cve_meta(cve_id, entry, patch_diff):
    """Gather CVE metadata used by the with_desc recognition prompt."""
    patch_path = os.path.join(_paths.ROOT, entry["yaml_path"])
    description = ""
    if os.path.exists(patch_path):
        with open(patch_path) as fh:
            description = (yaml.safe_load(fh) or {}).get("description", "") or ""
    cve_json_path = os.path.join(DATASET_DIR, f"{cve_id}.json")
    cwe_id, cwe_name = extract_cwe(cve_json_path)
    return {
        "cve_id": cve_id,
        "cve_description": description or "(no description available)",
        "cwe_id": cwe_id,
        "cwe_name": cwe_name,
        "patch_diff": patch_diff,
    }


def fill_recognition_prompts(selected, decoys_data):
    """Generate Eval 1 recognition prompts for every OS representative."""
    log("\n=== Generating recognition prompts (per-OS reps) ===")
    total_zero = 0
    total_desc = 0
    total_src_zero = 0
    total_src_desc = 0
    skipped = 0
    skipped_source = 0

    zero_tmpl = open(os.path.join(PROMPTS_DIR, "00_zeroshot_cve.md")).read()
    desc_tmpl = open(os.path.join(PROMPTS_DIR, "01_withdesc_cve.md")).read()
    src_zero_tmpl = open(os.path.join(PROMPTS_DIR, "02_source_zeroshot.md")).read()
    src_desc_tmpl = open(os.path.join(PROMPTS_DIR, "03_source_withdesc.md")).read()

    for i, entry in enumerate(selected):
        cve_id = entry["cve_id"]
        if cve_id not in decoys_data:
            continue

        cve_decoys = decoys_data[cve_id]
        cve_dir = os.path.join(FILLED_DIR, cve_id)
        os.makedirs(cve_dir, exist_ok=True)

        patch_path = os.path.join(_paths.ROOT, entry["yaml_path"])
        patch_content = open(patch_path).read() if os.path.exists(patch_path) else ""
        patch_diff = extract_hunks(patch_content) if patch_content else ""
        cve_meta = _read_cve_meta(cve_id, entry, patch_diff)

        cve_has_any = False
        for bpath, decoy_entry in cve_decoys.items():
            plat = decoy_entry.get("platform")
            if plat not in ("linux", "windows"):
                continue
            if "decompiled" not in decoy_entry:
                log(f"  WARN {cve_id}/{plat}: decoy entry missing 'decompiled'")
                continue
            cve_has_any = True

            functions_text, _gt = build_functions_text(decoy_entry)

            zero_path = os.path.join(cve_dir, f"00_zeroshot_cve_{plat}.txt")
            if not os.path.exists(zero_path):
                content = zero_tmpl.replace("{functions_text}", functions_text)
                with open(zero_path, "w") as f:
                    f.write(content)
            total_zero += 1

            desc_path = os.path.join(cve_dir, f"01_withdesc_cve_{plat}.txt")
            if not os.path.exists(desc_path):
                content = desc_tmpl
                content = content.replace("{cve_id}", cve_meta["cve_id"])
                content = content.replace("{cwe_id}", cve_meta["cwe_id"])
                content = content.replace("{cwe_name}", cve_meta["cwe_name"])
                content = content.replace(
                    "{cve_description}", cve_meta["cve_description"])
                content = content.replace("{patch_diff}", cve_meta["patch_diff"])
                content = content.replace("{functions_text}", functions_text)
                with open(desc_path, "w") as f:
                    f.write(content)
            total_desc += 1

            source_snippets = decoy_entry.get("source_snippets") or {}
            vuln_name = decoy_entry.get("vulnerable")
            if vuln_name and source_snippets.get(vuln_name):
                src_functions_text, _ = build_source_functions_text(decoy_entry)

                src_zero_path = os.path.join(
                    cve_dir, f"02_source_zeroshot_{plat}.txt")
                if not os.path.exists(src_zero_path):
                    content = src_zero_tmpl.replace(
                        "{functions_text}", src_functions_text)
                    with open(src_zero_path, "w") as f:
                        f.write(content)
                total_src_zero += 1

                src_desc_path = os.path.join(
                    cve_dir, f"03_source_withdesc_{plat}.txt")
                if not os.path.exists(src_desc_path):
                    content = src_desc_tmpl
                    content = content.replace("{cve_id}", cve_meta["cve_id"])
                    content = content.replace("{cwe_id}", cve_meta["cwe_id"])
                    content = content.replace("{cwe_name}", cve_meta["cwe_name"])
                    content = content.replace(
                        "{cve_description}", cve_meta["cve_description"])
                    content = content.replace(
                        "{patch_diff}", cve_meta["patch_diff"])
                    content = content.replace(
                        "{functions_text}", src_functions_text)
                    with open(src_desc_path, "w") as f:
                        f.write(content)
                total_src_desc += 1
            else:
                skipped_source += 1

        if not cve_has_any:
            skipped += 1

        if (i + 1) % 20 == 0 or i == 0:
            log(f"  [{i+1}/{len(selected)}] {cve_id} "
                f"(bin_z={total_zero}, bin_d={total_desc}, "
                f"src_z={total_src_zero}, src_d={total_src_desc}, "
                f"skipped={skipped}, no_src={skipped_source})")

    log(f"  Recognition prompts: "
        f"binary_zeroshot={total_zero}, binary_with_desc={total_desc}, "
        f"source_zeroshot={total_src_zero}, source_with_desc={total_src_desc}, "
        f"skipped={skipped}, missing_source={skipped_source}")


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
                mi = min((len(l) - len(l.lstrip()) for l in hl if l.strip()), default=0)
                cleaned = "\n".join(l[mi:] for l in hl)
                header = f"--- {cf} :: {cfn}"
                if ca and ca != cfn:
                    header += f" (affects: {ca})"
                code_changes.append(f"{header}\n{cleaned}")
            continue
        i += 1
    return "\n\n".join(code_changes) if code_changes else "(no code diff available)"


def extract_cwe(cve_json_path):
    """Extract CWE ID and name from CVE JSON (checks CNA then ADP containers)."""
    if not os.path.exists(cve_json_path):
        return "N/A", "N/A"
    data = json.load(open(cve_json_path))
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


def fill_cve(entry, num_candidates=5):
    """Fill template-based prompts for one CVE."""
    cve_id = entry["cve_id"]

    patch_path = os.path.join(_paths.ROOT, entry["yaml_path"])
    patch_content = open(patch_path).read()

    desc = (yaml.safe_load(patch_content) or {}).get("description", "") or ""

    patch_diff = extract_hunks(patch_content)

    cve_json_path = os.path.join(DATASET_DIR, f"{cve_id}.json")
    cwe_id, cwe_name = extract_cwe(cve_json_path)

    ref = entry["reference"]
    ref_info = _as_bin_info(ref)
    ref_api = None
    try:
        ref_api = load_with_debug(ref["full_path"], ref["binary_id"])
    except Exception as e:
        log(f"    WARN: failed to load reference {ref['file_name']}: {e}")

    sv = entry.get("sample_variant")
    sv_info = _as_bin_info(sv)
    sv_api = None
    if sv and sv.get("full_path") and os.path.exists(sv["full_path"]):
        try:
            sv_api = load_with_debug(sv["full_path"], sv["binary_id"])
        except Exception as e:
            log(f"    WARN: failed to load sample_variant "
                f"{sv.get('file_name', '?')}: {e}")

    affected_fns = entry["affected_functions"]
    reference_analysis = format_build_analysis(
        ref_api, ref_info or {}, affected_fns, "reference")
    variant_analysis = (
        format_build_analysis(sv_api, sv_info or {}, affected_fns, "cross-build")
        if sv_info else "(no cross-build sample variant available for this CVE)"
    )

    api_doc = open(os.path.join(PROMPTS_DIR, "api_documentation.md")).read()

    placeholders = {
        "{cve_id}": cve_id,
        "{cve_description}": desc,
        "{cwe_id}": cwe_id,
        "{cwe_name}": cwe_name,
        "{patch_diff}": patch_diff,
        "{affected_binary}": ref["file_name"],
        "{affected_functions}": ", ".join(affected_fns),
        "{example_source_function}": affected_fns[0] if affected_fns else "?",
        "{reference_analysis}": reference_analysis,
        "{variant_analysis}": variant_analysis,
        "{reference_build_key}": (ref_info or {}).get("build_key", "?") or "?",
        "{variant_build_key}": (sv_info or {}).get("build_key", "n/a") or "n/a",
        "{api_documentation}": api_doc,
        "{num_candidates}": str(num_candidates),
    }

    output_dir = os.path.join(FILLED_DIR, cve_id)
    os.makedirs(output_dir, exist_ok=True)

    templates = [
        "10_strategy_gen.md",
        "20_agent_zeroshot.md",
        "21_agent_follow.md",
    ]

    for tmpl in templates:
        content = open(os.path.join(PROMPTS_DIR, tmpl)).read()
        for k, v in placeholders.items():
            content = content.replace(k, v)
        if tmpl == "21_agent_follow.md":
            out_name = "21_agent_follow_template.txt"
        else:
            out_name = tmpl.replace(".md", ".txt")
        out_path = os.path.join(output_dir, out_name)
        with open(out_path, "w") as f:
            f.write(content)

    return cve_id


def _subprocess_fill(cve_json_str, num_candidates):
    """Entry point for subprocess: fill one CVE, exit."""
    entry = json.loads(cve_json_str)
    import binaryapi as _b
    _b._CACHE_DIR = os.path.expanduser("~/.cache/binaryapi_debug")
    fill_cve(entry, num_candidates=num_candidates)


_PLACEHOLDER_RE = re.compile(
    r'\{(?:cve_id|cve_description|cwe_id|cwe_name|patch_diff|affected_binary'
    r'|affected_functions|example_source_function'
    r'|reference_analysis|variant_analysis'
    r'|reference_build_key|variant_build_key'
    r'|api_documentation|num_candidates)\}'
)


def _is_done(cve_id):
    """Check if a CVE already has all filled prompts (without unresolved placeholders)."""
    output_dir = os.path.join(FILLED_DIR, cve_id)
    expected = ["10_strategy_gen.txt",
                "20_agent_zeroshot.txt", "21_agent_follow_template.txt"]
    for name in expected:
        path = os.path.join(output_dir, name)
        if not os.path.exists(path):
            return False
        try:
            content = open(path).read()
        except OSError:
            return False
        if _PLACEHOLDER_RE.search(content):
            return False
    return True


def _run_with_timeout(entry, timeout, num_candidates):
    """Run fill_cve in a subprocess with hard kill on timeout."""
    import subprocess
    cve_id = entry["cve_id"]
    cmd = [
        sys.executable, "-c",
        "import json, sys; sys.path.insert(0, 'benchmark/eval'); "
        "from fill_prompts import _subprocess_fill; "
        f"_subprocess_fill(sys.stdin.read(), {num_candidates})"
    ]
    try:
        proc = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        _, stderr = proc.communicate(
            input=json.dumps(entry).encode(), timeout=timeout)
        if proc.returncode == 0:
            return (cve_id, True, None)
        else:
            return (cve_id, False, stderr.decode()[-500:])
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        return (cve_id, False, f"timeout after {timeout}s")


def main():
    import argparse
    import concurrent.futures
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-cves", type=int, default=None)
    parser.add_argument("--skip-recognition", action="store_true",
                        help="Skip per-binary recognition prompt generation")
    parser.add_argument("--num-candidates", type=int, default=5,
                        help="Value rendered into {num_candidates} placeholder")
    parser.add_argument("--workers", "-j", type=int, default=1,
                        help="Number of parallel workers (default: 1)")
    parser.add_argument("--timeout", type=int, default=180,
                        help="Per-CVE timeout in seconds (default: 180)")
    args = parser.parse_args()

    selected = json.load(open(SELECTED))
    if args.max_cves:
        selected = selected[:args.max_cves]

    todo = [e for e in selected if not _is_done(e["cve_id"])]
    done_count = len(selected) - len(todo)

    log(f"Filling prompts for {len(selected)} CVEs "
        f"(workers={args.workers}, timeout={args.timeout}s)...")
    log(f"  Already done: {done_count}, remaining: {len(todo)}")

    success = done_count
    failed = 0
    timed_out = 0

    if args.workers <= 1:
        for i, entry in enumerate(todo):
            cve_id, ok, err = _run_with_timeout(
                entry, args.timeout, args.num_candidates)
            if ok:
                success += 1
            else:
                if "timeout" in (err or ""):
                    timed_out += 1
                failed += 1
                log(f"  ERROR {cve_id}: {err}")
            if (i + 1) % 10 == 0 or i == 0:
                log(f"  [{success}/{len(selected)}] {cve_id}")
    else:
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=args.workers) as executor:
            futures = {
                executor.submit(
                    _run_with_timeout, entry,
                    args.timeout, args.num_candidates): entry["cve_id"]
                for entry in todo
            }
            for i, future in enumerate(
                    concurrent.futures.as_completed(futures)):
                cve_id = futures[future]
                try:
                    _, ok, err = future.result()
                except Exception as e:
                    ok, err = False, str(e)
                if ok:
                    success += 1
                else:
                    if "timeout" in (err or ""):
                        timed_out += 1
                    failed += 1
                    log(f"  ERROR {cve_id}: {err}")
                if (i + 1) % 10 == 0 or i == 0:
                    log(f"  [{success}/{len(selected)}] {cve_id} "
                        f"({success} ok, {failed} err, "
                        f"{timed_out} timeout)")

    log(f"\nTemplates: {success} succeeded, {failed} failed "
        f"({timed_out} timeouts).")

    if not args.skip_recognition and os.path.exists(DECOYS_PATH):
        decoys_data = json.load(open(DECOYS_PATH))
        fill_recognition_prompts(selected, decoys_data)
    elif not args.skip_recognition:
        log(f"\nSkipping recognition: {DECOYS_PATH} not found. "
            f"Run prepare.py first.")

    log(f"\nOutput: {FILLED_DIR}")


if __name__ == "__main__":
    main()
