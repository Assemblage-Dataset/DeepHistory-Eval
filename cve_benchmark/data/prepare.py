"""CVE selection + ground truth mapping + decoy selection for the benchmark."""

import csv
import hashlib
import json
import os
import random
import re
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _paths
import query

PATCH_DIR = _paths.PATCH_DIR
AB_DIR = _paths.AB_DIR
OUTPUT_SELECTED = _paths.SELECTED_JSON
OUTPUT_GT = _paths.GROUND_TRUTH_JSON
OUTPUT_DECOYS = _paths.DECOYS_JSON
STRIPPED_DIR = _paths.STRIPPED_DIR
SHARD_DIR = _paths.SHARD_DIR

SHARD_SCHEMA_VERSION = 4

RANDOM_SEED = 0xDEEF
random.seed(RANDOM_SEED)


def _version_sort_key(version_str):
    """Parse a version string into a tuple for descending sort."""
    if not version_str:
        return ((0,), "")
    nums = []
    suffix = ""
    m = re.match(r"^([0-9]+(?:\.[0-9]+)*)(.*)$", version_str.strip())
    if m:
        nums = tuple(int(x) for x in m.group(1).split("."))
        suffix = m.group(2)
    else:
        suffix = version_str.strip()
    return (tuple(nums) if nums else (0,), suffix)


def _parse_affected_diff_sizes(content):
    """Return {affected_function: added+removed line count} from patch YAML body."""
    sizes = {}
    entries = re.split(r'^  - commit:', content, flags=re.MULTILINE)[1:]
    for e in entries:
        m = re.search(r'^    affected_function: "([^"]+)"', e, re.MULTILINE)
        if not m:
            continue
        func = m.group(1)
        hi = e.find('    hunks: |')
        if hi == -1:
            continue
        hunks = e[hi + len('    hunks: |'):]
        count = 0
        for line in hunks.split("\n"):
            s = line.lstrip(" \t")
            if not s:
                continue
            c = s[0]
            if c == '+' and not s.startswith('+++'):
                count += 1
            elif c == '-' and not s.startswith('---'):
                count += 1
        sizes[func] = sizes.get(func, 0) + count
    return sizes


def parse_patch_yaml(path):
    """Extract fields from a patch YAML without a YAML parser (avoids special char issues)."""
    content = open(path).read()
    result = {"cve_id": "", "package": "", "description": "",
              "affected_functions": [], "has_code_changes": False,
              "diff_sizes": {}}

    for line in content.split("\n"):
        if line.startswith("cve_id:"):
            result["cve_id"] = line.split(":", 1)[1].strip().strip('"')
        elif line.startswith("package:"):
            result["package"] = line.split(":", 1)[1].strip().strip('"')
        elif line.startswith("description:"):
            result["description"] = line.split(":", 1)[1].strip().strip('"')

    for m in re.finditer(r'  - name: "([^"]+)"', content):
        result["affected_functions"].append(m.group(1))

    if "- commit:" in content and "code_changes: []" not in content:
        result["has_code_changes"] = True

    result["diff_sizes"] = _parse_affected_diff_sizes(content)
    result["affected_functions"].sort(
        key=lambda fn: -result["diff_sizes"].get(fn, 0))

    return result


def load_affected_binaries(cve_id):
    """Load affected_binaries CSV for a CVE."""
    path = os.path.join(AB_DIR, f"{cve_id}.csv")
    if not os.path.exists(path):
        return [], []
    affected = []
    fixed = []
    with open(path) as f:
        for row in csv.DictReader(f):
            bid = int(row["binary_id"])
            status = row["affected"]
            if status == "yes":
                affected.append(bid)
            elif status == "no":
                fixed.append(bid)
    return affected, fixed


def classify_difficulty(ref, variant):
    """Classify variant difficulty relative to reference binary."""
    diffs = []
    if ref.opt_label != variant.opt_label:
        diffs.append("opt")
    if ref.compiler_label != variant.compiler_label:
        diffs.append("compiler")
    if ref.os_label != variant.os_label:
        diffs.append("os")
    if ref.version != variant.version:
        diffs.append("version")

    if not diffs:
        return "D0_same"
    if diffs == ["opt"]:
        return "D1_cross_opt"
    if diffs == ["compiler"]:
        return "D2_cross_compiler"
    if diffs == ["version"]:
        return "D4_cross_version"
    return "D5_cross_everything"


SKIP_BINARIES = {
    "compileridc.exe", "compileridc", "compileridcxx.exe", "compileridcxx",
    "compileridc.obj", "compileridfortran.exe",
}

SKIP_EXTENSIONS = {".lib", ".a", ".pdb", ".obj", ".o", ".exp", ".ilk"}


def is_analyzable(rec):
    """Check if a binary can be loaded by BinaryAPI (ELF or PE executable/DLL)."""
    fname = rec.file_name.lower()
    if fname in SKIP_BINARIES:
        return False
    for ext in SKIP_EXTENSIONS:
        if fname.endswith(ext):
            return False
    return True


def is_library_binary(rec):
    """True for dynamic libraries (Windows .dll, Linux .so*)."""
    fname = rec.file_name.lower()
    if fname.endswith(".dll"):
        return True
    if fname.endswith(".so") or ".so." in fname:
        return True
    return False


def name_matches_package(rec, package_name):
    """Check if binary file name closely matches the package name."""
    fname = rec.file_name.lower().replace("-", "").replace("_", "")
    pkg = package_name.lower().replace("-", "").replace("_", "")
    pkg_variants = {pkg}
    if pkg.startswith("lib"):
        pkg_variants.add(pkg[3:])
    else:
        pkg_variants.add("lib" + pkg)

    if ".so" in fname:
        stem = fname.split(".so", 1)[0]
    else:
        stem = fname.rsplit(".", 1)[0]
    stem_no_ver = stem.rstrip("0123456789")
    for pv in pkg_variants:
        if stem_no_ver == pv or stem == pv:
            return 0
    for pv in pkg_variants:
        if pv in stem:
            return 1
    return 2


def _variant_sort_key(v, preferred_bids=None):
    """Sort key for cap_variants trimming (preferred_bids first, then libs, then alpha)."""
    preferred_bids = preferred_bids or set()
    fname = (v.get("file_name") or "").lower()
    is_lib = fname.endswith(".dll") or fname.endswith(".so") or ".so." in fname
    in_preferred = v.get("binary_id") in preferred_bids
    return (0 if in_preferred else 1,
            0 if is_lib else 1,
            fname,
            v.get("build_key") or "",
            v.get("version") or "")


def _bids_with_any_affected_fn(bids, fn_names):
    """Return {binary_id} for bids whose `functions` table contains any of `fn_names`."""
    names = [f for f in (fn_names or []) if f]
    return query.bids_with_any_function(bids or [], names)


def cap_variants(variants, max_affected, max_fixed,
                 preferred_bids=None, pinned_bids=None):
    """Deduplicate variants by (file_name, build_key, version) and cap totals."""
    pinned_bids = pinned_bids or set()
    affected_groups = {}
    fixed_groups = {}
    pinned_variants = []
    for v in variants:
        if v.get("binary_id") in pinned_bids:
            pinned_variants.append(v)
            continue
        key = (v.get("file_name") or "",
               v.get("build_key") or "",
               v.get("version") or "")
        target = affected_groups if v.get("has_vulnerability") else fixed_groups
        prev = target.get(key)
        if prev is None or v.get("binary_id", 0) < prev.get("binary_id", 0):
            target[key] = v

    def _pick(groups, cap):
        items = sorted(groups.values(),
                       key=lambda v: _variant_sort_key(v, preferred_bids))
        return items[:cap] if cap and len(items) > cap else items

    return (pinned_variants
            + _pick(affected_groups, max_affected)
            + _pick(fixed_groups, max_fixed))


def select_sample_variant(ref, variants):
    """Pick a sample variant for Eval 2 strategy generation."""
    ref_os = ref.os_label

    affected = [v for v in variants if v.get("has_vulnerability")]
    if not affected:
        return None

    ref_comp = ref.compiler_label
    ref_opt = ref.opt_label
    ref_ver = ref.version

    def rank(v):
        v_os = "linux" if v.get("platform") == "linux" else "windows"
        os_diff = 0 if v_os != ref_os else 1

        v_comp = (v.get("toolset_version") or
                  ("gcc" if v.get("platform") == "linux" else "unknown"))
        comp_diff = 0 if v_comp != ref_comp else 1

        v_opt = (v.get("optimization") or "O0").lstrip("-")
        opt_diff = 0 if v_opt != ref_opt else 1

        ver_diff = 0 if v.get("version") != ref_ver else 1

        return (os_diff, comp_diff, opt_diff, ver_diff, v.get("binary_id", 0))

    affected.sort(key=rank)
    return affected[0]


def select_reference(records, package_name="", fn_carrying_bids=None):
    """Pick reference binary by function carrying / name match / library / opt / version."""
    opt_rank = {"Od": 0, "O0": 0, "O1": 1, "O2": 2, "O3": 3}

    analyzable = [r for r in records if is_analyzable(r)]
    if not analyzable:
        return None

    fn_carrying = fn_carrying_bids or set()

    def sort_key(r):
        ver_nums, ver_suffix = _version_sort_key(r.version)
        return (
            0 if r.binary_id in fn_carrying else 1,
            name_matches_package(r, package_name),
            0 if is_library_binary(r) else 1,
            opt_rank.get(r.opt_label, 9),
            tuple(-n for n in ver_nums),
            ver_suffix,
            r.binary_id,
        )

    analyzable.sort(key=sort_key)
    return analyzable[0]


def _get_pdb_paths(binary_id):
    """Return PDB file paths for a binary."""
    return query.get_pdb_paths(binary_id)


def _load_with_debug(binary_path, binary_id):
    """Load binary via BinaryAPI with PDB debug symbols."""
    from binaryapi import BinaryAPI
    pdb_paths = _get_pdb_paths(binary_id)
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


def _resolve_func(api, func_name, db_confirmed_names=None):
    """Resolve source function name to Ghidra name (exact, normalized, or short-name fallback)."""
    if func_name in api._functions:
        return func_name

    target_norm = normalize_fn_name(func_name)
    if target_norm and target_norm in api._functions:
        return target_norm
    if target_norm:
        for dname in api._functions:
            if normalize_fn_name(dname) == target_norm:
                return dname

    if "::" in func_name:
        if db_confirmed_names is not None and func_name not in db_confirmed_names:
            return None
        short = func_name.rsplit("::", 1)[1]
        if short in api._functions:
            return short
    return None


_FUNCLET_RE = re.compile(r"^`([^']+)'::`\d+'::[A-Za-z_]+\$\d+")
_ANON_NS_RE = re.compile(r"`anonymous namespace'|`anonymousnamespace'")


def normalize_fn_name(name):
    """Canonicalize a function name so MSVC-PDB and Itanium-ELF forms match."""
    if not name:
        return name
    n = name.strip()

    m = _FUNCLET_RE.match(n)
    if m:
        n = m.group(1)

    if n.endswith(")"):
        depth = 0
        for i in range(len(n) - 1, -1, -1):
            c = n[i]
            if c == ")":
                depth += 1
            elif c == "(":
                depth -= 1
                if depth == 0:
                    n = n[:i].rstrip()
                    break

    n = _ANON_NS_RE.sub("(anonymous namespace)", n)
    return n.strip()


_TOKEN_RE = re.compile(r'[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+')


def _tokenize(name):
    """Split a function name on underscore + camelCase + digit boundaries."""
    tokens = []
    for part in name.split("_"):
        subs = _TOKEN_RE.findall(part)
        tokens.extend(subs if subs else [part])
    return [t for t in tokens if t]


def _token_eq(a, b):
    return a.lower() == b.lower()


def _select_decoys_codebleu(decomp_map, vuln_name, n=4, min_lines=20):
    """Select n decoy debug-names ranked by CodeBLEU similarity to the vuln."""
    if not vuln_name or vuln_name not in decomp_map:
        return []
    from codebleu import calc_codebleu
    vuln_code = decomp_map[vuln_name]
    if not vuln_code or vuln_code.startswith("// Decompilation"):
        return []

    scored = []
    for name, code in decomp_map.items():
        if name == vuln_name:
            continue
        if not code or code.startswith("// Decompilation"):
            continue
        if len(code.split("\n")) < min_lines:
            continue
        try:
            score = calc_codebleu([vuln_code], [code], lang='c')['codebleu']
        except Exception:
            continue
        scored.append((score, name))
    scored.sort(key=lambda t: (-t[0], t[1]))
    return [name for _, name in scored[:n]]


def select_decoys(all_func_names, vulnerable_func, n=4):
    """Select n decoy function names using token-aware prefix/suffix match."""
    vuln_tokens = _tokenize(vulnerable_func)
    candidates = [f for f in all_func_names if f != vulnerable_func]
    if len(candidates) <= n:
        return list(candidates)
    if not vuln_tokens:
        return []

    selected = []
    selected_set = set()

    def _take(batch):
        batch.sort(key=lambda f: abs(len(_tokenize(f)) - len(vuln_tokens)))
        for m in batch:
            if m in selected_set:
                continue
            selected.append(m)
            selected_set.add(m)
            if len(selected) >= n:
                return True
        return False

    for k in range(len(vuln_tokens), 0, -1):
        prefix = vuln_tokens[:k]
        batch = []
        for f in candidates:
            if f in selected_set:
                continue
            toks = _tokenize(f)
            if len(toks) >= k and all(_token_eq(p, t) for p, t in zip(prefix, toks)):
                batch.append(f)
        if _take(batch):
            return selected[:n]

    for k in range(len(vuln_tokens), 0, -1):
        suffix = vuln_tokens[-k:]
        batch = []
        for f in candidates:
            if f in selected_set:
                continue
            toks = _tokenize(f)
            if len(toks) >= k and all(_token_eq(p, t) for p, t in zip(suffix, toks[-k:])):
                batch.append(f)
        if _take(batch):
            return selected[:n]

    return selected[:n]


def _body_hash(code):
    """Hash a decompiled function body for equivalence checks."""
    brace = code.find("{")
    body = code[brace:] if brace >= 0 else code
    return hashlib.sha1(body.encode()).hexdigest()


def _random_fill_decoys(stripped_api, already_names, n_needed, min_lines=20,
                        already_body_hashes=None):
    """Fill remaining decoy slots with random stripped functions (>=min_lines, deduped)."""
    if n_needed <= 0:
        return {}
    seen_bodies = set(already_body_hashes) if already_body_hashes else set()
    pool = [f for f in stripped_api.list_functions()
            if f["name"] not in already_names
            and f.get("size_bytes", 0) > 50]
    random.shuffle(pool)

    picked = {}
    for f in pool:
        if len(picked) >= n_needed:
            break
        sname = f["name"]
        code = stripped_api.decompile(sname)
        if not code or code.startswith("// Decompilation"):
            continue
        if len(code.split("\n")) < min_lines:
            continue
        bh = _body_hash(code)
        if bh in seen_bodies:
            continue
        seen_bodies.add(bh)
        picked[sname] = code
    return picked


def _prepare_binary(original_path):
    """Create stripped copy of a binary (no PDB for PE, llvm-strip for ELF)."""
    os.makedirs(STRIPPED_DIR, exist_ok=True)
    h = hashlib.sha256()
    with open(original_path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    file_hash = h.hexdigest()[:16]
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


_stripped_path_cache = {}
_stripped_api_cache = {}


def _get_stripped_path(original_path):
    """Get stripped binary path, caching to avoid redundant hashing."""
    if original_path not in _stripped_path_cache:
        _stripped_path_cache[original_path] = _prepare_binary(original_path)
    return _stripped_path_cache[original_path]


def _load_stripped_api(stripped_path):
    """Load BinaryAPI for a stripped binary using the default (non-debug) cache."""
    if stripped_path not in _stripped_api_cache:
        from binaryapi import BinaryAPI
        import binaryapi as _bmod
        old_cache = _bmod._CACHE_DIR
        _bmod._CACHE_DIR = os.path.expanduser("~/.cache/binaryapi")
        try:
            _stripped_api_cache[stripped_path] = BinaryAPI(stripped_path)
        finally:
            _bmod._CACHE_DIR = old_cache
    return _stripped_api_cache[stripped_path]


def _preload_one_binary(bpath, bid, timeout):
    """Subprocess: load debug + stripped BinaryAPI for one binary path. Returns (ok, detail)."""
    import subprocess as _sub
    code = (
        "import sys, os; "
        f"sys.path.insert(0, {BASE!r}); "
        f"sys.path.insert(0, {os.path.dirname(os.path.abspath(__file__))!r}); "
        "import binaryapi as _b; "
        "_b._CACHE_DIR = os.path.expanduser('~/.cache/binaryapi_debug'); "
        "from prepare import _load_with_debug, _get_stripped_path, "
        "_load_stripped_api; "
        f"_load_with_debug({bpath!r}, {bid}); "
        f"sp = _get_stripped_path({bpath!r}); "
        "_load_stripped_api(sp)"
    )
    try:
        proc = _sub.Popen(
            [sys.executable, "-c", code],
            stdout=_sub.DEVNULL, stderr=_sub.PIPE)
        _, stderr = proc.communicate(timeout=timeout)
    except _sub.TimeoutExpired:
        proc.kill()
        proc.wait()
        return False, "timeout"
    except Exception as e:
        return False, f"launch: {e}"
    if proc.returncode != 0:
        return False, (stderr.decode(errors="replace")[-300:]
                       if stderr else f"rc={proc.returncode}")
    return True, None


def _find_code_name(decomp_code, sub_name):
    """Find the actual FUN_xxx name in decompiled code matching a sub_xxx name."""
    if not sub_name.startswith("sub_"):
        return sub_name
    addr_suffix = sub_name[4:]
    pattern = re.compile(r'FUN_0*' + re.escape(addr_suffix) + r'\b')
    m = pattern.search(decomp_code)
    if m:
        return m.group(0)
    return sub_name


def _build_stripped_lookup(stripped_api):
    """Build exact + range-based address lookup for a stripped binary."""
    funcs = stripped_api.list_functions()
    by_addr = {f["address"]: f["name"] for f in funcs}
    ranges = []
    for f in funcs:
        start = int(f["address"], 16)
        size = f.get("size_bytes", 0)
        ranges.append((start, start + max(size, 1), f["name"]))
    ranges.sort()
    return by_addr, ranges


def _find_stripped_func(addr_str, by_addr, ranges):
    """Find stripped function by exact address, then by containing range."""
    name = by_addr.get(addr_str)
    if name:
        return name
    target = int(addr_str, 16)
    for start, end, name in ranges:
        if start <= target < end:
            return name
    return None


def _map_and_decompile(debug_api, stripped_api, func_names):
    """Map debug function names to stripped names via address, then decompile."""
    debug_addr = {f["name"]: f["address"] for f in debug_api.list_functions()}
    by_addr, ranges = _build_stripped_lookup(stripped_api)

    stripped_names = {}
    decompiled = {}
    seen_stripped = set()

    for fname in func_names:
        addr = debug_addr.get(fname)
        if not addr:
            continue
        sname = _find_stripped_func(addr, by_addr, ranges)
        if not sname or sname in seen_stripped:
            continue
        seen_stripped.add(sname)

        decomp = stripped_api.decompile(sname)
        if decomp and not decomp.startswith("// Decompilation unavailable"):
            decompiled[fname] = decomp
            stripped_names[fname] = _find_code_name(decomp, sname)
        else:
            stripped_names[fname] = sname

    return stripped_names, decompiled


def _process_binary_for_eval(debug_api, stripped_api, affected_funcs,
                              source_fetcher=None, generate_decoys=True,
                              binary_id=None):
    """Per-binary work shared by ground-truth mapping and decoy generation."""
    result = {
        "source_to_debug": {},
        "source_to_strip": {},
        "vuln_debug": None,
        "decoy_debug": [],
        "stripped_names": {},
        "decompiled": {},
        "source_codes": {},
        "function_count": len(stripped_api.list_functions()),
    }

    db_confirmed = None
    if binary_id is not None and affected_funcs:
        try:
            db_confirmed = query.get_function_names_present(
                binary_id, affected_funcs)
        except Exception:
            db_confirmed = None

    for src in affected_funcs:
        r = _resolve_func(debug_api, src, db_confirmed_names=db_confirmed)
        if r:
            result["source_to_debug"][src] = r

    if not result["source_to_debug"]:
        return result

    vuln_debug_names = list(result["source_to_debug"].values())
    sname_map, decomp = _map_and_decompile(
        debug_api, stripped_api, vuln_debug_names)
    for src, dname in result["source_to_debug"].items():
        if dname in sname_map:
            result["source_to_strip"][src] = sname_map[dname]

    for src, dname in result["source_to_debug"].items():
        if dname in decomp:
            result["vuln_debug"] = dname
            result["stripped_names"][dname] = sname_map[dname]
            result["decompiled"][dname] = decomp[dname]
            break

    if not result["vuln_debug"]:
        return result

    if not generate_decoys:
        return result

    vuln_sname = result["stripped_names"][result["vuln_debug"]]
    taken_snames = {vuln_sname}
    taken_body_hashes = {_body_hash(result["decompiled"][result["vuln_debug"]])}

    vuln_src = ""
    taken_source_hashes = set()
    if source_fetcher is not None:
        try:
            vuln_src_map = source_fetcher([result["vuln_debug"]])
        except Exception:
            vuln_src_map = {}
        vuln_src = vuln_src_map.get(result["vuln_debug"], "") or ""
        if vuln_src:
            taken_source_hashes.add(hashlib.sha1(vuln_src.encode()).hexdigest())
            result["source_codes"][result["vuln_debug"]] = vuln_src

    decoy_debug = _select_decoys_codebleu(
        debug_api._decompiled, result["vuln_debug"], n=4)

    decoy_sname_map, decoy_decomp = _map_and_decompile(
        debug_api, stripped_api, decoy_debug)

    decoy_src = {}
    if source_fetcher is not None and decoy_debug:
        try:
            decoy_src = source_fetcher(list(decoy_debug))
        except Exception:
            decoy_src = {}

    mapped = []
    for dname in decoy_debug:
        if dname not in decoy_decomp:
            continue
        sname = decoy_sname_map[dname]
        if sname in taken_snames:
            continue
        code = decoy_decomp[dname]
        bh = _body_hash(code)
        if bh in taken_body_hashes:
            continue
        src = decoy_src.get(dname, "") or ""
        if src:
            sh = hashlib.sha1(src.encode()).hexdigest()
            if sh in taken_source_hashes:
                continue
            taken_source_hashes.add(sh)
            result["source_codes"][dname] = src
        result["stripped_names"][dname] = sname
        result["decompiled"][dname] = code
        taken_snames.add(sname)
        taken_body_hashes.add(bh)
        mapped.append(dname)

    shortage = 4 - len(mapped)
    if shortage > 0:
        filled = _random_fill_decoys(
            stripped_api, already_names=taken_snames,
            n_needed=shortage, min_lines=20,
            already_body_hashes=taken_body_hashes)
        for sname, code in filled.items():
            result["stripped_names"][sname] = sname
            result["decompiled"][sname] = code
            mapped.append(sname)

    result["decoy_debug"] = mapped[:4]
    return result


def _fetch_source_snippets(ref_binary_id, debug_names, platform=None):
    """Look up source for each debug-resolved function name."""
    return query.get_source_codes(ref_binary_id, debug_names, platform=platform)


def _seed_for_cve(cve_id):
    """Deterministic per-CVE random seed."""
    import hashlib
    h = hashlib.sha1(cve_id.encode()).hexdigest()
    return RANDOM_SEED ^ int(h[:8], 16)


def _process_one_cve(entry, gt_binaries, with_decoys):
    """Process a single CVE end-to-end: load each binary, map GT, pick decoys."""
    sys.path.insert(0, BASE)
    import binaryapi as _bapi
    _bapi._CACHE_DIR = os.path.expanduser("~/.cache/binaryapi_debug")

    random.seed(_seed_for_cve(entry["cve_id"]))

    cve_id = entry["cve_id"]
    affected_funcs = entry["affected_functions"]
    ref = entry["reference"]
    ref_bin = {
        "binary_id": ref["binary_id"],
        "full_path": ref["full_path"],
        "has_vulnerability": True,
        "difficulty": "reference",
        "platform": ref.get("platform"),
    }
    all_bins = [ref_bin] + entry["variants"]

    reps = entry.get("eval1_reps") or {}
    rep_bids = set()
    for p in ("linux", "windows"):
        if reps.get(p) is not None:
            rep_bids.add(int(reps[p]))

    binary_updates = {}
    cve_decoys = {}
    rep_ok = {p: False for p in ("linux", "windows") if reps.get(p) is not None}

    for b in all_bins:
        bid = str(b["binary_id"])
        bpath = b.get("full_path", "")
        is_rep = int(b["binary_id"]) in rep_bids
        if not bpath or not os.path.exists(bpath):
            continue

        try:
            debug_api = _load_with_debug(bpath, b["binary_id"])
            stripped_api = _load_stripped_api(_get_stripped_path(bpath))
        except Exception as e:
            print(f"  WARN {cve_id}/{bid}: load failed: {e}",
                  file=sys.stderr, flush=True)
            continue

        src_fetcher = None
        if is_rep and b.get("has_vulnerability", True):
            rep_platform = b.get("platform")
            rep_bid_for_src = b["binary_id"]
            def src_fetcher(names,
                            _bid=rep_bid_for_src, _plat=rep_platform):
                return query.get_source_codes(_bid, names, platform=_plat)

        try:
            pb = _process_binary_for_eval(
                debug_api, stripped_api, affected_funcs,
                source_fetcher=src_fetcher,
                generate_decoys=(with_decoys and is_rep),
                binary_id=b["binary_id"])
        except Exception as e:
            print(f"  WARN {cve_id}/{bid}: processing failed: {e}",
                  file=sys.stderr, flush=True)
            continue

        if bid in gt_binaries:
            binary_updates[bid] = {
                "functions": pb["source_to_strip"],
                "function_count": pb["function_count"],
            }

        if not is_rep or not with_decoys:
            continue

        if not b.get("has_vulnerability", True):
            continue
        if not pb["vuln_debug"] or len(pb["decoy_debug"]) < 4:
            continue

        label_order = list(range(5))
        random.shuffle(label_order)
        gt_label = label_order.index(0)

        plat_key = "linux" if b.get("platform") == "linux" else "windows"
        entry_out = {
            "vulnerable": pb["vuln_debug"],
            "decoys": pb["decoy_debug"],
            "label_order": label_order,
            "ground_truth_label": gt_label,
            "decompiled": pb["decompiled"],
            "stripped_names": pb["stripped_names"],
            "platform": plat_key,
            "source_snippets": dict(pb["source_codes"]),
        }
        cve_decoys[bpath] = entry_out
        if plat_key in rep_ok:
            rep_ok[plat_key] = True

    dropped = bool(rep_ok) and not any(rep_ok.values())

    return {
        "cve_id": cve_id,
        "schema": SHARD_SCHEMA_VERSION,
        "dropped": dropped,
        "binary_updates": binary_updates,
        "decoys": cve_decoys,
    }


def _subprocess_main():
    """Worker subprocess entry point: reads payload from stdin, writes result JSON to out_path."""
    import json
    import traceback as _tb

    payload = json.loads(sys.stdin.read())
    try:
        result = _process_one_cve(
            payload["entry"],
            payload["gt_binaries"],
            payload["with_decoys"])
        with open(payload["out_path"], "w") as f:
            json.dump(result, f)
        sys.exit(0)
    except Exception as e:
        tb = _tb.format_exc()
        cve_id = payload.get("entry", {}).get("cve_id", "UNKNOWN")
        try:
            with open(payload["out_path"], "w") as f:
                json.dump({
                    "cve_id": cve_id,
                    "error": str(e),
                    "traceback": tb[-2000:],
                }, f)
        except Exception:
            pass
        print(tb, file=sys.stderr, flush=True)
        sys.exit(1)


def _apply_cve_result(result, ground_truth, decoys, dropped):
    """Merge one _process_one_cve result into the shared ground_truth/decoys."""
    cve_id = result["cve_id"]
    if result.get("error"):
        print(f"  ERROR {cve_id}: {result['error']}", flush=True)
        return
    if result.get("dropped"):
        print(f"  DROP {cve_id}: reference binary mapping failed", flush=True)
        dropped.append(cve_id)
        return
    gt_entry = ground_truth.get(cve_id)
    if gt_entry:
        for bid, upd in result.get("binary_updates", {}).items():
            if bid in gt_entry["binaries"]:
                gt_entry["binaries"][bid]["functions"] = upd["functions"]
                gt_entry["binaries"][bid]["function_count"] = upd["function_count"]
    if result.get("decoys"):
        decoys[cve_id] = result["decoys"]


def generate_decoys(selected, ground_truth, with_decoys=True):
    """Serial Part 3+4 (single-process fallback). Calls _process_one_cve."""
    decoys = {}
    dropped = []
    header = ("Ground-truth mapping + decoy selection" if with_decoys
              else "Ground-truth mapping (skip-decoys)")
    print(f"\n=== Part 3/4 (serial): {header} ===", flush=True)

    for i, entry in enumerate(selected):
        cve_id = entry["cve_id"]
        gt_entry = ground_truth.get(cve_id)
        if not gt_entry:
            continue

        result = _process_one_cve(entry, gt_entry["binaries"], with_decoys)
        _apply_cve_result(result, ground_truth, decoys, dropped)

        if (i + 1) % 20 == 0 or i == 0:
            n_dec = len(result.get("decoys", {}))
            print(f"  [{i+1}/{len(selected)}] {cve_id}: "
                  f"{n_dec} binaries with decoys", flush=True)

    for cve_id in dropped:
        ground_truth.pop(cve_id, None)
    return decoys, dropped


def generate_decoys_parallel(selected, ground_truth, with_decoys,
                             workers, timeout):
    """Parallel Part 3+4: one subprocess per CVE, up to `workers` concurrent."""
    import concurrent.futures
    import subprocess as _sub
    import json as _json

    os.makedirs(SHARD_DIR, exist_ok=True)

    decoys = {}
    dropped = []
    header = ("Ground-truth mapping + decoy selection" if with_decoys
              else "Ground-truth mapping (skip-decoys)")
    print(f"\n=== Part 3/4 (parallel workers={workers} "
          f"timeout={timeout}s): {header} ===", flush=True)

    def _run_one(entry):
        cve_id = entry["cve_id"]
        gt_entry = ground_truth.get(cve_id)
        if not gt_entry:
            return {"cve_id": cve_id, "error": "no gt scaffold"}

        out_path = os.path.join(SHARD_DIR, f"{cve_id}.json")

        if os.path.exists(out_path):
            try:
                cached = _json.load(open(out_path))
                if ("error" not in cached
                        and cached.get("schema") == SHARD_SCHEMA_VERSION):
                    return cached
                os.remove(out_path)
            except Exception:
                try:
                    os.remove(out_path)
                except OSError:
                    pass

        cmd = [
            sys.executable, "-c",
            "import sys; "
            f"sys.path.insert(0, {os.path.dirname(os.path.abspath(__file__))!r}); "
            "from prepare import _subprocess_main; _subprocess_main()"
        ]
        payload = _json.dumps({
            "entry": entry,
            "gt_binaries": gt_entry["binaries"],
            "with_decoys": with_decoys,
            "out_path": out_path,
        }).encode()

        try:
            proc = _sub.Popen(
                cmd, stdin=_sub.PIPE, stdout=_sub.PIPE, stderr=_sub.PIPE)
            _, stderr = proc.communicate(input=payload, timeout=timeout)
        except _sub.TimeoutExpired:
            proc.kill()
            proc.wait()
            return {"cve_id": cve_id, "error": f"timeout after {timeout}s"}
        except Exception as e:
            return {"cve_id": cve_id, "error": f"subprocess launch: {e}"}

        if proc.returncode != 0:
            err = stderr.decode(errors="replace")[-500:] if stderr else "rc!=0"
            return {"cve_id": cve_id, "error": err}

        try:
            return _json.load(open(out_path))
        except Exception as e:
            return {"cve_id": cve_id, "error": f"result read failed: {e}"}

    completed = 0
    errors = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(_run_one, e): e["cve_id"] for e in selected}
        for fut in concurrent.futures.as_completed(futures):
            cve_id = futures[fut]
            try:
                result = fut.result()
            except Exception as e:
                result = {"cve_id": cve_id, "error": f"executor: {e}"}

            completed += 1
            if result.get("error"):
                errors += 1
            _apply_cve_result(result, ground_truth, decoys, dropped)

            if completed == 1 or completed % 10 == 0:
                print(f"  [{completed}/{len(selected)}] "
                      f"errors={errors} dropped={len(dropped)} "
                      f"(last: {cve_id})", flush=True)

    for cve_id in dropped:
        ground_truth.pop(cve_id, None)
    print(f"\n  Parallel run done: completed={completed} "
          f"errors={errors} dropped={len(dropped)}", flush=True)
    return decoys, dropped


def _unique_binaries_for_entry(entry):
    """Collect unique {full_path: (binary_id, sha256_hex)} for one CVE entry."""
    ref = entry["reference"]
    unique_bins = {}
    seen_hashes = set()
    bins_iter = [{"full_path": ref["full_path"],
                  "binary_id": ref["binary_id"]}]
    bins_iter.extend(entry.get("variants", []))
    for b in bins_iter:
        p = b.get("full_path")
        if not (p and os.path.exists(p)):
            continue
        if p in unique_bins:
            continue
        h = hashlib.sha256()
        with open(p, "rb") as fp:
            for chunk in iter(lambda: fp.read(1 << 20), b""):
                h.update(chunk)
        digest = h.hexdigest()
        if digest in seen_hashes:
            continue
        seen_hashes.add(digest)
        unique_bins[p] = (b["binary_id"], digest)
    return unique_bins


_sha_preload_locks = {}
_sha_preload_locks_lock = None


def _sha_preload_lock(digest):
    """Return the process-wide threading.Lock for this binary SHA."""
    import threading
    global _sha_preload_locks_lock
    if _sha_preload_locks_lock is None:
        _sha_preload_locks_lock = threading.Lock()
    with _sha_preload_locks_lock:
        lock = _sha_preload_locks.get(digest)
        if lock is None:
            lock = threading.Lock()
            _sha_preload_locks[digest] = lock
        return lock


def _preload_one_binary_locked(path, bid, digest, timeout):
    """_preload_one_binary wrapped in a per-SHA lock."""
    with _sha_preload_lock(digest):
        return _preload_one_binary(path, bid, timeout)


def _try_load_cached_shard(out_path):
    """Return (cached_result, reused) for a clean shard at the current schema; removes stale/corrupt."""
    if not os.path.exists(out_path):
        return None, False
    try:
        cached = json.load(open(out_path))
        if ("error" not in cached
                and cached.get("schema") == SHARD_SCHEMA_VERSION):
            return cached, True
        os.remove(out_path)
    except Exception:
        try:
            os.remove(out_path)
        except OSError:
            pass
    return None, False


def _process_one_cve_external(entry, gt_entry, with_decoys, bin_workers,
                              per_bin_timeout, cve_timeout, out_path,
                              log_prefix=""):
    """Run preload + processing subprocess for ONE CVE end-to-end."""
    import concurrent.futures as _cf
    import subprocess as _sub

    unique_bins = _unique_binaries_for_entry(entry)

    pre_fail = 0
    pre_total = len(unique_bins)
    if unique_bins:
        with _cf.ThreadPoolExecutor(max_workers=bin_workers) as ex:
            futs = {ex.submit(_preload_one_binary_locked, p, bid, digest,
                              per_bin_timeout): p
                    for p, (bid, digest) in unique_bins.items()}
            for fut in _cf.as_completed(futs):
                p = futs[fut]
                try:
                    ok, detail = fut.result()
                except Exception as e:
                    ok, detail = False, f"executor: {e}"
                if not ok:
                    pre_fail += 1
                    prefix = f"  {log_prefix} " if log_prefix else "    "
                    print(f"{prefix}preload fail "
                          f"{os.path.basename(p)}: {detail}", flush=True)

    cve_id = entry["cve_id"]
    cmd = [
        sys.executable, "-c",
        "import sys; "
        f"sys.path.insert(0, {os.path.dirname(os.path.abspath(__file__))!r}); "
        "from prepare import _subprocess_main; _subprocess_main()"
    ]
    payload = json.dumps({
        "entry": entry,
        "gt_binaries": gt_entry["binaries"],
        "with_decoys": with_decoys,
        "out_path": out_path,
    }).encode()

    try:
        proc = _sub.Popen(
            cmd, stdin=_sub.PIPE, stdout=_sub.PIPE, stderr=_sub.PIPE)
        _, stderr = proc.communicate(input=payload, timeout=cve_timeout)
    except _sub.TimeoutExpired:
        proc.kill()
        proc.wait()
        result = {"cve_id": cve_id,
                  "error": f"cve-step timeout after {cve_timeout}s"}
    except Exception as e:
        result = {"cve_id": cve_id, "error": f"launch: {e}"}
    else:
        if proc.returncode != 0:
            err = (stderr.decode(errors="replace")[-500:]
                   if stderr else "rc!=0")
            result = {"cve_id": cve_id, "error": err}
        else:
            try:
                result = json.load(open(out_path))
            except Exception as e:
                result = {"cve_id": cve_id,
                          "error": f"read failed: {e}"}

    return result, pre_fail, pre_total


def generate_decoys_inner_parallel(selected, ground_truth, with_decoys,
                                    inner_workers, per_bin_timeout,
                                    cve_timeout):
    """CVE-sequential driver with per-CVE inner parallelism (preload pool + process)."""
    os.makedirs(SHARD_DIR, exist_ok=True)
    decoys = {}
    dropped = []
    header = ("Ground-truth mapping + decoy selection" if with_decoys
              else "Ground-truth mapping (skip-decoys)")
    print(f"\n=== Part 3/4 (inner-parallel "
          f"workers={inner_workers} "
          f"per_bin_timeout={per_bin_timeout}s "
          f"cve_timeout={cve_timeout}s): {header} ===", flush=True)

    n_total = len(selected)
    completed = 0
    errors = 0

    for i, entry in enumerate(selected):
        cve_id = entry["cve_id"]
        gt_entry = ground_truth.get(cve_id)
        if not gt_entry:
            continue

        out_path = os.path.join(SHARD_DIR, f"{cve_id}.json")

        cached, reused = _try_load_cached_shard(out_path)
        if reused:
            _apply_cve_result(cached, ground_truth, decoys, dropped)
            completed += 1
            if completed == 1 or completed % 20 == 0:
                print(f"  [{i+1}/{n_total}] {cve_id}: "
                      f"cached shard reused", flush=True)
            continue

        result, pre_fail, pre_total = _process_one_cve_external(
            entry, gt_entry, with_decoys,
            bin_workers=inner_workers,
            per_bin_timeout=per_bin_timeout,
            cve_timeout=cve_timeout,
            out_path=out_path)

        completed += 1
        if result.get("error"):
            errors += 1
        _apply_cve_result(result, ground_truth, decoys, dropped)

        status = ("OK" if not result.get("error")
                  else "ERR: " + str(result.get("error"))[:80])
        print(f"  [{i+1}/{n_total}] {cve_id}: "
              f"preload {pre_total-pre_fail}/{pre_total} "
              f"{status}", flush=True)

    for cve_id in dropped:
        ground_truth.pop(cve_id, None)
    print(f"\n  Inner-parallel done: completed={completed} "
          f"errors={errors} dropped={len(dropped)}", flush=True)
    return decoys, dropped


def generate_decoys_hybrid_parallel(selected, ground_truth, with_decoys,
                                    cve_workers, bin_workers,
                                    per_bin_timeout, cve_timeout):
    """CVE-parallel driver with per-CVE inner binary parallelism."""
    import concurrent.futures as _cf
    import threading as _th

    os.makedirs(SHARD_DIR, exist_ok=True)
    decoys = {}
    dropped = []
    header = ("Ground-truth mapping + decoy selection" if with_decoys
              else "Ground-truth mapping (skip-decoys)")
    print(f"\n=== Part 3/4 (hybrid-parallel "
          f"cve_workers={cve_workers} bin_workers={bin_workers} "
          f"peak_jvms={cve_workers * bin_workers} "
          f"per_bin_timeout={per_bin_timeout}s "
          f"cve_timeout={cve_timeout}s): {header} ===", flush=True)

    n_total = len(selected)
    counter_lock = _th.Lock()
    state = {"completed": 0, "errors": 0}

    def _one(entry):
        cve_id = entry["cve_id"]
        gt_entry = ground_truth.get(cve_id)
        if not gt_entry:
            return {"cve_id": cve_id, "skip": "no gt scaffold"}, 0, 0, False

        out_path = os.path.join(SHARD_DIR, f"{cve_id}.json")
        cached, reused = _try_load_cached_shard(out_path)
        if reused:
            return cached, 0, 0, True

        result, pre_fail, pre_total = _process_one_cve_external(
            entry, gt_entry, with_decoys,
            bin_workers=bin_workers,
            per_bin_timeout=per_bin_timeout,
            cve_timeout=cve_timeout,
            out_path=out_path,
            log_prefix=cve_id)
        return result, pre_fail, pre_total, False

    with _cf.ThreadPoolExecutor(max_workers=cve_workers) as cve_ex:
        futs = {cve_ex.submit(_one, e): e["cve_id"] for e in selected}
        for fut in _cf.as_completed(futs):
            cve_id = futs[fut]
            try:
                result, pre_fail, pre_total, was_cached = fut.result()
            except Exception as e:
                result, pre_fail, pre_total, was_cached = (
                    {"cve_id": cve_id, "error": f"executor: {e}"}, 0, 0, False)

            if result.get("skip"):
                continue

            _apply_cve_result(result, ground_truth, decoys, dropped)

            with counter_lock:
                state["completed"] += 1
                if result.get("error"):
                    state["errors"] += 1
                c = state["completed"]

                status = ("OK" if not result.get("error")
                          else "ERR: " + str(result.get("error"))[:80])
                if was_cached:
                    print(f"  [{c}/{n_total}] {cve_id}: "
                          f"cached shard reused", flush=True)
                else:
                    print(f"  [{c}/{n_total}] {cve_id}: "
                          f"preload {pre_total-pre_fail}/{pre_total} "
                          f"{status}", flush=True)

    for cve_id in dropped:
        ground_truth.pop(cve_id, None)
    print(f"\n  Hybrid-parallel done: completed={state['completed']} "
          f"errors={state['errors']} dropped={len(dropped)}", flush=True)
    return decoys, dropped


def merge_shards_only(selected, ground_truth):
    """Read existing shards and merge into ground_truth + decoys (no Ghidra, no drops)."""
    os.makedirs(SHARD_DIR, exist_ok=True)
    decoys = {}
    n_reused = 0
    n_missing = 0
    n_stale = 0
    n_dropped_flag = 0

    print(f"\n=== Part 3/4 (shards-only): merging existing shards ===",
          flush=True)
    for entry in selected:
        cve_id = entry["cve_id"]
        out_path = os.path.join(SHARD_DIR, f"{cve_id}.json")
        cached, reused = _try_load_cached_shard(out_path)
        if reused:
            local_dropped = []
            _apply_cve_result(cached, ground_truth, decoys, local_dropped)
            if local_dropped:
                n_dropped_flag += 1
            else:
                n_reused += 1
        elif os.path.exists(out_path):
            n_stale += 1
        else:
            n_missing += 1

    print(f"  shards merged: {n_reused}  "
          f"ref-drop shards (left in selected): {n_dropped_flag}  "
          f"missing (in-flight): {n_missing}  stale: {n_stale}",
          flush=True)
    return decoys, []


def backfill_source_snippets():
    """Attach DB / shard source to every Eval 1 decoy entry (idempotent overwrite)."""
    if not os.path.exists(OUTPUT_DECOYS) or not os.path.exists(OUTPUT_SELECTED):
        print(f"ERROR: missing {OUTPUT_DECOYS} or {OUTPUT_SELECTED}. "
              "Run prepare.py without --source-backfill first.")
        return

    selected = json.load(open(OUTPUT_SELECTED))
    decoys = json.load(open(OUTPUT_DECOYS))

    bid_meta = {}
    for entry in selected:
        r = entry.get("reference", {})
        if r.get("binary_id") is not None:
            bid_meta[int(r["binary_id"])] = (r.get("full_path"),
                                             r.get("platform"))
        for v in entry.get("variants", []):
            if v.get("binary_id") is not None:
                bid_meta[int(v["binary_id"])] = (v.get("full_path"),
                                                 v.get("platform"))
    path_to_bid = {fp: bid for bid, (fp, _) in bid_meta.items() if fp}

    updated = 0
    missing_vuln = 0
    total_names = 0
    total_found = 0

    for entry in selected:
        cve_id = entry["cve_id"]
        if cve_id not in decoys:
            continue
        for bpath, de in decoys[cve_id].items():
            vuln = de.get("vulnerable")
            decoy_names = de.get("decoys", [])
            if not vuln:
                continue
            bid = path_to_bid.get(bpath)
            if bid is None:
                continue
            platform = bid_meta[bid][1]
            names = [vuln] + list(decoy_names)
            src_map = query.get_source_codes(bid, names, platform=platform)
            de["source_snippets"] = src_map
            updated += 1
            total_names += len(names)
            total_found += len(src_map)
            if vuln not in src_map:
                missing_vuln += 1

    with open(OUTPUT_DECOYS, "w") as f:
        json.dump(decoys, f, indent=2)

    print(f"Backfilled source_snippets for {updated} binary entries.")
    print(f"  names attempted: {total_names}, resolved: {total_found} "
          f"({100*total_found/total_names:.1f}%)" if total_names else "")
    print(f"  entries missing vulnerable source: {missing_vuln} "
          f"(these stay binary-only in Eval 1)")


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-decoys", action="store_true",
                        help="Skip Part 4 decoy selection (requires BinaryAPI)")
    parser.add_argument("--source-backfill", action="store_true",
                        help="Only refresh source_snippets in an existing "
                             "decoys.json (no Ghidra, no re-selection)")
    parser.add_argument("-j", "--workers", type=int, default=8,
                        help="Per-CVE binary preload workers (default: 8). "
                             "With --cve-workers > 1 this is the INNER cap; "
                             "peak Ghidra JVMs = cve_workers x workers. "
                             "0 = in-process serial fallback (no resume).")
    parser.add_argument("--cve-workers", type=int, default=1,
                        help="Concurrent CVE subprocesses (default: 1 = "
                             "CVE-sequential). Peak JVMs = cve_workers x "
                             "workers; budget ~2.5 GB RAM per JVM. "
                             "E.g. 8x4=32 JVMs ~ 80 GB.")
    parser.add_argument("--timeout", type=int, default=3600,
                        help="Per-CVE process-step timeout in seconds "
                             "(default: 3600 = 1 h). Large hdf5 / assimp "
                             "binaries can spend tens of minutes in "
                             "decompile after preload.")
    parser.add_argument("--per-bin-timeout", type=int, default=3600,
                        help="Per-binary preload subprocess timeout "
                             "(default: 3600 = 1 h). Covers one binary's "
                             "debug + stripped Ghidra analysis under "
                             "inner-pool contention.")
    parser.add_argument("--shards-only", action="store_true",
                        help="Skip all Ghidra work. Run Part 1-2 CVE "
                             "selection, then merge existing "
                             "_prepare_shards/*.json into selected.json / "
                             "ground_truth.json / decoys.json. CVEs "
                             "without a shard are dropped from selected.")
    parser.add_argument("--max-affected", type=int, default=20,
                        help="Max affected variants kept per CVE after "
                             "deduplication by (build_key, version). "
                             "(default: 20)")
    parser.add_argument("--max-fixed", type=int, default=10,
                        help="Max fixed (post-patch) variants kept per CVE "
                             "after deduplication by (build_key, version). "
                             "(default: 10)")
    args = parser.parse_args()
    _paths.ensure_dirs()

    if args.source_backfill:
        backfill_source_snippets()
        return

    print("Loading patch YAMLs...")
    patch_files = sorted(f for f in os.listdir(PATCH_DIR) if f.endswith(".yaml"))

    selected = []
    ground_truth = {}
    stats = {"total_yamls": 0, "no_functions": 0, "no_code_changes": 0,
             "no_affected_bins": 0, "bins_not_on_disk": 0, "too_few_configs": 0,
             "no_affected_variant": 0, "selected": 0}

    for pf in patch_files:
        cve_id = pf.replace(".yaml", "")
        stats["total_yamls"] += 1
        yaml_data = parse_patch_yaml(os.path.join(PATCH_DIR, pf))

        if not yaml_data["affected_functions"]:
            stats["no_functions"] += 1
            continue

        if not yaml_data["has_code_changes"]:
            stats["no_code_changes"] += 1
            continue

        affected_bids, fixed_bids = load_affected_binaries(cve_id)
        if not affected_bids:
            stats["no_affected_bins"] += 1
            continue

        affected_records = []
        for bid in affected_bids:
            rec = query.get_binary_by_id(bid)
            if rec and rec.exists:
                affected_records.append(rec)

        if not affected_records:
            stats["bins_not_on_disk"] += 1
            continue

        build_keys = set(r.build_key for r in affected_records)
        if len(build_keys) < 2:
            stats["too_few_configs"] += 1
            continue

        fn_carrying_all = _bids_with_any_affected_fn(
            [r.binary_id for r in affected_records],
            yaml_data["affected_functions"],
        )

        ref = select_reference(
            list(affected_records),
            yaml_data["package"],
            fn_carrying_bids=fn_carrying_all,
        )
        if ref is None:
            stats["bins_not_on_disk"] += 1
            continue

        variants = []
        for rec in affected_records:
            if rec.binary_id == ref.binary_id:
                continue
            if not is_analyzable(rec):
                continue
            variants.append({
                "binary_id": rec.binary_id,
                "path": rec.path,
                "full_path": rec.full_path,
                "file_name": rec.file_name,
                "platform": rec.platform,
                "toolset_version": rec.toolset_version,
                "optimization": rec.optimization,
                "version": rec.version,
                "difficulty": classify_difficulty(ref, rec),
                "has_vulnerability": True,
                "build_key": rec.build_key,
            })

        for bid in fixed_bids:
            rec = query.get_binary_by_id(bid)
            if rec and rec.exists and is_analyzable(rec):
                variants.append({
                    "binary_id": rec.binary_id,
                    "path": rec.path,
                    "full_path": rec.full_path,
                    "file_name": rec.file_name,
                    "platform": rec.platform,
                    "toolset_version": rec.toolset_version,
                    "optimization": rec.optimization,
                    "version": rec.version,
                    "difficulty": None,
                    "has_vulnerability": False,
                    "build_key": rec.build_key,
                })

        _cand_bids = [ref.binary_id] + [v["binary_id"] for v in variants]
        preferred_bids = _bids_with_any_affected_fn(
            _cand_bids, yaml_data["affected_functions"])

        rng = random.Random(_seed_for_cve(cve_id))
        rep_pool = [{"binary_id": ref.binary_id, "platform": ref.platform}]
        for v in variants:
            if v.get("has_vulnerability"):
                rep_pool.append({"binary_id": v["binary_id"],
                                 "platform": v.get("platform")})
        linux_bids = [c["binary_id"] for c in rep_pool
                      if c["platform"] == "linux"
                      and c["binary_id"] in preferred_bids]
        win_bids = [c["binary_id"] for c in rep_pool
                    if c["platform"] and c["platform"] != "linux"
                    and c["binary_id"] in preferred_bids]
        eval1_reps = {
            "linux": rng.choice(linux_bids) if linux_bids else None,
            "windows": rng.choice(win_bids) if win_bids else None,
        }
        pinned = {bid for bid in eval1_reps.values() if bid is not None}
        pinned.discard(ref.binary_id)

        variants = cap_variants(variants, args.max_affected, args.max_fixed,
                                preferred_bids=preferred_bids,
                                pinned_bids=pinned)

        sample_variant = select_sample_variant(ref, variants)
        if sample_variant is None:
            stats["no_affected_variant"] += 1
            continue

        entry = {
            "cve_id": cve_id,
            "package": yaml_data["package"],
            "yaml_path": f"cves/30_patch/{pf}",
            "affected_functions": yaml_data["affected_functions"],
            "reference": {
                "binary_id": ref.binary_id,
                "path": ref.path,
                "full_path": ref.full_path,
                "file_name": ref.file_name,
                "platform": ref.platform,
                "toolset_version": ref.toolset_version,
                "optimization": ref.optimization,
                "version": ref.version,
                "build_key": ref.build_key,
            },
            "sample_variant": sample_variant,
            "variants": variants,
            "eval1_reps": eval1_reps,
        }
        selected.append(entry)

        gt_entry = {
            "source_functions": yaml_data["affected_functions"],
            "binaries": {},
        }

        all_bins = [{"binary_id": ref.binary_id, "path": ref.path,
                      "full_path": ref.full_path,
                      "has_vulnerability": True, "difficulty": "reference"}]
        for v in variants:
            all_bins.append(v)

        for b in all_bins:
            gt_entry["binaries"][str(b["binary_id"])] = {
                "path": b.get("path", ""),
                "full_path": b["full_path"],
                "has_vulnerability": b["has_vulnerability"],
                "difficulty": b.get("difficulty"),
                "source_functions": yaml_data["affected_functions"],
                "functions": {},
            }

        ground_truth[cve_id] = gt_entry
        stats["selected"] += 1

    print(f"\n=== Selection Stats (pre-mapping) ===")
    for k, v in stats.items():
        print(f"  {k}: {v}")

    from collections import Counter
    diff_counts = Counter()
    for entry in selected:
        for v in entry["variants"]:
            if v["has_vulnerability"]:
                diff_counts[v["difficulty"]] += 1
            else:
                diff_counts["fixed"] += 1
    print(f"\nVariant breakdown:")
    for d, c in sorted(diff_counts.items()):
        print(f"  {d}: {c}")

    if args.shards_only:
        decoys, dropped = merge_shards_only(selected, ground_truth)
    elif args.cve_workers > 1 and args.workers >= 1:
        decoys, dropped = generate_decoys_hybrid_parallel(
            selected, ground_truth,
            with_decoys=not args.skip_decoys,
            cve_workers=args.cve_workers,
            bin_workers=args.workers,
            per_bin_timeout=args.per_bin_timeout,
            cve_timeout=args.timeout)
    elif args.workers >= 1:
        decoys, dropped = generate_decoys_inner_parallel(
            selected, ground_truth,
            with_decoys=not args.skip_decoys,
            inner_workers=args.workers,
            per_bin_timeout=args.per_bin_timeout,
            cve_timeout=args.timeout)
    else:
        decoys, dropped = generate_decoys(
            selected, ground_truth,
            with_decoys=not args.skip_decoys)

    dropped_set = set(dropped)
    if dropped_set:
        selected = [e for e in selected if e["cve_id"] not in dropped_set]
        print(f"\n  Dropped {len(dropped_set)} CVEs "
              f"(reference mapping failed): "
              f"{', '.join(sorted(dropped_set)[:5])}"
              f"{'...' if len(dropped_set) > 5 else ''}")

    with open(OUTPUT_SELECTED, "w") as f:
        json.dump(selected, f, indent=2)

    meta_path = os.path.join(
        os.path.dirname(OUTPUT_SELECTED), "selection_meta.json")
    with open(meta_path, "w") as f:
        json.dump({"random_seed": RANDOM_SEED,
                   "cve_count": len(selected),
                   "dropped_after_mapping": sorted(dropped_set),
                   }, f, indent=2)

    if not args.skip_decoys:
        with open(OUTPUT_DECOYS, "w") as f:
            json.dump(decoys, f, indent=2)
        print(f"\n  {OUTPUT_DECOYS} ({len(decoys)} CVEs with decoys)")
    else:
        print("\nSkipped decoy generation (--skip-decoys) -- "
              "ground-truth mapping still ran.")

    with open(OUTPUT_GT, "w") as f:
        json.dump(ground_truth, f, indent=2)
    print(f"  {OUTPUT_SELECTED} ({len(selected)} CVEs)")
    print(f"  {OUTPUT_GT} ({len(ground_truth)} CVEs)")


if __name__ == "__main__":
    main()
