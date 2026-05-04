#!/usr/bin/env python3
"""For each dataset CVE, write cves/20_affected_binaries/<CVE>.csv listing every binary in the DB for that package and whether it is actually affected."""

import argparse
import json
import os
import re
import csv
import sys
from pathlib import Path
from collections import defaultdict

import duckdb
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import _paths

DB_PATH = _paths.DUCKDB_PATH
DATASET_DIR = Path(_paths.DATASET_DIR)
PATCH_DIR = Path(_paths.PATCH_DIR)
OUTPUT_DIR = Path(_paths.AB_DIR)
CVE_PKG_CSV = Path(_paths.CVE_PKG_CSV)
VERSIONS_JSON = Path(_paths.CVES_DIR) / "versions.json"
BINARY_VERSIONS_JSON = Path(_paths.CVES_DIR) / "binary_versions.json"


def log(msg):
    print(msg, flush=True)


def normalize_version(ver):
    """Normalize version string for comparison."""
    ver = str(ver).strip()
    ver = re.sub(r'^(v|R_|REL_|release-|libpng-|R_2_|OpenSSL_)', '', ver, flags=re.I)
    ver = ver.replace('_', '.')
    ver = re.sub(r'-(signed|beta|rc\d+|alpha|dev|pre).*$', '', ver, flags=re.I)
    return ver


def version_tuple(ver):
    """Parse version string into tuple for comparison."""
    ver = normalize_version(ver)
    parts = re.findall(r'\d+', ver)
    return tuple(int(p) for p in parts) if parts else ()


def version_in_range(our_ver, v_start=None, v_end_exc=None, v_end_inc=None):
    """Check if our_ver is within [v_start, v_end_exc) or [v_start, v_end_inc]."""
    vt = version_tuple(our_ver)
    if not vt:
        return None

    if v_start:
        st = version_tuple(v_start)
        if st and vt < st:
            return False

    if v_end_exc:
        et = version_tuple(v_end_exc)
        if et:
            if vt >= et:
                return False
            return True

    if v_end_inc:
        et = version_tuple(v_end_inc)
        if et:
            if vt > et:
                return False
            return True

    if v_start:
        return True

    return None


def get_affected_versions_from_nvd(cve_id, cve_json_path, pkg_name, our_versions):
    """Determine which of our versions are affected using NVD data."""
    data = json.load(open(cve_json_path))
    cna = data.get("containers", {}).get("cna", {})
    affected_list = cna.get("affected", [])

    affected = set()
    unaffected = set()
    checked = False

    for a in affected_list:
        product = a.get("product", "").lower()
        if pkg_name.lower() not in product and product not in pkg_name.lower():
            pkg_clean = pkg_name.lower().replace("-", "").replace("_", "")
            prod_clean = product.replace("-", "").replace("_", "")
            if pkg_clean not in prod_clean and prod_clean not in pkg_clean:
                if product != "n/a" and product:
                    continue

        for v in a.get("versions", []):
            ver = v.get("version", "")
            status = v.get("status", "")
            less_than = v.get("lessThan", "")
            less_eq = v.get("lessThanOrEqual", "")

            if less_than or less_eq:
                checked = True
                for our_ver in our_versions:
                    result = version_in_range(our_ver, ver if ver != "n/a" else None, less_than, less_eq)
                    if result is True:
                        affected.add(our_ver)
                    elif result is False:
                        unaffected.add(our_ver)
            elif ">=" in ver or "<" in ver:
                checked = True
                parts = re.split(r',\s*', ver)
                v_start = None
                v_end_exc = None
                v_end_inc = None
                for part in parts:
                    m = re.match(r'>=?\s*([\d.]+)', part)
                    if m:
                        v_start = m.group(1)
                    m = re.match(r'<\s*([\d.]+)', part)
                    if m:
                        v_end_exc = m.group(1)
                    m = re.match(r'<=\s*([\d.]+)', part)
                    if m:
                        v_end_inc = m.group(1)
                for our_ver in our_versions:
                    result = version_in_range(our_ver, v_start, v_end_exc, v_end_inc)
                    if result is True:
                        affected.add(our_ver)
                    elif result is False:
                        unaffected.add(our_ver)
            elif ver and ver != "n/a" and status == "affected":
                checked = True
                exact = ver.lstrip("=").strip()
                for our_ver in our_versions:
                    if normalize_version(our_ver) == normalize_version(exact):
                        affected.add(our_ver)
                    else:
                        unaffected.add(our_ver)

    return affected, unaffected, checked


_VER_TOKEN = r'v?[\d]+\.[\d]+[\d.A-Za-z_\-]*'

_VER_RE = re.compile(r'^v?\d+(\.\d+)+')


def get_affected_from_description(desc, our_versions, pkg=None):
    """Extract version info from description text."""
    affected = set()
    unaffected = set()
    checked = False

    for pat in (
        rf'before\s+({_VER_TOKEN})',
        rf'prior\s+to\s+({_VER_TOKEN})',
        rf'earlier\s+than\s+({_VER_TOKEN})',
        rf'versions?\s+(?:prior\s+to|before|older\s+than)\s+({_VER_TOKEN})',
    ):
        for m in re.finditer(pat, desc, re.I):
            fixed_ver = m.group(1)
            checked = True
            for our_ver in our_versions:
                r = version_in_range(our_ver, None, fixed_ver, None)
                if r is True: affected.add(our_ver)
                elif r is False: unaffected.add(our_ver)

    for pat in (
        rf'through\s+({_VER_TOKEN})',
        rf'up\s+to\s+(?:and\s+including\s+)?({_VER_TOKEN})',
        rf'({_VER_TOKEN})\s+and\s+(?:earlier|below|prior|older)',
        rf'({_VER_TOKEN})\s+and\s+prior\s+versions?',
    ):
        for m in re.finditer(pat, desc, re.I):
            last_ver = m.group(1)
            checked = True
            for our_ver in our_versions:
                r = version_in_range(our_ver, None, None, last_ver)
                if r is True: affected.add(our_ver)
                elif r is False: unaffected.add(our_ver)

    if pkg:
        pkg_aliases = {pkg, pkg.lower(), pkg.replace('-', ''),
                       pkg.replace('lib', '', 1) if pkg.startswith('lib') else pkg,
                       'lib' + pkg if not pkg.startswith('lib') else pkg}
        for alias in pkg_aliases:
            for pat in (
                rf'\b{re.escape(alias)}\s+({_VER_TOKEN})\s+(?:is|was|contains?|allows?|has|exhibits?|suffers?)',
                rf'\bin\s+{re.escape(alias)}\s+({_VER_TOKEN})\b',
                rf'\b{re.escape(alias)}\s+(?:version\s+)?({_VER_TOKEN})\s+is\s+vulnerable',
                rf'\b{re.escape(alias)}\s+v?({_VER_TOKEN})\s+was\s+discovered',
            ):
                for m in re.finditer(pat, desc, re.I):
                    exact = m.group(1)
                    checked = True
                    for our_ver in our_versions:
                        if version_tuple(our_ver) == version_tuple(exact):
                            affected.add(our_ver)
                        else:
                            unaffected.add(our_ver)

    return affected, unaffected, checked


def _tail_ident(name: str) -> str:
    """Return the trailing identifier of a C++ qualified name."""
    if "::" in name:
        name = name.split("::")[-1]
    return re.split(r"[(\s<]", name)[0]


_WORD_RE_CACHE = {}


def _symbol_hit(yaml_name: str, bin_symbols: list[str]) -> bool:
    """Whether yaml_name appears in the binary's symbol set (exact or trailing-ident match)."""
    if not yaml_name:
        return False
    tail = _tail_ident(yaml_name)
    if not tail or len(tail) < 4:
        return False
    if tail not in _WORD_RE_CACHE:
        _WORD_RE_CACHE[tail] = re.compile(rf"\b{re.escape(tail)}\b")
    tail_re = _WORD_RE_CACHE[tail]
    for s in bin_symbols:
        if s == yaml_name or s == tail:
            return True
        if tail_re.search(s):
            return True
    return False


_FUNC_CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]{2,})\s*\(")
_HUNK_HEADER_RE = re.compile(r"^@@ .*? @@\s*(.*)$")
_FUNC_BLACKLIST = {
    "if", "else", "for", "while", "do", "switch", "return", "sizeof",
    "typedef", "static", "const", "void", "int", "char", "long", "short",
    "unsigned", "signed", "struct", "union", "enum", "break", "continue",
    "goto", "case", "default", "inline", "extern", "register", "volatile",
    "assert", "memcpy", "memset", "memmove", "memcmp", "strcpy", "strncpy",
    "strcmp", "strncmp", "strlen", "strcat", "strncat", "malloc", "free",
    "calloc", "realloc", "printf", "fprintf", "snprintf", "sprintf",
    "fputs", "fgets", "fread", "fwrite", "fopen", "fclose", "exit",
    "abort", "min", "max", "MIN", "MAX", "NULL",
}


def _ident_from_signature(raw):
    if not raw or raw == "n/a":
        return ""
    return re.split(r"[(\s<]", raw.strip().strip('"').strip())[0]


_C_CPP_EXTS = {".c", ".cc", ".cpp", ".cxx", ".c++", ".h", ".hpp", ".hxx", ".h++", ".inl", ".ipp", ".S", ".s", ".asm"}

_FOREIGN_BINDING_DIRS = (
    "/php/", "/python/", "/py/", "/ruby/", "/csharp/", "/java/",
    "/javascript/", "/js/", "/node_modules/", "/nodejs/", "/go/",
    "/kotlin/", "/swift/", "/rust/",
)
_AUTOGEN_PATTERNS = (".pb.h", ".pb.cc", ".pb.c", ".pb.cpp", ".grpc.pb.",)


def _is_real_c_source(path: str) -> bool:
    """True iff the path is a C/C++ source file genuinely part of the C build."""
    if not path:
        return False
    if Path(path).suffix.lower() not in _C_CPP_EXTS:
        return False
    lower = "/" + path.lower().lstrip("/")
    if any(d in lower for d in _FOREIGN_BINDING_DIRS):
        return False
    if any(p in lower for p in _AUTOGEN_PATTERNS):
        return False
    return True


def classify_patch_ecosystem(cve_id: str) -> str:
    """Inspect file extensions referenced in a patch YAML; returns 'c_cpp' / 'other' / 'unknown'."""
    p = PATCH_DIR / f"{cve_id}.yaml"
    if not p.exists():
        return "unknown"
    try:
        data = yaml.safe_load(p.read_text()) or {}
    except Exception:
        return "unknown"
    cc = data.get("code_changes") or []
    files = [entry.get("file", "") for entry in cc if isinstance(entry, dict)]
    files = [f for f in files if f]
    if not files:
        return "unknown"
    has_real_c = any(_is_real_c_source(f) for f in files)
    return "c_cpp" if has_real_c else "other"


def load_affected_functions(cve_id):
    """Return the deduped list of function-name candidates relevant to this CVE."""
    p = PATCH_DIR / f"{cve_id}.yaml"
    if not p.exists():
        return []
    try:
        data = yaml.safe_load(p.read_text()) or {}
    except Exception:
        return []

    names = []

    for entry in data.get("affected_functions") or []:
        if not isinstance(entry, dict):
            continue
        src = entry.get("source_file") or ""
        if src and not _is_real_c_source(src):
            continue
        n = (entry.get("name") or "").strip().strip('"').strip()
        if n and len(n) >= 4 and n not in _FUNC_BLACKLIST:
            names.append(n)

    for cc in data.get("code_changes") or []:
        if not isinstance(cc, dict):
            continue
        fpath = cc.get("file") or ""
        if not _is_real_c_source(fpath):
            continue
        for key in ("fix_function", "function"):
            if key in cc:
                ident = _ident_from_signature(cc[key])
                if ident and len(ident) >= 4 and ident not in _FUNC_BLACKLIST:
                    names.append(ident)
        hunks_text = cc.get("hunks") or ""
        for line in hunks_text.splitlines():
            m = _HUNK_HEADER_RE.match(line)
            if m:
                sig_ident = _ident_from_signature(m.group(1))
                if sig_ident and len(sig_ident) >= 4 and sig_ident not in _FUNC_BLACKLIST:
                    names.append(sig_ident)
                continue
            if line.startswith("-") and not line.startswith("---"):
                for mc in _FUNC_CALL_RE.finditer(line[1:]):
                    ident = mc.group(1)
                    if len(ident) >= 4 and ident not in _FUNC_BLACKLIST:
                        names.append(ident)

    seen = set(); out = []
    for n in names:
        if n not in seen:
            seen.add(n); out.append(n)
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--cves",
        help="comma-separated CVE ids to process (skip others)",
    )
    ap.add_argument(
        "--max-cves", type=int,
        help="process only the first N CVEs (sorted)",
    )
    args = ap.parse_args()

    conn = duckdb.connect(DB_PATH, read_only=True)
    cur = conn.cursor()
    cur.execute(
        "SELECT DISTINCT github_url, package_name FROM binaries "
        "WHERE package_name IS NOT NULL AND github_url IS NOT NULL "
        "AND github_url != ''"
    )
    gh_to_pkg = {}
    gh_conflicts = set()
    for gh, pkg in cur.fetchall():
        if gh in gh_to_pkg and gh_to_pkg[gh] != pkg:
            gh_conflicts.add(gh)
        else:
            gh_to_pkg[gh] = pkg
    if gh_conflicts:
        log(f"WARN: {len(gh_conflicts)} github_urls map to multiple packages; kept first")

    cur.execute(
        "SELECT DISTINCT github_url, repo_commit, version FROM binaries "
        "WHERE version IS NOT NULL AND github_url IS NOT NULL AND github_url != '' "
        "AND repo_commit IS NOT NULL AND repo_commit != ''"
    )
    gh_commit_to_ver = {}
    for gh, commit, ver in cur.fetchall():
        gh_commit_to_ver.setdefault((gh, commit), ver)

    cur.execute(
        "SELECT id, package_name, version, file_name, github_url, repo_commit "
        "FROM binaries"
    )
    pkg_binaries = defaultdict(list)
    pkg_versions = defaultdict(set)
    n_pkg_recovered = 0
    n_ver_direct = 0
    n_ver_rosetta = 0
    for bid, pkg, ver, fname, gh, commit in cur.fetchall():
        if not pkg and gh:
            pkg = gh_to_pkg.get(gh)
            if pkg:
                n_pkg_recovered += 1
        if not pkg:
            continue
        if not ver and commit:
            c = str(commit)
            if _VER_RE.match(c):
                ver = c
                n_ver_direct += 1
            elif gh and (gh, commit) in gh_commit_to_ver:
                ver = gh_commit_to_ver[(gh, commit)]
                n_ver_rosetta += 1
        pkg_binaries[pkg].append((bid, ver, fname))
        if ver:
            pkg_versions[pkg].add(ver)
    log(f"DB: {sum(len(v) for v in pkg_binaries.values())} binaries "
        f"across {len(pkg_binaries)} packages "
        f"(package_name: {n_pkg_recovered} recovered via github_url; "
        f"version: {n_ver_direct} direct + {n_ver_rosetta} rosetta)")

    symbol_cache: dict[int, list[str]] = {}
    def get_symbols(bid: int) -> list[str]:
        cached = symbol_cache.get(bid)
        if cached is not None:
            return cached
        rows = conn.execute(
            "SELECT name FROM functions WHERE binary_id=?", [bid]
        ).fetchall()
        names = [r[0] for r in rows if r[0]]
        symbol_cache[bid] = names
        return names

    cve_pkg = {}
    with open(CVE_PKG_CSV) as f:
        for row in csv.DictReader(f):
            if row["package_name"]:
                cve_pkg[row["cve"]] = row["package_name"]

    existing_binver = {}
    if BINARY_VERSIONS_JSON.exists():
        existing_binver = json.load(open(BINARY_VERSIONS_JSON))

    nvd_versions = {}
    if VERSIONS_JSON.exists():
        nvd_versions = json.load(open(VERSIONS_JSON))

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    verified = sorted(f.replace(".json", "") for f in os.listdir(DATASET_DIR) if f.endswith(".json"))
    if args.cves:
        wanted = {c.strip() for c in args.cves.split(",") if c.strip()}
        verified = [c for c in verified if c in wanted]
    if args.max_cves:
        verified = verified[: args.max_cves]
    log(f"Processing {len(verified)} verified CVEs...")

    stats = {"total": 0, "with_affected_version": 0, "with_confirmed_binary": 0, "no_version_info": 0, "no_pkg_match": 0, "wrong_ecosystem": 0}

    for i, cve_id in enumerate(verified):
        pkg = cve_pkg.get(cve_id, "")
        if not pkg or pkg not in pkg_versions:
            stats["no_pkg_match"] += 1
            continue

        stats["total"] += 1
        our_versions = pkg_versions[pkg]
        cve_json_path = DATASET_DIR / f"{cve_id}.json"

        affected_vers = set()
        unaffected_vers = set()
        checked = False

        if cve_id in existing_binver:
            bv = existing_binver[cve_id]
            affected_vers = set(bv.get("affected_versions", []))
            unaffected_vers = set(bv.get("unaffected_versions", []))
            if affected_vers or unaffected_vers:
                checked = True

        if not checked:
            aff, unaff, chk = get_affected_versions_from_nvd(cve_id, cve_json_path, pkg, our_versions)
            if chk:
                affected_vers |= aff
                unaffected_vers |= unaff
                checked = True

        if not checked:
            data = json.load(open(cve_json_path))
            desc = data.get("containers", {}).get("cna", {}).get("descriptions", [{}])[0].get("value", "")
            aff, unaff, chk = get_affected_from_description(desc, our_versions, pkg=pkg)
            if chk:
                affected_vers |= aff
                unaffected_vers |= unaff
                checked = True

        if not checked and cve_id in nvd_versions:
            vdata = nvd_versions[cve_id]
            for v_entry in vdata.get("versions", []):
                v_range = v_entry.get("affected_range", "")
                fixed = v_entry.get("fixed_version", "")
                last_aff = v_entry.get("last_affected", "")
                if fixed:
                    for our_ver in our_versions:
                        r = version_in_range(our_ver, None, fixed, None)
                        if r is True:
                            affected_vers.add(our_ver)
                        elif r is False:
                            unaffected_vers.add(our_ver)
                    checked = True
                elif last_aff:
                    for our_ver in our_versions:
                        r = version_in_range(our_ver, None, None, last_aff)
                        if r is True:
                            affected_vers.add(our_ver)
                        elif r is False:
                            unaffected_vers.add(our_ver)
                    checked = True

        if not checked:
            stats["no_version_info"] += 1
            affected_vers = set()
            unaffected_vers = set()

        ecosystem = classify_patch_ecosystem(cve_id)
        if ecosystem == "other":
            stats["wrong_ecosystem"] = stats.get("wrong_ecosystem", 0) + 1
            out_path = OUTPUT_DIR / f"{cve_id}.csv"
            with open(out_path, "w", newline="") as f:
                w = csv.writer(f)
                w.writerow(["binary_id", "package_name", "version", "file_name", "affected", "reason"])
                for bid, ver, fname in sorted(pkg_binaries[pkg], key=lambda x: (x[1] or "")):
                    w.writerow([bid, pkg, ver, fname, "no", "wrong_ecosystem"])
            continue

        affected_funcs = load_affected_functions(cve_id)
        has_patch_yaml = (PATCH_DIR / f"{cve_id}.yaml").exists()

        if affected_vers:
            stats["with_affected_version"] += 1

        out_path = OUTPUT_DIR / f"{cve_id}.csv"
        any_confirmed = False
        with open(out_path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["binary_id", "package_name", "version", "file_name", "affected", "reason"])
            for bid, ver, fname in sorted(pkg_binaries[pkg], key=lambda x: (x[1] or "")):
                if ver in affected_vers:
                    if not affected_funcs:
                        if has_patch_yaml:
                            status, reason = "unknown", "no_extractable_funcs"
                        else:
                            status, reason = "yes", "version_match_no_patch_yaml"
                    else:
                        syms = get_symbols(bid)
                        if not syms:
                            status, reason = "no", "no_symbol_data"
                        elif any(_symbol_hit(fn, syms) for fn in affected_funcs):
                            status, reason = "yes", "version+function_match"
                            any_confirmed = True
                        else:
                            status, reason = "no", "version_match_function_absent"
                elif ver in unaffected_vers:
                    status, reason = "no", "version_mismatch"
                else:
                    status, reason = "unknown", "no_version_info"
                w.writerow([bid, pkg, ver, fname, status, reason])

        if any_confirmed:
            stats["with_confirmed_binary"] += 1

        if (i + 1) % 50 == 0:
            log(f"  [{i+1}/{len(verified)}] cache={len(symbol_cache)} "
                f"confirmed_CVEs={stats['with_confirmed_binary']}")

    conn.close()
    log(f"\n=== Done ===")
    log(f"Total CVEs processed: {stats['total']}")
    log(f"With >=1 version-matched binary: {stats['with_affected_version']}")
    log(f"With >=1 function-confirmed binary: {stats['with_confirmed_binary']}")
    log(f"Wrong ecosystem (non C/C++ patch): {stats['wrong_ecosystem']}")
    log(f"No version info (all unknown): {stats['no_version_info']}")
    log(f"No package in DB: {stats['no_pkg_match']}")
    log(f"Output: {OUTPUT_DIR}/")


if __name__ == "__main__":
    main()
