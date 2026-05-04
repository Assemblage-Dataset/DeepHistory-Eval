#!/usr/bin/env python3
"""Unified patch pipeline for dataset CVEs (fetch + enrich subcommands)."""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import duckdb
import yaml


sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import _paths

DATASET_DIR = Path(_paths.DATASET_DIR)
PATCH_DIR = Path(_paths.PATCH_DIR)
NOPATCH_DIR = Path(_paths.NOPATCH_DIR)
DIFFS_DIR = Path(_paths.DIFFS_DIR)
CVE_PKG_CSV = Path(_paths.CVE_PKG_CSV)
ADVISORY_DIR = Path(_paths.ADVISORY_DIR)
SECRETS_ENV = Path(_paths.SECRETS_ENV)
DB_PATH = _paths.DUCKDB_PATH

DEBIAN_LIST_URL = (
    "https://salsa.debian.org/security-tracker-team/security-tracker/"
    "-/raw/master/data/CVE/list"
)
DEBIAN_LIST_CACHE = Path("/tmp/debian_cve_list.txt")


COMMIT_URL_RE = re.compile(
    r"(https?://(?:github\.com|gitlab\.[^/]+)/([^/\s]+/[^/\s]+))/commit/([0-9a-f]{7,40})"
)
GITHUB_COMMIT_RE = re.compile(
    r"(https?://github\.com/[^/]+/[^/]+)/commit/([0-9a-f]{7,40})"
)
GITHUB_PR_RE = re.compile(r"https?://github\.com/([^/]+/[^/]+)/pull/(\d+)")
GHSA_URL_RE = re.compile(
    r"https?://github\.com/([^/]+/[^/]+)/security/advisories/(GHSA-[a-z0-9-]+)",
    re.IGNORECASE,
)
GITLAB_COMMIT_RE = re.compile(
    r"(https?://gitlab\.[^/]+/[^/]+/[^/]+)/-/commit/([0-9a-f]{7,40})"
)
HUNK_HEADER_RE = re.compile(
    r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@\s*(.*)$"
)
DIFF_FILE_RE = re.compile(r"^diff --git a/(.+?) b/(.+?)$")

HUNK_CAP_BYTES = 64 * 1024


def _load_github_token() -> str:
    if SECRETS_ENV.exists():
        for line in SECRETS_ENV.read_text().splitlines():
            if line.startswith("GITHUB_TOKEN="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    return os.environ.get("GITHUB_TOKEN", "")


GITHUB_TOKEN = _load_github_token()


def gh_api(url: str, accept: str = "application/vnd.github+json") -> dict | None:
    headers = {"User-Agent": "patch-pipeline", "Accept": accept}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"token {GITHUB_TOKEN}"
    for attempt in range(3):
        try:
            with urllib.request.urlopen(
                urllib.request.Request(url, headers=headers), timeout=15
            ) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            if e.code in (403, 429):
                reset = int(e.headers.get("X-RateLimit-Reset", 0) or 0)
                wait = max(0, reset - time.time()) + 2
                if 0 < wait < 120 and attempt < 2:
                    time.sleep(wait)
                    continue
            if e.code in (404, 422):
                return None
            time.sleep(2)
        except Exception:
            time.sleep(2)
    return None


def fetch_osv(cve_id: str) -> dict | None:
    url = f"https://api.osv.dev/v1/vulns/{cve_id}"
    for attempt in range(3):
        try:
            with urllib.request.urlopen(
                urllib.request.Request(url), timeout=15
            ) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            if e.code == 429 and attempt < 2:
                time.sleep(2 ** attempt)
                continue
            return None
        except Exception:
            if attempt < 2:
                time.sleep(2 ** attempt)
                continue
            return None
    return None


def fetch_plain(url: str) -> str | None:
    headers = {"User-Agent": "patch-pipeline"}
    for attempt in range(3):
        try:
            with urllib.request.urlopen(
                urllib.request.Request(url, headers=headers), timeout=30
            ) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < 2:
                time.sleep(2 ** (attempt + 2))
                continue
            return None
        except Exception:
            if attempt < 2:
                time.sleep(2)
                continue
            return None
    return None


def derive_diff_url(commit_url: str) -> str | None:
    """Return a plain-text diff URL for the given commit URL, or None."""
    m = GITHUB_COMMIT_RE.search(commit_url)
    if m:
        return f"{m.group(1)}/commit/{m.group(2)}.diff"
    m = GITLAB_COMMIT_RE.search(commit_url)
    if m:
        return f"{m.group(1)}/-/commit/{m.group(2)}.diff"
    m = re.match(
        r"(https?://git\.savannah\.gnu\.org/cgit/[^?]+?)/commit/", commit_url
    )
    if m:
        base = m.group(1)
        sha_m = re.search(r"id=([0-9a-f]{7,40})", commit_url)
        if sha_m:
            return f"{base}/patch/?id={sha_m.group(1)}"
    return None


def parse_hunks(diff_text: str, max_bytes: int = HUNK_CAP_BYTES) -> list[dict]:
    """Parse a unified diff into [{file, fix_function, hunks}, ...]."""
    idx = diff_text.find("diff --git")
    if idx > 0 and not diff_text[:idx].strip().startswith("diff"):
        diff_text = diff_text[idx:]

    out: list[dict] = []
    cur_file: str | None = None
    cur_hunk: list[str] = []
    cur_func: str = ""

    def flush() -> None:
        if cur_file and cur_hunk:
            out.append(
                {
                    "file": cur_file,
                    "fix_function": cur_func.strip(),
                    "hunks": "".join(cur_hunk),
                }
            )

    for line in diff_text.splitlines(keepends=True):
        stripped = line.rstrip("\n")
        m = DIFF_FILE_RE.match(stripped)
        if m:
            flush()
            cur_file = m.group(2)
            cur_hunk = []
            cur_func = ""
            continue
        m = HUNK_HEADER_RE.match(stripped)
        if m:
            flush()
            cur_func = m.group(5) or ""
            cur_hunk = [line]
            continue
        if cur_hunk:
            if line.startswith("diff --git "):
                continue
            cur_hunk.append(line)
    flush()

    total = 0
    capped: list[dict] = []
    for h in out:
        size = len(h["hunks"])
        if total + size > max_bytes:
            h = dict(h)
            h["hunks"] = h["hunks"][: max(0, max_bytes - total)]
            capped.append(h)
            break
        total += size
        capped.append(h)
    return capped


def yaml_scalar(value: object) -> str:
    s = "" if value is None else str(value)
    if s == "":
        return '""'
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


_REJECTED_IDENT_TOKENS = {
    "static", "extern", "inline", "const", "volatile", "register",
    "typedef", "struct", "class", "enum", "union", "template",
    "virtual", "auto", "void", "int", "char", "long", "short",
    "float", "double", "unsigned", "signed", "bool", "size_t",
    "public", "private", "protected", "namespace", "using",
    "explicit", "friend", "override", "final",
    "if", "else", "for", "while", "do", "switch", "case",
    "return", "break", "continue", "goto", "sizeof", "typeof",
    "catch", "throw", "try", "new", "delete",
    "true", "false", "null", "None", "NULL",
}


def extract_function_name(raw: str) -> str:
    """Extract a function identifier from a diff hunk header's trailing context."""
    s = raw.strip()
    if not s:
        return ""
    m = re.match(r"^(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", s)
    if m:
        return m.group(1)
    head = re.split(r"[{;]", s, maxsplit=1)[0]
    matches = re.findall(
        r"(~?[A-Za-z_][A-Za-z0-9_]*(?:\s*::\s*~?[A-Za-z_][A-Za-z0-9_]*)*)\s*\(",
        head,
    )
    if not matches:
        return ""
    last = matches[-1]
    last = re.sub(r"\s*::\s*", "::", last)
    if last.lstrip("~") in _REJECTED_IDENT_TOKENS:
        return ""
    return last


def write_patch_yaml(
    cve_id: str,
    package: str,
    description: str,
    commits: list[dict],
    code_changes: list[dict],
    out_path: Path,
) -> None:
    affected: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for cc in code_changes:
        raw = cc.get("fix_function") or ""
        ident = extract_function_name(raw)
        key = (ident, cc["file"])
        if ident and key not in seen:
            seen.add(key)
            affected.append((ident, cc["file"]))

    lines = [
        f"cve_id: {cve_id}",
        f"package: {package}",
        f"description: {yaml_scalar(description)}",
        "",
        "affected_functions:",
    ]
    for name, source_file in affected:
        lines.append(f"  - name: {yaml_scalar(name)}")
        lines.append(f"    source_file: {yaml_scalar(source_file)}")
    if not affected:
        lines.append("  []")
    lines.append("")
    lines.append("fix_commits:")
    for c in commits:
        lines.append(f"  - sha: {yaml_scalar(c['commit'])}")
        lines.append(f"    repo: {yaml_scalar(c['repo'])}")
        lines.append(f"    url: {yaml_scalar(c.get('url', ''))}")
        lines.append(f"    source: {yaml_scalar(c.get('source', 'unknown'))}")
    lines.append("")
    lines.append("code_changes:")
    if code_changes:
        for cc in code_changes:
            lines.append(f"  - commit: {yaml_scalar(cc['commit'])}")
            lines.append(f"    file: {yaml_scalar(cc['file'])}")
            lines.append(f"    fix_function: {yaml_scalar(cc.get('fix_function', ''))}")
            lines.append("    hunks: |")
            for hunk_line in cc.get("hunks", "").splitlines():
                lines.append("      " + hunk_line)
    else:
        lines.append("  []")
    out_path.write_text("\n".join(lines) + "\n")


def write_nopatch_yaml(
    cve_id: str, package: str, description: str, reason: str, out_path: Path
) -> None:
    lines = [
        f"cve_id: {cve_id}",
        f"package: {package}",
        f"description: {yaml_scalar(description)}",
        f"reason: {yaml_scalar(reason)}",
        "",
    ]
    out_path.write_text("\n".join(lines))


def get_description(cve_path: Path) -> str:
    data = json.loads(cve_path.read_text())
    descs = data.get("containers", {}).get("cna", {}).get("descriptions", []) or []
    for d in descs:
        if d.get("lang") == "en":
            return (d.get("value") or "")[:2000]
    if descs:
        return (descs[0].get("value") or "")[:2000]
    return ""


def load_cve_pkg_map() -> dict[str, str]:
    m: dict[str, str] = {}
    if not CVE_PKG_CSV.exists():
        return m
    with CVE_PKG_CSV.open() as f:
        next(f, None)
        for line in f:
            parts = line.rstrip("\n").split(",", 1)
            if len(parts) == 2:
                m[parts[1]] = parts[0]
    return m


def fetch_and_cache_diff(cve_id: str, commit: dict) -> str | None:
    """Download (or read from cache) the .diff for a commit; return its text."""
    sha = commit["commit"]
    cve_dir = DIFFS_DIR / cve_id
    cve_dir.mkdir(parents=True, exist_ok=True)
    diff_path = cve_dir / f"{sha[:10]}.diff"
    if (
        diff_path.exists()
        and diff_path.stat().st_size > 0
        and not diff_path.read_text(errors="ignore").startswith("#")
    ):
        return diff_path.read_text(errors="ignore")
    url = commit.get("url", "")
    diff_url = derive_diff_url(url)
    if not diff_url:
        diff_path.write_text(
            f"# Non-parseable commit URL: {url}\n# commit: {sha}\n"
        )
        return None
    text = fetch_plain(diff_url)
    if not text:
        diff_path.write_text(f"# FETCH FAILED for {url}\n")
        return None
    diff_path.write_text(text)
    return text


def commits_to_code_changes(
    cve_id: str, commits: list[dict]
) -> tuple[list[dict], list[dict]]:
    """Fetch all diffs, return (kept_commits, code_changes)."""
    kept: list[dict] = []
    code_changes: list[dict] = []
    for c in commits:
        text = fetch_and_cache_diff(cve_id, c)
        if not text:
            continue
        kept.append(c)
        for h in parse_hunks(text):
            code_changes.append(
                {
                    "commit": c["commit"],
                    "file": h["file"],
                    "fix_function": h["fix_function"],
                    "hunks": h["hunks"],
                }
            )
    return kept, code_changes


def convert_nopatch_to_patch(
    cve_id: str,
    commits: list[dict],
    source_label: str,
    dry_run: bool = False,
) -> str:
    nopatch_path = NOPATCH_DIR / f"{cve_id}.yaml"
    patch_path = PATCH_DIR / f"{cve_id}.yaml"
    if patch_path.exists():
        return "already-patch"
    if not nopatch_path.exists():
        return "not-in-nopatch"

    for c in commits:
        c.setdefault("source", source_label)

    kept, code_changes = commits_to_code_changes(cve_id, commits)
    if not kept:
        return "fetch-failed"
    if dry_run:
        return f"would-convert ({len(kept)} commits, {len(code_changes)} hunks)"

    nd = yaml.safe_load(nopatch_path.read_text()) or {}
    write_patch_yaml(
        cve_id=cve_id,
        package=nd.get("package", "") or "",
        description=nd.get("description", "") or "",
        commits=kept,
        code_changes=code_changes,
        out_path=patch_path,
    )
    nopatch_path.unlink()
    return f"ok ({len(kept)} commits, {len(code_changes)} hunks)"


def _dedup_commits(d: dict[str, list[dict]]) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for cve, commits in d.items():
        seen: set[tuple[str, str]] = set()
        uniq: list[dict] = []
        for c in commits:
            key = (c["repo"].rstrip("/"), c["commit"])
            if key in seen:
                continue
            seen.add(key)
            uniq.append(c)
        if uniq:
            out[cve] = uniq
    return out


def extract_from_cve_json(cve_path: Path) -> tuple[list[dict], list[tuple]]:
    data = json.loads(cve_path.read_text())
    commits: list[dict] = []
    prs: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()
    refs: list[dict] = []
    cna = data.get("containers", {}).get("cna", {})
    refs.extend(cna.get("references", []) or [])
    for adp in data.get("containers", {}).get("adp", []) or []:
        refs.extend(adp.get("references", []) or [])
    for ref in refs:
        url = ref.get("url", "")
        m = COMMIT_URL_RE.search(url)
        if m:
            key = (m.group(1), m.group(3))
            if key not in seen:
                seen.add(key)
                commits.append(
                    {
                        "repo": f"https://github.com/{m.group(2)}"
                        if "github.com" in m.group(1)
                        else m.group(1),
                        "commit": m.group(3),
                        "url": url,
                        "source": "cve_json",
                    }
                )
        m = GITHUB_PR_RE.search(url)
        if m:
            prs.append((m.group(1), m.group(2), url))
    return commits, prs


def extract_from_osv(osv: dict) -> tuple[list[dict], list[tuple]]:
    commits: list[dict] = []
    prs: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()
    for ref in osv.get("references", []) or []:
        url = ref.get("url", "")
        m = COMMIT_URL_RE.search(url)
        if m:
            key = (m.group(1), m.group(3))
            if key not in seen:
                seen.add(key)
                commits.append(
                    {
                        "repo": f"https://github.com/{m.group(2)}"
                        if "github.com" in m.group(1)
                        else m.group(1),
                        "commit": m.group(3),
                        "url": url,
                        "source": "osv_ref",
                    }
                )
        m = GITHUB_PR_RE.search(url)
        if m:
            prs.append((m.group(1), m.group(2), url))
    for aff in osv.get("affected", []) or []:
        for rng in aff.get("ranges", []) or []:
            if rng.get("type") != "GIT":
                continue
            repo = rng.get("repo", "")
            for ev in rng.get("events", []) or []:
                sha = ev.get("fixed")
                if sha:
                    key = (repo, sha)
                    if key not in seen:
                        seen.add(key)
                        commits.append(
                            {
                                "repo": repo,
                                "commit": sha,
                                "url": f"{repo}/commit/{sha}" if repo else "",
                                "source": "osv_range",
                            }
                        )
    return commits, prs


def resolve_pr_merge(repo: str, pr_num: str) -> str | None:
    data = gh_api(f"https://api.github.com/repos/{repo}/pulls/{pr_num}")
    if data and data.get("merged") and data.get("merge_commit_sha"):
        return data["merge_commit_sha"]
    return None


def cmd_fetch(args: argparse.Namespace) -> None:
    PATCH_DIR.mkdir(parents=True, exist_ok=True)
    NOPATCH_DIR.mkdir(parents=True, exist_ok=True)
    DIFFS_DIR.mkdir(parents=True, exist_ok=True)

    dataset = {
        f.replace(".json", "")
        for f in os.listdir(DATASET_DIR)
        if f.endswith(".json")
    }
    covered = {
        f.replace(".yaml", "")
        for f in os.listdir(PATCH_DIR)
        if f.endswith(".yaml")
    } | {
        f.replace(".yaml", "")
        for f in os.listdir(NOPATCH_DIR)
        if f.endswith(".yaml")
    }
    todo = sorted(dataset - covered)
    print(f"dataset={len(dataset)} covered={len(dataset & covered)} todo={len(todo)}")
    if not todo:
        return

    cve_pkg = load_cve_pkg_map()
    print(f"GitHub token: {'set' if GITHUB_TOKEN else 'NOT SET (60 req/hr)'}")

    results: dict[str, dict] = {}

    def phase1(cve_id: str) -> tuple[str, list[dict], list[tuple]]:
        try:
            cs, prs = extract_from_cve_json(DATASET_DIR / f"{cve_id}.json")
            osv = fetch_osv(cve_id)
            if osv and osv.get("id"):
                osv_cs, osv_prs = extract_from_osv(osv)
                cs.extend(osv_cs)
                prs.extend(osv_prs)
            seen_c: set[tuple[str, str]] = set()
            uniq_c: list[dict] = []
            for c in cs:
                key = (c["repo"].rstrip("/"), c["commit"])
                if key not in seen_c:
                    seen_c.add(key)
                    uniq_c.append(c)
            seen_p: set[str] = set()
            uniq_p: list[tuple[str, str, str]] = []
            for repo, num, url in prs:
                key = f"{repo}/{num}"
                if key not in seen_p:
                    seen_p.add(key)
                    uniq_p.append((repo, num, url))
            return cve_id, uniq_c, uniq_p
        except Exception:
            return cve_id, [], []

    print(f"Phase 1: collecting commits + PR candidates for {len(todo)} CVEs...")
    with cf.ThreadPoolExecutor(max_workers=6) as ex:
        for i, (cve_id, cs, prs) in enumerate(ex.map(phase1, todo)):
            results[cve_id] = {"commits": cs, "prs": prs}
            if (i + 1) % 20 == 0:
                print(f"  {i + 1}/{len(todo)} done")

    need_pr = [c for c, v in results.items() if not v["commits"] and v["prs"]]
    print(f"Phase 2a: resolve PR merge commits for {len(need_pr)} CVEs")
    for cve_id in need_pr:
        for repo, num, pr_url in results[cve_id]["prs"]:
            sha = resolve_pr_merge(repo, num)
            if sha:
                results[cve_id]["commits"].append(
                    {
                        "repo": f"https://github.com/{repo}",
                        "commit": sha,
                        "url": f"https://github.com/{repo}/commit/{sha}",
                        "source": "github_pr",
                        "pr_url": pr_url,
                    }
                )
            time.sleep(0.3)

    has = sum(1 for v in results.values() if v["commits"])
    print(f"after phase 1+2a: {has} with commits, {len(results) - has} without")

    stats = {"patch": 0, "nopatch": 0, "fetch_fail": 0}
    for cve_id in todo:
        package = cve_pkg.get(cve_id, "")
        cve_path = DATASET_DIR / f"{cve_id}.json"
        description = get_description(cve_path)
        commits = results.get(cve_id, {}).get("commits", [])

        if not commits:
            if not args.dry_run:
                write_nopatch_yaml(
                    cve_id,
                    package,
                    description,
                    "no fix commit found in CVE JSON references or OSV",
                    NOPATCH_DIR / f"{cve_id}.yaml",
                )
            stats["nopatch"] += 1
            continue

        kept, code_changes = commits_to_code_changes(cve_id, commits)
        if not kept:
            if not args.dry_run:
                write_nopatch_yaml(
                    cve_id,
                    package,
                    description,
                    "commit URLs present but diff fetch failed",
                    NOPATCH_DIR / f"{cve_id}.yaml",
                )
            stats["fetch_fail"] += 1
            continue

        if not args.dry_run:
            write_patch_yaml(
                cve_id=cve_id,
                package=package,
                description=description,
                commits=kept,
                code_changes=code_changes,
                out_path=PATCH_DIR / f"{cve_id}.yaml",
            )
        stats["patch"] += 1

    print(f"\n=== fetch done ===")
    print(f"  patch YAMLs written: {stats['patch']}")
    print(f"  nopatch YAMLs written: {stats['nopatch']}")
    print(f"  nopatch due to fetch failure: {stats['fetch_fail']}")


def path0_local_ghsa(targets: set[str]) -> dict[str, list[dict]]:
    """Scan local advisory-database for commit URLs in target CVEs."""
    if not ADVISORY_DIR.exists():
        print("  advisory-database not found -- skipping path 0")
        return {}
    pat_file = Path("/tmp/_patch_pipeline_patterns.txt")
    pat_file.write_text("\n".join(targets))
    try:
        out = subprocess.check_output(
            ["grep", "-rlF", "-f", str(pat_file), str(ADVISORY_DIR)],
            text=True,
            timeout=180,
        )
    except subprocess.CalledProcessError:
        return {}
    hits = [l.strip() for l in out.strip().split("\n") if l.strip()]

    result: dict[str, list[dict]] = {}
    for path in hits:
        try:
            adv = json.loads(Path(path).read_text())
        except Exception:
            continue
        aliases = [a for a in (adv.get("aliases") or []) if a in targets]
        if not aliases:
            continue
        for ref in adv.get("references", []) or []:
            m = COMMIT_URL_RE.search(ref.get("url", ""))
            if m:
                entry = {
                    "repo": f"https://github.com/{m.group(2)}"
                    if "github.com" in m.group(1)
                    else m.group(1),
                    "commit": m.group(3),
                    "url": ref["url"],
                }
                for cve in aliases:
                    result.setdefault(cve, []).append(entry)
        for aff in adv.get("affected", []) or []:
            for rng in aff.get("ranges", []) or []:
                if rng.get("type") != "GIT":
                    continue
                repo = rng.get("repo", "")
                for ev in rng.get("events", []) or []:
                    sha = ev.get("fixed")
                    if sha and re.match(r"^[0-9a-f]{7,40}$", sha):
                        entry = {
                            "repo": repo,
                            "commit": sha,
                            "url": f"{repo}/commit/{sha}" if "github.com" in repo else "",
                        }
                        for cve in aliases:
                            result.setdefault(cve, []).append(entry)
    return _dedup_commits(result)


def ensure_debian_list(force: bool = False) -> Path:
    if DEBIAN_LIST_CACHE.exists() and not force:
        age = time.time() - DEBIAN_LIST_CACHE.stat().st_mtime
        if age < 24 * 3600:
            return DEBIAN_LIST_CACHE
    print(f"  downloading {DEBIAN_LIST_URL} ...")
    urllib.request.urlretrieve(DEBIAN_LIST_URL, DEBIAN_LIST_CACHE)
    return DEBIAN_LIST_CACHE


def parse_debian_notes(targets: set[str]) -> dict[str, list[str]]:
    path = ensure_debian_list()
    notes: dict[str, list[str]] = {}
    cur: str | None = None
    with path.open() as f:
        for line in f:
            if line.startswith("CVE-"):
                m = re.match(r"^(CVE-\d{4}-\d+)", line)
                cur = m.group(1) if m else None
                continue
            if cur is None or cur not in targets:
                continue
            if "NOTE:" in line:
                for u in re.findall(r"https?://\S+", line):
                    notes.setdefault(cur, []).append(u.rstrip(".,;"))
    return notes


def path1_2_debian(
    targets: set[str], include_nongithub: bool = True
) -> dict[str, list[dict]]:
    notes = parse_debian_notes(targets)
    result: dict[str, list[dict]] = {}
    for cve, urls in notes.items():
        for u in urls:
            m = GITHUB_COMMIT_RE.search(u)
            if m:
                result.setdefault(cve, []).append(
                    {"repo": m.group(1), "commit": m.group(2), "url": u}
                )
                continue
            if not include_nongithub:
                continue
            m = GITLAB_COMMIT_RE.search(u)
            if m:
                result.setdefault(cve, []).append(
                    {"repo": m.group(1), "commit": m.group(2), "url": u}
                )
                continue
            m = re.match(
                r"(https?://git\.savannah\.gnu\.org/cgit/[^?]+?)/commit/", u
            )
            sha_m = re.search(r"id=([0-9a-f]{7,40})", u)
            if m and sha_m:
                result.setdefault(cve, []).append(
                    {"repo": m.group(1), "commit": sha_m.group(1), "url": u}
                )
    return _dedup_commits(result)


def path3_github_prs(targets: set[str]) -> dict[str, list[dict]]:
    notes = parse_debian_notes(targets)
    result: dict[str, list[dict]] = {}
    for cve, urls in notes.items():
        if any(GITHUB_COMMIT_RE.search(u) for u in urls):
            continue
        pr_candidates: list[tuple[str, str, str]] = []
        for u in urls:
            m = GITHUB_PR_RE.search(u)
            if m:
                pr_candidates.append((m.group(1), m.group(2), u))
        for owner_repo, num, pr_url in pr_candidates:
            data = gh_api(f"https://api.github.com/repos/{owner_repo}/pulls/{num}")
            time.sleep(0.3)
            if data and data.get("merged") and data.get("merge_commit_sha"):
                sha = data["merge_commit_sha"]
                result.setdefault(cve, []).append(
                    {
                        "repo": f"https://github.com/{owner_repo}",
                        "commit": sha,
                        "url": f"https://github.com/{owner_repo}/commit/{sha}",
                    }
                )
    return _dedup_commits(result)


def path4_ghsa_api(targets: set[str]) -> dict[str, list[dict]]:
    notes = parse_debian_notes(targets)
    result: dict[str, list[dict]] = {}
    for cve, urls in notes.items():
        if any(GITHUB_COMMIT_RE.search(u) for u in urls):
            continue
        for u in urls:
            m = GHSA_URL_RE.search(u)
            if not m:
                continue
            owner_repo, ghsa_id = m.group(1), m.group(2)
            data = gh_api(
                f"https://api.github.com/repos/{owner_repo}/security-advisories/{ghsa_id}"
            )
            time.sleep(0.3)
            if not data:
                continue
            body = data.get("description", "") or ""
            for commit_m in re.finditer(
                r"https?://github\.com/[^/\s]+/[^/\s]+/commit/[0-9a-f]{7,40}", body
            ):
                curl = commit_m.group(0)
                cm = GITHUB_COMMIT_RE.search(curl)
                if cm:
                    result.setdefault(cve, []).append(
                        {"repo": cm.group(1), "commit": cm.group(2), "url": curl}
                    )
    return _dedup_commits(result)


def _load_package_repos() -> dict[str, str]:
    repos: dict[str, str] = {}
    with duckdb.connect(DB_PATH, read_only=True) as conn:
        rows = conn.execute(
            "SELECT package_name, MIN(github_url) FROM binaries "
            "WHERE package_name != '' AND package_name IS NOT NULL "
            "GROUP BY package_name"
        ).fetchall()
    for pkg, url in rows:
        m = re.search(r"github\.com/([^/]+/[^/.\s]+)", url or "")
        if m:
            repos[pkg] = m.group(1)
    return repos


def path5_github_commit_search(
    targets: set[str], rate_delay: float = 2.2
) -> dict[str, list[dict]]:
    pkg_repo = _load_package_repos()
    queryable: list[tuple[str, str, str]] = []
    for cve in targets:
        nopatch_path = NOPATCH_DIR / f"{cve}.yaml"
        if not nopatch_path.exists():
            continue
        data = yaml.safe_load(nopatch_path.read_text()) or {}
        reason = (data.get("reason") or "").strip()
        if not reason.startswith("no fix commit"):
            continue
        pkg = data.get("package", "") or ""
        if pkg in pkg_repo:
            queryable.append((cve, pkg, pkg_repo[pkg]))
    print(f"  path 5: {len(queryable)} CVEs queryable")

    result: dict[str, list[dict]] = {}
    for i, (cve, _pkg, repo) in enumerate(queryable):
        url = (
            f"https://api.github.com/search/commits?q=repo:{repo}+{cve}"
            "&per_page=5"
        )
        data = gh_api(url, accept="application/vnd.github.cloak-preview+json")
        time.sleep(rate_delay)
        if not data or data.get("total_count", 0) == 0:
            continue
        for it in data.get("items", []):
            sha = it.get("sha", "")
            if sha:
                result.setdefault(cve, []).append(
                    {
                        "repo": f"https://github.com/{repo}",
                        "commit": sha,
                        "url": f"https://github.com/{repo}/commit/{sha}",
                    }
                )
        if (i + 1) % 15 == 0:
            print(f"    {i + 1}/{len(queryable)} searched, {len(result)} hits")
    return _dedup_commits(result)


def load_enrich_targets() -> set[str]:
    dataset = {
        f.replace(".json", "")
        for f in os.listdir(DATASET_DIR)
        if f.endswith(".json")
    }
    nopatch = {
        f.replace(".yaml", "")
        for f in os.listdir(NOPATCH_DIR)
        if f.endswith(".yaml")
    }
    return dataset & nopatch


ENRICH_PATHS = {
    "0": ("local GHSA advisory DB", "ghsa_local"),
    "1": ("Debian tracker (GitHub commits)", "debian_tracker"),
    "2": ("Debian tracker (GitLab + Savannah)", "debian_tracker"),
    "3": ("GitHub PR -> merge commit", "github_pr"),
    "4": ("GitHub Security Advisory API", "github_ghsa_api"),
    "5": ("GitHub commit search by CVE ID", "github_commit_search"),
}


def run_enrich_path(key: str, targets: set[str]) -> dict[str, list[dict]]:
    if key == "0":
        return path0_local_ghsa(targets)
    if key == "1":
        return path1_2_debian(targets, include_nongithub=False)
    if key == "2":
        full = path1_2_debian(targets, include_nongithub=True)
        gh_only = path1_2_debian(targets, include_nongithub=False)
        out: dict[str, list[dict]] = {}
        for cve, lst in full.items():
            if cve in gh_only:
                continue
            ng = [c for c in lst if "github.com" not in c["repo"]]
            if ng:
                out[cve] = ng
        return out
    if key == "3":
        return path3_github_prs(targets)
    if key == "4":
        return path4_ghsa_api(targets)
    if key == "5":
        return path5_github_commit_search(targets)
    return {}


def cmd_enrich(args: argparse.Namespace) -> None:
    if not PATCH_DIR.exists() or not NOPATCH_DIR.exists():
        print("ERROR: cves/30_patch or cves/31_nopatch does not exist", file=sys.stderr)
        sys.exit(2)

    chosen = [s.strip() for s in args.only_paths.split(",") if s.strip()]
    print(f"GitHub token: {'set' if GITHUB_TOKEN else 'NOT SET (60 req/hr)'}")
    total_recovered = 0
    for key in chosen:
        if key not in ENRICH_PATHS:
            print(f"unknown path {key!r}")
            continue
        name, source_label = ENRICH_PATHS[key]
        targets = load_enrich_targets()
        print(f"\n=== Path {key} -- {name} ({len(targets)} targets) ===")
        commits_map = run_enrich_path(key, targets)
        print(f"  candidates: {len(commits_map)} CVEs")
        recovered = 0
        for cve, commits in sorted(commits_map.items()):
            result = convert_nopatch_to_patch(
                cve, commits, source_label, dry_run=args.dry_run
            )
            print(f"  {cve}: {result}")
            if result.startswith(("ok", "would-convert")):
                recovered += 1
        total_recovered += recovered
        print(f"  path {key} recovered: {recovered}")

    remaining = len(load_enrich_targets())
    print(f"\n=== enrich done ===")
    print(f"Total recovered this run: {total_recovered}")
    print(f"Remaining nopatch in dataset: {remaining}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_fetch = sub.add_parser(
        "fetch",
        help="fetch patches for dataset CVEs not yet in patch/ or nopatch/",
    )
    p_fetch.add_argument(
        "--dry-run",
        action="store_true",
        help="don't write YAMLs, just report what would happen",
    )
    p_fetch.set_defaults(func=cmd_fetch)

    p_enrich = sub.add_parser(
        "enrich",
        help="upgrade dataset CVEs from nopatch/ to patch/ via extra sources",
    )
    p_enrich.add_argument(
        "--only-paths",
        default="0,1,2,3,4,5",
        help="comma-separated subset of 0,1,2,3,4,5 (default: all)",
    )
    p_enrich.add_argument(
        "--dry-run",
        action="store_true",
        help="don't write YAMLs or delete nopatch files",
    )
    p_enrich.set_defaults(func=cmd_enrich)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
