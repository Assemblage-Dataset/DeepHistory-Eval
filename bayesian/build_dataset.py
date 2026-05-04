#!/usr/bin/env python3
"""Build the release-pair table (release_pairs.csv) for the Linear Bayesian Model."""
from __future__ import annotations

import argparse
import json
import math
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from itertools import combinations
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

import duckdb
import numpy as np
import pandas as pd

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent

DEFAULT_MANIFEST = ROOT / "versim" / "malconv" / "manifest_aligned.json"
DEFAULT_SIMILARITY = ROOT / "versim" / "malconv" / "similarity.npy"
DEFAULT_DUCKDB = ROOT / "data" / "deephistory.duckdb"
DEFAULT_DATE_CACHE = ROOT / "archive" / "version_dates_cache.json"
DEFAULT_SOURCE_ROOT = ROOT / "source_codes"
DEFAULT_OUT = HERE / "release_pairs.csv"
DEFAULT_REPORT = HERE / "dataset_build_report.json"

SOURCE_EXTENSIONS = {
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".h",
    ".hh",
    ".hpp",
    ".hxx",
    ".ipp",
    ".inl",
}


@dataclass(frozen=True)
class VersionInfo:
    package: str
    version: str
    commit: str
    github_url: str
    date: datetime
    source_repo: Path | None
    source_file_count: int | None
    n_binaries: int


def parse_owner_repo(url: str | None) -> tuple[str, str] | None:
    if not url:
        return None
    parsed = urlparse(str(url))
    if "github.com" not in parsed.netloc.lower():
        return None
    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) < 2:
        return None
    owner, repo = parts[0], parts[1]
    if repo.endswith(".git"):
        repo = repo[:-4]
    return owner, repo


def parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
        text += "T00:00:00Z"
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(
            timezone.utc
        )
    except ValueError:
        return None


def parse_version_as_date(version: str | None) -> datetime | None:
    if not version:
        return None
    match = re.search(r"(20\d{2})(\d{2})(\d{2})", str(version))
    if not match:
        return None
    year, month, day = map(int, match.groups())
    if 1 <= month <= 12 and 1 <= day <= 31:
        try:
            return datetime(year, month, day, tzinfo=timezone.utc)
        except ValueError:
            return None
    return None


def load_date_cache(path: Path) -> dict[str, dict[str, str | None]]:
    if not path.exists():
        return {}
    return json.loads(path.read_text())


def cache_date_for_version(
    date_cache: dict[str, dict[str, str | None]], github_url: str, version: str
) -> datetime | None:
    owner_repo = parse_owner_repo(github_url)
    if not owner_repo:
        return None
    owner, repo = owner_repo
    candidates = [
        f"{owner}/{repo}",
        f"{owner.lower()}/{repo}",
        f"{owner}/{repo.lower()}",
        f"{owner.lower()}/{repo.lower()}",
    ]
    for key in candidates:
        cached = date_cache.get(key, {}).get(version)
        parsed = parse_datetime(cached)
        if parsed is not None:
            return parsed
    return None


def run_git(repo: Path, args: list[str], timeout: int = 60) -> str | None:
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo), *args],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout


def find_source_repo(
    source_root: Path,
    github_url: str | None,
    commit: str | None,
    fallback_cache: dict[tuple[str | None, str | None], Path | None],
    commit_index_cache: dict[str, dict[str, Path]] | None = None,
) -> Path | None:
    key = (github_url, commit)
    if key in fallback_cache:
        return fallback_cache[key]

    owner_repo = parse_owner_repo(github_url)
    candidates: list[Path] = []
    if owner_repo:
        owner, repo = owner_repo
        base = source_root / owner / repo
        if commit:
            candidates.append(base / commit)
        if base.exists():
            candidates.extend(p for p in base.iterdir() if p.is_dir())

    if commit and commit_index_cache is not None:
        if "index" not in commit_index_cache:
            index: dict[str, Path] = {}
            for owner_dir in source_root.iterdir() if source_root.exists() else []:
                if not owner_dir.is_dir():
                    continue
                for repo_dir in owner_dir.iterdir():
                    if not repo_dir.is_dir():
                        continue
                    for commit_dir in repo_dir.iterdir():
                        if commit_dir.is_dir() and (commit_dir / ".git").exists():
                            index.setdefault(commit_dir.name, commit_dir)
            commit_index_cache["index"] = index
        indexed = commit_index_cache["index"].get(commit)
        if indexed is not None:
            candidates.append(indexed)

    for candidate in candidates:
        if not candidate.exists() or not (candidate / ".git").exists():
            continue
        if commit:
            ok = run_git(candidate, ["cat-file", "-e", f"{commit}^{{commit}}"])
            if ok is None:
                continue
        fallback_cache[key] = candidate
        return candidate

    fallback_cache[key] = None
    return None


def is_source_path(path: str) -> bool:
    suffix = Path(path).suffix.lower()
    return suffix in SOURCE_EXTENSIONS


def source_files_at_commit(repo: Path, commit: str) -> set[str] | None:
    out = run_git(repo, ["ls-tree", "-r", "--name-only", commit], timeout=120)
    if out is None:
        return None
    return {line for line in out.splitlines() if is_source_path(line)}


def git_commit_date(repo: Path, commit: str) -> datetime | None:
    out = run_git(repo, ["show", "-s", "--format=%cI", commit])
    if out is None:
        return None
    return parse_datetime(out.strip())


def changed_source_files(repo: Path, commit_a: str, commit_b: str) -> set[str] | None:
    out = run_git(repo, ["diff", "--name-only", commit_a, commit_b], timeout=120)
    if out is None:
        return None
    return {line for line in out.splitlines() if is_source_path(line)}


def commit_distance(repo: Path, older: str, newer: str) -> int | None:
    out = run_git(repo, ["rev-list", "--count", f"{older}..{newer}"])
    if out is not None:
        try:
            value = int(out.strip())
            if value > 0 or older == newer:
                return value
        except ValueError:
            pass
    out = run_git(repo, ["rev-list", "--count", f"{older}...{newer}"])
    if out is None:
        return None
    try:
        return int(out.strip())
    except ValueError:
        return None


def mode_text(values: Iterable[object]) -> str:
    counts: dict[str, int] = {}
    for value in values:
        if pd.isna(value):
            continue
        text = str(value).strip()
        if text:
            counts[text] = counts.get(text, 0) + 1
    if not counts:
        return ""
    return max(counts.items(), key=lambda item: (item[1], item[0]))[0]


def load_manifest(path: Path) -> pd.DataFrame:
    data = json.loads(path.read_text())
    df = pd.DataFrame(data)
    required = {"id", "package", "version", "identity_key"}
    missing = sorted(required - set(df.columns))
    if missing:
        raise ValueError(f"{path} missing required manifest columns: {missing}")
    df["matrix_index"] = np.arange(len(df), dtype=np.int64)
    return df


def load_selected_binary_metadata(manifest: pd.DataFrame, db_path: Path) -> pd.DataFrame:
    con = duckdb.connect(str(db_path), read_only=True)
    selected = manifest[["id", "matrix_index"]].copy()
    con.register("selected_ids", selected)
    db_meta = con.execute(
        """
        SELECT
            s.matrix_index,
            b.id,
            b.package_name,
            b.version AS db_version,
            b.repo_commit,
            b.github_url
        FROM selected_ids s
        LEFT JOIN binaries b ON b.id = s.id
        """
    ).fetchdf()
    merged = manifest.merge(db_meta, on=["id", "matrix_index"], how="left")
    merged["package"] = merged["package_name"].fillna(merged["package"])
    merged["version"] = merged["db_version"].fillna(merged["version"])
    return merged


def build_version_info(
    binary_meta: pd.DataFrame,
    date_cache: dict[str, dict[str, str | None]],
    source_root: Path,
) -> tuple[dict[tuple[str, str], VersionInfo], dict[str, int]]:
    repo_cache: dict[tuple[str | None, str | None], Path | None] = {}
    commit_index_cache: dict[str, dict[str, Path]] = {}
    stats = {
        "version_groups": 0,
        "missing_commit": 0,
        "missing_date": 0,
        "missing_source_repo": 0,
        "missing_source_file_count": 0,
    }
    versions: dict[tuple[str, str], VersionInfo] = {}

    for (package, version), group in binary_meta.groupby(["package", "version"]):
        stats["version_groups"] += 1
        commit = mode_text(group["repo_commit"])
        github_url = mode_text(group["github_url"])
        if not commit:
            stats["missing_commit"] += 1
            continue

        repo = find_source_repo(
            source_root, github_url, commit, repo_cache, commit_index_cache
        )
        if repo is None:
            stats["missing_source_repo"] += 1

        date = git_commit_date(repo, commit) if repo else None
        if date is None:
            date = cache_date_for_version(date_cache, github_url, str(version))
        if date is None:
            date = parse_version_as_date(str(version))
        if date is None:
            stats["missing_date"] += 1
            continue

        versions[(str(package), str(version))] = VersionInfo(
            package=str(package),
            version=str(version),
            commit=commit,
            github_url=github_url,
            date=date,
            source_repo=repo,
            source_file_count=None,
            n_binaries=int(len(group)),
        )

    return versions, stats


def pair_indices_by_package_version(
    binary_meta: pd.DataFrame,
) -> dict[tuple[str, str], pd.DataFrame]:
    return {
        (str(package), str(version)): group.copy()
        for (package, version), group in binary_meta.groupby(["package", "version"])
    }


def mean_malconv_similarity(
    sim: np.ndarray,
    groups: dict[tuple[str, str], pd.DataFrame],
    package: str,
    version_a: str,
    version_b: str,
) -> tuple[float | None, int, int, str]:
    ga = groups.get((package, version_a))
    gb = groups.get((package, version_b))
    if ga is None or gb is None or ga.empty or gb.empty:
        return None, 0, 0, "missing_manifest_group"

    total = 0.0
    n_pairs = 0
    n_blocks = 0
    for identity, ia_df in ga.groupby("identity_key"):
        ib_df = gb[gb["identity_key"] == identity]
        if ib_df.empty:
            continue
        ia = ia_df["matrix_index"].to_numpy(dtype=np.int64)
        ib = ib_df["matrix_index"].to_numpy(dtype=np.int64)
        block = np.asarray(sim[np.ix_(ia, ib)], dtype=np.float64)
        total += float(np.nansum(block))
        n_pairs += int(block.size)
        n_blocks += 1

    if n_pairs > 0:
        return total / n_pairs, n_pairs, n_blocks, "identity_key"

    ia = ga["matrix_index"].to_numpy(dtype=np.int64)
    ib = gb["matrix_index"].to_numpy(dtype=np.int64)
    block = np.asarray(sim[np.ix_(ia, ib)], dtype=np.float64)
    return float(np.nanmean(block)), int(block.size), 0, "package_fallback"


def iter_version_pairs(
    versions: list[VersionInfo], adjacent_only: bool
) -> Iterable[tuple[VersionInfo, VersionInfo]]:
    ordered = sorted(versions, key=lambda item: (item.date, item.version))
    if adjacent_only:
        for i in range(len(ordered) - 1):
            yield ordered[i], ordered[i + 1]
    else:
        yield from combinations(ordered, 2)


def build_rows(args: argparse.Namespace) -> tuple[pd.DataFrame, dict[str, object]]:
    manifest = load_manifest(args.manifest)
    binary_meta = load_selected_binary_metadata(manifest, args.duckdb)
    if args.max_packages:
        selected_packages = sorted(binary_meta["package"].dropna().astype(str).unique())[
            : args.max_packages
        ]
        binary_meta = binary_meta[
            binary_meta["package"].astype(str).isin(selected_packages)
        ].copy()
    date_cache = load_date_cache(args.date_cache)
    versions, version_stats = build_version_info(
        binary_meta, date_cache, args.source_root
    )
    groups = pair_indices_by_package_version(binary_meta)
    sim = np.load(args.similarity, mmap_mode="r")

    package_to_versions: dict[str, list[VersionInfo]] = {}
    for info in versions.values():
        package_to_versions.setdefault(info.package, []).append(info)

    rows: list[dict[str, object]] = []
    skipped = {
        "too_few_versions": 0,
        "missing_source_repo_pair": 0,
        "missing_git_metrics": 0,
        "missing_similarity": 0,
    }
    package_items = sorted(package_to_versions.items())
    if args.max_packages:
        package_items = package_items[: args.max_packages]

    source_files_cache: dict[tuple[Path, str], set[str] | None] = {}
    changed_cache: dict[tuple[Path, str, str], set[str] | None] = {}
    commit_distance_cache: dict[tuple[Path, str, str], int | None] = {}

    for package, package_versions in package_items:
        if args.verbose:
            print(
                f"[build_dataset] package={package} versions={len(package_versions)} "
                f"rows_so_far={len(rows)}",
                flush=True,
            )
        if len(package_versions) < args.min_versions:
            skipped["too_few_versions"] += 1
            continue

        for older, newer in iter_version_pairs(package_versions, args.adjacent_only):
            if older.source_repo is None and newer.source_repo is None:
                skipped["missing_source_repo_pair"] += 1
                continue
            repo = newer.source_repo or older.source_repo
            assert repo is not None

            changed_key = (repo, older.commit, newer.commit)
            if changed_key not in changed_cache:
                changed_cache[changed_key] = changed_source_files(
                    repo, older.commit, newer.commit
                )
            changed = changed_cache[changed_key]

            dist_key = (repo, older.commit, newer.commit)
            if dist_key not in commit_distance_cache:
                commit_distance_cache[dist_key] = commit_distance(
                    repo, older.commit, newer.commit
                )
            commits_between = commit_distance_cache[dist_key]

            older_file_count = older.source_file_count
            if older_file_count is None and older.source_repo is not None:
                fc_key = (older.source_repo, older.commit)
                if fc_key not in source_files_cache:
                    source_files_cache[fc_key] = source_files_at_commit(
                        older.source_repo, older.commit
                    )
                files = source_files_cache[fc_key]
                older_file_count = len(files) if files is not None else None

            if changed is None or commits_between is None or not older_file_count:
                skipped["missing_git_metrics"] += 1
                continue

            similarity, n_binary_pairs, n_identity_blocks, sim_scope = (
                mean_malconv_similarity(
                    sim, groups, package, older.version, newer.version
                )
            )
            if similarity is None or not math.isfinite(similarity):
                skipped["missing_similarity"] += 1
                continue

            days = abs((newer.date - older.date).total_seconds()) / 86400.0
            changed_count = len(changed)
            rows.append(
                {
                    "package": package,
                    "version_a": older.version,
                    "version_b": newer.version,
                    "date_a": older.date.isoformat(),
                    "date_b": newer.date.isoformat(),
                    "commit_a": older.commit,
                    "commit_b": newer.commit,
                    "days": days,
                    "commits_between": commits_between,
                    "changed_source_files": changed_count,
                    "source_files_base": older_file_count,
                    "norm_changed_source_files": changed_count / older_file_count,
                    "log_changed_source_files": math.log1p(changed_count),
                    "malconv_similarity": similarity,
                    "malconv_binary_pairs": n_binary_pairs,
                    "malconv_identity_blocks": n_identity_blocks,
                    "malconv_scope": sim_scope,
                    "n_binaries_a": older.n_binaries,
                    "n_binaries_b": newer.n_binaries,
                }
            )

    report = {
        "manifest_rows": int(len(manifest)),
        "packages_seen": int(len(package_to_versions)),
        "packages_used": int(len({row["package"] for row in rows})),
        "rows": int(len(rows)),
        "adjacent_only": bool(args.adjacent_only),
        "min_versions": int(args.min_versions),
        "max_packages": args.max_packages,
        "version_stats": version_stats,
        "skipped": skipped,
    }
    return pd.DataFrame(rows), report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--similarity", type=Path, default=DEFAULT_SIMILARITY)
    parser.add_argument("--duckdb", type=Path, default=DEFAULT_DUCKDB)
    parser.add_argument("--date-cache", type=Path, default=DEFAULT_DATE_CACHE)
    parser.add_argument("--source-root", type=Path, default=DEFAULT_SOURCE_ROOT)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--min-versions", type=int, default=2)
    parser.add_argument("--max-packages", type=int, default=None)
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument(
        "--adjacent-only",
        action="store_true",
        help="Use only neighboring releases in chronological order.",
    )
    args = parser.parse_args()

    rows, report = build_rows(args)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    rows.to_csv(args.out, index=False)
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True))
    print(f"wrote {args.out} ({len(rows)} rows)")
    print(f"wrote {args.report}")
    if rows.empty:
        raise SystemExit("no release pairs were produced")


if __name__ == "__main__":
    main()
