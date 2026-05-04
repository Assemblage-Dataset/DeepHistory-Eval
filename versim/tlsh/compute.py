"""Compute TLSH hashes + pairwise distances over the binary corpus."""
from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import duckdb
import numpy as np
import tlsh

_HASHES: "list[str]" = []


def _init_diff_worker(hashes: "list[str]") -> None:
    """Pool initializer: stash the full hash list in each worker."""
    global _HASHES
    _HASHES = hashes


def _diff_row(i: int) -> "tuple[int, list[int]]":
    """Compute distances from row i to columns i+1..N-1."""
    h_i = _HASHES[i]
    return i, [tlsh.diff(h_i, _HASHES[j]) for j in range(i + 1, len(_HASHES))]

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
RELEASE_ROOT = Path(os.environ.get("DEEPHISTORY_ROOT", ROOT))
DH = Path(os.environ.get("DEEPHISTORY_BIN", RELEASE_ROOT / "data" / "binaries"))
DB = Path(
    os.environ.get("DEEPHISTORY_DB", RELEASE_ROOT / "data" / "deephistory.duckdb")
)
MANIFEST = ROOT / "versim" / "malconv" / "manifest.json"


def hash_one(rec: dict) -> "tuple[dict, str | None]":
    p = DH / rec["path"]
    try:
        with open(p, "rb") as f:
            data = f.read()
        h = tlsh.hash(data)
        if not h or h == "TNULL":
            return rec, None
        return rec, h
    except (OSError, ValueError):
        return rec, None


def load_cached_hashes() -> "dict[int, str]":
    f = HERE / "hashes.json"
    if not f.exists():
        return {}
    return {r["id"]: r["hash"] for r in json.loads(f.read_text())}


def progress(label: str, i: int, n: int, t0: float) -> None:
    if i % max(1, n // 50) == 0 or i == n:
        elapsed = time.time() - t0
        rate = i / elapsed if elapsed > 0 else 0
        eta = (n - i) / rate if rate > 0 else 0
        print(f"  {label}: {i}/{n} ({100*i/n:5.1f}%)  "
              f"{rate:6.1f}/s  eta {eta:5.0f}s",
              file=sys.stderr, flush=True)


def load_corpus_manifest() -> "list[dict]":
    return json.loads(MANIFEST.read_text())


def load_corpus_db(min_versions: int, include_debug: bool) -> "list[dict]":
    """Query DuckDB for shared libraries with cross-version coverage."""
    con = duckdb.connect(str(DB), read_only=True)
    build_modes = "('RelWithDebInfo','Debug','Release')" if include_debug \
        else "('RelWithDebInfo')"
    cur = con.execute(f"""
        WITH pkg_v AS (
          SELECT package_name, COUNT(DISTINCT version) AS n_versions
          FROM binaries
          GROUP BY package_name
        )
        SELECT b.id, b.package_name, b.file_name, b.platform, b.version,
               b.path, b.hash, b.optimization, b.toolset_version
        FROM binaries b
        JOIN pkg_v p ON b.package_name = p.package_name
        WHERE b.build_mode IN {build_modes}
          AND b.platform IN ('linux','PE32+')
          AND ((b.platform='linux' AND b.file_name LIKE 'lib%.so')
            OR (b.platform='PE32+' AND b.file_name LIKE '%.dll'))
          AND b.file_name NOT LIKE '%test%'
          AND b.file_name NOT LIKE '%gtest%'
          AND b.file_name NOT LIKE 'CompilerId%'
          AND p.n_versions >= ?
        ORDER BY b.package_name, b.file_name, b.platform, b.version, b.id
    """, (min_versions,))
    rows = cur.fetchall()
    con.close()
    return [
        {"id": r[0], "identity_key": f"{r[1]}/{r[2]}/{r[3]}",
         "package": r[1], "file_name": r[2], "platform": r[3],
         "version": r[4], "path": r[5], "hash": r[6],
         "optimization": r[7], "toolset_version": r[8]}
        for r in rows
    ]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", choices=("manifest", "db", "sqlite"),
                    default="manifest",
                    help="manifest = read versim/malconv/manifest.json (3598 "
                         "binaries); db = query deephistory.duckdb directly")
    ap.add_argument("--min-versions", type=int, default=2,
                    help="--source db: keep only packages with >=N "
                         "distinct versions (default 2)")
    ap.add_argument("--include-debug", action="store_true",
                    help="--source db: also include Debug/Release builds")
    ap.add_argument("--rehash", action="store_true",
                    help="Ignore cache, re-hash every binary")
    ap.add_argument("--no-distances", action="store_true",
                    help="Stop after hashing; do not build distance matrix")
    ap.add_argument("--workers", type=int, default=16,
                    help="hashing thread pool size (I/O bound)")
    ap.add_argument("--dist-workers", type=int, default=os.cpu_count() or 16,
                    help="distance compute process pool size (CPU bound)")
    args = ap.parse_args()

    if args.source == "manifest":
        corpus = load_corpus_manifest()
        print(f"corpus (manifest): {len(corpus)} binaries", file=sys.stderr)
    else:
        corpus = load_corpus_db(args.min_versions, args.include_debug)
        print(f"corpus (db, min_versions>={args.min_versions}, "
              f"debug={args.include_debug}): {len(corpus)} binaries",
              file=sys.stderr)

    cache = {} if args.rehash else load_cached_hashes()
    print(f"cache hit: {len(cache)} hashes", file=sys.stderr)

    todo = [r for r in corpus if r["id"] not in cache]
    new_hashes: "list[tuple[dict, str]]" = []
    if todo:
        t0 = time.time()
        done = 0
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            futs = [ex.submit(hash_one, r) for r in todo]
            for fut in as_completed(futs):
                rec, h = fut.result()
                done += 1
                if h is not None:
                    new_hashes.append((rec, h))
                progress("hash", done, len(todo), t0)
        print(f"newly hashed: {len(new_hashes)} / {len(todo)} "
              f"({len(todo) - len(new_hashes)} failed)", file=sys.stderr)

    by_id = {r["id"]: r for r in corpus}
    all_records: "list[tuple[dict, str]]" = []
    for rid, h in cache.items():
        if rid in by_id:
            all_records.append((by_id[rid], h))
    all_records.extend(new_hashes)
    all_records.sort(key=lambda x: (x[0]["package"], x[0]["identity_key"],
                                    x[0]["version"], x[0]["id"]))
    print(f"total hashed: {len(all_records)} / {len(corpus)}", file=sys.stderr)

    meta = [r for r, _ in all_records]
    hs = [h for _, h in all_records]
    (HERE / "meta.json").write_text(json.dumps(meta, indent=2))
    (HERE / "hashes.json").write_text(json.dumps(
        [{"id": m["id"], "package": m["package"],
          "identity_key": m["identity_key"], "version": m["version"],
          "hash": h} for m, h in zip(meta, hs)], indent=2))

    if args.no_distances:
        print("--no-distances: stopping after hash output", file=sys.stderr)
        return

    N = len(hs)
    nw = max(1, args.dist_workers)
    print(f"computing {N}x{N} distance matrix "
          f"({N*(N-1)//2:,} pairs) with {nw} workers...",
          file=sys.stderr)

    D = np.zeros((N, N), dtype=np.int16)
    t0 = time.time()
    done = 0
    with mp.Pool(processes=nw,
                 initializer=_init_diff_worker, initargs=(hs,)) as pool:
        for i, row in pool.imap_unordered(_diff_row, range(N), chunksize=8):
            row_arr = np.asarray(row, dtype=np.int16)
            D[i, i + 1:] = row_arr
            D[i + 1:, i] = row_arr
            done += 1
            progress("dist", done, N, t0)
    np.save(HERE / "distances.npy", D)
    print(f"wrote {HERE / 'distances.npy'} "
          f"({D.nbytes / 1e6:.1f} MB)", file=sys.stderr)
    print(f"distance: min={D[D>0].min() if (D>0).any() else 0} "
          f"median={int(np.median(D[np.triu_indices(N, 1)]))} "
          f"max={D.max()}", file=sys.stderr)


if __name__ == "__main__":
    main()
