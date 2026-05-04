"""Select the MalConv similarity corpus from the DeepHistory DuckDB."""
import argparse
import json
import os
from pathlib import Path

import duckdb

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
RELEASE_ROOT = Path(os.environ.get("DEEPHISTORY_ROOT", ROOT))
DB = Path(
    os.environ.get("DEEPHISTORY_DB", RELEASE_ROOT / "data" / "deephistory.duckdb")
)
OUT = HERE / "manifest.json"

PREF_OPT = {
    "linux": ["-O2", "-O3", "-O1", "-O0"],
    "PE32+": ["O2", "O1", "Od"],
}
PREF_TOOLSET = {
    "linux": ["clang-18.1.3", "gcc-13.3.0"],
    "PE32+": ["vc143", "vc142", "vc141"],
}
MIN_VERSIONS = 2


def best_optimization_for_identity(con, package, file_name, platform):
    """Pick the optimization that maximises version coverage for this identity."""
    cur = con.execute(
        """
        SELECT optimization, COUNT(DISTINCT version) AS v
        FROM binaries
        WHERE package_name=? AND file_name=? AND platform=? AND build_mode='RelWithDebInfo'
        GROUP BY optimization
        """,
        (package, file_name, platform),
    )
    rows = cur.fetchall()
    pref = PREF_OPT[platform]
    rows.sort(key=lambda r: (-r[1], pref.index(r[0]) if r[0] in pref else 99))
    return rows[0][0] if rows else None


def pick_identities(con, min_versions):
    cur = con.execute("""
        SELECT package_name, file_name, platform, COUNT(DISTINCT version) AS vcount
        FROM binaries
        WHERE platform IN ('linux','PE32+')
          AND build_mode='RelWithDebInfo'
          AND ((platform='linux' AND file_name LIKE 'lib%.so')
            OR (platform='PE32+' AND file_name LIKE '%.dll'))
          AND file_name NOT LIKE '%test%'
          AND file_name NOT LIKE '%gtest%'
          AND file_name NOT LIKE 'CompilerId%'
        GROUP BY package_name, file_name, platform
        HAVING vcount >= ?
        ORDER BY package_name, file_name, platform
    """, (min_versions,))
    return cur.fetchall()


def pick_one_per_version(con, package, file_name, platform, fixed_opt):
    cur = con.execute(
        """
        SELECT id, version, optimization, toolset_version, path, hash
        FROM binaries
        WHERE package_name=? AND file_name=? AND platform=? AND build_mode='RelWithDebInfo'
          AND optimization=?
        """,
        (package, file_name, platform, fixed_opt),
    )
    rows = cur.fetchall()
    by_version = {}
    for row in rows:
        by_version.setdefault(row[1], []).append(row)
    pref_ts = PREF_TOOLSET[platform]
    picked = []
    for version in sorted(by_version):
        cands = by_version[version]
        cands.sort(key=lambda r: (
            pref_ts.index(r[3]) if r[3] in pref_ts else 99,
            r[5],
        ))
        picked.append(cands[0])
    return picked


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--min-versions",
        type=int,
        default=MIN_VERSIONS,
        help="Minimum number of distinct versions per binary identity.",
    )
    args = parser.parse_args()

    with duckdb.connect(str(DB), read_only=True) as con:
        identities = pick_identities(con, args.min_versions)
        print(f"Picked {len(identities)} identities")
        manifest = []
        for pkg, fname, plat, vcount in identities:
            ident_key = f"{pkg}/{fname}/{plat}"
            opt_fixed = best_optimization_for_identity(con, pkg, fname, plat)
            if opt_fixed is None:
                continue
            bins = pick_one_per_version(con, pkg, fname, plat, opt_fixed)
            if len(bins) < args.min_versions:
                continue
            print(
                f"  {ident_key:55s} opt={opt_fixed:<4s}  "
                f"versions={len(bins)}/{vcount}"
            )
            for bid, version, opt, ts, path, sha in bins:
                manifest.append({
                    "id": bid,
                    "identity_key": ident_key,
                    "package": pkg,
                    "file_name": fname,
                    "platform": plat,
                    "version": version,
                    "path": path,
                    "hash": sha,
                    "optimization": opt,
                    "toolset_version": ts,
                })
    print(f"Total binaries: {len(manifest)}")
    OUT.write_text(json.dumps(manifest, indent=2))
    print(f"Wrote {OUT}")


if __name__ == "__main__":
    main()
