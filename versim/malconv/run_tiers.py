"""Run pick -> embed -> similarity for multiple version-count thresholds."""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
PYTHON = os.environ.get("PYTHON", sys.executable)
TIERS_DIR = HERE / "tiers"
TIERS = [10, 5, 2]


def run(cmd):
    print(f"$ {' '.join(str(c) for c in cmd)}", flush=True)
    subprocess.run([str(c) for c in cmd], check=True)


def snapshot(n: int):
    dst = TIERS_DIR / f"v{n}"
    dst.mkdir(parents=True, exist_ok=True)
    for fname in [
        "manifest.json",
        "manifest_aligned.json",
        "embeddings.npz",
        "similarity.npy",
        "similarity_meta.json",
        "similarity_summary.json",
    ]:
        src = HERE / fname
        if src.exists():
            shutil.copy2(src, dst / fname)
    return dst


def report(snap_dir: Path, n: int):
    s = json.loads((snap_dir / "similarity_summary.json").read_text())
    manifest = json.loads((snap_dir / "manifest_aligned.json").read_text())
    n_pkg = len({m["package"] for m in manifest})
    return {
        "min_versions": n,
        "packages": n_pkg,
        "identities": s["n_identities"],
        "binaries": s["n_binaries"],
        "mean": s["mean_cross_version_similarity"],
        "median": s["median_cross_version_similarity"],
        "std": s["std_cross_version_similarity"],
        "min": s["min_observed_similarity"],
        "max": s["max_observed_similarity"],
    }


def main():
    rows = []
    for n in TIERS:
        print(f"\n=== MIN_VERSIONS >= {n} ===", flush=True)
        run([PYTHON, HERE / "pick_corpus.py", "--min-versions", str(n)])
        run([PYTHON, HERE / "embed.py"])
        run([PYTHON, HERE / "similarity.py"])
        snap = snapshot(n)
        rows.append(report(snap, n))

    print("\n=== Comparison ===")
    hdr = ["min_v", "pkg", "ids", "bins", "mean", "median", "std", "min", "max"]
    fmt = "{:>6} {:>5} {:>5} {:>6} {:>7} {:>7} {:>7} {:>8} {:>7}"
    print(fmt.format(*hdr))
    for r in rows:
        print(fmt.format(
            r["min_versions"], r["packages"], r["identities"], r["binaries"],
            f"{r['mean']:.4f}", f"{r['median']:.4f}", f"{r['std']:.4f}",
            f"{r['min']:.4f}", f"{r['max']:.4f}",
        ))

    summary_path = TIERS_DIR / "comparison.json"
    summary_path.write_text(json.dumps(rows, indent=2))
    print(f"\nWrote {summary_path}")


if __name__ == "__main__":
    main()
