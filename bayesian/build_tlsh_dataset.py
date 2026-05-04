#!/usr/bin/env python3
"""Add TLSH distance and sigmoid similarity columns to release pairs."""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path

import numpy as np
import pandas as pd

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
DEFAULT_INPUT = HERE / "release_pairs.csv"
DEFAULT_META = ROOT / "versim" / "tlsh" / "meta.json"
DEFAULT_DISTANCES = ROOT / "versim" / "tlsh" / "distances.npy"
DEFAULT_OUT = HERE / "release_pairs_tlsh.csv"
DEFAULT_REPORT = HERE / "tlsh_transform_report.json"


def load_tlsh_meta(path: Path, distances: np.ndarray) -> pd.DataFrame:
    meta = pd.DataFrame(json.loads(path.read_text()))
    required = {"id", "package", "version", "identity_key"}
    missing = sorted(required - set(meta.columns))
    if missing:
        raise ValueError(f"{path} missing required metadata columns: {missing}")
    if distances.shape[0] != distances.shape[1]:
        raise ValueError(f"{distances.shape} is not a square TLSH distance matrix")
    if len(meta) != distances.shape[0]:
        raise ValueError(
            f"{path} has {len(meta)} rows, but distance matrix is {distances.shape}"
        )
    meta["matrix_index"] = np.arange(len(meta), dtype=np.int64)
    return meta


def groups_by_package_version(meta: pd.DataFrame) -> dict[tuple[str, str], pd.DataFrame]:
    return {
        (str(package), str(version)): group.copy()
        for (package, version), group in meta.groupby(["package", "version"])
    }


def mean_tlsh_distance(
    distances: np.ndarray,
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
        block = np.asarray(distances[np.ix_(ia, ib)], dtype=np.float64)
        total += float(np.nansum(block))
        n_pairs += int(block.size)
        n_blocks += 1

    if n_pairs > 0:
        return total / n_pairs, n_pairs, n_blocks, "identity_key"

    ia = ga["matrix_index"].to_numpy(dtype=np.int64)
    ib = gb["matrix_index"].to_numpy(dtype=np.int64)
    block = np.asarray(distances[np.ix_(ia, ib)], dtype=np.float64)
    if block.size == 0 or not np.isfinite(block).any():
        return None, 0, 0, "missing_distance"
    return float(np.nanmean(block)), int(block.size), 0, "package_fallback"


def squeeze_unit_interval(values: np.ndarray) -> np.ndarray:
    out = values.copy()
    finite = np.isfinite(out)
    n = int(finite.sum())
    if n == 0:
        return out
    out[finite] = (out[finite] * (n - 1) + 0.5) / n
    return out


def sigmoid_similarity(
    distances: np.ndarray,
    midpoint: float,
    tau: float,
) -> np.ndarray:
    z = (distances - midpoint) / tau
    z = np.clip(z, -709.0, 709.0)
    return 1.0 / (1.0 + np.exp(z))


def describe(values: pd.Series) -> dict[str, float | int]:
    clean = values.replace([np.inf, -np.inf], np.nan).dropna().astype(float)
    if clean.empty:
        return {"count": 0}
    return {
        "count": int(len(clean)),
        "min": float(clean.min()),
        "median": float(clean.median()),
        "mean": float(clean.mean()),
        "p90": float(clean.quantile(0.9)),
        "max": float(clean.max()),
        "zeros": int((clean == 0.0).sum()),
    }


def add_tlsh_columns(args: argparse.Namespace) -> tuple[pd.DataFrame, dict[str, object]]:
    release_pairs = pd.read_csv(args.input)
    distances = np.load(args.distances, mmap_mode="r")
    meta = load_tlsh_meta(args.meta, distances)
    groups = groups_by_package_version(meta)

    distance_rows: list[dict[str, object]] = []
    skipped = {"missing_distance": 0}
    for row in release_pairs.itertuples(index=False):
        distance, n_binary_pairs, n_identity_blocks, scope = mean_tlsh_distance(
            distances,
            groups,
            str(row.package),
            str(row.version_a),
            str(row.version_b),
        )
        if distance is None or not math.isfinite(distance):
            skipped["missing_distance"] += 1
        distance_rows.append(
            {
                "tlsh_distance": distance,
                "tlsh_binary_pairs": n_binary_pairs,
                "tlsh_identity_blocks": n_identity_blocks,
                "tlsh_scope": scope,
            }
        )

    out = pd.concat([release_pairs, pd.DataFrame(distance_rows)], axis=1)
    clean_distances = (
        out["tlsh_distance"].replace([np.inf, -np.inf], np.nan).dropna().astype(float)
    )
    if clean_distances.empty:
        raise ValueError("No finite TLSH distances were computed")

    median_distance = float(clean_distances.median())
    tau_source = "median"
    if median_distance <= 0.0:
        positive = clean_distances[clean_distances > 0.0]
        if positive.empty:
            raise ValueError("All finite TLSH distances are zero; cannot choose tau")
        median_distance = float(positive.median())
        tau_source = "positive_median"

    d90 = float(clean_distances.quantile(0.9))
    sigmoid_midpoint = median_distance
    if d90 > sigmoid_midpoint:
        sigmoid_tau = (d90 - sigmoid_midpoint) / math.log(9.0)
        sigmoid_tau_source = "p90_maps_to_0.1"
    else:
        sigmoid_tau = median_distance / math.log(3.0)
        sigmoid_tau_source = "median_maps_to_0.5_fallback"
    sigmoid_raw = sigmoid_similarity(
        out["tlsh_distance"].astype(float).to_numpy(),
        midpoint=sigmoid_midpoint,
        tau=sigmoid_tau,
    )
    out["tlsh_similarity_sigmoid_median"] = squeeze_unit_interval(sigmoid_raw)
    out["tlsh_similarity_sigmoid"] = out["tlsh_similarity_sigmoid_median"]

    report = {
        "input": str(args.input),
        "meta": str(args.meta),
        "distances": str(args.distances),
        "output": str(args.out),
        "rows": int(len(out)),
        "valid_tlsh_rows": int(clean_distances.size),
        "skipped": skipped,
        "distance_summary": describe(out["tlsh_distance"]),
        "tau_source": tau_source,
        "sigmoid": {
            "column": "tlsh_similarity_sigmoid_median",
            "midpoint": sigmoid_midpoint,
            "midpoint_source": "median",
            "tau": sigmoid_tau,
            "tau_source": sigmoid_tau_source,
            "transform": "squeezed(1 / (1 + exp((tlsh_distance - midpoint) / tau)))",
            "target": "median distance maps to 0.5; p90 distance maps to 0.1",
        },
        "squeeze": "(s * (n - 1) + 0.5) / n, where n is finite transformed rows",
    }
    return out, report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--meta", type=Path, default=DEFAULT_META)
    parser.add_argument("--distances", type=Path, default=DEFAULT_DISTANCES)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    args = parser.parse_args()

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    df, report = add_tlsh_columns(args)
    df.to_csv(args.out, index=False)
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True))
    print(f"wrote {args.out}")
    print(f"wrote {args.report}")
    print(
        f"sigmoid midpoint={report['sigmoid']['midpoint']} tau={report['sigmoid']['tau']}"
    )


if __name__ == "__main__":
    main()
