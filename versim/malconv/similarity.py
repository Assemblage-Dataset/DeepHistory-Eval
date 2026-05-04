"""Compute pairwise cosine similarity from embeddings.npz."""
import json
from pathlib import Path
from itertools import combinations

import numpy as np

HERE = Path(__file__).resolve().parent
EMB = HERE / "embeddings.npz"
MANIFEST = HERE / "manifest_aligned.json"
OUT_MAT = HERE / "similarity.npy"
OUT_META = HERE / "similarity_meta.json"
OUT_SUMMARY = HERE / "similarity_summary.json"


def cosine_matrix(X: np.ndarray) -> np.ndarray:
    norms = np.linalg.norm(X, axis=1, keepdims=True)
    norms = np.where(norms == 0, 1.0, norms)
    Xn = X / norms
    return (Xn @ Xn.T).astype(np.float32)


def main():
    z = np.load(EMB, allow_pickle=False)
    embs = z["embeddings"]
    manifest = json.loads(MANIFEST.read_text())
    assert len(manifest) == embs.shape[0], (len(manifest), embs.shape)
    print(f"Embeddings: {embs.shape}")

    sim = cosine_matrix(embs)
    np.save(OUT_MAT, sim)
    print(f"Wrote {OUT_MAT}: shape={sim.shape}")

    OUT_META.write_text(json.dumps([
        {
            "id": m["id"],
            "identity_key": m["identity_key"],
            "package": m["package"],
            "file_name": m["file_name"],
            "platform": m["platform"],
            "version": m["version"],
        }
        for m in manifest
    ], indent=2))

    groups: dict[str, list[int]] = {}
    for i, m in enumerate(manifest):
        groups.setdefault(m["identity_key"], []).append(i)

    per_identity = []
    intra_pairs = []
    for key, idxs in groups.items():
        if len(idxs) < 2:
            per_identity.append({"identity_key": key, "n_versions": len(idxs),
                                 "min_cosine": None, "mean_cosine": None})
            continue
        pair_sims = [float(sim[a, b]) for a, b in combinations(idxs, 2)]
        per_identity.append({
            "identity_key": key,
            "n_versions": len(idxs),
            "min_cosine": min(pair_sims),
            "mean_cosine": float(np.mean(pair_sims)),
            "max_cosine": max(pair_sims),
        })
        intra_pairs.extend(pair_sims)

    intra_pairs_arr = np.array(intra_pairs, dtype=np.float64)
    summary = {
        "n_binaries": int(embs.shape[0]),
        "n_identities": len(groups),
        "intra_identity_pairs": int(len(intra_pairs)),
        "mean_cross_version_similarity": float(intra_pairs_arr.mean()),
        "std_cross_version_similarity": float(intra_pairs_arr.std()),
        "median_cross_version_similarity": float(np.median(intra_pairs_arr)),
        "min_observed_similarity": float(intra_pairs_arr.min()),
        "max_observed_similarity": float(intra_pairs_arr.max()),
        "per_identity": per_identity,
    }
    OUT_SUMMARY.write_text(json.dumps(summary, indent=2))
    print(f"Wrote {OUT_SUMMARY}")
    print(f"  mean cross-version sim: {summary['mean_cross_version_similarity']:.4f} "
          f"(sigma={summary['std_cross_version_similarity']:.4f})")
    print(f"  median: {summary['median_cross_version_similarity']:.4f}")
    print(f"  min: {summary['min_observed_similarity']:.4f}")
    print(f"  max: {summary['max_observed_similarity']:.4f}")


if __name__ == "__main__":
    main()
