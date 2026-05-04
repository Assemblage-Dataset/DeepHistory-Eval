"""Compute MalConvGCT embeddings for every binary in manifest.json."""
import json
import os
import sys
import time
from pathlib import Path

import numpy as np
import torch

torch.set_num_threads(1)

sys.path.insert(0, str(Path(__file__).resolve().parent))
from model import load_model, embed_bytes  # noqa: E402

import multiprocessing as mp  # noqa: E402

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
RELEASE_ROOT = Path(os.environ.get("DEEPHISTORY_ROOT", ROOT))
DH = Path(os.environ.get("DEEPHISTORY_BIN", RELEASE_ROOT / "data" / "binaries"))
MANIFEST = HERE / "manifest.json"
CACHE = HERE / "embeddings_cache.npz"
OUT = HERE / "embeddings.npz"
N_WORKERS = int(os.environ.get("EMBED_WORKERS", "128"))

_MODEL = None


def _worker_init():
    """Each worker loads its own model copy and uses 1 torch thread."""
    global _MODEL
    torch.set_num_threads(1)
    _MODEL = load_model("cpu")


def _embed_one(args):
    """Worker task: read bytes for one entry, return (sha, embedding | None)."""
    sha, path_str = args
    path = DH / path_str
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return sha, None
    emb = embed_bytes(_MODEL, raw)
    return sha, emb.astype(np.float32)


def load_cache():
    if not CACHE.exists():
        return {}
    z = np.load(CACHE, allow_pickle=False)
    return {h: e for h, e in zip(z["hashes"].tolist(), z["embeddings"])}


def save_cache(cache):
    if not cache:
        return
    hashes = np.array(list(cache.keys()))
    embs = np.stack(list(cache.values())).astype(np.float32)
    np.savez(CACHE, hashes=hashes, embeddings=embs)


def main():
    manifest = json.loads(MANIFEST.read_text())
    print(f"manifest: {len(manifest)} binaries", flush=True)
    cache = load_cache()
    print(f"cache hits: {len(cache)}", flush=True)

    todo = []
    cache_results = {}
    for entry in manifest:
        sha = entry["hash"]
        if sha in cache:
            cache_results[id(entry)] = cache[sha]
        else:
            todo.append((sha, entry["path"]))

    print(f"to embed: {len(todo)} (skipping {len(cache_results)} cached)",
          flush=True)

    new_results = {}
    if todo:
        t0 = time.time()
        last_save = t0
        with mp.Pool(processes=N_WORKERS, initializer=_worker_init) as pool:
            for n, (sha, emb) in enumerate(
                    pool.imap_unordered(_embed_one, todo, chunksize=4), 1):
                if emb is not None:
                    new_results[sha] = emb
                    cache[sha] = emb
                if n % 100 == 0 or n == len(todo):
                    elapsed = time.time() - t0
                    rate = n / elapsed if elapsed > 0 else 0
                    eta = (len(todo) - n) / rate if rate > 0 else 0
                    print(f"  [{n}/{len(todo)}] rate={rate:.1f}/s "
                          f"eta={eta:.0f}s elapsed={elapsed:.0f}s",
                          flush=True)
                if time.time() - last_save > 30:
                    save_cache(cache)
                    last_save = time.time()
        save_cache(cache)
        print(f"newly embedded: {len(new_results)} / {len(todo)} "
              f"(missing on disk: {len(todo) - len(new_results)})",
              flush=True)

    keep_entries = []
    keep_embs = []
    for entry in manifest:
        sha = entry["hash"]
        if sha in cache:
            keep_entries.append(entry)
            keep_embs.append(cache[sha])
    if len(keep_entries) < len(manifest):
        print(f"WARN: {len(manifest) - len(keep_entries)} binaries missing on "
              f"disk; dropped from output", flush=True)

    embs = np.stack(keep_embs).astype(np.float32)
    hashes = np.array([e["hash"] for e in keep_entries])
    keys = np.array([e["identity_key"] for e in keep_entries])
    np.savez(OUT, embeddings=embs, hashes=hashes, identity_keys=keys)
    (HERE / "manifest_aligned.json").write_text(
        json.dumps(keep_entries, indent=2))
    print(f"Wrote {OUT}: shape={embs.shape}", flush=True)


if __name__ == "__main__":
    main()
