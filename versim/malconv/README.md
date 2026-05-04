# MalConv Binary Similarity

This directory reproduces the MalConv-based version-similarity study. It feeds
unstripped Linux `.so` and Windows `.dll` binaries through pretrained MalConvGCT,
takes the 256-dimensional penultimate activation as the embedding, then computes
pairwise cosine similarity.

## Required Artifacts

- `DEEPHISTORY_DB` or `../../data/deephistory.duckdb`
- `DEEPHISTORY_BIN` or `../../data/binaries/`
- MalConv2 upstream code containing `MalConvGCT_nocat.py`
- pretrained `malconvGCT_nocat.checkpoint`

By default the code expects:

```
versim/malconv/upstream/MalConvGCT_nocat.py
versim/malconv/upstream/malconvGCT_nocat.checkpoint
```

Alternatively:

```bash
export MALCONV_UPSTREAM=/path/to/MalConv2
export MALCONV_CHECKPOINT=/path/to/malconvGCT_nocat.checkpoint
```

## Dependencies

```bash
pip install numpy duckdb torch
```

The figure scripts also require `matplotlib` and `scipy`.

## Run

From the `code_release/` root:

```bash
python versim/malconv/pick_corpus.py
python versim/malconv/embed.py
python versim/malconv/similarity.py
python versim/figures/tlsh_vs_malconv_fig.py
```

Outputs:

- `manifest.json`
- `embeddings.npz`
- `manifest_aligned.json`
- `similarity.npy`
- `similarity_meta.json`
- `similarity_summary.json`

`EMBED_WORKERS` controls embedding parallelism.
Use `python versim/malconv/pick_corpus.py --min-versions N` to change the
minimum cross-version coverage threshold.

