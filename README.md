# DeepHistory Eval Code Release

This directory contains the public replication code for the DeepHistory
experiments.

To replicate the production of the Dataset itself, 
please refer to https://github.com/Assemblage-Dataset/Assemblage

Please download dataset from https://huggingface.co/datasets/changliu8541/assemblage-deephistory 
before running experiments



## Contents

```
cve_benchmark/   CVE recognition, hunting, transfer, scoring, and BinaryAPI
versim/           MalConv/TLSH version-similarity studies and figure scripts
bayesian_rep/    beta regression over release-pair similarity
```

Most scripts are resumable and skip existing result files.

## Required External Artifacts

The CVE inputs and version-date cache are bundled in this repository. The
binary store, DuckDB, and `<owner>/<repo>/<commit>/` source checkouts are
external; place them next to this README or set the environment variables
listed below.

```
code_release/
|-- cves/                         # bundled
|   |-- 10_dataset_cve_json/      # raw CVE JSON inputs
|   |-- 20_affected_binaries/     # CVE -> binary mapping CSVs
|   |-- 30_patch/                 # patch YAMLs
|   +-- cve-package.csv           # CVE -> package_name mapping
|-- archive/                      # bundled
|   +-- version_dates_cache.json  # needed for Bayesian rebuilds
|-- source_codes_manifest.txt     # bundled list of expected checkouts
|-- data/                         # external (not in repo)
|   |-- deephistory.duckdb        # binary metadata DuckDB
|   +-- binaries/                 # content-addressed binary store
+-- source_codes/                 # external (not in repo)
    +-- <owner>/<repo>/<commit>/  # git checkouts listed in the manifest
```

Path overrides:

| Variable | Default |
| --- | --- |
| `DEEPHISTORY_ROOT` | this `code_release/` directory |
| `DEEPHISTORY_DB` | `$DEEPHISTORY_ROOT/data/deephistory.duckdb` |
| `DEEPHISTORY_BIN` | `$DEEPHISTORY_ROOT/data/binaries` |
| `DEEPHISTORY_CVES` | `$DEEPHISTORY_ROOT/cves` |
| `DEEPHISTORY_SECRETS_ENV` | `$DEEPHISTORY_ROOT/secrets.env` |

`binaryapi.py` also requires Ghidra:

```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra
```

## Python Environments

The CVE benchmark environment is provided:

```bash
cd code_release
conda env create -f cve_benchmark/environment.yml
conda activate deephistory
```

The similarity and Bayesian studies use additional packages. Install them in a
separate environment if preferred:

```bash
pip install numpy pandas matplotlib scipy duckdb python-tlsh
pip install torch
pip install jax numpyro arviz netcdf4
```

For frontier-model runs, set `OPENROUTER_API_KEY` in the environment or in
`secrets.env`. For CVE patch fetching, set `GITHUB_TOKEN` to avoid unauthenticated
GitHub rate limits. Local model runs expect Ollama at `localhost:11434` with the
model IDs used by the scripts, currently `gemma4:26b`. For Qwen related API, we are using
condor managed cluster.

## CVE Benchmark


```bash
./run.sh
```

Full run:

```bash
python data/prepare.py --cve-workers 4 -j 32 \
    --per-bin-timeout 14400 --timeout 14400
python eval/fill_eval1_prompts.py
python eval/fill_prompts.py --num-candidates 5 -j 4
python eval/eval1_recognition.py \
    --models gemma4 qwen3.6 gemini3.1 gpt5.4 opus4.7
python eval/eval2_hunting.py \
    --phases solo strategy guided \
    --agents gemma4 qwen3.6 \
    --strategy-models gemini3.1 gpt5.4 opus4.7
python eval/eval3.py \
    --phases solo guided \
    --agents gemma4 qwen3.6 \
    --strategy-models gemini3.1 gpt5.4 opus4.7
python eval/score.py
```

Outputs are rooted under `cve_benchmark/`: `filled_prompts/`, `outputs/`,
`response/`, `results/raw/`, and `results/tables/`.

## Version Similarity

The MalConv path depends on the upstream MalConv2 code and pretrained
MalConvGCT checkpoint. Put them under `versim/malconv/upstream/`, with
`malconvGCT_nocat.checkpoint` inside that directory, or set:

```bash
export MALCONV_UPSTREAM=/path/to/MalConv2
export MALCONV_CHECKPOINT=/path/to/malconvGCT_nocat.checkpoint
```

Then run from `code_release/`:

```bash
python versim/malconv/pick_corpus.py
python versim/malconv/embed.py
python versim/malconv/similarity.py
python versim/tlsh/compute.py
python versim/figures/tlsh_vs_malconv_fig.py
```

`EMBED_WORKERS` controls MalConv embedding parallelism. TLSH can also be run
directly from the database with `python versim/tlsh/compute.py --source db`.

## Bayesian Regression

This rebuild requires the similarity outputs above, `data/deephistory.duckdb`,
`archive/version_dates_cache.json`, and `source_codes/` git checkouts.

```bash
python bayesian_rep/build_dataset.py --verbose
python bayesian_rep/build_tlsh_dataset.py
python bayesian_rep/fit_model.py
python bayesian_rep/fit_model.py \
    --input bayesian_rep/release_pairs_tlsh.csv \
    --target tlsh_similarity_sigmoid_median \
    --out-nc bayesian_rep/normalized_file_change/tlsh_sigmoid/mcmc_samples.nc \
    --out-summary bayesian_rep/normalized_file_change/tlsh_sigmoid/summary.csv \
    --out-model-input bayesian_rep/normalized_file_change/tlsh_sigmoid/model_input.csv \
    --out-metadata bayesian_rep/normalized_file_change/tlsh_sigmoid/model_metadata.json
python bayesian_rep/plot_metric_comparison.py
```

Test:

```bash
python bayesian_rep/build_dataset.py --max-packages 5 --adjacent-only
python bayesian_rep/fit_model.py --num-warmup 20 --num-samples 20 --num-pp-samples 10
```

## Notes

- `BinaryAPI` caches Ghidra analyses by SHA-256 under
  `~/.cache/binaryapi/`; set `BINARYAPI_CACHE_DIR` to move the cache.
- `cve_benchmark/results/raw/` result files are idempotent: re-runs skip
  records already present there.
- Cluster bundle directories from internal runs are not part of this release;
  `cve_benchmark/run.sh` is the supported local pilot entry point.
