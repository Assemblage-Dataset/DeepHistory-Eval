# Linear Bayesian Model Replication

Hierarchical beta regression over release pairs. Response is cross-version
MalConv cosine similarity (or sigmoid-transformed TLSH similarity).
Covariates: release distance in days, commits between releases, and changed
source files normalized by the older release's source-file count.

Inputs the pipeline derives from:

- `versim/malconv/manifest_aligned.json`
- `versim/malconv/similarity.npy`
- `versim/tlsh/meta.json`
- `versim/tlsh/distances.npy`
- `data/deephistory.duckdb`
- `archive/version_dates_cache.json`
- `source_codes/**/<repo>/<commit>/`

Install the modeling dependencies before running this section:

```bash
pip install numpy pandas duckdb jax numpyro arviz netcdf4 matplotlib
```

## Run

Use the env that has `numpyro`, `jax`, `arviz`, `duckdb`:

```bash
# 1. Build the release-pair table.
python bayesian_rep/build_dataset.py --verbose

# 2. Add raw TLSH distance + sigmoid response columns.
python bayesian_rep/build_tlsh_dataset.py

# 3. Fit MalConv response (default --feature-set normalized_file_change).
python bayesian_rep/fit_model.py

# 4. Fit TLSH sigmoid response.
python bayesian_rep/fit_model.py \
    --input bayesian_rep/release_pairs_tlsh.csv \
    --target tlsh_similarity_sigmoid_median \
    --out-nc bayesian_rep/normalized_file_change/tlsh_sigmoid/mcmc_samples.nc \
    --out-summary bayesian_rep/normalized_file_change/tlsh_sigmoid/summary.csv \
    --out-model-input bayesian_rep/normalized_file_change/tlsh_sigmoid/model_input.csv \
    --out-metadata bayesian_rep/normalized_file_change/tlsh_sigmoid/model_metadata.json

# 5. Combined 95% HDI figure.
python bayesian_rep/plot_metric_comparison.py
```

Smoke test:

```bash
python bayesian_rep/build_dataset.py --max-packages 5 --adjacent-only
python bayesian_rep/fit_model.py --num-warmup 20 --num-samples 20 --num-pp-samples 10
```

## TLSH response

The raw aggregated TLSH distance is mapped to a beta-regression response
with `s = 1 / (1 + exp((d - midpoint) / tau))`, then squeezed into `(0, 1)`
via `(s * (n - 1) + 0.5) / n`. `midpoint = median(d)` and `tau` is chosen so
the 90th-percentile distance maps to 0.1.

## Outputs

| File | Description |
| --- | --- |
| `release_pairs.csv` | One package-version pair per row. |
| `dataset_build_report.json` | Counts and skipped-row diagnostics. |
| `release_pairs_tlsh.csv` | Release pairs with raw TLSH distance and sigmoid response. |
| `tlsh_transform_report.json` | TLSH distance + sigmoid transform diagnostics. |
| `normalized_file_change/{malconv,tlsh_sigmoid}/{model_input.csv,model_metadata.json,mcmc_samples.nc,summary.csv}` | Per-target fit artifacts. |
| `normalized_file_change/bayesianRegressMalconvTLSHNormalizedFileChange95HDI.{pdf,png}` | Combined MalConv + TLSH 95% HDI figure. |

## Modeling notes

`build_dataset.py` compares versions in chronological order. `--adjacent-only`
uses neighboring releases; omit it for every dated pair within a package.
MalConv similarity aggregates over binary pairs sharing `identity_key` when
possible, falling back to the package-level cross-version mean.

`fit_model.py` standardizes covariates by default. Use `--no-standardize` to
fit on raw scales.
