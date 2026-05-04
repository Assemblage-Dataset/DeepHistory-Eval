# cve_benchmark -- vulnerability localization in stripped binaries

Given a known CVE (description + patch diff), locate the vulnerable
function in a stripped binary using only a query API over Ghidra
(`binaryapi.py`). The benchmark ships three evaluations:

| Eval | Task | Binaries | Prompt template |
|------|------|----------|-----------------|
| 1 | Pick 1-of-5 from decompiled (or source) snippets | reference per OS | `00_zeroshot_cve.md`, `01_withdesc_cve.md`, `02_source_zeroshot.md`, `03_source_withdesc.md` |
| 2 | Agent hunts on the reference binary (solo / strategy-guided) | reference + sample variant | `20_agent_zeroshot.md`, `21_agent_follow.md` (+ `10_strategy_gen.md`) |
| 3 | Same agents, cross-build variants D1..D5 + fixed | each variant | reuses Eval 2 templates and Eval 2 strategies |

Five models: local **gemma4:26b** and **qwen3.6:latest** via Ollama
(both 256K context); frontier **Gemini 3.1 Pro**, **GPT-5.4**, **Opus
4.7** for recognition + strategy generation.

## Layout (release default)

```
code_release/
  cve_benchmark/         <-- this package
    cve_pipeline/        CVE collection (binary mapping + patch fetch)
    data/                prepare.py + duckdb-backed query layer
    eval/                fill prompts, run evals, score
    prompts/             prompt templates
    binaryapi.py         Ghidra wrapper (read-only, allowlisted)
    _paths.py            central path / DB config (env-var overrides)
    environment.yml      conda env (python 3.9 + pyghidra + duckdb)
    run.sh               5-CVE pilot
  data/
    deephistory.duckdb   binary metadata (binaries, functions, pdbs, cve_binary_function)
    binaries/            content-addressed binary tree (matches binaries.path)
  cves/
    10_dataset_cve_json/ raw MITRE / NVD JSONs (input)
    20_affected_binaries/ per-CVE CSVs of affected binary IDs (built by cve_pipeline)
    30_patch/            per-CVE YAMLs with fix-commit hunks (built by cve_pipeline)
    cve-package.csv      CVE -> package_name (must match binaries.package_name)
```

`_paths.py` reads:

| Env var | Default | Purpose |
|---------|---------|---------|
| `DEEPHISTORY_ROOT` | parent of cve_benchmark/ | base for the next three |
| `DEEPHISTORY_DB`   | `$ROOT/data/deephistory.duckdb` | DuckDB binary metadata |
| `DEEPHISTORY_BIN`  | `$ROOT/data/binaries`           | content-addressed binary tree |
| `DEEPHISTORY_CVES` | `$ROOT/cves`                    | 10_/20_/30_ stage directories |
| `GHIDRA_INSTALL_DIR` | (required) | Ghidra install (used by `binaryapi.py`) |

## Setup

```bash
conda env create -f environment.yml      # python 3.9, pyghidra, duckdb
conda activate deephistory
export GHIDRA_INSTALL_DIR=/path/to/ghidra
```

Pull the local LLMs and start Ollama (`localhost:11434`):

```bash
ollama pull gemma4:26b
ollama pull qwen3.6:latest
```

Frontier calls go through OpenRouter. Keys live in
`$DEEPHISTORY_ROOT/secrets.env`, `DEEPHISTORY_SECRETS_ENV`, or env vars:

```
GITHUB_TOKEN=ghp_...           # patch_pipeline.py: GitHub API auth (5000 req/hr)
OPENROUTER_API_KEY=...         # eval/backends.py: frontier models
```

## Quick start (5-CVE pilot, local model only)

```bash
./run.sh
```

Generates `data/selected.json`, `data/ground_truth.json`,
`data/decoys.json`, fills prompts under `filled_prompts/`, runs Eval 1
+ Eval 2 solo on `gemma4`, and writes scored tables to
`results/tables/`.

## Full pipeline

### A. (optional) Rebuild CVE inputs

```bash
python cve_pipeline/map_affected_binaries.py            # cves/20_affected_binaries/*.csv
python cve_pipeline/patch_pipeline.py fetch             # cves/30_patch + cves/31_nopatch
python cve_pipeline/patch_pipeline.py enrich            # try six extra sources
```

### B. Prepare

```bash
python data/prepare.py --cve-workers 4 -j 32 \
    --per-bin-timeout 14400 --timeout 14400
```

Resumable: per-CVE shards land under `data/_prepare_shards/`. Re-running
keeps clean shards and only re-runs the missing CVEs.

```bash
python data/prepare.py --shards-only       # aggregate without Ghidra
```

### C. Fill prompts

```bash
python eval/fill_eval1_prompts.py                       # Eval 1 (no Ghidra)
python eval/fill_prompts.py --num-candidates 5 -j 4     # Eval 2/3 templates (Ghidra)
```

### D. Run evals

```bash
# Eval 1 -- recognition (binary/source x zeroshot/with-desc)
python eval/eval1_recognition.py \
    --models gemma4 qwen3.6 gemini3.1 gpt5.4 opus4.7

# Eval 2 -- hunting on reference binaries (solo + strategy + guided)
#          must run before Eval 3 (produces strategies)
python eval/eval2_hunting.py \
    --phases solo strategy guided \
    --agents gemma4 qwen3.6 \
    --strategy-models gemini3.1 gpt5.4 opus4.7

# Eval 3 -- cross-build transfer; reuses Eval 2 strategies verbatim
python eval/eval3.py \
    --phases solo guided \
    --agents gemma4 qwen3.6 \
    --strategy-models gemini3.1 gpt5.4 opus4.7
```

### E. Score

```bash
python eval/score.py     # writes results/tables/*.{csv,md} + summary.json
```

## Outputs (rooted in cve_benchmark/)

| Path | Producer |
|------|----------|
| `data/_prepare_shards/{cve}.json` | `data/prepare.py` |
| `data/{selected,ground_truth,decoys}.json` | `data/prepare.py` |
| `filled_prompts/{cve}/*.txt`     | `eval/fill_eval1_prompts.py`, `eval/fill_prompts.py` |
| `outputs/{cve}/strategies/{model}.md` | `eval/eval2_hunting.py` (Phase 2) |
| `outputs/{cve}/agent_logs/*.txt` | `eval/eval{2,3}*.py` |
| `response/{model}/{cve}/*.json`  | raw LLM responses (debugging) |
| `results/raw/*.json`             | per-execution result records |
| `results/tables/*.{csv,md}`      | scored tables (`eval/score.py`) |

Result-file naming carries the eval phase:

- `*_recognition_*.json` -- Eval 1
- `*_hunting_*.json`     -- Eval 2
- `*_transfer_*.json`    -- Eval 3

## Notes

- `binaryapi.py` caches Ghidra analyses by SHA-256 to
  `~/.cache/binaryapi/`. Same content = same cache.
- All eval scripts are idempotent: a re-run skips files that already
  exist in `results/raw/`.
- Eval 2/3 grading: the ground-truth `functions` map is empty for
  Linux variants (PDBs only exist on PE binaries); `score.py` falls
  back to basename matching against `source_functions` for those rows.
- DuckDB connections are read-only; `prepare.py` opens a fresh
  connection per query (cheap with read-only) so worker subprocesses
  don't share handles.
