#!/usr/bin/env bash
# Pilot pipeline for the cve_benchmark release.
#
# Generates selected.json / ground_truth.json / decoys.json from the
# bundled DuckDB, fills prompts, and runs the local-only evaluations
# on a 5-CVE pilot subset. Runs from the cve_benchmark/ directory.
#
# Required env (export or set inline):
#   GHIDRA_INSTALL_DIR  Ghidra install root (used by binaryapi.py)
#
# Optional overrides -- defaults assume the release-relative layout
# (../data/deephistory.duckdb, ../data/binaries, ../cves):
#   DEEPHISTORY_ROOT, DEEPHISTORY_DB, DEEPHISTORY_BIN, DEEPHISTORY_CVES
#
# Run with one of the local Ollama models pulled (gemma4:26b or
# qwen3.6:latest) and Ollama serving at localhost:11434.

set -euo pipefail

cd "$(dirname "$0")"

: "${GHIDRA_INSTALL_DIR:?Set GHIDRA_INSTALL_DIR before running}"
: "${PILOT_CVES:=5}"
: "${PILOT_AGENT:=gemma4}"
PYTHON="${PYTHON:-python}"

echo "[1/5] CVE selection + decoys (pilot, $PILOT_CVES CVEs)"
"$PYTHON" data/prepare.py --cve-workers 1 -j 4 --max-affected 5 --max-fixed 2

echo "[2/5] Fill Eval 1 prompts (no Ghidra, reads shards)"
"$PYTHON" eval/fill_eval1_prompts.py

echo "[3/5] Fill Eval 2/3 templates (Ghidra)"
"$PYTHON" eval/fill_prompts.py --num-candidates 5 --workers 4

echo "[4/5] Eval 1 recognition (local model only)"
"$PYTHON" eval/eval1_recognition.py --models "$PILOT_AGENT" --max-cves "$PILOT_CVES"

echo "[5/5] Eval 2 solo agent + score"
"$PYTHON" eval/eval2_hunting.py --phases solo --agents "$PILOT_AGENT" \
    --max-cves "$PILOT_CVES" --max-variants 1
"$PYTHON" eval/score.py

echo
echo "Done. Tables: results/tables/*.md"
