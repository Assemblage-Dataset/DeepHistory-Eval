"""Central path / DB configuration for the cve_benchmark release."""

import os

PKG_DIR = os.path.dirname(os.path.abspath(__file__))
RELEASE_ROOT = os.path.dirname(PKG_DIR)

ROOT = os.environ.get("DEEPHISTORY_ROOT", RELEASE_ROOT)

DUCKDB_PATH = os.environ.get(
    "DEEPHISTORY_DB", os.path.join(ROOT, "data", "deephistory.duckdb"))
BINARY_BASE_DIR = os.environ.get(
    "DEEPHISTORY_BIN", os.path.join(ROOT, "data", "binaries"))
CVES_DIR = os.environ.get(
    "DEEPHISTORY_CVES", os.path.join(ROOT, "cves"))

DATASET_DIR = os.path.join(CVES_DIR, "10_dataset_cve_json")
AB_DIR      = os.path.join(CVES_DIR, "20_affected_binaries")
PATCH_DIR   = os.path.join(CVES_DIR, "30_patch")
NOPATCH_DIR = os.path.join(CVES_DIR, "31_nopatch")
DIFFS_DIR   = os.path.join(CVES_DIR, "diffs")
CVE_PKG_CSV = os.path.join(CVES_DIR, "cve-package.csv")

ADVISORY_DIR = os.environ.get(
    "DEEPHISTORY_ADVISORY_DB",
    os.path.join(ROOT, "advisory-database", "advisories"))
SECRETS_ENV = os.environ.get(
    "DEEPHISTORY_SECRETS_ENV", os.path.join(ROOT, "secrets.env"))

DATA_OUT          = os.path.join(PKG_DIR, "data")
SHARD_DIR         = os.path.join(DATA_OUT, "_prepare_shards")
SELECTED_JSON     = os.path.join(DATA_OUT, "selected.json")
GROUND_TRUTH_JSON = os.path.join(DATA_OUT, "ground_truth.json")
DECOYS_JSON       = os.path.join(DATA_OUT, "decoys.json")

PROMPTS_DIR    = os.path.join(PKG_DIR, "prompts")
FILLED_DIR     = os.path.join(PKG_DIR, "filled_prompts")
STRIPPED_DIR   = os.path.join(PKG_DIR, "stripped_binaries")
RESULTS_DIR    = os.path.join(PKG_DIR, "results", "raw")
TABLES_DIR     = os.path.join(PKG_DIR, "results", "tables")
RESPONSE_DIR   = os.path.join(PKG_DIR, "response")
LOGS_DIR       = os.path.join(PKG_DIR, "logs")
OUTPUTS_DIR    = os.path.join(PKG_DIR, "outputs")


def ensure_dirs():
    """Create the writable output directories. Idempotent."""
    for d in (DATA_OUT, SHARD_DIR, FILLED_DIR, STRIPPED_DIR,
              RESULTS_DIR, TABLES_DIR, RESPONSE_DIR, LOGS_DIR, OUTPUTS_DIR):
        os.makedirs(d, exist_ok=True)
