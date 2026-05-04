#!/usr/bin/env python3
"""Fit the hierarchical beta regression for the Linear Bayesian Model."""
from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path

import numpy as np
import pandas as pd

HERE = Path(__file__).resolve().parent
os.environ.setdefault("MPLCONFIGDIR", str(HERE / ".mplconfig"))
os.environ.setdefault("XDG_CACHE_HOME", str(HERE / ".cache"))

import arviz as az
import jax
import jax.numpy as jnp
import numpyro
import numpyro.distributions as dist
from jax import random
from numpyro.infer import MCMC, NUTS, Predictive

DEFAULT_INPUT = HERE / "release_pairs.csv"
DEFAULT_OUTPUT_DIR = HERE / "normalized_file_change" / "malconv"
DEFAULT_MODEL_INPUT = DEFAULT_OUTPUT_DIR / "model_input.csv"
DEFAULT_METADATA = DEFAULT_OUTPUT_DIR / "model_metadata.json"
DEFAULT_NC = DEFAULT_OUTPUT_DIR / "mcmc_samples.nc"
DEFAULT_SUMMARY = DEFAULT_OUTPUT_DIR / "summary.csv"

FULL_FEATURES = [
    ("days", "days"),
    ("commits_between", "commits"),
    ("norm_changed_source_files", "file change"),
    ("log_changed_source_files", "log(num. files)"),
]
NORMALIZED_FILE_CHANGE_FEATURES = [
    ("days", "days"),
    ("commits_between", "commits"),
    ("norm_changed_source_files", "file change"),
]
FEATURE_SETS = {
    "full": FULL_FEATURES,
    "normalized_file_change": NORMALIZED_FILE_CHANGE_FEATURES,
}
DEFAULT_TARGET = "malconv_similarity"


def hierarchical_beta_model(
    project_idx,
    x,
    y=None,
    n_projects: int | None = None,
    n_features: int | None = None,
):
    if n_projects is None:
        n_projects = int(project_idx.max()) + 1
    if n_features is None:
        n_features = int(x.shape[1])

    alpha_global = numpyro.sample("alpha_global", dist.Normal(0.0, 2.0))
    sigma_alpha = numpyro.sample("sigma_alpha", dist.HalfNormal(1.0))
    beta_global = numpyro.sample(
        "beta_global", dist.Normal(0.0, 1.0).expand([n_features]).to_event(1)
    )
    sigma_beta = numpyro.sample(
        "sigma_beta", dist.HalfNormal(1.0).expand([n_features]).to_event(1)
    )

    with numpyro.plate("project", n_projects):
        alpha_offset = numpyro.sample("alpha_offset", dist.Normal(0.0, 1.0))
        beta_offset = numpyro.sample(
            "beta_offset", dist.Normal(0.0, 1.0).expand([n_features]).to_event(1)
        )

    alpha_project = numpyro.deterministic(
        "alpha_project", alpha_global + alpha_offset * sigma_alpha
    )
    beta_project = numpyro.deterministic(
        "beta_project", beta_global + beta_offset * sigma_beta
    )

    kappa = numpyro.sample("kappa", dist.HalfNormal(20.0))
    eta = alpha_project[project_idx] + jnp.sum(beta_project[project_idx] * x, axis=1)
    mu = jnp.clip(jax.nn.sigmoid(eta), 1e-5, 1.0 - 1e-5)
    numpyro.sample("obs", dist.BetaProportion(mu, kappa), obs=y)


def load_model_data(
    csv_path: Path,
    target: str,
    standardize: bool,
    features: list[tuple[str, str]],
    feature_set: str,
) -> tuple[pd.DataFrame, dict[str, object], np.ndarray, np.ndarray, np.ndarray]:
    df = pd.read_csv(csv_path)
    required = {"package", target, *[name for name, _ in features]}
    missing = sorted(required - set(df.columns))
    if missing:
        raise ValueError(f"{csv_path} missing required columns: {missing}")

    cols = [name for name, _ in features]
    work = df.replace([np.inf, -np.inf], np.nan).dropna(
        subset=["package", target, *cols]
    )
    work = work[(work[target] > -1.0) & (work[target] < 1.00001)].copy()
    work[target] = work[target].clip(0.001, 0.999)
    projects = sorted(work["package"].astype(str).unique())
    project_to_idx = {project: i for i, project in enumerate(projects)}
    work["project_idx"] = work["package"].astype(str).map(project_to_idx).astype(int)

    scaler: dict[str, dict[str, float]] = {}
    x_cols = []
    for raw, _label in features:
        out_col = f"{raw}_z" if standardize else raw
        values = work[raw].astype(float).to_numpy()
        if standardize:
            mean = float(np.nanmean(values))
            std = float(np.nanstd(values))
            if not np.isfinite(std) or std == 0.0:
                std = 1.0
            work[out_col] = (values - mean) / std
            scaler[raw] = {"mean": mean, "std": std}
        else:
            work[out_col] = values
            scaler[raw] = {"mean": 0.0, "std": 1.0}
        x_cols.append(out_col)

    x = work[x_cols].to_numpy(dtype=np.float32)
    y = work[target].to_numpy(dtype=np.float32)
    project_idx = work["project_idx"].to_numpy(dtype=np.int32)
    metadata = {
        "target": target,
        "feature_set": feature_set,
        "features": [
            {"column": raw, "label": label, "model_column": model_col}
            for (raw, label), model_col in zip(features, x_cols)
        ],
        "standardized": standardize,
        "scaler": scaler,
        "projects": projects,
        "n_rows": int(len(work)),
        "n_projects": int(len(projects)),
    }
    return work, metadata, project_idx, x, y


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--out-nc", type=Path, default=DEFAULT_NC)
    parser.add_argument("--out-summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--out-model-input", type=Path, default=DEFAULT_MODEL_INPUT)
    parser.add_argument("--out-metadata", type=Path, default=DEFAULT_METADATA)
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument(
        "--feature-set",
        choices=sorted(FEATURE_SETS),
        default="normalized_file_change",
        help="Covariate set to use. normalized_file_change drops log(num. files).",
    )
    parser.add_argument("--num-warmup", type=int, default=2000)
    parser.add_argument("--num-samples", type=int, default=4000)
    parser.add_argument("--num-chains", type=int, default=1)
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--num-pp-samples", type=int, default=200)
    parser.add_argument("--no-standardize", action="store_true")
    args = parser.parse_args()

    for path in (
        args.out_nc,
        args.out_summary,
        args.out_model_input,
        args.out_metadata,
    ):
        path.parent.mkdir(parents=True, exist_ok=True)

    standardize = not args.no_standardize
    features = FEATURE_SETS[args.feature_set]
    data_df, metadata, project_idx, x, y = load_model_data(
        args.input, args.target, standardize, features, args.feature_set
    )
    data_df.to_csv(args.out_model_input, index=False)
    args.out_metadata.write_text(json.dumps(metadata, indent=2, sort_keys=True))
    print(
        f"loaded {metadata['n_rows']} rows across {metadata['n_projects']} projects"
    )

    numpyro.enable_x64()
    numpyro.set_host_device_count(max(args.num_chains, 1))
    kernel = NUTS(hierarchical_beta_model, target_accept_prob=0.9)
    mcmc = MCMC(
        kernel,
        num_warmup=args.num_warmup,
        num_samples=args.num_samples,
        num_chains=args.num_chains,
        progress_bar=True,
    )
    mcmc.run(
        random.PRNGKey(args.seed),
        jnp.asarray(project_idx),
        jnp.asarray(x),
        y=jnp.asarray(y),
        n_projects=metadata["n_projects"],
        n_features=len(features),
    )
    mcmc.print_summary()

    posterior = mcmc.get_samples()
    take = min(args.num_pp_samples, next(iter(posterior.values())).shape[0])
    posterior_thin = {key: value[:take] for key, value in posterior.items()}
    pp = Predictive(
        hierarchical_beta_model,
        posterior_samples=posterior_thin,
        return_sites=["obs"],
    )(
        random.PRNGKey(args.seed + 1),
        jnp.asarray(project_idx),
        jnp.asarray(x),
        y=None,
        n_projects=metadata["n_projects"],
        n_features=len(features),
    )

    coords = {
        "project": metadata["projects"],
        "feature": [item["label"] for item in metadata["features"]],
        "obs_id": np.arange(len(y)),
    }
    dims = {
        "beta_global": ["feature"],
        "sigma_beta": ["feature"],
        "beta_project": ["project", "feature"],
        "beta_offset": ["project", "feature"],
        "alpha_project": ["project"],
        "alpha_offset": ["project"],
        "obs": ["obs_id"],
    }
    idata = az.from_numpyro(
        posterior=mcmc,
        coords=coords,
        dims=dims,
    )
    pp_obs = np.asarray(pp["obs"])
    if pp_obs.ndim == 2:
        pp_obs = pp_obs[None, :, :]
    extra = az.from_dict(
        posterior_predictive={"obs": pp_obs},
        observed_data={"obs": y},
        constant_data={"project_idx": project_idx, "x": x},
        coords=coords,
        dims={
            "obs": ["obs_id"],
            "project_idx": ["obs_id"],
            "x": ["obs_id", "feature"],
        },
    )
    idata.extend(extra)

    args.out_nc.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        prefix=f".{args.out_nc.name}.",
        suffix=".tmp",
        dir=args.out_nc.parent,
        delete=False,
    ) as tmp:
        tmp_path = Path(tmp.name)
    try:
        idata.to_netcdf(tmp_path)
        tmp_path.replace(args.out_nc)
    finally:
        if tmp_path.exists():
            tmp_path.unlink()
    print(f"wrote {args.out_nc}")

    summary = az.summary(
        idata,
        var_names=[
            "alpha_global",
            "beta_global",
            "sigma_alpha",
            "sigma_beta",
            "kappa",
            "alpha_project",
            "beta_project",
        ],
        hdi_prob=0.95,
    )
    summary.to_csv(args.out_summary)
    print(f"wrote {args.out_summary}")


if __name__ == "__main__":
    main()
