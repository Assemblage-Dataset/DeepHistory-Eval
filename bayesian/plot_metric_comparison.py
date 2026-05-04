#!/usr/bin/env python3
"""Plot MalConv and TLSH sigmoid-median global coefficient 95% HDIs together."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

HERE = Path(__file__).resolve().parent
os.environ.setdefault("MPLCONFIGDIR", str(HERE / ".mplconfig"))
os.environ.setdefault("XDG_CACHE_HOME", str(HERE / ".cache"))

import matplotlib as mpl
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
import pandas as pd

DEFAULT_BASE = HERE / "normalized_file_change"
DEFAULT_MALCONV = DEFAULT_BASE / "malconv" / "summary.csv"
DEFAULT_TLSH = DEFAULT_BASE / "tlsh_sigmoid" / "summary.csv"
DEFAULT_MALCONV_METADATA = DEFAULT_BASE / "malconv" / "model_metadata.json"
DEFAULT_TLSH_METADATA = DEFAULT_BASE / "tlsh_sigmoid" / "model_metadata.json"
DEFAULT_OUT_CSV = DEFAULT_BASE / "metricComparison95HDI.csv"
DEFAULT_OUT_PDF = DEFAULT_BASE / "bayesianRegressMalconvTLSHNormalizedFileChange95HDI.pdf"
DEFAULT_OUT_PNG = DEFAULT_BASE / "bayesianRegressMalconvTLSHNormalizedFileChange95HDI.png"
FIG_WIDTH = 5.4
FIG_HEIGHT_BASE = 0.95
FIG_HEIGHT_PER_ROW = 0.30
MIN_FIG_HEIGHT = 2.05
PNG_DPI = 600

FALLBACK_PARAMETERS = [
    ("alpha_global", "bias"),
    ("beta_global[days]", "days"),
    ("beta_global[commits]", "commits"),
    ("beta_global[file change]", "file change"),
]

METRICS = [
    ("malconv", "MalConv", "#0072B2", -0.14),
    ("tlsh", "TLSH", "#D55E00", 0.14),
]


def setup_style() -> None:
    mpl.rcParams.update(
        {
            "font.family": "sans-serif",
            "font.sans-serif": ["Roboto", "Arial", "Helvetica", "DejaVu Sans"],
            "font.size": 9,
            "axes.labelsize": 9,
            "xtick.labelsize": 8,
            "ytick.labelsize": 8,
            "axes.facecolor": "white",
            "figure.facecolor": "white",
            "savefig.facecolor": "white",
            "axes.edgecolor": "#333333",
            "axes.linewidth": 0.6,
            "axes.spines.top": False,
            "axes.spines.right": False,
            "savefig.dpi": PNG_DPI,
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
        }
    )


def parameters_from_metadata(
    malconv_metadata: Path | None,
    tlsh_metadata: Path | None,
) -> list[tuple[str, str]]:
    metadata_labels = []
    for metadata_path in (malconv_metadata, tlsh_metadata):
        if metadata_path is None or not metadata_path.exists():
            continue
        metadata = json.loads(metadata_path.read_text())
        metadata_labels.append([item["label"] for item in metadata["features"]])
    if metadata_labels:
        labels = metadata_labels[0]
        for other in metadata_labels[1:]:
            if other != labels:
                raise ValueError(
                    "MalConv and TLSH metadata use different feature labels: "
                    f"{labels} != {other}"
                )
        return [("alpha_global", "bias")] + [
            (f"beta_global[{label}]", label) for label in labels
        ]
    return FALLBACK_PARAMETERS


def load_rows(
    malconv_summary: Path,
    tlsh_summary: Path,
    parameters: list[tuple[str, str]],
) -> pd.DataFrame:
    summaries = {
        "malconv": pd.read_csv(malconv_summary, index_col=0),
        "tlsh": pd.read_csv(tlsh_summary, index_col=0),
    }

    rows = []
    for metric, _, _, _ in METRICS:
        summary = summaries[metric]
        for param, label in parameters:
            row = summary.loc[param]
            rows.append(
                {
                    "metric": metric,
                    "parameter": param,
                    "label": label,
                    "mean": row["mean"],
                    "hdi_2.5%": row["hdi_2.5%"],
                    "hdi_97.5%": row["hdi_97.5%"],
                    "r_hat": row["r_hat"],
                }
            )
    return pd.DataFrame(rows)


def plot_comparison(
    df: pd.DataFrame,
    parameters: list[tuple[str, str]],
    out_pdf: Path,
    out_png: Path,
) -> None:
    y_positions = {label: i for i, (_, label) in enumerate(reversed(parameters))}

    fig_height = max(
        MIN_FIG_HEIGHT,
        FIG_HEIGHT_BASE + FIG_HEIGHT_PER_ROW * len(parameters),
    )
    fig, ax = plt.subplots(figsize=(FIG_WIDTH, fig_height))
    for metric, metric_label, color, offset in METRICS:
        subset = df[df["metric"] == metric]
        for _, row in subset.iterrows():
            y = y_positions[row["label"]] + offset
            ax.plot(
                [row["hdi_2.5%"], row["hdi_97.5%"]],
                [y, y],
                color=color,
                lw=1.4,
                solid_capstyle="round",
            )
            ax.plot(
                row["mean"],
                y,
                marker="o",
                linestyle="None",
                color=color,
                markersize=4.5,
                markerfacecolor="white",
                markeredgecolor=color,
                markeredgewidth=1.0,
            )

    legend_handles = [
        Line2D(
            [0],
            [0],
            color=color,
            marker="o",
            markerfacecolor="white",
            markeredgecolor=color,
            markeredgewidth=1.0,
            linewidth=1.4,
            markersize=4.5,
            label=metric_label,
        )
        for _, metric_label, color, _ in METRICS
    ]
    ax.legend(
        handles=legend_handles,
        frameon=False,
        loc="lower right",
        borderaxespad=0.2,
        handlelength=1.6,
        labelspacing=0.25,
    )

    ax.axvline(0.0, color="#bbbbbb", linewidth=0.6, zorder=0)
    ax.grid(axis="x", linewidth=0.4, color="#dddddd", zorder=0)
    ax.set_axisbelow(True)
    ax.set_yticks(range(len(parameters)))
    ax.set_yticklabels([label for _, label in reversed(parameters)])
    ax.set_ylim(-0.42, len(parameters) - 0.58)
    ax.tick_params(axis="y", length=0, pad=3)
    ax.set_xlabel("Logit impact (95% HDI)", labelpad=2)
    fig.tight_layout()
    fig.savefig(out_pdf, bbox_inches="tight")
    fig.savefig(out_png, dpi=PNG_DPI, bbox_inches="tight")
    plt.close(fig)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--malconv-summary", type=Path, default=DEFAULT_MALCONV)
    parser.add_argument("--tlsh-summary", type=Path, default=DEFAULT_TLSH)
    parser.add_argument(
        "--malconv-metadata", type=Path, default=DEFAULT_MALCONV_METADATA
    )
    parser.add_argument("--tlsh-metadata", type=Path, default=DEFAULT_TLSH_METADATA)
    parser.add_argument("--out-csv", type=Path, default=DEFAULT_OUT_CSV)
    parser.add_argument("--out-pdf", type=Path, default=DEFAULT_OUT_PDF)
    parser.add_argument("--out-png", type=Path, default=DEFAULT_OUT_PNG)
    args = parser.parse_args()

    setup_style()
    parameters = parameters_from_metadata(args.malconv_metadata, args.tlsh_metadata)
    df = load_rows(args.malconv_summary, args.tlsh_summary, parameters)
    args.out_csv.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(args.out_csv, index=False)
    plot_comparison(df, parameters, args.out_pdf, args.out_png)

    print(f"wrote {args.out_csv}")
    print(f"wrote {args.out_pdf}")
    print(f"wrote {args.out_png}")


if __name__ == "__main__":
    main()
