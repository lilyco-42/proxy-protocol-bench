#!/usr/bin/env python3
"""Plot goodput and completion for the published runs (requires matplotlib)."""
import argparse
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
from matplotlib import pyplot as plt
from matplotlib.colors import Normalize

from summarize import summarize


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("files", nargs="+", type=Path)
    cli.add_argument("--out", required=True, type=Path)
    args = cli.parse_args()
    data = [json.loads(path.read_text(encoding="utf-8")) for path in args.files]
    columns = [{row["case"]: row for row in summarize(run)} for run in data]
    all_cases = sorted(set().union(*(column.keys() for column in columns)) - {"direct-https"})
    all_cases.insert(0, "direct-https")
    fig, ax = plt.subplots(figsize=(11, .32 * len(all_cases) + 1.65))
    cmap = plt.colormaps["Blues"]
    norm = Normalize(vmin=0, vmax=max((row["p50_mbps"] or 0 for col in columns for row in col.values()), default=1) or 1)
    for col, rows in enumerate(columns):
        for y, case in enumerate(all_cases):
            row = rows.get(case)
            if row is None:
                color, label = "#f3f4f6", "—"
            elif row["p50_mbps"] is None:
                color, label = "#fef2f2", f"0/{row['total']} complete"
            else:
                color = cmap(.12 + .67 * norm(row["p50_mbps"]))
                label = f"{row['p50_mbps']:.2f} Mbps   ·   {row['passed']}/{row['total']}"
            ax.add_patch(plt.Rectangle((col, y), 1, 1, facecolor=color, edgecolor="white", linewidth=1))
            ax.text(col + .5, y + .5, label, va="center", ha="center", fontsize=9,
                    color="white" if isinstance(color, tuple) and color[0] < .36 else "#0f172a")
    ax.set(xlim=(0, len(columns)), ylim=(len(all_cases), 0))
    ax.set_xticks([i + .5 for i in range(len(data))], [run["label"] for run in data])
    ax.set_yticks([i + .5 for i in range(len(all_cases))], all_cases)
    ax.tick_params(axis="both", length=0)
    ax.xaxis.tick_top()
    for spine in ax.spines.values():
        spine.set_visible(False)
    fig.suptitle("Los Angeles proxy benchmark", x=.025, y=.98, ha="left", fontsize=19, weight="bold")
    fig.text(.025, .032, "Median goodput of complete downloads and completion count. A dash indicates no run.", fontsize=9)
    fig.tight_layout(rect=(0, .055, 1, .92))
    fig.savefig(args.out, dpi=160)


if __name__ == "__main__":
    main()
