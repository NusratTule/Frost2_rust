#!/usr/bin/env python3
"""
Parse frost2_rust/results.csv (possibly single-line concatenated format) and emit:
  - Plain-text and LaTeX tables
  - Matplotlib figures (PNG + PDF)
  - Figure caption snippets

Run from frost2_rust:  python3 scripts/generate_benchmark_artifacts.py
"""
from __future__ import annotations

import csv
import io
import re
from pathlib import Path

# Project paths
ROOT = Path(__file__).resolve().parents[1]
CSV_PATH = ROOT / "results.csv"
OUT_DIR = ROOT / "benchmark_artifacts"

VARIANTS = [
    ("FROST1", "FROST1"),
    ("Binding", "Binding (FROST2)"),
    ("FROST-2+", "FROST-2+"),
    ("FROST-2#", "FROST-2#"),
    ("ROAST", "ROAST"),
]

UNITS = "milliseconds (ms)"


def parse_results_csv(path: Path) -> tuple[dict, str]:
    """Return (phase -> {variant -> (mean, median, std)}), meta comment string."""
    text = path.read_text(encoding="utf-8")
    meta_lines = []
    for ln in text.splitlines():
        s = ln.strip().strip('"').strip()
        if s.startswith("#"):
            meta_lines.append(s.lstrip("#").strip())
    meta = " ".join(meta_lines) if meta_lines else ""

    # Normalise: join non-comment body into one logical CSV stream
    # Lines may be quoted like "# comment ..."
    def _is_data_line(ln: str) -> bool:
        s = ln.strip().strip('"').strip()
        if not s:
            return False
        if s.startswith("#"):
            return False
        return True

    body_lines = [ln for ln in text.splitlines() if _is_data_line(ln)]
    blob = "\n".join(body_lines)

    # Try standard CSV first
    reader = csv.reader(io.StringIO(blob))
    rows = list(reader)
    if len(rows) >= 2 and len(rows[0]) >= 16:
        header = rows[0]
        data_rows = rows[1:]
    else:
        # Single-line concatenated: Phase,...,ROAST_std,setup,0.002,...
        t = blob.replace("\n", ",").split(",")
        if len(t) < 32 or t[0] != "Phase":
            raise ValueError(f"Unrecognised CSV layout in {path}")
        header = t[:16]
        rest = t[16:]
        if len(rest) % 16 != 0:
            raise ValueError(f"Expected multiple of 16 data fields, got {len(rest)}")
        data_rows = []
        for i in range(0, len(rest), 16):
            data_rows.append(rest[i : i + 16])

    colnames = header[1:]  # FROST1_mean, ...
    phases: dict[str, dict[str, tuple[float, float, float]]] = {}
    for row in data_rows:
        if len(row) != 16:
            raise ValueError(f"Bad row width: {row}")
        phase = row[0].strip()
        vals = row[1:]
        phases[phase] = {}
        for vi, (key, _lbl) in enumerate(VARIANTS):
            base = 3 * vi
            m, med, s = float(vals[base]), float(vals[base + 1]), float(vals[base + 2])
            phases[phase][key] = (m, med, s)

    return phases, meta


def fmt3(x: float) -> str:
    return f"{x:.3f}"


def write_plain_tables(phases: dict, meta: str, out: Path) -> None:
    lines = [
        "Runtime benchmark — Ristretto255, SHA-512",
        f"Source: {CSV_PATH.name}",
        f"Metadata: {meta}",
        f"Units: {UNITS}",
        "",
        "--- Full phase breakdown (mean | median | std per variant) ---",
        "",
    ]
    vkeys = [k for k, _ in VARIANTS]
    for phase in phases:
        lines.append(phase)
        lines.append("-" * len(phase))
        header = f"{'':22}" + "".join(f"{k:>14}" for k in vkeys)
        lines.append(header)
        for stat, label in [(0, "mean"), (1, "median"), (2, "std")]:
            row = f"{label:22}"
            for vk in vkeys:
                row += f"{fmt3(phases[phase][vk][stat]):>14}"
            lines.append(row)
        lines.append("")
    out.write_text("\n".join(lines), encoding="utf-8")


def latex_escape(s: str) -> str:
    return s.replace("#", "\\#").replace("_", "\\_")


def write_latex_table(phases: dict, meta: str, out: Path) -> None:
    vkeys = [k for k, _ in VARIANTS]
    colspec = "l" + "rrr" * len(vkeys)
    cap = meta.replace("&", r"\&").replace("_", r"\_")
    lines = [
        r"% Auto-generated from " + CSV_PATH.name,
        r"% Requires: \usepackage{booktabs}",
        r"% " + cap,
        r"\begin{table}[t]",
        r"  \centering",
        r"  \caption{Runtime by phase (" + UNITS + r"). " + cap + r"}",
        r"  \label{tab:bench-autogen}",
        r"  \scriptsize",
        r"  \setlength{\tabcolsep}{2pt}",
        f"  \\begin{{tabular}}{{{colspec}}}",
        r"    \toprule",
        r"    Phase & " + " & ".join(
            rf"\multicolumn{{3}}{{c}}{{{latex_escape(k)}}}" for k in vkeys
        )
        + r" \\",
        r"    & "
        + " & ".join(r"$\mu$ & mdn & $\sigma$" for _ in vkeys)
        + r" \\",
        r"    \midrule",
    ]
    main_phases = [
        "setup",
        "Key generation",
        "Preprocess",
        "signing",
        "combining",
        "verifying",
        "preprocess per participant",
        "signing per participant",
    ]
    for phase in main_phases:
        if phase not in phases:
            continue
        row = f"    {latex_escape(phase)}"
        for vk in vkeys:
            m, med, s = phases[phase][vk]
            row += f" & {m:.3f} & {med:.3f} & {s:.3f}"
        row += r" \\"
        lines.append(row)
    lines.extend(
        [
            r"    \bottomrule",
            r"  \end{tabular}",
            r"\end{table}",
        ]
    )
    out.write_text("\n".join(lines), encoding="utf-8")


def write_captions(out: Path) -> None:
    text = """Figure 1 (suggested). Mean signing phase duration across variants for n=20, t=7, alpha=7, five trials, seed 42. All times in milliseconds. FROST-style schemes cluster near 3.1–3.3 ms; ROAST is higher due to coordinator and session overhead in this harness.

Figure 2 (suggested). Mean duration of major phases for FROST1 only (same parameters). Key generation dominates; preprocessing and signing are secondary; setup, combining, and verification are negligible at this scale.

Figure 3 (optional). Mean preprocess and signing time per participant across variants. ROAST shows larger per-participant preprocess and signing means than the FROST-style paths, consistent with wrapper logic attributed in those counters.
"""
    out.write_text(text, encoding="utf-8")


def write_plot_data_files(phases: dict, meta: str, out_dir: Path) -> None:
    """Emit CSV snippets for pgfplots / gnuplot if matplotlib is unavailable."""
    vkeys = [k for k, _ in VARIANTS]
    out_dir.mkdir(parents=True, exist_ok=True)
    # signing means
    lines = ["variant,mean_signing_ms"]
    for k in vkeys:
        lines.append(f"{k},{phases['signing'][k][0]:.6f}")
    (out_dir / "data_signing_mean.csv").write_text("\n".join(lines), encoding="utf-8")
    # FROST1 phases
    sub = ["setup", "Key generation", "Preprocess", "signing", "combining", "verifying"]
    lines2 = ["phase,mean_ms"]
    for p in sub:
        lines2.append(f"{p},{phases[p]['FROST1'][0]:.6f}")
    (out_dir / "data_frost1_phases_mean.csv").write_text("\n".join(lines2), encoding="utf-8")
    (out_dir / "run_meta.txt").write_text(meta, encoding="utf-8")

    # Minimal pgfplots snippet (paste after \usepackage{pgfplots})
    pgf = r"""\begin{tikzpicture}
\begin{axis}[
  ybar, bar width=12pt, ymin=0,
  ylabel={Mean time (ms)},
  symbolic x coords={FROST1,Binding,FROST-2+,FROST-2\#,ROAST},
  xtick=data, x tick label style={rotate=18,anchor=east},
  width=0.9\linewidth, height=5cm, grid=major,
]
\addplot coordinates {
"""
    pgf_names = ["FROST1", "Binding", "FROST-2+", r"FROST-2\#", "ROAST"]
    for kn, k in zip(pgf_names, vkeys):
        pgf += f"  ({kn},{phases['signing'][k][0]:.6f})\n"
    pgf += r"""};
\end{axis}
\end{tikzpicture}
"""
    (out_dir / "pgfplots_signing_mean.tex").write_text(pgf, encoding="utf-8")


def plot_figures(phases: dict, meta: str, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    write_plot_data_files(phases, meta, out_dir)

    try:
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError:
        print("matplotlib not installed; skipped PNG/PDF (CSV data written).")
        return
    vkeys = [k for k, _ in VARIANTS]
    labels = [lbl for _, lbl in VARIANTS]
    x = np.arange(len(vkeys))

    # --- Fig 1: mean signing ---
    fig, ax = plt.subplots(figsize=(8, 4))
    means = [phases["signing"][k][0] for k in vkeys]
    bars = ax.bar(x, means, color=["#4477aa", "#66ccee", "#228833", "#ccbb44", "#aa3377"])
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=15, ha="right")
    ax.set_ylabel(f"Mean time ({UNITS})")
    ax.set_title(f"Signing phase (mean)\n{meta}")
    ax.grid(axis="y", alpha=0.3)
    for b, m in zip(bars, means):
        ax.annotate(f"{m:.3f}", xy=(b.get_x() + b.get_width() / 2, m), ha="center", va="bottom", fontsize=8)
    fig.tight_layout()
    fig.savefig(out_dir / "fig_signing_mean.png", dpi=150)
    fig.savefig(out_dir / "fig_signing_mean.pdf")
    plt.close(fig)

    # --- Fig 2: FROST1 phase means (main phases only) ---
    sub = ["setup", "Key generation", "Preprocess", "signing", "combining", "verifying"]
    pmeans = [phases[p]["FROST1"][0] for p in sub]
    fig, ax = plt.subplots(figsize=(9, 4))
    xp = np.arange(len(sub))
    ax.bar(xp, pmeans, color="#4477aa")
    ax.set_xticks(xp)
    ax.set_xticklabels(sub, rotation=20, ha="right")
    ax.set_ylabel(f"Mean time ({UNITS})")
    ax.set_title(f"FROST1: phase means\n{meta}")
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(out_dir / "fig_frost1_phases_mean.png", dpi=150)
    fig.savefig(out_dir / "fig_frost1_phases_mean.pdf")
    plt.close(fig)

    # --- Fig 3: per-participant means ---
    fig, ax = plt.subplots(figsize=(8, 4))
    w = 0.35
    pre = [phases["preprocess per participant"][k][0] for k in vkeys]
    sig = [phases["signing per participant"][k][0] for k in vkeys]
    ax.bar(x - w / 2, pre, w, label="preprocess / participant")
    ax.bar(x + w / 2, sig, w, label="signing / participant")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=15, ha="right")
    ax.set_ylabel(f"Mean time ({UNITS})")
    ax.set_title(f"Per-participant means\n{meta}")
    ax.legend()
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(out_dir / "fig_per_participant_mean.png", dpi=150)
    fig.savefig(out_dir / "fig_per_participant_mean.pdf")
    plt.close(fig)


def main() -> None:
    phases, meta = parse_results_csv(CSV_PATH)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    write_plain_tables(phases, meta, OUT_DIR / "tables_plain.txt")
    write_latex_table(phases, meta, OUT_DIR / "tables_benchmark.tex")
    write_captions(OUT_DIR / "figure_captions.txt")
    plot_figures(phases, meta, OUT_DIR)
    print(f"Wrote artifacts under {OUT_DIR}")


if __name__ == "__main__":
    main()
