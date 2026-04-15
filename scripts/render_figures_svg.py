#!/usr/bin/env python3
"""Render benchmark figures as standalone SVG (no LaTeX, no matplotlib)."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "benchmark_artifacts" / "figures_svg"

# From results.csv (n=20, t=7, alpha=7, T=5, seed=42)
SIGNING = [
    ("FROST1", 3.145),
    ("Binding", 3.176),
    ("FROST-2+", 3.268),
    ("FROST-2#", 3.308),
    ("ROAST", 9.260),
]

FROST1_PHASES = [
    ("Key generation", 184.529),
    ("Preprocess", 0.415),
    ("signing", 3.145),
    ("verifying", 0.076),
]


def bar_chart_svg(
    title: str,
    y_label: str,
    items: list[tuple[str, float]],
    filename: str,
    ymax: float | None = None,
    width: int = 720,
    height: int = 420,
) -> str:
    n = len(items)
    margin_l, margin_r, margin_t, margin_b = 72, 40, 56, 100
    plot_w = width - margin_l - margin_r
    plot_h = height - margin_t - margin_b
    vals = [v for _, v in items]
    ymax = ymax if ymax is not None else max(vals) * 1.12
    if ymax <= 0:
        ymax = 1.0
    bar_w = plot_w / n * 0.65
    gap = plot_w / n * 0.175
    x0 = margin_l + gap

    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" font-family="Helvetica,Arial,sans-serif">',
        f'<rect width="100%" height="100%" fill="#fafafa"/>',
        f'<text x="{width//2}" y="28" text-anchor="middle" font-size="15" font-weight="600">{title}</text>',
        f'<text transform="translate(22,{margin_t + plot_h//2}) rotate(-90)" text-anchor="middle" font-size="12">{y_label}</text>',
        f'<line x1="{margin_l}" y1="{margin_t}" x2="{margin_l}" y2="{margin_t+plot_h}" stroke="#333" stroke-width="1"/>',
        f'<line x1="{margin_l}" y1="{margin_t+plot_h}" x2="{width-margin_r}" y2="{margin_t+plot_h}" stroke="#333" stroke-width="1"/>',
    ]
    # y tick 0 and max
    lines.append(
        f'<text x="{margin_l-8}" y="{margin_t+plot_h+4}" text-anchor="end" font-size="11">0</text>'
    )
    lines.append(
        f'<text x="{margin_l-8}" y="{margin_t+8}" text-anchor="end" font-size="11">{ymax:.2f}</text>'
    )

    colors = ["#4477aa", "#66ccee", "#228833", "#ccbb44", "#aa3377"]
    for i, ((label, val), c) in enumerate(zip(items, colors * 3)):
        h = (val / ymax) * plot_h
        x = x0 + i * (bar_w + gap * 2 / n)
        y = margin_t + plot_h - h
        lines.append(
            f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_w:.1f}" height="{max(h,0.5):.1f}" fill="{c}" stroke="#222" stroke-width="0.5"/>'
        )
        lines.append(
            f'<text x="{x+bar_w/2:.1f}" y="{y-6:.1f}" text-anchor="middle" font-size="10">{val:.3f}</text>'
        )
        # x label (rotate)
        lx = x + bar_w / 2
        ly = margin_t + plot_h + 18
        lines.append(
            f'<text x="{lx:.1f}" y="{ly}" text-anchor="end" font-size="10" transform="rotate(-35 {lx:.1f} {ly})">{label}</text>'
        )

    lines.append("</svg>")
    return "\n".join(lines)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    s1 = bar_chart_svg(
        "Mean signing time by variant (ms) — n=20, t=7, α=7, 5 trials, seed 42",
        "Mean time (ms)",
        SIGNING,
        "figure_signing_by_variant.svg",
        ymax=10.0,
    )
    (OUT / "figure_signing_by_variant.svg").write_text(s1, encoding="utf-8")

    s2 = bar_chart_svg(
        "FROST1: mean time by phase (ms) — same parameters",
        "Mean time (ms)",
        FROST1_PHASES,
        "figure_frost1_phases.svg",
        ymax=200.0,
    )
    (OUT / "figure_frost1_phases.svg").write_text(s2, encoding="utf-8")

    print(f"Wrote {OUT / 'figure_signing_by_variant.svg'}")
    print(f"Wrote {OUT / 'figure_frost1_phases.svg'}")


if __name__ == "__main__":
    main()
