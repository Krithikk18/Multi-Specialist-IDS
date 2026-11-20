"""common/plot_style.py -- the one fixed paper style for every V2 figure (matplotlib, PNG 300 dpi).

Base: V1's 05_profile_devices.py setup_style() (DejaVu Sans, 9 / 10 pt, no top / right spines,
300 dpi) and V1's 07 / 07a surface / ink colours, so V1 and V2 figures match in the paper.

Class colours follow the class id, never the plot order (a class keeps its colour in every figure):
  id 0 benign     neutral gray #6f6e69 (the background class, deliberately not a hue)
  id 1..          categorical slots in fixed order: blue #2a78d6, orange #eb6834, aqua #1baf7a, then
                  yellow, magenta, green, violet, red (reference palette, light steps)
Validated (dataviz validate_palette.js, light, surface #fcfcfb, --pairs all) for the 4 current classes:
worst CVD dE 9.2 (deutan), worst normal-vision dE 17.4 -> pass; aqua is < 3:1 contrast on the surface,
so bars carry direct value labels (relief rule). Slots past the 3rd attack class do NOT pass all-pairs
(yellow vs orange): figures with > 4 classes must facet or add a secondary encoding.
"""

from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

DPI = 300
SURFACE, TEXT1, TEXT2, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#e6e5e0"   # == V1 07 / 07a
BENIGN_GRAY = "#6f6e69"
NEUTRAL_LIGHT = "#b5b4ae"           # second neutral for non-class series (paired with TEXT2 by lightness)
CATEGORICAL = ("#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6", "#e34948")
SEQUENTIAL_CMAP = "Blues"           # one hue, light -> dark (magnitude only)


def apply() -> None:
    """Set the paper rcParams (call once per script, before any figure)."""
    plt.rcParams.update({
        "font.family": "DejaVu Sans", "font.size": 9, "axes.titlesize": 10, "axes.labelsize": 10,
        "xtick.labelsize": 9, "ytick.labelsize": 9, "legend.fontsize": 8.5, "figure.titlesize": 10,
        "axes.spines.top": False, "axes.spines.right": False, "axes.edgecolor": TEXT2,
        "axes.labelcolor": TEXT1, "xtick.color": TEXT2, "ytick.color": TEXT2, "text.color": TEXT1,
        "axes.grid": False, "grid.color": GRID, "grid.linewidth": 0.6,
        "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE,
        "savefig.dpi": DPI, "pdf.fonttype": 42, "ps.fonttype": 42,
    })


def class_color(class_id: int) -> str:
    """Colour of a class by its id (benign 0 = gray; ids 1.. = categorical slots, never cycled)."""
    if class_id == 0:
        return BENIGN_GRAY
    if not 1 <= class_id <= len(CATEGORICAL):
        raise ValueError(f"class id {class_id}: no fixed colour (max {len(CATEGORICAL)} attack classes); "
                         "facet or fold instead of cycling hues")
    return CATEGORICAL[class_id - 1]


def save(fig, path: Path) -> str:
    """Write a 300 dpi PNG (tight bbox, paper surface) and close the figure. Refuses to overwrite."""
    path = Path(path)
    if path.exists():
        raise FileExistsError(f"refusing to overwrite {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=DPI, bbox_inches="tight", facecolor=SURFACE)
    plt.close(fig)
    return str(path)
