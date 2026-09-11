"""
Generates the system architecture diagram (architecture_diagram.png).
"""

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

STAGES = [
    ("Network Telemetry", "latency, packet loss, bandwidth,\nCPU, memory, iface errors, traffic"),
    ("Data Processing", "per-device / per-metric time series,\nrolling baseline windows"),
    ("Anomaly Detection", "rolling z-score + persistence filter\n+ Isolation Forest cross-check"),
    ("Root-Cause Analysis", "temporal precedence + causal vs.\nsymptom metrics + topology reasoning"),
    ("Security Assessment", "signature-based heuristic classification:\noperational vs. security"),
    ("Incident Report", "root cause, confidence, affected devices,\nevidence trail, recommended action"),
]

BRANCH_LABELS = ("Affected Devices\n& Components", "Security\nClassification")

fig, ax = plt.subplots(figsize=(7.5, 12))
ax.set_xlim(0, 10)
ax.set_ylim(0, 34)
ax.axis("off")

box_w, box_h = 7.0, 3.0
x_center = 5.0
y_positions = [31, 26.5, 22, 17.5, 13, 4.5]  # last one (Incident Report) lower, branch sits between

colors = ["#4C72B0", "#4C72B0", "#DD8452", "#55A868", "#C44E52", "#8172B2"]

def draw_box(y, title, subtitle, color):
    box = FancyBboxPatch((x_center - box_w / 2, y - box_h / 2), box_w, box_h,
                          boxstyle="round,pad=0.15,rounding_size=0.3",
                          linewidth=1.5, edgecolor=color, facecolor=color, alpha=0.15)
    ax.add_patch(box)
    ax.text(x_center, y + 0.5, title, ha="center", va="center", fontsize=12, fontweight="bold", color=color)
    ax.text(x_center, y - 0.7, subtitle, ha="center", va="center", fontsize=8.5, color="#333333")

for (title, subtitle), y, color in zip(STAGES[:4], y_positions[:4], colors[:4]):
    draw_box(y, title, subtitle, color)

for i in range(3):
    ax.add_patch(FancyArrowPatch((x_center, y_positions[i] - box_h / 2),
                                  (x_center, y_positions[i + 1] + box_h / 2),
                                  arrowstyle="-|>", mutation_scale=18, color="#555555", linewidth=1.5))

# Branch: Root-Cause Analysis -> Affected Devices & Security Assessment (parallel)
branch_y = 8.7
branch_box_w = 3.3
left_x, right_x = 3.0, 7.0

left_box = FancyBboxPatch((left_x - branch_box_w / 2, branch_y - 1.1), branch_box_w, 2.2,
                           boxstyle="round,pad=0.12,rounding_size=0.25",
                           linewidth=1.5, edgecolor="#55A868", facecolor="#55A868", alpha=0.15)
ax.add_patch(left_box)
ax.text(left_x, branch_y, BRANCH_LABELS[0], ha="center", va="center", fontsize=9.5, fontweight="bold", color="#55A868")

right_box = FancyBboxPatch((right_x - branch_box_w / 2, branch_y - 1.1), branch_box_w, 2.2,
                            boxstyle="round,pad=0.12,rounding_size=0.25",
                            linewidth=1.5, edgecolor="#C44E52", facecolor="#C44E52", alpha=0.15)
ax.add_patch(right_box)
ax.text(right_x, branch_y, "Security\nAssessment", ha="center", va="center", fontsize=9.5, fontweight="bold", color="#C44E52")

# arrow from root-cause box down to the two branches
ax.add_patch(FancyArrowPatch((x_center, y_positions[3] - box_h / 2), (left_x, branch_y + 1.1),
                              arrowstyle="-|>", mutation_scale=16, color="#555555", linewidth=1.3))
ax.add_patch(FancyArrowPatch((x_center, y_positions[3] - box_h / 2), (right_x, branch_y + 1.1),
                              arrowstyle="-|>", mutation_scale=16, color="#555555", linewidth=1.3))

# both branches converge into Incident Report
report_y = y_positions[5]
ax.add_patch(FancyArrowPatch((left_x, branch_y - 1.1), (x_center - 0.3, report_y + box_h / 2),
                              arrowstyle="-|>", mutation_scale=16, color="#555555", linewidth=1.3))
ax.add_patch(FancyArrowPatch((right_x, branch_y - 1.1), (x_center + 0.3, report_y + box_h / 2),
                              arrowstyle="-|>", mutation_scale=16, color="#555555", linewidth=1.3))

draw_box(report_y, *STAGES[5][:1].__add__(("root cause, confidence, affected devices,\nevidence trail, recommended action",)), colors[5])

ax.set_title("Network Intelligence System — Pipeline Architecture", fontsize=13, fontweight="bold", pad=15)

plt.tight_layout()
plt.savefig("architecture_diagram.png", dpi=180, bbox_inches="tight", facecolor="white")
print("Saved architecture_diagram.png")