"""
Anomaly detection layer.

Primary method: per (device, metric) rolling baseline z-score.
   - Baseline computed from an early "quiet" window of the series
     (mimics learning normal behavior before evaluating live data).
   - A point is anomalous if |z| exceeds a metric-aware threshold
     for at least `persist` consecutive steps (avoids single-sample noise).

Secondary cross-check: Isolation Forest over the multi-metric feature
   vector per device per timestep. Used only to corroborate / raise
   confidence, never as the sole trigger -- keeps the system explainable.
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

Z_THRESHOLD = 3.0
PERSIST = 3          # consecutive anomalous points required
BASELINE_FRACTION = 0.5  # first half of series used to learn "normal"


def compute_baselines(df: pd.DataFrame, baseline_fraction: float = BASELINE_FRACTION):
    baselines = {}
    for (dev, metric), g in df.groupby(["device", "metric"]):
        g = g.sort_values("time")
        n_base = max(10, int(len(g) * baseline_fraction))
        base_vals = g["value"].values[:n_base]
        baselines[(dev, metric)] = (base_vals.mean(), max(base_vals.std(), 1e-6))
    return baselines


def zscore_anomalies(df: pd.DataFrame, baselines=None) -> pd.DataFrame:
    """Returns df with added columns: zscore, is_point_anomaly, is_anomaly (persisted)."""
    if baselines is None:
        baselines = compute_baselines(df)

    out = []
    for (dev, metric), g in df.groupby(["device", "metric"]):
        g = g.sort_values("time").copy()
        mean, std = baselines[(dev, metric)]
        g["zscore"] = (g["value"] - mean) / std
        g["is_point_anomaly"] = g["zscore"].abs() > Z_THRESHOLD

        # persistence filter: require PERSIST consecutive anomalous points
        flags = g["is_point_anomaly"].values
        persisted = np.zeros(len(flags), dtype=bool)
        run = 0
        for i, f in enumerate(flags):
            run = run + 1 if f else 0
            if run >= PERSIST:
                persisted[max(0, i - PERSIST + 1):i + 1] = True
        g["is_anomaly"] = persisted
        out.append(g)
    return pd.concat(out, ignore_index=True)


def isolation_forest_scores(df: pd.DataFrame, contamination: float = 0.1) -> pd.DataFrame:
    """Per-device multivariate anomaly score across all metrics at each timestep."""
    wide = df.pivot_table(index=["device", "time"], columns="metric", values="value").reset_index()
    metric_cols = [c for c in wide.columns if c not in ("device", "time")]

    scores = []
    for dev, g in wide.groupby("device"):
        X = g[metric_cols].values
        if len(X) < 20:
            g = g.copy()
            g["iso_score"] = 0.0
            g["iso_anomaly"] = False
            scores.append(g)
            continue
        clf = IsolationForest(contamination=contamination, random_state=42)
        clf.fit(X)
        raw = clf.decision_function(X)  # higher = more normal
        g = g.copy()
        g["iso_score"] = -raw  # flip so higher = more anomalous
        g["iso_anomaly"] = clf.predict(X) == -1
        scores.append(g)
    result = pd.concat(scores, ignore_index=True)
    return result[["device", "time", "iso_score", "iso_anomaly"]]


def detect(df: pd.DataFrame) -> pd.DataFrame:
    """Full detection pipeline: z-score anomalies + isolation forest cross-check merged in."""
    z = zscore_anomalies(df)
    iso = isolation_forest_scores(df)
    merged = z.merge(iso, on=["device", "time"], how="left")
    return merged


def summarize_anomaly_events(detected: pd.DataFrame) -> pd.DataFrame:
    """
    Collapse per-timestep anomaly flags into discrete events:
    one row per (device, metric) anomalous run, with onset time,
    peak severity, and whether isolation-forest corroborated it.
    """
    events = []
    for (dev, metric), g in detected.groupby(["device", "metric"]):
        g = g.sort_values("time")
        flags = g["is_anomaly"].values
        times = g["time"].values
        zscores = g["zscore"].values
        iso_flags = g["iso_anomaly"].fillna(False).values

        in_run = False
        start_idx = None
        for i, f in enumerate(flags):
            if f and not in_run:
                in_run, start_idx = True, i
            if in_run and (not f or i == len(flags) - 1):
                end_idx = i if not f else i
                run_slice = slice(start_idx, end_idx if not f else end_idx + 1)
                events.append({
                    "device": dev,
                    "metric": metric,
                    "onset_time": int(times[start_idx]),
                    "end_time": int(times[end_idx - 1] if not f else times[end_idx]),
                    "peak_zscore": float(np.max(np.abs(zscores[run_slice]))),
                    "iso_corroborated": bool(np.any(iso_flags[run_slice])),
                })
                in_run = False
    return pd.DataFrame(events).sort_values("onset_time") if events else pd.DataFrame(
        columns=["device", "metric", "onset_time", "end_time", "peak_zscore", "iso_corroborated"])