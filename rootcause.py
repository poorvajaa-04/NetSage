"""
Root-cause analysis engine.

Core idea (a heuristic that mirrors how a network engineer often reasons
about incidents -- not a deterministic law of networking):
  1. A TRUE root cause tends to show anomalies EARLIEST in time.
  2. A TRUE root cause tends to show anomalies in "causal" metrics
     (CPU, memory, interface errors, traffic volume, connection counts) --
     these reflect a device's own internal state or the traffic it's
     actually generating/receiving.
     "Symptom" metrics (latency, packet loss, bandwidth utilization) are
     more often *inherited* from an upstream problem than the origin of one.
     This is a heuristic weighting used by the prototype's scoring model,
     not an absolute causal rule -- a device's own latency CAN be a root
     cause in some real-world failure modes.
  3. A TRUE root cause topologically EXPLAINS other anomalous devices --
     i.e. the other anomalous devices sit within a small number of hops
     downstream of it in the topology graph.

We score every anomalous device as a root-cause candidate on those three
axes, then report the top candidate with an explicit evidence trail and
a confidence score (not just a raw number).
"""

import numpy as np
import pandas as pd
import networkx as nx

CAUSAL_METRICS = {
    "cpu_pct", "memory_pct", "iface_errors_per_min",
    "traffic_in_mbps", "traffic_out_mbps", "unique_src_ips", "syn_count",
}
SYMPTOM_METRICS = {"latency_ms", "packet_loss_pct", "bandwidth_util_pct"}

MAX_EXPLAIN_HOPS = 2


def analyze(events: pd.DataFrame, graph: nx.Graph) -> dict:
    """
    events: output of detection.summarize_anomaly_events
    Returns a dict with root_cause, confidence, affected_devices, evidence trail,
    and the full ranked candidate table (for transparency / debugging).
    """
    if events.empty:
        return {
            "root_cause_device": None,
            "confidence": 0.0,
            "affected_devices": [],
            "evidence": ["No anomalies detected in this window."],
            "candidates": pd.DataFrame(),
        }

    anomalous_devices = sorted(events["device"].unique())
    first_onset = events.groupby("device")["onset_time"].min().to_dict()
    device_metrics = events.groupby("device")["metric"].apply(set).to_dict()
    device_peak_z = events.groupby("device")["peak_zscore"].max().to_dict()
    device_iso = events.groupby("device")["iso_corroborated"].any().to_dict()

    global_earliest = min(first_onset.values())
    global_latest_span = max(1, max(first_onset.values()) - global_earliest)

    rows = []
    for dev in anomalous_devices:
        # 1. temporal precedence score: earlier onset -> higher score (0..1)
        temporal_score = 1.0 - (first_onset[dev] - global_earliest) / global_latest_span

        # 2. causal-metric score: fraction of this device's anomalous metrics
        #    that are "causal" type rather than "symptom" type
        metrics_here = device_metrics[dev]
        causal_hits = len(metrics_here & CAUSAL_METRICS)
        symptom_hits = len(metrics_here & SYMPTOM_METRICS)
        causal_score = causal_hits / max(1, causal_hits + symptom_hits)

        # 3. topological explanatory power: how many OTHER anomalous devices
        #    fall within MAX_EXPLAIN_HOPS of this device (i.e. this device's
        #    problem could plausibly propagate to them)
        try:
            reach = nx.single_source_shortest_path_length(graph, dev, cutoff=MAX_EXPLAIN_HOPS)
        except nx.NodeNotFound:
            reach = {dev: 0}
        explained = [d for d in anomalous_devices if d != dev and d in reach]
        explain_score = len(explained) / max(1, len(anomalous_devices) - 1)

        severity_score = min(1.0, device_peak_z[dev] / 15.0)  # normalize, cap at 1
        iso_bonus = 0.05 if device_iso.get(dev, False) else 0.0

        composite = (
            0.35 * temporal_score +
            0.30 * explain_score +
            0.20 * causal_score +
            0.10 * severity_score +
            iso_bonus
        )

        rows.append({
            "device": dev,
            "onset_time": first_onset[dev],
            "temporal_score": round(temporal_score, 3),
            "causal_score": round(causal_score, 3),
            "explain_score": round(explain_score, 3),
            "severity_score": round(severity_score, 3),
            "iso_corroborated": device_iso.get(dev, False),
            "explains_devices": explained,
            "anomalous_metrics": sorted(metrics_here),
            "composite_score": round(composite, 3),
        })

    candidates = pd.DataFrame(rows).sort_values("composite_score", ascending=False).reset_index(drop=True)
    top = candidates.iloc[0]
    runner_up_score = candidates.iloc[1]["composite_score"] if len(candidates) > 1 else 0.0

    # confidence: combination of absolute score and margin over runner-up
    margin = max(0.0, top["composite_score"] - runner_up_score)
    confidence = min(0.99, 0.5 * top["composite_score"] + 0.5 * min(1.0, margin / 0.25))

    evidence = [
        f"{top['device']} shows the earliest anomaly onset (t={top['onset_time']}) among all "
        f"{len(anomalous_devices)} anomalous device(s).",
        f"{top['device']}'s anomalous metrics are {top['anomalous_metrics']} "
        f"({'mostly causal/internal-state signals' if top['causal_score'] >= 0.5 else 'mostly symptom signals, weaker causal evidence'}).",
    ]
    if top["explains_devices"]:
        evidence.append(
            f"Within {MAX_EXPLAIN_HOPS} topology hops of {top['device']} are the other anomalous "
            f"device(s): {top['explains_devices']}, consistent with fault propagation outward from this point."
        )
    else:
        evidence.append(
            f"{top['device']} is topologically isolated from the other anomalies -- "
            f"treat as a possibly independent or localized incident."
        )
    if top["iso_corroborated"]:
        evidence.append("Multivariate outlier detection (Isolation Forest) independently corroborates this device as anomalous.")

    affected = sorted(set(anomalous_devices))

    return {
        "root_cause_device": top["device"],
        "confidence": round(float(confidence), 2),
        "affected_devices": affected,
        "evidence": evidence,
        "candidates": candidates,
    }