"""
Security assessment layer.

Distinguishes "this is a performance/operational problem" from
"this looks like a security event" using SIGNATURE-BASED HEURISTIC
CLASSIFICATION -- pattern matching against a small set of hand-authored
signatures, not a trained classifier or a definitive attack determination.
It mirrors how a NOC/SOC analyst forms an initial hypothesis:

  - Security indicators: sudden (step-like, not gradual) spikes in
    unique source IP count and/or SYN/connection counts.
      * High indicator + high traffic volume + packet loss/bandwidth
        saturation  -> volumetric attack (DDoS) signature
      * High indicator + traffic volume roughly NORMAL              -> reconnaissance / port-scan signature
  - Operational indicators: gradual (ramping) anomalies concentrated
    in resource metrics (CPU, memory, interface errors) with NO
    unusual connection/source diversity -> hardware/capacity/link issue signature.

Onset "abruptness" (step vs. ramp) is estimated directly from the raw
series and is one of the strongest discriminators available without
deep packet inspection. These signatures are a starting hypothesis for
a human analyst, not a substitute for one -- a real deployment should
treat "security" classifications here as a prioritized alert for
investigation, not a confirmed verdict.
"""

import numpy as np
import pandas as pd

SECURITY_INDICATOR_METRICS = {"unique_src_ips", "syn_count"}
VOLUME_METRICS = {"traffic_in_mbps", "traffic_out_mbps", "bandwidth_util_pct", "packet_loss_pct"}
OPERATIONAL_METRICS = {"cpu_pct", "memory_pct", "iface_errors_per_min"}


def _abruptness(df: pd.DataFrame, device: str, metric: str, onset_time: int, window: int = 6) -> float:
    """
    0 = very gradual ramp, 1 = near-instant step change.
    Measured as: fraction of the eventual (window-end) deviation from
    baseline already reached within the first 2 steps after onset.
    """
    g = df[(df.device == device) & (df.metric == metric)].sort_values("time")
    baseline = g[g.time < onset_time]["value"]
    if baseline.empty:
        return 0.5
    base_mean = baseline.mean()

    post = g[(g.time >= onset_time) & (g.time < onset_time + window)]["value"].values
    if len(post) < 2:
        return 0.5
    early_dev = abs(post[min(1, len(post) - 1)] - base_mean)
    final_dev = abs(post[-1] - base_mean)
    if final_dev < 1e-6:
        return 0.5
    return float(np.clip(early_dev / final_dev, 0, 1))


def assess(events: pd.DataFrame, df: pd.DataFrame, root_cause_device: str) -> dict:
    if events.empty or root_cause_device is None:
        return {"classification": "none", "confidence": 0.0, "indicators": []}

    root_events = events[events.device == root_cause_device]
    metrics_here = set(root_events["metric"])

    sec_hits = metrics_here & SECURITY_INDICATOR_METRICS
    vol_hits = metrics_here & VOLUME_METRICS
    op_hits = metrics_here & OPERATIONAL_METRICS

    avg_abruptness = np.mean([
        _abruptness(df, root_cause_device, m, int(root_events[root_events.metric == m]["onset_time"].iloc[0]))
        for m in metrics_here
    ]) if metrics_here else 0.5

    indicators = []
    if sec_hits:
        indicators.append(f"Anomalous connection/source-diversity metrics: {sorted(sec_hits)}")
    if vol_hits:
        indicators.append(f"Anomalous traffic-volume/saturation metrics: {sorted(vol_hits)}")
    if op_hits:
        indicators.append(f"Anomalous internal resource metrics: {sorted(op_hits)}")
    indicators.append(f"Onset shape: {'abrupt/step-like' if avg_abruptness > 0.6 else 'gradual ramp'} "
                       f"(abruptness={avg_abruptness:.2f})")

    if sec_hits and vol_hits and avg_abruptness > 0.55:
        classification = "security"
        subtype = "volumetric_attack_ddos"
        confidence = min(0.97, 0.55 + 0.2 * len(sec_hits) + 0.2 * (avg_abruptness - 0.5))
        indicators.append("Pattern matches a volumetric/DDoS-style attack: high connection diversity "
                           "AND traffic saturation arriving abruptly.")
    elif sec_hits and not vol_hits:
        classification = "security"
        subtype = "reconnaissance_or_scan"
        confidence = min(0.9, 0.5 + 0.25 * len(sec_hits))
        indicators.append("Pattern matches reconnaissance/scanning: unusual connection/source diversity "
                           "with traffic volume remaining near-normal (low bandwidth impact).")
    elif op_hits and not sec_hits:
        classification = "operational"
        subtype = "resource_or_link_degradation"
        confidence = min(0.95, 0.5 + 0.15 * len(op_hits) + 0.2 * (1 - avg_abruptness))
        indicators.append("Pattern matches an operational fault: gradual resource/interface degradation "
                           "with no connection-diversity or traffic-volume anomaly.")
    else:
        classification = "operational"
        subtype = "symptom_only_inherited"
        confidence = 0.4
        indicators.append("Root-cause device shows only downstream 'symptom' metrics (latency/loss/bandwidth) "
                           "with no clear causal or security signature -- treat root cause with lower confidence.")

    return {
        "classification": classification,
        "subtype": subtype,
        "confidence": round(float(confidence), 2),
        "indicators": indicators,
        "abruptness": round(float(avg_abruptness), 2),
    }