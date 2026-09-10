"""
Synthetic telemetry generator.

Generates per-device, per-timestep telemetry for a fixed set of metrics,
with realistic baseline noise, and supports injecting one of several
labeled scenarios (used later as ground truth to sanity-check the
detection / root-cause / security pipeline).

Metrics per device per timestep:
    latency_ms
    packet_loss_pct
    bandwidth_util_pct
    cpu_pct
    memory_pct
    iface_errors_per_min
    traffic_in_mbps
    traffic_out_mbps
    unique_src_ips        (security-relevant)
    syn_count             (security-relevant)
"""

import numpy as np
import pandas as pd
import networkx as nx

from topology import build_topology, DEVICE_ROLES

METRICS = [
    "latency_ms", "packet_loss_pct", "bandwidth_util_pct", "cpu_pct",
    "memory_pct", "iface_errors_per_min", "traffic_in_mbps",
    "traffic_out_mbps", "unique_src_ips", "syn_count",
]

BASELINE = {
    # metric: (mean, std) - role-independent baseline, lightly role-adjusted below
    "latency_ms": (5.0, 0.8),
    "packet_loss_pct": (0.1, 0.05),
    "bandwidth_util_pct": (30.0, 5.0),
    "cpu_pct": (25.0, 5.0),
    "memory_pct": (40.0, 4.0),
    "iface_errors_per_min": (0.2, 0.15),
    "traffic_in_mbps": (50.0, 8.0),
    "traffic_out_mbps": (45.0, 8.0),
    "unique_src_ips": (20.0, 4.0),
    "syn_count": (30.0, 6.0),
}

SCENARIOS = [
    "normal",
    "link_degradation",
    "cpu_overload",
    "ddos_attack",
    "port_scan",
    "cascading_failure",
]


def _baseline_series(metric, n, rng):
    mean, std = BASELINE[metric]
    series = rng.normal(mean, std, n)
    return np.clip(series, a_min=0, a_max=None)


def _propagate_decay(graph, source, n_hops_effect, hop_decay=0.5):
    """Return {device: decay_factor} for devices within n_hops of source."""
    lengths = nx.single_source_shortest_path_length(graph, source, cutoff=n_hops_effect)
    return {dev: hop_decay ** hop for dev, hop in lengths.items()}


def simulate(scenario: str = "normal", n_steps: int = 120, seed: int = 42,
             anomaly_start: int = 70, anomaly_len: int = 30):
    """
    Returns:
        df: long-format DataFrame [time, device, metric, value]
        ground_truth: dict describing what was injected (for validation only)
    """
    assert scenario in SCENARIOS, f"unknown scenario {scenario}"
    rng = np.random.default_rng(seed)
    graph = build_topology()
    devices = list(DEVICE_ROLES.keys())
    t = np.arange(n_steps)

    data = {dev: {m: _baseline_series(m, n_steps, rng) for m in METRICS} for dev in devices}

    ground_truth = {"scenario": scenario, "root_cause_device": None,
                     "affected_devices": [], "window": None, "type": None}

    a0, a1 = anomaly_start, min(anomaly_start + anomaly_len, n_steps)
    window_idx = np.arange(a0, a1)
    ramp = np.linspace(0, 1, len(window_idx))  # gradual onset ramp

    if scenario == "normal":
        pass

    elif scenario == "link_degradation":
        # A single link (DIST-R1 <-> ACC-SW1) degrades: rising latency, packet loss,
        # interface errors on both endpoints, decaying impact on downstream SRV1.
        root = "DIST-R1"
        ground_truth.update(root_cause_device=root, type="operational",
                             window=(int(a0), int(a1)))
        decay = _propagate_decay(graph, root, n_hops_effect=2, hop_decay=0.5)
        for dev, factor in decay.items():
            data[dev]["latency_ms"][window_idx] += ramp * 40 * factor
            data[dev]["packet_loss_pct"][window_idx] += ramp * 8 * factor
            data[dev]["iface_errors_per_min"][window_idx] += ramp * 15 * factor
            data[dev]["bandwidth_util_pct"][window_idx] += ramp * 10 * factor
        ground_truth["affected_devices"] = list(decay.keys())

    elif scenario == "cpu_overload":
        # CORE1 CPU climbs due to resource exhaustion -> latency ripples to everything downstream.
        root = "CORE1"
        ground_truth.update(root_cause_device=root, type="operational",
                             window=(int(a0), int(a1)))
        decay = _propagate_decay(graph, root, n_hops_effect=3, hop_decay=0.6)
        data[root]["cpu_pct"][window_idx] += ramp * 65
        data[root]["memory_pct"][window_idx] += ramp * 30
        for dev, factor in decay.items():
            if dev == root:
                continue
            data[dev]["latency_ms"][window_idx] += ramp * 25 * factor
            data[dev]["packet_loss_pct"][window_idx] += ramp * 3 * factor
        ground_truth["affected_devices"] = list(decay.keys())

    elif scenario == "ddos_attack":
        # Volumetric attack hitting the edge firewall: huge traffic_in, unique_src_ips,
        # syn_count spike (sudden, not gradual), packet loss & bandwidth saturate downstream.
        root = "FW1"
        ground_truth.update(root_cause_device=root, type="security",
                             window=(int(a0), int(a1)))
        sudden = np.ones(len(window_idx))  # step function, not ramp -> attack signature
        decay = _propagate_decay(graph, root, n_hops_effect=2, hop_decay=0.4)
        data[root]["traffic_in_mbps"][window_idx] += sudden * 400
        data[root]["unique_src_ips"][window_idx] += sudden * 3000
        data[root]["syn_count"][window_idx] += sudden * 5000
        data[root]["packet_loss_pct"][window_idx] += sudden * 12
        data[root]["bandwidth_util_pct"][window_idx] += sudden * 60
        for dev, factor in decay.items():
            if dev == root:
                continue
            data[dev]["bandwidth_util_pct"][window_idx] += sudden * 35 * factor
            data[dev]["packet_loss_pct"][window_idx] += sudden * 5 * factor
        ground_truth["affected_devices"] = list(decay.keys())

    elif scenario == "port_scan":
        # Reconnaissance against SRV2: unique_src_ips / syn_count spike, but traffic
        # volume and latency stay essentially normal -> should NOT look operational.
        root = "SRV2"
        ground_truth.update(root_cause_device=root, type="security",
                             window=(int(a0), int(a1)))
        sudden = np.ones(len(window_idx))
        data[root]["unique_src_ips"][window_idx] += sudden * 250
        data[root]["syn_count"][window_idx] += sudden * 800
        # deliberately no packet_loss/bandwidth/traffic-volume impact --
        # that's the defining signature that separates recon from a volumetric attack
        ground_truth["affected_devices"] = [root]

    elif scenario == "cascading_failure":
        # DIST-R2 degrades hard (near-failure): its own metrics blow up, and the
        # single access switch + server behind it inherit almost the full effect
        # (no redundancy on that branch) -> tests multi-hop root-cause + widest blast radius.
        root = "DIST-R2"
        ground_truth.update(root_cause_device=root, type="operational",
                             window=(int(a0), int(a1)))
        decay = _propagate_decay(graph, root, n_hops_effect=2, hop_decay=0.75)
        data[root]["cpu_pct"][window_idx] += ramp * 70
        data[root]["iface_errors_per_min"][window_idx] += ramp * 25
        for dev, factor in decay.items():
            data[dev]["latency_ms"][window_idx] += ramp * 50 * factor
            data[dev]["packet_loss_pct"][window_idx] += ramp * 15 * factor
            data[dev]["bandwidth_util_pct"][window_idx] += ramp * 20 * factor
        ground_truth["affected_devices"] = list(decay.keys())

    # assemble long-format dataframe
    rows = []
    for dev in devices:
        for m in METRICS:
            for i, val in enumerate(data[dev][m]):
                rows.append((i, dev, m, float(val)))
    df = pd.DataFrame(rows, columns=["time", "device", "metric", "value"])
    return df, ground_truth