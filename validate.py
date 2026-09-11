"""
Validation script: runs every injectable scenario end-to-end and compares
the pipeline's predictions against the simulator's known ground truth.

Run:  python3 validate.py
"""

from simulator import simulate, SCENARIOS
from detection import detect, summarize_anomaly_events
from rootcause import analyze
from security import assess
from topology import build_topology


def run_validation(seed: int = 42):
    graph = build_topology()
    rows = []
    for scenario in SCENARIOS:
        df, gt = simulate(scenario, n_steps=120, seed=seed, anomaly_start=70, anomaly_len=30)
        detected = detect(df)
        events = summarize_anomaly_events(detected)
        rc = analyze(events, graph)
        sec = assess(events, df, rc["root_cause_device"])

        predicted_type = sec["classification"] if rc["root_cause_device"] else "none"
        expected_type = gt["type"] if gt["type"] else "none"
        rows.append({
            "scenario": scenario,
            "expected_root_cause": gt["root_cause_device"],
            "predicted_root_cause": rc["root_cause_device"],
            "root_cause_match": gt["root_cause_device"] == rc["root_cause_device"],
            "expected_type": expected_type,
            "predicted_type": predicted_type,
            "type_match": expected_type == predicted_type,
            "root_cause_confidence": rc["confidence"],
            "classification_confidence": sec["confidence"],
            "affected_device_count": len(rc["affected_devices"]),
        })
    return rows


def print_table(rows):
    headers = ["scenario", "expected_root_cause", "predicted_root_cause", "root_cause_match",
               "expected_type", "predicted_type", "type_match",
               "root_cause_confidence", "classification_confidence"]
    widths = {h: max(len(h), max(len(str(r[h])) for r in rows)) for h in headers}
    header_line = " | ".join(h.ljust(widths[h]) for h in headers)
    print(header_line)
    print("-" * len(header_line))
    for r in rows:
        print(" | ".join(str(r[h]).ljust(widths[h]) for h in headers))

    total = len(rows)
    rc_correct = sum(r["root_cause_match"] for r in rows)
    type_correct = sum(r["type_match"] for r in rows)
    print()
    print(f"Root-cause accuracy    : {rc_correct}/{total}")
    print(f"Classification accuracy: {type_correct}/{total}")


if __name__ == "__main__":
    rows = run_validation()
    print_table(rows)