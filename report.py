"""
Incident report generator.

Turns the outputs of detection -> root-cause -> security assessment into
a single structured, human-readable incident report, mirroring what a
NOC engineer would write up.
"""

from datetime import datetime


def build_report(events, rootcause_result, security_result, scenario_label=None) -> str:
    rc = rootcause_result
    sec = security_result
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if rc["root_cause_device"] is None:
        return (
            f"INCIDENT REPORT -- generated {ts}\n"
            f"{'='*60}\n"
            f"No anomalies detected in the analyzed window. Network behavior "
            f"is within expected baseline for all monitored devices/metrics.\n"
        )

    lines = []
    lines.append(f"INCIDENT REPORT -- generated {ts}")
    lines.append("=" * 60)
    if scenario_label:
        lines.append(f"(Simulated scenario for validation: {scenario_label})")
    lines.append("")
    lines.append(f"PROBABLE ROOT CAUSE : {rc['root_cause_device']}")
    lines.append(f"CONFIDENCE           : {rc['confidence'] * 100:.0f}%")
    lines.append(f"CLASSIFICATION        : {sec['classification'].upper()} "
                 f"({sec.get('subtype', 'n/a')}) -- confidence {sec['confidence']*100:.0f}%")
    lines.append(f"AFFECTED DEVICES ({len(rc['affected_devices'])}): {', '.join(rc['affected_devices'])}")
    lines.append("")
    lines.append("ROOT-CAUSE REASONING")
    lines.append("-" * 60)
    for i, ev in enumerate(rc["evidence"], 1):
        lines.append(f"  {i}. {ev}")
    lines.append("")
    lines.append("SECURITY ASSESSMENT")
    lines.append("-" * 60)
    for i, ind in enumerate(sec["indicators"], 1):
        lines.append(f"  {i}. {ind}")
    lines.append("")
    lines.append("RECOMMENDED ACTION")
    lines.append("-" * 60)
    if sec["classification"] == "security":
        if sec.get("subtype") == "volumetric_attack_ddos":
            lines.append("  Engage DDoS mitigation (rate-limiting / upstream scrubbing) at "
                         f"{rc['root_cause_device']}; notify security team; preserve flow logs for forensics.")
        else:
            lines.append(f"  Investigate source IPs hitting {rc['root_cause_device']}; consider "
                         "temporary ACL/firewall tightening; notify security team; monitor for follow-on activity.")
    else:
        lines.append(f"  Dispatch network engineering to inspect {rc['root_cause_device']} "
                     "(check hardware health, interface counters, link state, and current load); "
                     "consider failover/traffic rerouting if redundancy is available.")
    lines.append("")
    lines.append("EVENT DETAIL (all anomalous device/metric pairs)")
    lines.append("-" * 60)
    for _, row in events.sort_values("onset_time").iterrows():
        lines.append(f"  [t={row.onset_time:>3}-{row.end_time:<3}] {row.device:<9} {row.metric:<22} "
                     f"peak|z|={row.peak_zscore:5.1f}  iso_corroborated={row.iso_corroborated}")

    return "\n".join(lines)