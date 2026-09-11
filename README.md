# NetSage 🌐
> 🔗 **Live Demo:** [Launch NetSage](https://netsage-jxerrqvha8pmdt5c9mtyum.streamlit.app/)

A prototype that transforms raw network telemetry into an explainable incident
report, using topology-aware root-cause reasoning and signature-based security
classification instead of simple threshold monitoring.

---

## 🎯 Problem Statement

Traditional monitoring systems detect that a metric crossed a threshold (e.g.
"packet loss > 5% on R3") but cannot answer the questions a network
administrator actually needs answered:

* What caused it?
* Which device is the likely source?
* Which other devices are affected?
* Is this a performance issue or a potential security event?
* How confident is the system in its conclusion?

## 🚀 Objective

Build a prototype that follows this pipeline:
<div align="center">

```text
Network Telemetry → Data Processing → Anomaly Detection → Root-Cause Analysis → Security Assessment → Incident Report
```
</div>
and, in doing so, demonstrates engineering reasoning rather than
threshold-based alerting.


## 💡 Proposed Solution

A layered pipeline where each stage produces evidence the next stage
consumes:

1. Learn a **per-device, per-metric baseline** of normal behavior instead of
   a fixed global threshold.
2. Flag **persistent** statistical deviations from that baseline, cross-checked
   by a second, independent detector (Isolation Forest).
3. Rank every anomalous device as a **root-cause candidate** using temporal
   precedence, metric type, and topology, rather than assuming the loudest
   alarm is the cause.
4. Classify the leading candidate's anomaly pattern against **operational vs.
   security signatures**.
5. Assemble all of the above into a **structured incident report** with an
   explicit evidence trail and confidence scores.

## 🏗️ System Architecture

<div align="center">

```text
                +---------------------------+
                |     Network Telemetry     |
                | latency / loss / bandwidth|
                | CPU / memory / iface errs |
                | traffic / src-ips / SYNs  |
                +-------------+-------------+
                              |
                              v
                +---------------------------+
                |      Data Processing      |
                | per-device/per-metric     |
                | time series + baselines   |
                +-------------+-------------+
                              |
                              v
                +---------------------------+
                |     Anomaly Detection     |
                | rolling z-score           |
                | + persistence filter      |
                | + Isolation Forest check  |
                +-------------+-------------+
                              |
                              v
                +---------------------------+
                |    Root-Cause Analysis    |
                | temporal precedence       |
                | causal vs symptom metrics |
                | topology reasoning        |
                +-------------+-------------+
                              |
                +-------------+-------------+
                |                           |
                v                           v
    +----------------------+   +----------------------+
    |  Affected Devices    |   |  Security Assessment |
    |  & Components        |   |  (heuristic signature|
    |                      |   |   classification)    |
    +-----------+----------+   +-----------+----------+
                |                           |
                +-------------+-------------+
                              |
                              v
                +---------------------------+
                |      Incident Report      |
                | root cause + confidence   |
                | affected devices          |
                | evidence trail            |
                | recommended action        |
                +-------------+-------------+
                              |
                              v
                +---------------------------+
                |    Streamlit Dashboard    |
                | topology / telemetry      |
                | ranking table / report    |
                +---------------------------+
```

</div>

## 🛠️ Technology Stack

| Purpose                             | Library                           |
| ----------------------------------- | --------------------------------- |
| Data handling / time series         | `pandas`, `numpy`                 |
| Topology modeling & graph reasoning | `networkx`                        |
| Anomaly cross-check                 | `scikit-learn` (Isolation Forest) |
| Dashboard                           | `streamlit`                       |
| Visualization                       | `plotly`                          |
| Language                            | Python 3                          |

## 📁 Project Structure

| File           | Role                                                                                                                                                          |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `topology.py`  | Defines the device graph (firewall -> core -> distribution -> access -> servers).                                                                             |
| `simulator.py` | Generates synthetic multi-metric telemetry with 5 injectable anomaly scenarios.                                                                               |
| `detection.py` | Rolling-baseline z-score per (device, metric) with a persistence filter, cross-checked by an Isolation Forest over each device's multivariate feature vector. |
| `rootcause.py` | Ranks anomalous devices as root-cause candidates.                                                                                                             |
| `security.py`  | Signature-based heuristic classification: operational vs. security.                                                                                           |
| `report.py`    | Assembles a structured, human-readable incident report.                                                                                                       |
| `app.py`       | Streamlit dashboard.                                                                                                                                          |
| `validate.py`  | Runs all scenarios against ground truth and prints an accuracy table.                                                                                         |

## 🔍 How It Works

### Telemetry Generation

`simulator.py` produces per-device time series for 10 metrics (latency,
packet loss, bandwidth utilization, CPU, memory, interface errors, traffic
in/out, unique source IPs, SYN count) on a fixed baseline plus Gaussian
noise, then optionally injects one labeled anomaly scenario with topology-aware
propagation to neighboring devices.

### Data Processing

Telemetry is reshaped into long-format (`time, device, metric, value`) and
wide per-device feature matrices, and a rolling baseline (mean/std learned
from an early "quiet" window) is computed per (device, metric) pair.

### Anomaly Detection

* **Primary**: z-score against the learned baseline, with a persistence
  filter requiring several consecutive anomalous points (suppresses
  single-sample noise).
* **Secondary cross-check**: Isolation Forest over each device's full
  multivariate feature vector at each timestep, used only to corroborate,
  never as the sole trigger -- this keeps the system explainable rather than
  a black box.

### Root-Cause Analysis

Every anomalous device is scored as a root-cause candidate on three
heuristic axes (see `rootcause.py` for the exact weighting):

* **Temporal precedence** -- did this device's anomalies start earliest?
* **Causal vs. symptom metric type** -- CPU/memory/interface-error/traffic
  anomalies are weighted as more likely causal; latency/loss/bandwidth
  anomalies are weighted as more likely inherited symptoms. *This is a
  heuristic assumption used for scoring, not a deterministic causal law.*
* **Topological explanatory power** -- how many other anomalous devices sit
  within a small number of hops, i.e., could plausibly have inherited the
  problem from this device.

The top-scoring candidate is reported with a confidence score derived from
its absolute score and its margin over the runner-up.

### Security Assessment

The root cause's anomaly pattern is matched against heuristic signatures --
signature-based heuristic classification, not a trained classifier or a
legal/forensic determination. Each pattern maps to the exact classification
string the code returns (see `security.py`):

* Connection/source-diversity spike + traffic/bandwidth saturation, arriving
  abruptly -> `security` / **`volumetric_attack_ddos`**.
* Connection/source-diversity spike with **normal** traffic volume ->
  `security` / **`reconnaissance_or_scan`**.
* Gradual resource/interface degradation with no connection-diversity
  anomaly -> `operational` / **`resource_or_link_degradation`**.
* Root cause shows only inherited symptom metrics with no clear causal or
  security signature -> `operational` / **`symptom_only_inherited`** (lower
  confidence, flagged as a weaker attribution).

### Incident Reporting

`report.py` renders root cause, confidence, classification, affected
devices, a numbered evidence trail, a recommended action, and the full
per-event anomaly detail into one report (viewable in the dashboard or
downloadable as `.txt`).

## ⚙️ Design Decisions

* **Rule-based + statistical over pure ML.** Root-cause and security logic
  are explicit and inspectable (you can read exactly why a conclusion was
  reached); Isolation Forest is used only as a corroborating signal. This
  was a deliberate choice given the problem's emphasis on *explainable*
  reasoning over raw accuracy.
* **Synthetic data with known ground truth** rather than real telemetry, so
  the pipeline's conclusions can be directly checked against what actually
  happened (see Validation, below).
* **Topology-aware propagation** in the simulator (anomaly effects decay
  with hop distance from the injected source) so root-cause reasoning has a
  genuine multi-device signal to work with, not just an isolated spike.

## 🧪 Scenarios

| Scenario            | Root Cause                                          | Expected Type | Main Evidence                                                            |
| ------------------- | --------------------------------------------------- | ------------- | ------------------------------------------------------------------------ |
| `normal`            | None                                                | Normal        | No persistent anomalies                                                  |
| `link_degradation`  | A distribution router's link                        | Operational   | Rising latency/loss/interface errors, decaying with topology distance    |
| `cpu_overload`      | An overloaded core router                           | Operational   | CPU/memory anomaly at source, latency ripples downstream                 |
| `ddos_attack`       | Edge firewall                                       | Security      | Abrupt traffic + connection/source-diversity spike, bandwidth saturation |
| `port_scan`         | A server                                            | Security      | Abrupt connection/source-diversity spike, traffic volume stays normal    |
| `cascading_failure` | A distribution router (no redundancy on its branch) | Operational   | Resource/interface anomaly at source, severe multi-hop propagation       |

## ✅ Validation & Test Cases

The problem statement calls out specific test-case types (latency spike,
packet loss, traffic anomaly, noisy telemetry). Here is how the prototype's
scenarios map onto them explicitly:

| Test Case           | Injected Via                                                                            | Metrics Exercised                                                                                         | Verified Outcome                                                                                                          |
| ------------------- | --------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| **Latency spike**   | `link_degradation`, `cpu_overload`                                                      | `latency_ms` (+ correlated `packet_loss_pct`, `iface_errors_per_min`)                                     | Root cause traced to the originating device, classified `operational`                                                     |
| **Packet loss**     | `link_degradation`, `cascading_failure`, `ddos_attack`                                  | `packet_loss_pct` alongside either interface errors (operational) or traffic/connection spikes (security) | Same packet-loss symptom correctly attributed to two different causes depending on accompanying metrics                   |
| **Traffic anomaly** | `ddos_attack` (volume spike), `port_scan` (connection-count spike without volume spike) | `traffic_in_mbps`, `traffic_out_mbps`, `unique_src_ips`, `syn_count`                                      | Volumetric spike -> `volumetric_attack_ddos`; count-only spike -> `reconnaissance_or_scan` (system distinguishes the two) |
| **Noisy telemetry** | `normal`                                                                                | All 10 metrics, Gaussian noise only, no injected anomaly                                                  | Zero anomaly events raised, no false-positive incident generated                                                          |

Run:

```bash
python3 validate.py
```

This simulates all 6 scenarios, runs the full pipeline, and compares
predictions against the simulator's known ground truth for root cause and
classification.

## 📊 Results

Actual output from `validate.py` (seed=42):

```text
scenario          | expected_root_cause | predicted_root_cause | root_cause_match | expected_type | predicted_type | type_match | root_cause_confidence | classification_confidence
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
normal            | None                | None                 | True             | none          | none           | True       | 0.0                   | 0.0
link_degradation  | DIST-R1             | DIST-R1              | True             | operational   | operational    | True       | 0.58                  | 0.78
cpu_overload      | CORE1               | CORE1                | True             | operational   | operational    | True       | 0.39                  | 0.84
ddos_attack       | FW1                 | FW1                  | True             | security      | security       | True       | 0.7                   | 0.97
port_scan         | SRV2                | SRV2                 | True             | security      | security       | True       | 0.85                  | 0.9
cascading_failure | DIST-R2             | DIST-R2              | True             | operational   | operational    | True       | 0.7                   | 0.9

Root-cause accuracy    : 6/6
Classification accuracy: 6/6
```

Note `cpu_overload` has the lowest root-cause confidence (0.39) -- appropriate,
since a gradually-ramping CPU anomaly is inherently harder to pin down in
time than an abrupt event, and the confidence score correctly reflects that
lower certainty rather than reporting false precision.

## 🎬 Working Demonstration

Run:

```bash
pip install -r requirements.txt
streamlit run app.py
```

Then in the sidebar:

1. Start with **normal** -- confirm the dashboard shows no incident, root
   cause "--", 0 affected devices.
2. Switch to **ddos_attack** -- watch traffic/connection-diversity anomalies
   appear at `FW1`, the root-cause ranking table put `FW1` on top, the
   security layer classify it as `volumetric_attack_ddos`, and the report
   explain why.
3. Switch to **cascading_failure** -- same walkthrough, but demonstrates the
   system correctly reasons about a multi-hop *operational* fault rather
   than defaulting to "security" just because many devices are affected.
   This is the scenario that best shows the system is not merely an attack
   classifier.

Recommended presentation order: `normal -> ddos_attack -> cascading_failure`.

## ⚠️ Limitations

* **Synthetic data.** The simulator's anomaly injection is simplified
  relative to real network failure modes; validation against real telemetry
  has not been performed.
* **Hand-tuned weights.** The root-cause composite score's weights (temporal
  / topology / causal-type / severity) and the security signature thresholds
  were chosen by reasoning about plausible engineering priorities, not fit
  to labeled historical incident data.
* **Small, fixed topology.** The 11-device topology is illustrative; the
  approach has not been tested for scalability on large or dynamically
  changing topologies.
* **Heuristic causality, not verified causality.** The "causal vs. symptom"
  metric weighting is a modeling assumption, not a guarantee -- a device's
  own latency spike *can* be a genuine root cause in some real failure
  modes that this prototype would under-weight.
* **Security classification is a hypothesis, not a verdict.** Signatures
  here mirror an analyst's first read of the data, not a forensic
  determination; a real deployment should route "security" classifications
  to human/SOC investigation.

## 🔮 Future Improvements

* Replace the synthetic simulator with a real telemetry feed (SNMP,
  streaming telemetry, NetFlow/sFlow).
* Add a seasonal baseline (time-of-day/day-of-week) instead of a single
  static baseline window.
* Fit the composite scoring weights on labeled historical incidents instead
  of hand-tuning them.
* Extend the security layer with real signature libraries (known scan
  sequences, published DDoS traffic shapes) and/or a trained classifier
  validated against labeled attack traffic.
* Support larger/dynamic topologies and multiple concurrent incidents.

## 🚀 Installation & Execution

```bash
pip install -r requirements.txt

# Launch the interactive dashboard
python -m streamlit run app.py

# Or run headless validation against ground truth
python3 validate.py
```
