import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
import networkx as nx

from topology import build_topology, DEVICE_ROLES
from simulator import simulate, SCENARIOS, METRICS
from detection import detect, summarize_anomaly_events
from rootcause import analyze
from security import assess
from report import build_report

st.set_page_config(page_title="Network Intelligence System", layout="wide")

st.title("🌐 NetSage")
st.caption("Telemetry → Anomaly Detection → Root-Cause Analysis → Security Assessment → Incident Report")

# ---------------- Sidebar controls ----------------
with st.sidebar:
    st.header("Simulation Controls")
    scenario = st.selectbox(
        "Scenario", SCENARIOS,
        format_func=lambda s: s.replace("_", " ").title(),
        index=0,
    )
    seed = st.number_input("Random seed", min_value=0, max_value=9999, value=42, step=1)
    n_steps = st.slider("Time steps", 60, 200, 120, step=10)
    anomaly_start = st.slider("Anomaly onset (t)", 10, 150, 70, step=5)
    anomaly_len = st.slider("Anomaly duration (steps)", 5, 60, 30, step=5)
    run = st.button("▶ Run Analysis", type="primary", width="stretch")
    st.markdown("---")
    st.caption(
        "Scenarios ending in *_attack / port_scan are labeled security in the "
        "simulator ground truth; others are operational. The system does NOT "
        "see this label -- it must infer classification independently."
    )

if "result" not in st.session_state:
    run = True  # auto-run on first load

if run:
    df, ground_truth = simulate(scenario, n_steps=n_steps, seed=int(seed),
                                 anomaly_start=anomaly_start, anomaly_len=anomaly_len)
    detected = detect(df)
    events = summarize_anomaly_events(detected)
    graph = build_topology()
    rc_result = analyze(events, graph)
    sec_result = assess(events, df, rc_result["root_cause_device"])
    report_text = build_report(events, rc_result, sec_result, scenario_label=scenario)
    st.session_state["result"] = dict(
        df=df, ground_truth=ground_truth, detected=detected, events=events,
        graph=graph, rc_result=rc_result, sec_result=sec_result, report_text=report_text,
    )

R = st.session_state["result"]
df, ground_truth = R["df"], R["ground_truth"]
detected, events = R["detected"], R["events"]
graph, rc_result, sec_result = R["graph"], R["rc_result"], R["sec_result"]
report_text = R["report_text"]

# ---------------- Top-level summary cards ----------------
col1, col2, col3, col4 = st.columns(4)
col1.metric("Root Cause", rc_result["root_cause_device"] or "—")
col2.metric("Root-Cause Confidence", f"{rc_result['confidence']*100:.0f}%" if rc_result["root_cause_device"] else "—")
col3.metric("Classification", sec_result["classification"].upper() if sec_result["classification"] != "none" else "—")
col4.metric("Affected Devices", len(rc_result["affected_devices"]))

st.markdown("---")

left, right = st.columns([1.1, 1])

# ---------------- Topology visualization ----------------
with left:
    st.subheader("Network Topology")
    pos = nx.spring_layout(graph, seed=7)
    affected = set(rc_result["affected_devices"])
    root = rc_result["root_cause_device"]

    edge_x, edge_y = [], []
    for u, v in graph.edges():
        edge_x += [pos[u][0], pos[v][0], None]
        edge_y += [pos[u][1], pos[v][1], None]
    edge_trace = go.Scatter(x=edge_x, y=edge_y, mode="lines",
                             line=dict(width=1.5, color="#888"), hoverinfo="none")

    node_x, node_y, node_color, node_text, node_size = [], [], [], [], []
    for n in graph.nodes():
        node_x.append(pos[n][0]); node_y.append(pos[n][1])
        if n == root:
            node_color.append("#d62728"); node_size.append(38)
        elif n in affected:
            node_color.append("#ff7f0e"); node_size.append(30)
        else:
            node_color.append("#2ca02c"); node_size.append(24)
        node_text.append(f"{n} ({DEVICE_ROLES[n]})")

    node_trace = go.Scatter(
        x=node_x, y=node_y, mode="markers+text", text=list(graph.nodes()),
        textposition="bottom center", hovertext=node_text, hoverinfo="text",
        marker=dict(size=node_size, color=node_color, line=dict(width=2, color="white")),
    )
    fig = go.Figure(data=[edge_trace, node_trace])
    fig.update_layout(showlegend=False, height=420, margin=dict(l=10, r=10, t=10, b=10),
                       xaxis=dict(visible=False), yaxis=dict(visible=False))
    st.plotly_chart(fig, width="stretch")
    st.caption("🔴 Root cause &nbsp;&nbsp; 🟠 Affected &nbsp;&nbsp; 🟢 Normal")

# ---------------- Root cause candidate ranking ----------------
with right:
    st.subheader("Root-Cause Candidate Ranking")
    if not rc_result["candidates"].empty:
        show_cols = ["device", "onset_time", "temporal_score", "causal_score",
                     "explain_score", "severity_score", "composite_score"]
        st.dataframe(rc_result["candidates"][show_cols], width="stretch", hide_index=True)
    else:
        st.info("No anomalies detected -- nothing to rank.")

st.markdown("---")

# ---------------- Metric time series ----------------
st.subheader("Telemetry Explorer")
devs = sorted(df["device"].unique())
default_dev = rc_result["root_cause_device"] or devs[0]
sel_device = st.selectbox("Device", devs, index=devs.index(default_dev))
dev_metrics = sorted(df[df.device == sel_device]["metric"].unique())
sel_metrics = st.multiselect("Metrics", dev_metrics, default=dev_metrics[:3])

if sel_metrics:
    plot_df = df[(df.device == sel_device) & (df.metric.isin(sel_metrics))]
    fig2 = px.line(plot_df, x="time", y="value", color="metric",
                    title=f"{sel_device} — raw telemetry")
    dev_events = events[events.device == sel_device]
    for _, ev in dev_events.iterrows():
        fig2.add_vrect(x0=ev.onset_time, x1=ev.end_time, fillcolor="red", opacity=0.12, line_width=0)
    fig2.update_layout(height=380)
    st.plotly_chart(fig2, width="stretch")

with st.expander("Show all detected anomaly events (raw table)"):
    st.dataframe(events, width="stretch", hide_index=True)

st.markdown("---")

# ---------------- Incident report ----------------
st.subheader("📋 Explainable Incident Report")
st.text(report_text)
st.download_button("Download report (.txt)", report_text, file_name="incident_report.txt")

with st.expander("Ground truth (simulator's actual injected scenario — for validation only)"):
    st.json(ground_truth)