"""Interactive, exploratory CTU-13 dashboard (no ML training or scoring)."""

from pathlib import Path

import matplotlib.pyplot as plt
import networkx as nx
import pandas as pd
import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = PROJECT_ROOT / "CTU-13" / "capture20110817.binetflow.2format"

st.set_page_config(page_title="NetGuard | CTU-13", page_icon="🛡️", layout="wide")
st.markdown("""
<style>
.stApp {background:#061628;color:#dbeafe} [data-testid="stSidebar"] {background:linear-gradient(180deg,#0b2a52,#07182d)} [data-testid="stSidebar"] * {color:#dbeafe}
.block-container {max-width:1500px;padding-top:1.4rem}.hero{padding:.45rem 0 1.1rem}.hero h1{margin:0;color:#f8fafc;font-size:2rem}.muted{color:#91a9c7;margin-top:.2rem}
.panel{background:linear-gradient(135deg,#0c2747,#0a203b);border:1px solid #1b426c;border-radius:11px;padding:1rem 1.05rem;min-height:126px}.panel h3{margin:0 0 .65rem;color:#f8fafc;font-size:1rem}
.kpi-label{color:#a9bcd5;font-size:.82rem}.kpi-value{color:#f8fafc;font-weight:700;font-size:1.8rem;margin:.15rem 0}.kpi-note{color:#38d39f;font-size:.76rem}
div[data-testid="stDataFrame"]{border:1px solid #1b426c;border-radius:10px;overflow:hidden}
</style>""", unsafe_allow_html=True)

@st.cache_data(show_spinner=False)
def load_flows(rows: int) -> pd.DataFrame:
    """Load a bounded sample so the 491 MB CTU-13 file is not fully read."""
    return pd.read_csv(DATA_PATH, nrows=rows, low_memory=False)

def label_status(label: object) -> str:
    text = str(label).lower()
    if "botnet" in text or "malicious" in text:
        return "Malicious"
    if "background" in text or text in {"nan", "normal"}:
        return "Normal"
    return "Suspicious"

def build_graph(flows: pd.DataFrame) -> nx.DiGraph:
    return nx.from_pandas_edgelist(flows, source="SrcAddr", target="DstAddr", create_using=nx.DiGraph())

def draw_network(graph: nx.DiGraph, statuses: dict[str, str]) -> plt.Figure:
    preview_nodes = sorted(graph.degree, key=lambda item: item[1], reverse=True)[:100]
    preview = graph.subgraph([node for node, _ in preview_nodes]).copy()
    fig, ax = plt.subplots(figsize=(8, 4.9), facecolor="#0a203b")
    ax.set_facecolor("#0a203b")
    pos = nx.spring_layout(preview, seed=18, k=.45)
    colors = {"Normal":"#2d8cff", "Suspicious":"#f6aa32", "Malicious":"#f04b60"}
    node_colors = [colors.get(statuses.get(node, "Normal"), "#2d8cff") for node in preview.nodes]
    nx.draw_networkx_edges(preview, pos, ax=ax, edge_color="#42627f", alpha=.4, arrows=False)
    nx.draw_networkx_nodes(preview, pos, ax=ax, node_color=node_colors, node_size=36, alpha=.95)
    ax.axis("off")
    return fig

with st.sidebar:
    st.markdown("## 🛡️ NetGuard")
    st.caption("Graph-Based Botnet Detection")
    st.divider()
    st.markdown("🏠  **Dashboard**\n\n🕸️  Network Graph\n\n🛡️  Detections\n\n📊  Model Performance\n\n🕘  Incident History")
    st.divider()
    st.markdown("⚙️  Settings")
    sample_size = st.slider("Flows to sample", 500, 10_000, 2_000, 500)

if not DATA_PATH.exists():
    st.error(f"CTU-13 flow file not found: {DATA_PATH}")
    st.stop()

flows = load_flows(sample_size)
graph = build_graph(flows)
flows["Status"] = flows.get("Label", pd.Series(index=flows.index, dtype="object")).map(label_status)
host_status = flows.groupby("SrcAddr")["Status"].agg(lambda v: "Malicious" if "Malicious" in set(v) else "Suspicious" if "Suspicious" in set(v) else "Normal").to_dict()
malicious_hosts = sum(status == "Malicious" for status in host_status.values())

st.markdown('<div class="hero"><h1>Welcome to NetGuard</h1><div class="muted">Explore CTU-13 network flows and graph relationships. Detection and model scores remain exploratory until a trained model is added.</div></div>', unsafe_allow_html=True)

cards = [("🖥️", "Total Hosts Analyzed", f"{graph.number_of_nodes():,}", "from the active sample"), ("⚠️", "Potentially Malicious Hosts", f"{malicious_hosts:,}", "based on dataset labels"), ("🎯", "Model Accuracy", "—", "not trained yet"), ("🕘", "Flows in Sample", f"{len(flows):,}", "current dashboard selection")]
for col, (icon, title, value, note) in zip(st.columns(4), cards):
    col.markdown(f'<div class="panel"><div class="kpi-label">{icon}&nbsp; {title}</div><div class="kpi-value">{value}</div><div class="kpi-note">● {note}</div></div>', unsafe_allow_html=True)

st.write("")
left, right = st.columns((1.15, .9), gap="large")
with left:
    st.markdown('<div class="panel"><h3>Network Graph</h3>', unsafe_allow_html=True)
    st.caption("Top 100 hosts by observed connections. Blue = normal/background, amber = other, red = botnet/malicious label.")
    st.pyplot(draw_network(graph, host_status), use_container_width=True)
    st.markdown("</div>", unsafe_allow_html=True)
with right:
    st.markdown('<div class="panel"><h3>Recent Detections</h3>', unsafe_allow_html=True)
    columns = [c for c in ["StartTime", "SrcAddr", "DstAddr", "Proto", "Label", "Status"] if c in flows]
    recent = flows[columns].sort_values("Status", key=lambda s: s.map({"Malicious":0, "Suspicious":1, "Normal":2}))
    st.dataframe(recent.head(12), use_container_width=True, hide_index=True, height=330)
    st.markdown("</div>", unsafe_allow_html=True)

bottom_left, bottom_middle, bottom_right = st.columns((1.05, .55, 1.05), gap="large")
with bottom_left:
    st.markdown('<div class="panel"><h3>Traffic Profile</h3>', unsafe_allow_html=True)
    st.bar_chart(flows["SrcAddr"].value_counts().head(10), color="#2d8cff", height=220)
    st.caption("Top source IPs by observed flow count")
    st.markdown("</div>", unsafe_allow_html=True)
with bottom_middle:
    st.markdown('<div class="panel"><h3>Dataset</h3>', unsafe_allow_html=True)
    st.selectbox("Active dataset", ["CTU-13"], label_visibility="collapsed")
    st.markdown("✅ Data loaded  \n✅ Graph constructed  \n✅ Features pending  \n○ Model not trained")
    st.markdown("</div>", unsafe_allow_html=True)
with bottom_right:
    st.markdown('<div class="panel"><h3>Incident History</h3>', unsafe_allow_html=True)
    incidents = flows[flows["Status"] != "Normal"]
    cols = [c for c in ["StartTime", "SrcAddr", "DstAddr", "Label", "Status"] if c in incidents]
    st.dataframe(incidents[cols].head(8), use_container_width=True, hide_index=True, height=215)
    st.caption("These are dataset labels, not predictions from a trained classifier.")
    st.markdown("</div>", unsafe_allow_html=True)
