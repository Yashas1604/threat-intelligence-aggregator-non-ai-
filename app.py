"""
Threat Intelligence Aggregator (Non-AI)
Streamlit Web Dashboard - app.py
"""

import streamlit as st
import json
import os
import sys
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime

sys.path.insert(0, os.path.dirname(__file__))
from ioc_engine import (
    load_sample_feeds, load_feeds_from_urls,
    parse_all_feeds, normalize_all, correlate,
    generate_blocklists, generate_report, SAMPLE_FEEDS
)

# ─────────────────────────────────────────────
#  PAGE CONFIG
# ─────────────────────────────────────────────

st.set_page_config(
    page_title="Threat Intelligence Aggregator",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ─────────────────────────────────────────────
#  CUSTOM CSS
# ─────────────────────────────────────────────

st.markdown("""
<style>
    .main { background-color: #0e1117; }
    .block-container { padding-top: 1.5rem; padding-bottom: 1rem; }

    .top-header {
        background: linear-gradient(135deg, #1a1f2e 0%, #0d1117 100%);
        border: 1px solid #30363d;
        border-radius: 12px;
        padding: 1.5rem 2rem;
        margin-bottom: 1.5rem;
    }
    .top-header h1 {
        font-size: 1.6rem;
        font-weight: 700;
        color: #e6edf3;
        margin: 0;
        letter-spacing: -0.02em;
    }
    .top-header p {
        color: #8b949e;
        font-size: 0.85rem;
        margin: 4px 0 0;
    }
    .badge {
        display: inline-block;
        background: #1f6feb22;
        border: 1px solid #1f6feb;
        color: #58a6ff;
        font-size: 0.7rem;
        padding: 2px 10px;
        border-radius: 100px;
        font-weight: 600;
        margin-left: 10px;
        vertical-align: middle;
    }

    .metric-card {
        background: #161b22;
        border: 1px solid #30363d;
        border-radius: 10px;
        padding: 1.1rem 1.3rem;
        text-align: center;
    }
    .metric-label {
        color: #8b949e;
        font-size: 0.72rem;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        margin-bottom: 6px;
    }
    .metric-value {
        font-size: 2rem;
        font-weight: 700;
        color: #e6edf3;
        font-family: monospace;
        line-height: 1;
    }
    .metric-sub {
        color: #8b949e;
        font-size: 0.72rem;
        margin-top: 4px;
    }

    .metric-critical { color: #f85149 !important; }
    .metric-high     { color: #ff7b72 !important; }
    .metric-medium   { color: #e3b341 !important; }
    .metric-low      { color: #3fb950 !important; }

    .section-title {
        font-size: 0.8rem;
        font-weight: 600;
        color: #8b949e;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        margin-bottom: 0.75rem;
        padding-bottom: 6px;
        border-bottom: 1px solid #21262d;
    }

    .pill {
        display: inline-block;
        font-size: 0.68rem;
        font-weight: 600;
        padding: 2px 8px;
        border-radius: 100px;
        font-family: monospace;
    }
    .pill-CRITICAL { background: #f8514922; color: #f85149; border: 1px solid #f8514955; }
    .pill-HIGH     { background: #ff7b7222; color: #ff7b72; border: 1px solid #ff7b7255; }
    .pill-MEDIUM   { background: #e3b34122; color: #e3b341; border: 1px solid #e3b34155; }
    .pill-LOW      { background: #3fb95022; color: #3fb950; border: 1px solid #3fb95055; }

    .step-bar {
        display: flex;
        align-items: center;
        gap: 0;
        margin-bottom: 1.5rem;
        background: #161b22;
        border: 1px solid #30363d;
        border-radius: 10px;
        padding: 1rem 1.5rem;
        overflow-x: auto;
    }
    .step-item {
        display: flex;
        flex-direction: column;
        align-items: center;
        flex: 1;
        min-width: 80px;
    }
    .step-circle {
        width: 32px; height: 32px;
        border-radius: 50%;
        display: flex; align-items: center; justify-content: center;
        font-size: 0.75rem;
        font-weight: 700;
        font-family: monospace;
    }
    .step-done   { background: #1f6feb; color: white; }
    .step-wait   { background: #21262d; color: #8b949e; border: 1px solid #30363d; }
    .step-text {
        font-size: 0.65rem;
        color: #8b949e;
        margin-top: 5px;
        text-align: center;
        line-height: 1.3;
    }
    .step-arrow {
        color: #30363d;
        font-size: 1.2rem;
        padding: 0 4px;
        margin-bottom: 18px;
    }

    .feed-row {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 8px 0;
        border-bottom: 1px solid #21262d;
        font-size: 0.8rem;
    }
    .feed-row:last-child { border-bottom: none; }
    .dot-green { color: #3fb950; }
    .dot-yellow { color: #e3b341; }

    div[data-testid="stDataFrame"] { border-radius: 8px; overflow: hidden; }
    .stButton button {
        background: #1f6feb;
        color: white;
        border: none;
        border-radius: 8px;
        font-weight: 600;
        padding: 0.5rem 1.5rem;
        width: 100%;
    }
    .stButton button:hover { background: #388bfd; }
    .stDownloadButton button {
        background: #21262d;
        color: #e6edf3;
        border: 1px solid #30363d;
        border-radius: 8px;
        width: 100%;
    }
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────
#  SIDEBAR
# ─────────────────────────────────────────────

with st.sidebar:
    st.markdown("### ⚙️ Configuration")
    st.markdown("---")

    feed_mode = st.radio(
        "Feed Source",
        ["🧪 Sample Feeds (Demo)", "🌐 Live Threat Feeds", "📁 Upload Your Own"],
        index=0
    )

    uploaded_files = []
    if feed_mode == "📁 Upload Your Own":
        uploaded_files = st.file_uploader(
            "Upload IOC feed files (.txt)",
            accept_multiple_files=True,
            type=["txt", "csv"]
        )

    st.markdown("---")
    st.markdown("### 🔍 Filters")
    min_risk = st.slider("Minimum Risk Score", 0, 100, 0, step=5)
    selected_types = st.multiselect(
        "IOC Types",
        ["ip", "domain", "url", "hash_md5", "hash_sha256", "email"],
        default=["ip", "domain", "url", "hash_md5", "hash_sha256", "email"]
    )

    st.markdown("---")
    st.markdown(
        "<div style='font-size:0.72rem;color:#8b949e;text-align:center'>"
        "Threat Intelligence Aggregator<br>"
        "<b style='color:#58a6ff'>Non-AI · Rule-Based · Python</b><br><br>"
        "Built for cybersecurity portfolio<br>"
        "CHFI · CEH · ISC2 CC"
        "</div>",
        unsafe_allow_html=True
    )

# ─────────────────────────────────────────────
#  HEADER
# ─────────────────────────────────────────────

st.markdown("""
<div class="top-header">
    <h1>🛡️ Threat Intelligence Aggregator <span class="badge">NON-AI</span></h1>
    <p>Rule-based IOC feed ingestion · Parsing · Normalization · Correlation · Blocklist Generation · Reporting</p>
</div>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────
#  PIPELINE STATUS BAR
# ─────────────────────────────────────────────

steps = ["Load Feeds", "Parse Indicators", "Normalize Data", "Correlation Engine", "Blocklists", "Report"]

def render_pipeline(active_step=0):
    cols = st.columns(len(steps) * 2 - 1)
    for i, step in enumerate(steps):
        with cols[i * 2]:
            done = active_step > i
            cls = "step-done" if done else "step-wait"
            st.markdown(
                f'<div style="display:flex;flex-direction:column;align-items:center;">'
                f'<div class="step-circle {cls}">{i+1}</div>'
                f'<div class="step-text">{step}</div>'
                f'</div>',
                unsafe_allow_html=True
            )
        if i < len(steps) - 1:
            with cols[i * 2 + 1]:
                st.markdown(
                    '<div style="text-align:center;color:#30363d;font-size:1.2rem;padding-top:6px;">→</div>',
                    unsafe_allow_html=True
                )

# ─────────────────────────────────────────────
#  RUN PIPELINE
# ─────────────────────────────────────────────

LIVE_FEEDS = {
    "AlienVault_OTX_Malware_IPs": "https://reputation.alienvault.com/reputation.data",
    "Abuse_ch_URLhaus": "https://urlhaus.abuse.ch/downloads/text/",
    "Emerging_Threats_CNC": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    "PhishTank_URLs": "https://data.phishtank.com/data/online-valid.csv",
}

run_col, _ = st.columns([1, 3])
with run_col:
    run_clicked = st.button("▶ Run Pipeline")

if run_clicked or "pipeline_data" in st.session_state:

    if run_clicked:
        progress = st.progress(0, text="Starting pipeline...")

        # Step 1
        render_pipeline(1)
        progress.progress(15, text="Step 1: Loading feeds...")

        if feed_mode == "🌐 Live Threat Feeds":
            raw_data, feed_results = load_feeds_from_urls(LIVE_FEEDS)
        elif feed_mode == "📁 Upload Your Own" and uploaded_files:
            import tempfile, pathlib
            raw_data = {}
            feed_results = []
            from ioc_engine import FeedResult
            for uf in uploaded_files:
                content = uf.read().decode("utf-8", errors="ignore")
                lines = [l.strip() for l in content.splitlines() if l.strip()]
                raw_data[uf.name] = lines
                feed_results.append(FeedResult(uf.name, "uploaded", "success", len(lines)))
        else:
            raw_data, feed_results = load_sample_feeds()

        # Step 2
        render_pipeline(2)
        progress.progress(30, text="Step 2: Parsing indicators...")
        raw_iocs = parse_all_feeds(raw_data)

        # Step 3
        render_pipeline(3)
        progress.progress(50, text="Step 3: Normalizing data...")
        clean_iocs = normalize_all(raw_iocs)

        # Step 4
        render_pipeline(4)
        progress.progress(65, text="Step 4: Running correlation engine...")
        correlated = correlate(clean_iocs)

        # Step 5
        render_pipeline(5)
        progress.progress(80, text="Step 5: Generating blocklists...")
        blocklist_paths = generate_blocklists(correlated, "output")

        # Step 6
        render_pipeline(6)
        progress.progress(95, text="Step 6: Generating report...")
        result = generate_report(correlated, feed_results, blocklist_paths, "reports")

        progress.progress(100, text="✅ Pipeline complete!")

        st.session_state["pipeline_data"] = {
            "correlated": correlated,
            "feed_results": feed_results,
            "result": result,
            "blocklist_paths": blocklist_paths,
        }

    # Load from session
    data       = st.session_state["pipeline_data"]
    correlated = data["correlated"]
    feed_results = data["feed_results"]
    result     = data["result"]
    summary    = result["data"]["summary"]

    render_pipeline(6)

    st.markdown("---")

    # ─── METRICS ───
    c1, c2, c3, c4, c5 = st.columns(5)
    metrics = [
        (c1, "Feeds",        summary["total_feeds"],   "", ""),
        (c2, "Total IOCs",   summary["total_iocs"],    "", "after dedup"),
        (c3, "Critical",     summary["critical_iocs"], "metric-critical", "risk ≥ 80"),
        (c4, "High",         summary["high_iocs"],     "metric-high",     "risk 60–79"),
        (c5, "Medium / Low", f"{summary['medium_iocs']} / {summary['low_iocs']}", "metric-medium", ""),
    ]
    for col, label, val, cls, sub in metrics:
        with col:
            st.markdown(
                f'<div class="metric-card">'
                f'<div class="metric-label">{label}</div>'
                f'<div class="metric-value {cls}">{val}</div>'
                f'<div class="metric-sub">{sub}</div>'
                f'</div>',
                unsafe_allow_html=True
            )

    st.markdown("<br>", unsafe_allow_html=True)

    # ─── CHARTS ───
    left, right = st.columns(2)

    with left:
        st.markdown('<div class="section-title">Risk Distribution</div>', unsafe_allow_html=True)
        risk_data = {
            "Level":  ["Critical", "High", "Medium", "Low"],
            "Count":  [summary["critical_iocs"], summary["high_iocs"],
                       summary["medium_iocs"], summary["low_iocs"]],
            "Color":  ["#f85149", "#ff7b72", "#e3b341", "#3fb950"]
        }
        fig_risk = px.bar(
            risk_data, x="Level", y="Count", color="Level",
            color_discrete_map={
                "Critical": "#f85149", "High": "#ff7b72",
                "Medium": "#e3b341", "Low": "#3fb950"
            },
            template="plotly_dark"
        )
        fig_risk.update_layout(
            showlegend=False, plot_bgcolor="#161b22", paper_bgcolor="#161b22",
            margin=dict(l=10, r=10, t=10, b=10), height=260,
            xaxis=dict(showgrid=False), yaxis=dict(gridcolor="#21262d")
        )
        fig_risk.update_traces(marker_line_width=0)
        st.plotly_chart(fig_risk, use_container_width=True)

    with right:
        st.markdown('<div class="section-title">IOC Types Breakdown</div>', unsafe_allow_html=True)
        by_type = result["data"]["by_type"]
        type_labels = list(by_type.keys())
        type_values = list(by_type.values())
        fig_type = px.pie(
            names=type_labels, values=type_values,
            hole=0.55, template="plotly_dark",
            color_discrete_sequence=["#1f6feb","#3fb950","#e3b341","#f85149","#bc8cff","#ff7b72"]
        )
        fig_type.update_layout(
            plot_bgcolor="#161b22", paper_bgcolor="#161b22",
            margin=dict(l=10, r=10, t=10, b=10), height=260,
            legend=dict(font=dict(size=11), bgcolor="#161b22")
        )
        st.plotly_chart(fig_type, use_container_width=True)

    # ─── IOC TABLE ───
    st.markdown('<div class="section-title">IOC Intelligence Table</div>', unsafe_allow_html=True)

    ioc_list = [
        {
            "Risk Score": i.risk_score,
            "Type": i.ioc_type,
            "Indicator": i.value,
            "Seen in Feeds": i.seen_count,
            "Sources": i.source_feed,
            "Tags": ", ".join(i.tags),
            "First Seen": i.first_seen[:19],
        }
        for i in correlated
        if i.risk_score >= min_risk and i.ioc_type in selected_types
    ]

    df = pd.DataFrame(ioc_list)

    if not df.empty:
        st.dataframe(
            df,
            use_container_width=True,
            height=350,
            column_config={
                "Risk Score": st.column_config.ProgressColumn(
                    "Risk Score", min_value=0, max_value=100, format="%d"
                ),
                "Indicator": st.column_config.TextColumn("Indicator", width="large"),
                "Sources": st.column_config.TextColumn("Sources", width="large"),
            }
        )
    else:
        st.info("No IOCs match the current filters.")

    # ─── FEEDS STATUS ───
    st.markdown("<br>", unsafe_allow_html=True)
    fl, fr = st.columns(2)

    with fl:
        st.markdown('<div class="section-title">Feed Status</div>', unsafe_allow_html=True)
        for f in feed_results:
            dot = "🟢" if f.status == "success" else "🟡"
            st.markdown(
                f'<div class="feed-row">'
                f'<span>{dot} <b>{f.feed_name}</b></span>'
                f'<span style="color:#8b949e;font-size:0.75rem">{f.raw_lines} lines · {f.status}</span>'
                f'</div>',
                unsafe_allow_html=True
            )

    with fr:
        st.markdown('<div class="section-title">Download Reports</div>', unsafe_allow_html=True)

        json_path = result["json"]
        txt_path  = result["txt"]

        if os.path.exists(txt_path):
            with open(txt_path) as f:
                txt_content = f.read()
            st.download_button(
                "⬇ Download TXT Report",
                data=txt_content,
                file_name=os.path.basename(txt_path),
                mime="text/plain"
            )

        if os.path.exists(json_path):
            with open(json_path) as f:
                json_content = f.read()
            st.download_button(
                "⬇ Download JSON Report",
                data=json_content,
                file_name=os.path.basename(json_path),
                mime="application/json"
            )

        # Blocklists
        st.markdown('<div class="section-title" style="margin-top:1rem;">Blocklists Generated</div>', unsafe_allow_html=True)
        for cat, path in data["blocklist_paths"].items():
            if os.path.exists(path):
                with open(path) as f:
                    bl_content = f.read()
                st.download_button(
                    f"⬇ {cat} blocklist",
                    data=bl_content,
                    file_name=os.path.basename(path),
                    mime="text/plain",
                    key=f"bl_{cat}"
                )

else:
    render_pipeline(0)
    st.markdown("<br>", unsafe_allow_html=True)
    st.info("👆 Configure your feed source in the sidebar, then click **▶ Run Pipeline** to start.")

    with st.expander("ℹ️ About this tool"):
        st.markdown("""
        **Threat Intelligence Aggregator (Non-AI)** is a pure rule-based Python pipeline that:

        1. **Loads** IOC feeds from URLs, local files, or built-in samples
        2. **Parses** IPs, URLs, domains, MD5/SHA256 hashes, and emails using regex
        3. **Normalizes** data — drops private IPs, whitelisted entries, cleans values
        4. **Correlates** IOCs across feeds — boosts risk for multi-feed matches
        5. **Generates** category-based blocklists (one file per IOC type)
        6. **Reports** summaries, risk scores, and full JSON export

        **No AI or ML used** — all logic is deterministic and rule-based.
        """)
