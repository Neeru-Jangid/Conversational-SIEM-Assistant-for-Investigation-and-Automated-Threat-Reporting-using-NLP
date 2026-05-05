"""
ui/app.py  —  SIEM NLP Assistant v2

Layout:
  - Sidebar: controls, session context, query history
  - Main area: chat history (scrollable) + fixed bottom input
  - Result tabs: Results | Chart | DSL | KQL | Debug
  - No separate right panel — charts live in the Chat tab
"""

import json
import os
import sys
from datetime import datetime
import streamlit as st

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pipeline import SIEMPipeline

st.set_page_config(
    page_title="SIEM Intelligence",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Styling ────────────────────────────────────────────────────────────────────
st.markdown("""
<style>

/* ── THEME VARIABLES ───────────────────────────── */
:root{
    --primary: #5a7d7c;
    --accent: #a0c1d1;
    --light: #dadff7;
    --dark: #232c33;
    --muted: #b5b2c2;

    --bg-main: var(--light);
    --bg-panel: #ffffff;
    --bg-soft: #f3f5fb;

    --text-main: var(--dark);
    --text-soft: #4a5660;

    --border: rgba(35,44,51,0.15);
}

/* ── BASE APP ──────────────────────────────────── */
html, body, .stApp {
    background: var(--bg-main);
    color: var(--text-main);
    font-family: 'JetBrains Mono', monospace;
}

#MainMenu, footer {visibility:hidden;}

/* ── TOP BAR ───────────────────────────────────── */
.topbar{
    background: var(--bg-panel);
    border-bottom:1px solid var(--border);
    padding:12px 24px;
    display:flex;
    align-items:center;
    gap:12px;
}

.topbar-logo{
    font-family:'Syne',sans-serif;
    font-weight:800;
    font-size:18px;
    color:var(--primary);
}

.topbar-sub{
    font-size:11px;
    color:var(--text-soft);
}

.topbar-right{
    margin-left:auto;
}

.sdot{
    width:6px;
    height:6px;
    background:var(--primary);
    border-radius:50%;
}

/* ── SIDEBAR ───────────────────────────────────── */
[data-testid="stSidebar"]{
    background: var(--bg-soft) !important;
    border-right:1px solid var(--border);
}

/* ── CHAT MESSAGES ─────────────────────────────── */
div[data-testid="stChatMessageContent"]{
    background: var(--bg-panel) !important;
    border:1px solid var(--border) !important;
    border-radius:10px !important;
}

/* ── METRIC CARDS ─────────────────────────────── */
.mrow{
    display:flex;
    gap:10px;
    flex-wrap:wrap;
    margin:12px 0;
}

.mcrd{
 background:var(--panel);
 border:1px solid var(--border);
 border-radius:8px;
 padding:10px 14px;
 min-width:90px;
}

.mval{
 font-size:18px;
 font-weight:600;
 color:var(--primary);
}

.mlbl{
 font-size:10px;
 color:#6a7782;
 margin-top:3px;
}

/* --------- BADGES --------- */

.badges{
 display:flex;
 gap:6px;
 margin-bottom:10px;
}

.badge{
 padding:3px 8px;
 font-size:10px;
 border-radius:4px;
 border:1px solid var(--border);
 background:#f5f7fb;
 color:#4a5660;
}

/* --------- NARRATIVE --------- */

.narr{
 background:#f5f7fb;
 border-left:3px solid var(--primary);
 border-radius:6px;
 padding:12px 14px;
 font-size:13px;
 line-height:1.7;
}

/* --------- WARNING --------- */

.wbox{
 background:#fff7e6;
 border:1px solid #ffd48c;
 color:#8a6500;
 padding:8px 12px;
 border-radius:6px;
 font-size:12px;
}

.ebox{
 background:#ffecec;
 border:1px solid #ffb5b5;
 color:#9b2c2c;
 padding:10px 12px;
 border-radius:6px;
}

/* --------- KQL --------- */

.kqlbox{
 background:#f5f7fb;
 border:1px solid var(--border);
 border-radius:6px;
 padding:12px;
 font-size:12px;
}

/* --------- BUTTONS --------- */

.stButton > button{
 background:var(--panel);
 border:1px solid var(--border);
 border-radius:6px;
 color:var(--text);
 font-size:12px;
}

.stButton > button:hover{
 border-color:var(--primary);
 color:var(--primary);
}

/* --------- TABS --------- */

.stTabs [data-baseweb="tab"]{
 color:#6a7782;
 font-size:12px;
}

.stTabs [aria-selected="true"]{
 color:var(--primary);
 border-bottom:2px solid var(--primary);
}

/* --------- TABLE --------- */

[data-testid="stDataFrame"]{
 border:1px solid var(--border);
 border-radius:8px;
}

/* --------- CHAT INPUT --------- */

[data-testid="stChatInput"] textarea{
 color:var(--text);
}

/* --------- SCROLLBAR --------- */

::-webkit-scrollbar{
 width:6px;
}

::-webkit-scrollbar-thumb{
 background:#c5ccd4;
 border-radius:4px;
}

</style>
""", unsafe_allow_html=True)



# ── Session state ──────────────────────────────────────────────────────────────
_defaults = {
    "pipeline":          None,
    "messages":          [],
    "query_history":     [],
    "selected_queries":  [],
    "_gen_report":       None,
    "_report_preview":   None,
    "fresh_search":      False,
}
for k, v in _defaults.items():
    if k not in st.session_state:
        st.session_state[k] = v

if st.session_state.pipeline is None:
    st.session_state.pipeline = SIEMPipeline()

QUICK_QUERIES = [
    "Failed logins from admin user yesterday",
    "Malware detections this week with report",
    "VPN logins from Russia or China last 7 days",
    "Failed MFA attempts this week",
    "Brute force attacks on SSH last month",
    "Privilege escalation attempts last 7 days",
    "Suspicious PowerShell activity today",
    "File integrity violations this week",
    "Data exfiltration attempts last 30 days",
    "Port scans from external IPs yesterday",
]

# ── Top bar ────────────────────────────────────────────────────────────────────
st.markdown("""
<div class="topbar">
    <div class="topbar-logo">SIEM Intelligence</div>
    <div class="topbar-sub">NLP · Local · Air-gap ready</div>
    <div class="topbar-right">
        <span class="sdot"></span>
        <span class="mtag">llama3.1:8b &nbsp;·&nbsp; RTX 4060 &nbsp;·&nbsp; Hybrid DSL</span>
    </div>
</div>
""", unsafe_allow_html=True)

# ── Sidebar ────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown('<p style="font-family:Syne,sans-serif;font-size:14px;font-weight:700;color:#c0d4ea;margin:0 0 12px">Dashboard</p>', unsafe_allow_html=True)

    if st.button("Check System Health", use_container_width=True):
        with st.spinner("Checking…"):
            h = st.session_state.pipeline.health()
        es, ol = h["elasticsearch"], h["ollama"]
        (st.success if es.get("connected") else st.error)(
            f"OpenSearch · {es.get('document_count',0):,} docs"
            if es.get("connected") else f"OpenSearch · {es.get('message','down')}"
        )
        (st.success if ol.get("connected") and ol.get("main_model_available") else st.error)(
            f"Ollama · {ol.get('main_model','')}"
            if ol.get("connected") and ol.get("main_model_available")
            else f"Ollama · {ol.get('message','check models')}"
        )
        clf_ok = ol.get("classifier_model_available", False)
        clf_name = ol.get("classifier_model", "qwen2.5:7b")
        (st.success if clf_ok else st.warning)(
            f"Classifier · {clf_name}"
            if clf_ok
            else f"Classifier · {clf_name} not found — run: ollama pull {clf_name}"
        )
        st.caption(f"DSL Mode: {h['dsl_mode']}")

    st.divider()
    stats = st.session_state.pipeline.stats()
    c1, c2 = st.columns(2)
    c1.metric("Queries", stats["total_queries"])
    c2.metric("Session",  f"{stats['session_minutes']}m")

    if st.button("New Session", use_container_width=True):
        st.session_state.messages         = []
        st.session_state.query_history    = []
        st.session_state.selected_queries = []
        st.session_state.pipeline.reset()
        st.rerun()

    st.divider()

    # Fresh search toggle — bypasses in-memory filter for new topic queries
    st.markdown('<p style="font-size:10px;color:#2e4460;text-transform:uppercase;letter-spacing:.8px;margin-bottom:4px">Search Mode</p>', unsafe_allow_html=True)
    fresh = st.toggle(
        "Fresh Search",
        value=st.session_state.fresh_search,
        key="fresh_search_toggle",
        help="ON — always query OpenSearch directly, ignoring cached results. "
             "Use when switching to a completely different topic."
    )
    if fresh != st.session_state.fresh_search:
        st.session_state.fresh_search = fresh
    if st.session_state.fresh_search:
        st.markdown('<div style="font-size:10px;color:#00d4ff;font-family:JetBrains Mono,monospace">New topic mode — queries go straight to index</div>', unsafe_allow_html=True)
    else:
        st.markdown('<div style="font-size:10px;color:#2e4460;font-family:JetBrains Mono,monospace">Follow-up mode — cached results checked first</div>', unsafe_allow_html=True)
        log = st.session_state.pipeline.memory.session_log
        if log:
            st.caption(f"{len(log)} queries this session")
            for rec in reversed(log):
                fu = " · follow-up" if rec.is_follow_up else ""
                q_short = rec.natural_query[:55] + "…" if len(rec.natural_query) > 55 else rec.natural_query
                st.markdown(f"""
                <div class="ctxcard">
                    <div class="ctxmeta">#{rec.index}{fu} · {rec.executed_at.strftime("%H:%M:%S")}</div>
                    <div class="ctxq">{q_short}</div>
                    <div class="ctxmeta">
                        <span class="ctxi">{rec.intent}</span>
                        &nbsp;·&nbsp;{rec.result_count:,} results
                        &nbsp;·&nbsp;{rec.time_range}
                        &nbsp;·&nbsp;{rec.dsl_source}
                    </div>
                </div>
                """, unsafe_allow_html=True)
            qs = st.session_state.pipeline.memory.query_state
            if qs.last_dsl:
                st.markdown('<p style="font-size:10px;color:#2e4460;text-transform:uppercase;letter-spacing:.6px;margin:8px 0 4px">Active Filters</p>', unsafe_allow_html=True)
                for f in qs.last_dsl.get("body",{}).get("query",{}).get("bool",{}).get("filter",[]):
                    st.code(json.dumps(f, indent=2), language="json")
        else:
            st.caption("No queries yet.")

    st.divider()

    if st.session_state.query_history:
        st.markdown('<p style="font-size:10px;color:#2e4460;text-transform:uppercase;letter-spacing:.8px;margin-bottom:6px">Session Report</p>', unsafe_allow_html=True)
        st.caption("Select queries to include")
        selected = []
        for i, q in enumerate(st.session_state.query_history[-10:]):
            label = q["query"][:40] + "…" if len(q["query"]) > 40 else q["query"]
            if st.checkbox(label, key=f"qhist_{i}"):
                selected.append(q)
        st.session_state.selected_queries = selected

        if selected:
            report_title = st.text_input(
                "Report title",
                value=f"Security Report — {datetime.now().strftime('%Y-%m-%d')}",
                key="report_title_input",
                label_visibility="collapsed",
                placeholder="Report title…"
            )
            if st.button("Preview & Export Report", use_container_width=True):
                st.session_state._gen_report = {
                    "fmt":     "preview",
                    "title":   report_title,
                    "queries": selected,
                }

    st.divider()

    st.markdown('<p style="font-size:10px;color:#1e3050;line-height:1.8;font-family:JetBrains Mono,monospace">Llama 3.1 8B · nomic-embed-text<br>ChromaDB · Wazuh Indexer<br>All data stays local.</p>', unsafe_allow_html=True)

    st.divider()
    st.markdown('<p style="font-size:10px;color:#2e4460;text-transform:uppercase;letter-spacing:.8px;margin-bottom:8px;font-family:JetBrains Mono,monospace">Quick Queries</p>', unsafe_allow_html=True)
    for q in QUICK_QUERIES:
        if st.button(q, key=f"sq_{q}", use_container_width=True):
            st.session_state._inject = q
            st.rerun()


# ── Result renderer ────────────────────────────────────────────────────────────
def render_result(result: dict, msg_index: int = 0):
    """Render a pipeline result dict inside a chat message."""

    # ── Error ──────────────────────────────────────────────────────────────────
    if not result.get("success"):
        st.markdown(f'<div class="ebox">{result.get("error","Unknown error")}</div>', unsafe_allow_html=True)
        return

    # ── Guard (greeting / OOS / help) ──────────────────────────────────────────
    if result.get("dsl_source") == "guard":
        st.markdown(f'<div class="narr">{result.get("report",{}).get("narrative","")}</div>', unsafe_allow_html=True)
        return

    # ── Pending confirmation ────────────────────────────────────────────────────
    if result.get("dsl_source") == "pending_confirmation":
        cancel_key = f"cancelled_{msg_index}"
        acted_key  = f"acted_{msg_index}"

        # Already cancelled
        if st.session_state.get(cancel_key):
            st.markdown('<div style="font-size:11px;color:#2e4460;font-family:JetBrains Mono,monospace;padding:4px 0">Search cancelled.</div>', unsafe_allow_html=True)
            return

        # Already acted on — collapse and point to the new result below
        if st.session_state.get(acted_key):
            st.markdown('<div style="font-size:11px;color:#2e4460;font-family:JetBrains Mono,monospace;padding:4px 0">↳ Full index search run — see results below.</div>', unsafe_allow_html=True)
            return

        narrative = result.get("report", {}).get("narrative", "")
        st.markdown(f'<div class="confirm-box">{narrative}</div>', unsafe_allow_html=True)

        pending  = result.get("pending_query", result.get("user_input", ""))
        is_widen = pending.startswith("__widen__:")

        col_yes, col_no, _ = st.columns([1, 1, 3])
        with col_yes:
            btn_label = "Yes, widen to 30 days" if is_widen else "Yes, search full index"
            if st.button(btn_label, key=f"confirm_yes_{msg_index}"):
                st.session_state[acted_key] = True
                raw_query = pending.replace("__widen__:", "").replace("__fullsearch__:", "")
                prefix    = "__widen__:" if is_widen else "__fullsearch__:"
                st.session_state._inject = f"{prefix}{raw_query}"
                st.rerun()
        with col_no:
            if st.button("No, cancel", key=f"confirm_no_{msg_index}"):
                st.session_state[cancel_key] = True
                st.rerun()
        return

    report = result.get("report", {})
    siem   = result.get("siem_meta", {})
    src    = result.get("dsl_source", "")

    # ── Badges ─────────────────────────────────────────────────────────────────
    badges = ""
    if src == "memory_filter":
        badges += '<span class="badge badge-mem">Memory Filter</span>'
    elif src in ("llm", "llm_followup"):
        badges += '<span class="badge badge-llm">LLM DSL</span>'
    elif "template" in src:
        badges += '<span class="badge badge-tmpl">Template DSL</span>'
    if result.get("is_follow_up"):
        badges += '<span class="badge badge-fu">Follow-up</span>'
    if result.get("report_requested"):
        badges += '<span class="badge badge-rpt">Report</span>'
    if badges:
        st.markdown(f'<div class="badges">{badges}</div>', unsafe_allow_html=True)

    # ── Metrics ─────────────────────────────────────────────────────────────────
    if siem:
        m = report.get("metadata", {})
        cached_tag = ' <span style="font-size:10px;color:#00ffb4">(memory)</span>' if src == "memory_filter" else ""
        st.markdown(f"""
        <div class="mrow">
            <div class="mcrd"><div class="mval">{siem.get('total',0):,}</div><div class="mlbl">Total Found{cached_tag}</div></div>
            <div class="mcrd"><div class="mval">{m.get('showing',0)}</div><div class="mlbl">Showing</div></div>
            <div class="mcrd"><div class="mval">{siem.get('took_ms',0)}ms</div><div class="mlbl">Query Time</div></div>
            <div class="mcrd"><div class="mval">{siem.get('attempts',1)}</div><div class="mlbl">Attempts</div></div>
            <div class="mcrd"><div class="mval" style="font-size:12px">{siem.get('time_range') or m.get('time_range','—')}</div><div class="mlbl">Time Range</div></div>
        </div>
        """, unsafe_allow_html=True)
        if siem.get("warning"):
            st.markdown(f'<div class="wbox">{siem["warning"]}</div>', unsafe_allow_html=True)

    for w in (result.get("validation") or {}).get("warnings", []):
        st.markdown(f'<div class="wbox">{w}</div>', unsafe_allow_html=True)

    # ── Narrative ───────────────────────────────────────────────────────────────
    if report.get("narrative"):
        st.markdown(f'<div class="narr">{report["narrative"]}</div>', unsafe_allow_html=True)

    # ── Tabs: Results | Chart | DSL | KQL | Debug ───────────────────────────────
    t_results, t_chart, t_dsl, t_kql, t_debug = st.tabs(
        ["Results", "Chart", "DSL", "KQL", "Debug"]
    )

    with t_results:
        df = report.get("dataframe")
        raw_hits = result.get("_raw_hits", [])

        # For memory_filter results, build a smarter table based on query intent
        if src == "memory_filter" and raw_hits:
            import pandas as pd
            from datetime import datetime as _dt

            classification_data = result.get("classification", {})
            entities   = classification_data.get("entities", {})
            hint       = classification_data.get("event_type_hint", "all_events")
            core_q     = (classification_data.get("core_query") or "").lower()

            # Use what the LLM actually extracted — not re-parsed keyword guessing.
            # Entities tell us what fields are relevant to this query.
            has_ips       = bool(entities.get("ips"))
            has_countries = bool(entities.get("countries"))
            has_users     = bool(entities.get("users"))
            has_services  = bool(entities.get("services"))
            has_hosts     = bool(entities.get("hosts"))

            # For null/missing queries (no entities extracted but query asks about
            # a specific field), detect from the LLM's core_query what field
            # the user cares about — ask LLM once, don't re-parse in Python
            # Fallback: show all potentially interesting columns
            no_entities = not any([has_ips, has_countries, has_users, has_services, has_hosts])
            if no_entities:
                # Show everything — user asked something we couldn't classify into entities
                # (null checks, negations, etc.) so surface all available fields
                has_ips = has_countries = has_users = has_services = True

            def _ts(h):
                t = h.get("@timestamp", "")
                try:
                    return _dt.fromisoformat(t.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M")
                except Exception:
                    return t[:16]

            rows = []
            for h in raw_hits:
                row = {
                    "Time":        _ts(h),
                    "Type":        h.get("event_type", ""),
                    "Description": h.get("rule", {}).get("description", "")[:50],
                    "Severity":    h.get("rule", {}).get("level", ""),
                    "Src IP":      h.get("data", {}).get("srcip", "—") or "—",
                }
                if has_countries:
                    row["Src Country"] = h.get("geo", {}).get("country", "") or "—"
                    row["Dst Country"] = h.get("data", {}).get("network", {}).get("destination_country", "") or "—"
                if has_users:
                    row["User"] = h.get("user", {}).get("name", "—") or "—"
                if has_services:
                    row["Service"] = (
                        h.get("data", {}).get("service", "")
                        or h.get("data", {}).get("vpn", {}).get("protocol", "")
                        or h.get("data", {}).get("network", {}).get("protocol", "")
                        or "—"
                    )
                if has_ips:
                    row["Dst IP"] = h.get("data", {}).get("dstip", "—") or "—"
                if has_hosts:
                    row["Host"] = h.get("agent", {}).get("name", "—") or "—"
                rows.append(row)

            smart_df = pd.DataFrame(rows)
            st.dataframe(smart_df, use_container_width=True, hide_index=True)
            st.caption(f"Showing {len(smart_df)} filtered records from cache")

        elif df is not None and not df.empty:
            st.dataframe(df, use_container_width=True, hide_index=True)
            st.caption(f"Showing {len(df)} of {siem.get('total',0):,} total")
        else:
            st.info("No results returned for this query.")

    with t_chart:
        chart = report.get("chart")
        hits  = report.get("dataframe")  # we need raw hits not df — get from result
        aggs  = result.get("report", {})  # placeholder

        # ── Static chart from aggregations ─────────────────────────────────────
        if chart:
            st.plotly_chart(chart, use_container_width=True, key=f"static_chart_{msg_index}")
        else:
            st.info("No aggregation chart. Run a query with 'with report' to get charts.")

        # ── Interactive chart builder from raw hits ─────────────────────────────
        raw_hits = result.get("_raw_hits", [])
        if raw_hits:
            st.markdown('<div style="font-size:10px;color:#2e4460;text-transform:uppercase;letter-spacing:.8px;margin:16px 0 8px;font-family:JetBrains Mono,monospace">Build Custom Chart</div>', unsafe_allow_html=True)

            # Discover numeric and categorical fields from actual hits
            sample = raw_hits[0] if raw_hits else {}
            FLAT_FIELDS = {
                "event_type":             [h.get("event_type", "") for h in raw_hits],
                "rule.level":             [h.get("rule", {}).get("level") for h in raw_hits],
                "rule.groups (first)":    [h.get("rule", {}).get("groups", [""])[0] for h in raw_hits],
                "geo.country":            [h.get("geo", {}).get("country", "") for h in raw_hits],
                "agent.name":             [h.get("agent", {}).get("name", "") for h in raw_hits],
                "user.name":              [h.get("user", {}).get("name", "") for h in raw_hits],
                "data.srcip":             [h.get("data", {}).get("srcip", "") for h in raw_hits],
                "data.service":           [h.get("data", {}).get("service", "") for h in raw_hits],
                "data.vpn.protocol":      [h.get("data", {}).get("vpn", {}).get("protocol", "") for h in raw_hits],
            }
            # Only show fields that have non-empty values
            available = {k: v for k, v in FLAT_FIELDS.items()
                        if any(x for x in v if x is not None and x != "")}

            if available:
                cb1, cb2, cb3 = st.columns([2, 2, 1])
                with cb1:
                    field_choice = st.selectbox(
                        "Group by field",
                        options=list(available.keys()),
                        key=f"chart_field_{msg_index}"
                    )
                with cb2:
                    chart_type = st.selectbox(
                        "Chart type",
                        options=["Bar (horizontal)", "Bar (vertical)", "Pie", "Treemap"],
                        key=f"chart_type_{msg_index}"
                    )
                with cb3:
                    top_n = st.number_input(
                        "Top N",
                        min_value=3, max_value=30, value=10,
                        key=f"chart_topn_{msg_index}"
                    )

                # Count values
                from collections import Counter
                import plotly.express as px
                import plotly.graph_objects as go

                values = [str(v) for v in available[field_choice] if v is not None and v != ""]
                counts = Counter(values).most_common(int(top_n))
                if counts:
                    labels = [c[0][:30] for c in counts]
                    vals   = [c[1] for c in counts]
                    DARK   = "#0e1420"
                    FC     = "#e8edf5"

                    if chart_type == "Bar (horizontal)":
                        fig = px.bar(x=vals, y=labels, orientation="h",
                                     color=vals, color_continuous_scale=["#1e2a3d","#00d4ff"])
                    elif chart_type == "Bar (vertical)":
                        fig = px.bar(x=labels, y=vals,
                                     color=vals, color_continuous_scale=["#1e2a3d","#00d4ff"])
                    elif chart_type == "Pie":
                        fig = px.pie(names=labels, values=vals,
                                     color_discrete_sequence=px.colors.sequential.Blues_r)
                    else:  # Treemap
                        fig = px.treemap(names=labels, values=vals, parents=[""]*len(labels))

                    fig.update_layout(
                        plot_bgcolor=DARK, paper_bgcolor=DARK,
                        font_color=FC, margin=dict(l=10,r=10,t=30,b=10),
                        showlegend=False, coloraxis_showscale=False,
                        title=f"{field_choice} — top {top_n} from {len(raw_hits)} results",
                    )
                    if chart_type == "Bar (horizontal)":
                        fig.update_layout(yaxis={"categoryorder": "total ascending"})
                    st.plotly_chart(fig, use_container_width=True, key=f"custom_chart_{msg_index}_{field_choice}_{chart_type}")

    with t_dsl:
        dsl = result.get("dsl")
        if src == "memory_filter":
            # Memory filter ran in Python — no DSL was executed
            # Show what filter was actually applied instead of the old DSL
            classification_data = result.get("classification", {})
            entities   = classification_data.get("entities", {})
            hint       = classification_data.get("event_type_hint", "")
            core_q     = classification_data.get("core_query", result.get("user_input", ""))
            raw_hits   = result.get("_raw_hits", [])

            st.markdown(f"""
            <div style="background:#080e1c;border-left:2px solid #00ffb4;border-radius:0 6px 6px 0;
                        padding:11px 14px;margin-bottom:12px;font-family:'JetBrains Mono',monospace;font-size:12px;color:#7a9dbf">
                <div style="color:#00ffb4;font-size:10px;text-transform:uppercase;letter-spacing:.8px;margin-bottom:6px">
                    In-Memory Filter — no OpenSearch query executed
                </div>
                <div style="margin-bottom:4px"><span style="color:#2e4460">Query:</span> {core_q}</div>
                <div style="margin-bottom:4px"><span style="color:#2e4460">Results:</span> {len(raw_hits)} records from cache</div>
                <div style="margin-bottom:4px"><span style="color:#2e4460">Filter method:</span>
                    {"LLM semantic filter" if not any([entities.get(k) for k in ("users","ips","countries","hosts","services","techniques")] + [entities.get("severity_min")]) else "Rule-based entity filter"}
                </div>
            </div>
            """, unsafe_allow_html=True)

            # Show what constraints were extracted
            active = {}
            if hint and hint not in ("all_events", ""):
                active["Event type"] = hint.replace("_", " ")
            if entities.get("users"):         active["Users"]     = ", ".join(entities["users"])
            if entities.get("ips"):           active["IPs"]       = ", ".join(entities["ips"])
            if entities.get("countries"):     active["Countries"] = ", ".join(entities["countries"])
            if entities.get("services"):      active["Services"]  = ", ".join(entities["services"])
            if entities.get("severity_min"):  active["Min severity"] = str(entities["severity_min"])
            if entities.get("techniques"):    active["Techniques"] = ", ".join(entities["techniques"])

            if active:
                st.markdown('<div style="font-size:10px;color:#2e4460;text-transform:uppercase;letter-spacing:.6px;margin-bottom:6px">Constraints applied</div>', unsafe_allow_html=True)
                for k, v in active.items():
                    st.markdown(f'<div style="font-family:JetBrains Mono,monospace;font-size:11.5px;color:#5a80a8;margin-bottom:3px">· <span style="color:#c0d4ea">{k}:</span> {v}</div>', unsafe_allow_html=True)
            else:
                st.markdown('<div style="font-size:11px;color:#5a80a8;font-family:JetBrains Mono,monospace">Semantic filter — LLM evaluated each record against the query.</div>', unsafe_allow_html=True)

        elif dsl:
            st.caption(f"Index: `{dsl.get('index','—')}`")
            st.code(json.dumps(dsl.get("body", {}), indent=2), language="json")

    with t_kql:
        kql = report.get("kql", "")
        if kql:
            st.markdown(f'<div class="kqlbox">{kql}</div>', unsafe_allow_html=True)
        else:
            st.info("KQL not available.")

    with t_debug:
        st.json({
            "dsl_source":       src,
            "is_follow_up":     result.get("is_follow_up"),
            "report_requested": result.get("report_requested"),
            "classification":   result.get("classification"),
            "validation":       result.get("validation"),
            "siem_meta":        siem,
        })


# ── Main: chat history ─────────────────────────────────────────────────────────
if not st.session_state.messages:
    st.markdown("""
    <div style="text-align:center;padding:48px 20px 32px;max-width:560px;margin:0 auto">
        <div style="font-family:Syne,sans-serif;font-size:26px;font-weight:800;
                    background:linear-gradient(135deg,#00d4ff,#7b61ff);
                    -webkit-background-clip:text;-webkit-text-fill-color:transparent;
                    margin-bottom:12px">Ready to Investigate</div>
        <div style="font-size:12px;color:#2e4460;line-height:1.9;margin-bottom:28px">
            Llama 3.1 8B on RTX 4060 · All data stays local<br>
            Ask about any security event in plain language.<br>
            Follow-up queries filter your current results in memory first.
        </div>
    </div>
    """, unsafe_allow_html=True)
    ec = st.columns(2)
    for i, ex in enumerate([
        "Show failed logins yesterday",
        "Brute force attacks this week",
        "Malware detections with report",
        "VPN logins from Russia last 7 days",
    ]):
        with ec[i % 2]:
            if st.button(ex, key=f"ex_{i}", use_container_width=True):
                st.session_state._inject = ex
                st.rerun()

for i, msg in enumerate(st.session_state.messages):
    if msg["role"] == "user":
        with st.chat_message("user", avatar=None):
            st.markdown(msg["content"])
    else:
        with st.chat_message("assistant", avatar=None):
            render_result(msg.get("result", {}), msg_index=i)

# ── Session report generation ──────────────────────────────────────────────────
gen_req = st.session_state.pop("_gen_report", None)
if gen_req:
    title   = gen_req.get("title", "Security Report")
    queries = gen_req["queries"]

    with st.spinner(f"Building report for {len(queries)} quer{'y' if len(queries)==1 else 'ies'}…"):
        try:
            log = st.session_state.pipeline.memory.session_log
            selected_records = []
            for q in queries:
                for rec in log:
                    if rec.natural_query == q["query"] and rec not in selected_records:
                        selected_records.append(rec)
                        break

            if not selected_records:
                st.error("Could not match selected queries to session log.")
            else:
                connector = st.session_state.pipeline.connector
                queries_data = []
                for rec in selected_records:
                    if not rec.dsl:
                        continue
                    result = connector.execute(rec.dsl, allow_widen=True)
                    queries_data.append({
                        "natural_query": rec.natural_query,
                        "hits":          result.get("hits", []),
                        "aggregations":  result.get("aggregations", {}),
                        "narrative":     None,
                        "time_range":    rec.time_range,
                        "total":         result.get("total", 0),
                        "event_type":    rec.intent,
                        "dsl":           rec.dsl,
                    })

                if queries_data:
                    st.session_state._report_preview = {
                        "queries_data": queries_data,
                        "title":        title,
                    }
        except Exception as e:
            st.error(f"Report preparation failed: {e}")

# ── Report preview panel ───────────────────────────────────────────────────────
preview = st.session_state.get("_report_preview")
if preview:
    qd    = preview["queries_data"]
    title = preview["title"]

    from reports.report_builder import _risk_rating, _flag_records, _severity_label

    st.markdown("---")
    st.markdown(f"""
    <div style="background:#080e1c;border:1px solid #1a2a40;border-radius:10px;padding:20px 24px;margin-bottom:16px">
        <div style="font-family:Syne,sans-serif;font-size:20px;font-weight:800;
                    background:linear-gradient(135deg,#00d4ff,#7b61ff);
                    -webkit-background-clip:text;-webkit-text-fill-color:transparent;
                    margin-bottom:4px">{title}</div>
        <div style="font-size:10px;color:#2e4460;font-family:JetBrains Mono,monospace;text-transform:uppercase;letter-spacing:.8px">
            Security Intelligence Report &nbsp;·&nbsp; {datetime.now().strftime('%Y-%m-%d %H:%M')} &nbsp;·&nbsp;
            Risk: <span style="color:{'#ff4757' if _risk_rating(qd)=='CRITICAL' else '#ffa502' if _risk_rating(qd)=='HIGH' else '#00d4ff'}">{_risk_rating(qd)}</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Preview tabs
    pt1, pt2, pt3, pt4 = st.tabs(["Summary", "Event Tables", "Flagged Records", "Recommendations"])

    with pt1:
        total_events = sum(q.get("total", 0) for q in qd)
        st.markdown(f"**{len(qd)} investigations · {total_events:,} total events · Risk: {_risk_rating(qd)}**")
        for i, q in enumerate(qd, 1):
            st.markdown(f"**Investigation {i}: {q['natural_query']}**")
            st.markdown(f"*{q.get('time_range','—')} · {q.get('total',0):,} events*")
            if q.get("narrative"):
                st.markdown(q["narrative"])
            st.divider()

    with pt2:
        for i, q in enumerate(qd, 1):
            hits = q.get("hits", [])
            if not hits:
                continue
            st.markdown(f"**{i}. {q['natural_query']}** — {len(hits)} of {q.get('total',0):,} shown")
            import pandas as pd
            rows = [{
                "Time":        h.get("@timestamp","")[:16],
                "Type":        h.get("event_type",""),
                "Description": h.get("rule",{}).get("description","")[:50],
                "User":        h.get("user",{}).get("name","—") or "—",
                "Src IP":      h.get("data",{}).get("srcip","—") or "—",
                "Severity":    _severity_label(h.get("rule",{}).get("level","")),
            } for h in hits[:20]]
            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

    with pt3:
        all_hits = [h for q in qd for h in q.get("hits", [])]
        flagged  = _flag_records(all_hits)
        if flagged:
            st.markdown(f"**{len(flagged)} record(s) flagged**")
            rows = [{
                "Time":        h.get("@timestamp","")[:16],
                "Type":        h.get("event_type",""),
                "Description": h.get("rule",{}).get("description","")[:40],
                "Src IP":      h.get("data",{}).get("srcip","—") or "—",
                "Severity":    _severity_label(h.get("rule",{}).get("level","")),
                "Reason":      ", ".join(h.get("_flag_reasons",[])),
            } for h in flagged[:20]]
            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
        else:
            st.info("No records flagged.")

    with pt4:
        seen = set(q.get("event_type","default") for q in qd)
        _RECS = {
            "brute_force":          ["Implement account lockout after 5 failed attempts", "Enable geo-blocking", "Deploy rate limiting"],
            "failed_login":         ["Enforce MFA on all accounts", "Audit accounts with repeated failures", "Review password policies"],
            "malware_detection":    ["Isolate affected hosts immediately", "Run full AV/EDR scan", "Preserve forensic images"],
            "vpn_login":            ["Audit VPN access for high-risk countries", "Enforce MFA on VPN", "Alert on concurrent geo sessions"],
            "privilege_escalation": ["Audit sudo/admin access", "Enable PAM solution", "Implement just-in-time access"],
            "data_exfiltration":    ["Block large outbound transfers", "Implement DLP policies", "Review firewall rules"],
            "lateral_movement":     ["Segment the network", "Disable unnecessary SMB/WMI/RDP", "Deploy honeypot accounts"],
            "port_scan":            ["Block scanning source IPs", "Harden exposed services", "Enable IDS/IPS rules"],
        }
        for et in seen:
            recs = _RECS.get(et, ["Review affected systems and apply patches"])
            st.markdown(f"**{et.replace('_',' ').title()}**")
            for r in recs:
                st.markdown(f"- {r}")

    # Export buttons — shown after preview
    st.markdown("---")
    st.markdown('<div style="font-size:11px;color:#2e4460;font-family:JetBrains Mono,monospace;margin-bottom:10px">Files download to your browser\'s default downloads folder.</div>', unsafe_allow_html=True)

    from reports.report_builder import build_pdf_report, build_docx_report
    exp1, exp2, exp3 = st.columns([1, 1, 1])

    with exp1:
        pdf_bytes = build_pdf_report(qd, report_title=title)
        st.download_button(
            "Download PDF",
            data=pdf_bytes,
            file_name=f"siem_report_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf",
            mime="application/pdf",
            use_container_width=True,
            key=f"dl_pdf_{id(qd)}",
        )
    with exp2:
        docx_bytes = build_docx_report(qd, report_title=title)
        st.download_button(
            "Download DOCX",
            data=docx_bytes,
            file_name=f"siem_report_{datetime.now().strftime('%Y%m%d_%H%M')}.docx",
            mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            use_container_width=True,
            key=f"dl_docx_{id(qd)}",
        )
    with exp3:
        if st.button("Close Preview", use_container_width=True):
            st.session_state._report_preview = None
            st.rerun()

    st.markdown("---")

# ── Single chat_input — page-level, sticks to bottom ──────────────────────────
injected   = st.session_state.pop("_inject", None)
user_input = st.chat_input(
    "Ask anything — e.g. 'brute force last 7 days' or 'show brute force out of these'"
) or injected

if user_input:
    # ── Full-search and time-widen confirmation bypass ────────────────────────
    force_full  = st.session_state.get("fresh_search", False)
    allow_widen = False
    display_input = user_input

    if user_input.startswith("__fullsearch__:"):
        actual_query  = user_input[len("__fullsearch__:"):]
        force_full    = True
        display_input = f"(Full index search) {actual_query}"
        user_input    = actual_query

    elif user_input.startswith("__widen__:"):
        actual_query  = user_input[len("__widen__:"):]
        allow_widen   = True
        display_input = f"(Widened to 30 days) {actual_query}"
        user_input    = actual_query

    st.session_state.messages.append({"role": "user", "content": display_input})

    with st.status("Processing…", expanded=True) as status:
        steps_taken = []

        def on_step(msg: str):
            steps_taken.append(msg)
            status.update(label=msg)
            st.write(f"↳ {msg}")

        result = st.session_state.pipeline.run(
            user_input,
            force_full_search=force_full,
            allow_widen=allow_widen,
            on_step=on_step,
        )
        status.update(label="Done", state="complete", expanded=False)

    result["user_input"] = user_input
    st.session_state.messages.append({"role": "assistant", "result": result})

    if result.get("dsl_source") not in ("guard", "pending_confirmation") and result.get("success"):
        st.session_state.query_history.append({
            "query":      display_input,
            "intent":     result.get("classification", {}).get("intent_type", "unknown"),
            "total":      result.get("siem_meta", {}).get("total", 0),
            "time_range": result.get("report", {}).get("metadata", {}).get("time_range", ""),
        })

    st.rerun()