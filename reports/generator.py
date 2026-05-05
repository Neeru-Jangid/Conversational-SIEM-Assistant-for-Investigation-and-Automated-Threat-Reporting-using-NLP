"""
reports/generator.py

Formats raw SIEM results into:
  1. Pandas DataFrame (table)
  2. Plotly chart (aggregation visualization)
  3. KQL equivalent (for analysts who prefer it)
  4. Narrative summary (from Llama 3.1 8B)
"""

import json
import os
import sys
from datetime import datetime
#from typing import Optional

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ── Column display config ──────────────────────────────────────────────────────

def _get(doc: dict, path: str, default="—") -> str:
    """Safely retrieve nested field using dot notation."""
    keys = path.split(".")
    cur = doc
    for k in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(k, default)
        if cur == default:
            return default
    if isinstance(cur, list):
        return ", ".join(str(v) for v in cur[:3])
    return str(cur) if cur is not None else default


DISPLAY_COLUMNS = {
    "default": [
        ("Time", "@timestamp"),
        ("Type", "event_type"),
        ("Description", "rule.description"),
        ("Host", "agent.name"),
        ("Severity", "rule.level"),
    ],
    "failed_login": [
        ("Time", "@timestamp"), ("User", "user.name"),
        ("Source IP", "data.srcip"), ("Host", "agent.name"),
        ("Description", "rule.description"), ("Severity", "rule.level"),
    ],
    "malware_detection": [
        ("Time", "@timestamp"), ("Rule", "rule.description"),
        ("Agent", "agent.name"), ("File", "data.file.path"),
        ("Severity", "rule.level"),
    ],
    "vpn_login": [
        ("Time", "@timestamp"), ("User", "user.name"),
        ("Source IP", "data.srcip"), ("Country", "geo.country"),
        ("VPN Server", "data.vpn.server"), ("Description", "rule.description"),
    ],
    "mfa_event": [
        ("Time", "@timestamp"), ("User", "data.mfa.user"),
        ("Method", "data.mfa.method"), ("Success", "data.mfa.success"),
        ("Source IP", "data.srcip"), ("Severity", "rule.level"),
    ],
    "brute_force": [
        ("Time", "@timestamp"), ("Source IP", "data.srcip"),
        ("Target", "data.target_user"), ("Service", "data.service"),
        ("Attempts", "data.attempts"), ("Host", "agent.name"),
    ],
    "privilege_escalation": [
        ("Time", "@timestamp"), ("User", "user.name"),
        ("Host", "agent.name"), ("Command", "data.audit.command"),
        ("Description", "rule.description"), ("Severity", "rule.level"),
    ],
    "suspicious_powershell": [
        ("Time", "@timestamp"), ("Host", "agent.name"),
        ("Command", "data.process.command_line"),
        ("Parent", "data.process.parent"), ("Severity", "rule.level"),
    ],
    "file_integrity": [
        ("Time", "@timestamp"), ("File", "data.syscheck.path"),
        ("Event", "data.syscheck.event"), ("Host", "agent.name"),
        ("Severity", "rule.level"),
    ],
    "lateral_movement": [
        ("Time", "@timestamp"), ("Source IP", "data.srcip"),
        ("Destination IP", "data.dstip"), ("Technique", "data.technique"),
        ("User", "user.name"), ("Severity", "rule.level"),
    ],
    "data_exfiltration": [
        ("Time", "@timestamp"), ("Source IP", "data.srcip"),
        ("Destination IP", "data.dstip"),
        ("Destination Country", "data.network.destination_country"),
        ("Protocol", "data.network.protocol"), ("Severity", "rule.level"),
    ],
    "port_scan": [
        ("Time", "@timestamp"), ("Source IP", "data.srcip"),
        ("Destination IP", "data.dstip"), ("Host", "agent.name"),
        ("Description", "rule.description"),
    ],
}

SEVERITY_LABELS = {
    range(0, 5): "🟢 LOW",
    range(5, 10): "🟡 MEDIUM",
    range(10, 13): "🟠 HIGH",
    range(13, 16): "🔴 CRITICAL",
}


def _severity_label(level) -> str:
    try:
        lvl = int(level)
        for r, label in SEVERITY_LABELS.items():
            if lvl in r:
                return f"{label} ({lvl})"
    except Exception:
        pass
    return str(level)


def build_dataframe(hits: list[dict], event_type: str = "default") -> pd.DataFrame:
    """Build a clean DataFrame from ES hits using display column config."""
    if not hits:
        return pd.DataFrame()

    columns = DISPLAY_COLUMNS.get(event_type, DISPLAY_COLUMNS["default"])
    rows = []
    for hit in hits:
        row = {}
        for display_name, field_path in columns:
            value = _get(hit, field_path)
            if display_name == "Time" and value != "—":
                try:
                    value = datetime.fromisoformat(
                        value.replace("Z", "+00:00")
                    ).strftime("%Y-%m-%d %H:%M")
                except Exception:
                    pass
            if display_name == "Severity":
                value = _severity_label(value)
            row[display_name] = value
        rows.append(row)
    return pd.DataFrame(rows)


def build_chart(aggregations: dict, event_type: str, time_range: str):
    """Build a Plotly figure from ES aggregations."""
    if not aggregations:
        return None

    DARK = "#0e1420"
    FONT_COLOR = "#e8edf5"

    # Try timeline first for reports
    if "over_time" in aggregations:
        buckets = aggregations["over_time"].get("buckets", [])
        if buckets:
            times = [b.get("key_as_string", str(b["key"])) for b in buckets]
            counts = [b["doc_count"] for b in buckets]
            fig = px.area(
                x=times, y=counts,
                title=f"Event Timeline — {time_range}",
                labels={"x": "Time", "y": "Events"},
                color_discrete_sequence=["#00d4ff"],
            )
            fig.update_layout(
                plot_bgcolor=DARK, paper_bgcolor=DARK,
                font_color=FONT_COLOR, margin=dict(l=20, r=20, t=40, b=20),
                showlegend=False,
            )
            return fig

    # Bar chart for categorical aggregations
    priority = ["by_user", "by_src_ip", "by_rule", "by_agent",
                "by_type", "by_country", "by_category", "severity_dist",
                "by_technique", "by_method", "by_server", "by_destination"]

    for agg_name in priority:
        if agg_name not in aggregations:
            continue
        buckets = aggregations[agg_name].get("buckets", [])
        if not buckets:
            continue

        labels = [str(b["key"])[:30] for b in buckets[:12]]
        values = [b["doc_count"] for b in buckets[:12]]

        title = agg_name.replace("by_", "").replace("_", " ").title()
        fig = px.bar(
            x=values, y=labels,
            orientation="h",
            title=f"{title} — {time_range}",
            labels={"x": "Count", "y": title},
            color=values,
            color_continuous_scale=["#1e2a3d", "#00d4ff"],
        )
        fig.update_layout(
            plot_bgcolor=DARK, paper_bgcolor=DARK,
            font_color=FONT_COLOR, margin=dict(l=20, r=20, t=40, b=20),
            showlegend=False, coloraxis_showscale=False,
            yaxis={"categoryorder": "total ascending"},
        )
        return fig

    return None


def dsl_to_kql(dsl: dict) -> str:
    """
    Convert a DSL query body to approximate KQL equivalent.
    Not 100% faithful — useful for analysts who prefer KQL.
    """
    try:
        body = dsl.get("body", {})
        bool_q = body.get("query", {}).get("bool", {})
        clauses = bool_q.get("filter", []) + bool_q.get("must", [])

        kql_parts = []
        for clause in clauses:
            if "term" in clause:
                for field, value in clause["term"].items():
                    if field != "@timestamp":
                        kql_parts.append(f'{field}: "{value}"')
            elif "terms" in clause:
                for field, values in clause["terms"].items():
                    if field != "@timestamp":
                        kql_parts.append(f'{field}: ({" OR ".join(f"{v}" for v in values)})')
            elif "range" in clause:
                for field, bounds in clause["range"].items():
                    if field == "@timestamp":
                        gte = bounds.get("gte", "")
                        lte = bounds.get("lte", "now")
                        kql_parts.append(f'@timestamp >= "{gte}" and @timestamp <= "{lte}"')
                    else:
                        if "gte" in bounds:
                            kql_parts.append(f"{field} >= {bounds['gte']}")
            elif "match" in clause:
                for field, value in clause["match"].items():
                    kql_parts.append(f'{field}: "{value}"')

        return " and\n".join(kql_parts) if kql_parts else "* (match all)"
    except Exception:
        return "KQL conversion unavailable"


def format_report(
    hits: list[dict],
    aggregations: dict,
    event_type: str,
    time_range: str,
    total: int,
    narrative: str,
    dsl: dict = None,
) -> dict:
    """
    Assemble the full formatted report.

    Returns:
        Dict with: dataframe, chart, narrative, kql, metadata
    """
    # Determine best event type for column selection
    if not event_type or event_type not in DISPLAY_COLUMNS:
        # Infer from hits if possible
        if hits:
            event_type = hits[0].get("event_type", "default")

    df = build_dataframe(hits, event_type)
    chart = build_chart(aggregations, event_type, time_range)
    kql = dsl_to_kql(dsl) if dsl else ""

    return {
        "dataframe": df,
        "chart": chart,
        "narrative": narrative,
        "kql": kql,
        "metadata": {
            "event_type": event_type,
            "time_range": time_range,
            "total_found": total,
            "showing": len(hits),
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        },
    }
