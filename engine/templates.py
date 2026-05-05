"""
engine/templates.py

Template-based query builder. On RTX 4060 + Llama 3.1 8B, this serves as:

1. FALLBACK — when LLM DSL generation fails or produces invalid JSON
2. VALIDATOR — checks LLM output field names against live mappings  
3. FAST PATH — simple common queries (optional, can skip LLM entirely)

The hybrid approach in pipeline.py:
  - LLM generates DSL first (handles edge cases, complex conditions)
  - Validator checks the output
  - Template engine rebuilds if validation fails
"""

import json
import os
import re
import sys
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.settings import settings

# ── Date math ─────────────────────────────────────────────────────────────────

DATE_MATH = {
    "today": ("now/d", "now"),
    "right now": ("now-1h", "now"),
    "past hour": ("now-1h", "now"),
    "last hour": ("now-1h", "now"),
    "past 24 hours": ("now-24h", "now"),
    "last 24 hours": ("now-24h", "now"),
    "yesterday": ("now-1d/d", "now/d"),
    "last week": ("now-7d", "now"),
    "past week": ("now-7d", "now"),
    "this week": ("now/w", "now"),
    "last month": ("now-30d", "now"),
    "past month": ("now-30d", "now"),
    "this month": ("now/M", "now"),
    "last 3 days": ("now-3d", "now"),
    "last 7 days": ("now-7d", "now"),
    "last 14 days": ("now-14d", "now"),
    "last 30 days": ("now-30d", "now"),
    "last 90 days": ("now-90d", "now"),
    "default": ("now-24h", "now"),
}

# ── Intent → Template mapping ──────────────────────────────────────────────────

TEMPLATES = {
    "failed_logins": {
        "filter": [{"terms": {"rule.groups": ["authentication_failed", "win_authentication"]}}],
        "aggs": {
            "by_user": {"terms": {"field": "user.name", "size": 10}},
            "by_src_ip": {"terms": {"field": "data.srcip", "size": 10}},
            "over_time": {"date_histogram": {"field": "@timestamp", "calendar_interval": "hour"}},
        },
    },
    "malware_detection": {
        "filter": [
            {"terms": {"rule.groups": ["malware", "attack"]}},
            {"range": {"rule.level": {"gte": 10}}},
        ],
        "aggs": {
            "by_rule": {"terms": {"field": "rule.description", "size": 10}},
            "by_agent": {"terms": {"field": "agent.name", "size": 10}},
            "over_time": {"date_histogram": {"field": "@timestamp", "calendar_interval": "day"}},
        },
    },
    "vpn_activity": {
        "filter": [{"terms": {"rule.groups": ["vpn", "network"]}}],
        "aggs": {
            "by_user": {"terms": {"field": "user.name", "size": 10}},
            "by_country": {"terms": {"field": "geo.country", "size": 10}},
            "by_server": {"terms": {"field": "data.vpn.server", "size": 5}},
        },
    },
    "mfa_events": {
        "filter": [{"terms": {"rule.groups": ["mfa", "2fa"]}}],
        "aggs": {
            "by_user": {"terms": {"field": "data.mfa.user", "size": 10}},
            "by_method": {"terms": {"field": "data.mfa.method", "size": 5}},
        },
    },
    "brute_force": {
        "filter": [{"terms": {"rule.groups": ["brute_force", "authentication_failures"]}}],
        "aggs": {
            "by_src_ip": {"terms": {"field": "data.srcip", "size": 10}},
            "by_target": {"terms": {"field": "data.target_user", "size": 10}},
        },
    },
    "privilege_escalation": {
        "filter": [
            {"terms": {"rule.groups": ["privilege_escalation"]}},
            {"range": {"rule.level": {"gte": 10}}},
        ],
        "aggs": {
            "by_user": {"terms": {"field": "user.name", "size": 10}},
            "by_host": {"terms": {"field": "agent.name", "size": 10}},
        },
    },
    "port_scan": {
        "filter": [{"terms": {"rule.groups": ["network_scan", "recon"]}}],
        "aggs": {
            "by_src_ip": {"terms": {"field": "data.srcip", "size": 10}},
        },
    },
    "suspicious_powershell": {
        "filter": [
            {"terms": {"rule.groups": ["powershell", "attack"]}},
            {"range": {"rule.level": {"gte": 10}}},
        ],
        "aggs": {
            "by_host": {"terms": {"field": "agent.name", "size": 10}},
        },
    },
    "file_integrity": {
        "filter": [{"terms": {"rule.groups": ["syscheck"]}}],
        "aggs": {
            "by_event": {"terms": {"field": "data.syscheck.event", "size": 5}},
            "by_host": {"terms": {"field": "agent.name", "size": 10}},
        },
    },
    "lateral_movement": {
        "filter": [
            {"terms": {"rule.groups": ["lateral_movement"]}},
            {"range": {"rule.level": {"gte": 12}}},
        ],
        "aggs": {
            "by_technique": {"terms": {"field": "data.technique", "size": 10}},
        },
    },
    "data_exfiltration": {
        "filter": [
            {"terms": {"rule.groups": ["data_exfiltration"]}},
            {"range": {"rule.level": {"gte": 11}}},
        ],
        "aggs": {
            "by_destination": {"terms": {"field": "data.network.destination_country", "size": 10}},
        },
    },
    "high_severity": {
        "filter": [{"range": {"rule.level": {"gte": 12}}}],
        "aggs": {
            "by_category": {"terms": {"field": "event_type", "size": 12}},
            "by_agent": {"terms": {"field": "agent.name", "size": 10}},
            "severity_dist": {"terms": {"field": "rule.level", "size": 15}},
        },
    },
    "all_events": {
        "filter": [],
        "aggs": {
            "by_type": {"terms": {"field": "event_type", "size": 15}},
            "by_severity": {"terms": {"field": "rule.level", "size": 15}},
            "over_time": {"date_histogram": {"field": "@timestamp", "calendar_interval": "hour"}},
        },
    },
}

# ── Optional filter → field mapping ───────────────────────────────────────────

FILTER_FIELDS = {
    "user":        "user.name",
    "src_ip":      "data.srcip",
    "dst_ip":      "data.dstip",
    "host":        "agent.name",
    "agent":       "agent.name",
    "country":     "geo.country",
    "city":        "geo.city",
    "service":     "data.service",
    "file":        "data.syscheck.path",
    "technique":   "data.technique",
    "vpn_server":  "data.vpn.server",
    "mfa_method":  "data.mfa.method",
}


def parse_time_range(time_str: str) -> tuple[str, str]:
    """Convert natural language time expression to ES date math tuple."""
    if not time_str:
        return DATE_MATH["default"]
    normalized = time_str.lower().strip()
    if normalized in DATE_MATH:
        return DATE_MATH[normalized]
    # Dynamic: "last N days/hours/weeks"
    match = re.match(r"last\s+(\d+)\s+(hour|hours|day|days|week|weeks|month|months)", normalized)
    if match:
        n, unit = int(match.group(1)), match.group(2).rstrip("s")
        unit_char = {"hour": "h", "day": "d", "week": "w", "month": "M"}[unit]
        return (f"now-{n}{unit_char}", "now")
    return DATE_MATH["default"]


def build_from_template(
    intent: str,
    filters: dict,
    time_range: str,
    include_aggs: bool = False,
    max_results: int = 50,
) -> dict:
    """
    Build a DSL query from templates. Used as fallback when LLM DSL fails.
    """
    template = TEMPLATES.get(intent, TEMPLATES["high_severity"])
    gte, lte = parse_time_range(time_range)

    filter_clauses = [*template["filter"],
                      {"range": {"@timestamp": {"gte": gte, "lte": lte}}}]

    # Apply optional filters
    for key, value in filters.items():
        if value and key in FILTER_FIELDS:
            filter_clauses.append({"term": {FILTER_FIELDS[key]: str(value)}})

    body = {
        "query": {"bool": {"filter": filter_clauses, "must": [], "must_not": []}},
        "size": max_results,
        "sort": [{"@timestamp": {"order": "desc"}}],
    }

    if include_aggs:
        body["aggs"] = template.get("aggs", {})

    return {"index": settings.es_index, "body": body}


# ── Validator ──────────────────────────────────────────────────────────────────

# Fields that definitely exist in our generated data
KNOWN_VALID_FIELDS = {
    "@timestamp", "timestamp", "event_type", "rule.level", "rule.description",
    "rule.groups", "rule.id", "agent.name", "agent.ip", "user.name", "user.domain",
    "data.srcip", "data.dstip", "data.service", "data.technique",
    "data.win.eventdata.subjectUserName", "data.vpn.user", "data.vpn.server",
    "data.vpn.protocol", "data.vpn.location", "data.mfa.user", "data.mfa.method",
    "data.mfa.success", "data.network.bytes_out", "data.network.destination_country",
    "data.syscheck.path", "data.syscheck.event", "data.audit.command",
    "data.network.protocol", "data.target_user", "data.attempts",
    "geo.country", "geo.city", "geo.country_code", "geo.coordinates",
    "network.direction", "location",
}


def validate_dsl(dsl: dict) -> dict:
    """
    Validate LLM-generated DSL before execution.

    Returns:
        {"valid": bool, "errors": list, "warnings": list}
    """
    errors, warnings = [], []

    if "index" not in dsl:
        errors.append("Missing 'index' key")
    if "body" not in dsl:
        errors.append("Missing 'body' key")
        return {"valid": False, "errors": errors, "warnings": warnings}

    body = dsl["body"]
    if "query" not in body:
        errors.append("Missing 'query' in body")

    # Check size
    if body.get("size", 50) > 500:
        warnings.append("Size > 500 may cause performance issues. Capped at 500.")
        body["size"] = 500

    # Extract and check field names
    fields_used = _extract_fields(body)
    for field in fields_used:
        if field not in KNOWN_VALID_FIELDS and not field.startswith("_"):
            warnings.append(f"Field '{field}' may not exist — verify in Kibana")

    return {"valid": len(errors) == 0, "errors": errors, "warnings": warnings}


def _extract_fields(obj: dict, result: set = None) -> set:
    """
    Recursively extract field names from a DSL query.

    Handles two distinct uses of "terms" in DSL:
      Filter clause:  {"terms": {"geo.country": ["Russia", "China"]}}  → field = "geo.country"
      Agg bucket:     {"terms": {"field": "geo.country", "size": 10}}  → field = "geo.country"
    Without this distinction, agg config keys like "field" and "size" get
    incorrectly flagged as unknown field names.
    """
    if result is None:
        result = set()
    if not isinstance(obj, dict):
        return result

    # Keys where every dict key IS a field name (filter context)
    filter_field_keys = {"term", "match", "range", "wildcard", "prefix"}

    for key, value in obj.items():
        if key in filter_field_keys and isinstance(value, dict):
            result.update(value.keys())

        elif key == "terms" and isinstance(value, dict):
            if "field" in value:
                # Aggregation terms bucket — the value of "field" is the field name
                field_val = value.get("field", "")
                if field_val:
                    result.add(field_val)
            else:
                # Filter terms clause — the keys ARE field names
                result.update(k for k in value.keys() if k != "boost")

        elif isinstance(value, (dict, list)):
            items = value.values() if isinstance(value, dict) else value
            for item in items:
                if isinstance(item, dict):
                    _extract_fields(item, result)

    return result