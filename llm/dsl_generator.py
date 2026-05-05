"""
llm/dsl_generator.py

This is the key architectural upgrade over the previous project.

On RTX 4060 with Llama 3.1 8B, we can now ask the LLM to generate
Elasticsearch DSL DIRECTLY from natural language. The model is capable
enough to handle nested bool queries, date math, and aggregations.

The template engine (engine/templates.py) still exists as:
1. A fallback when LLM output is invalid
2. A validator to catch hallucinated field names
3. A fast path for very simple common queries

This gives better coverage of edge cases while maintaining reliability.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from llm.client import ollama

# ── Schema context injected into every DSL generation prompt ──────────────────
# Llama 3.1 8B needs explicit field name guidance to avoid hallucination.

SCHEMA_CONTEXT = """
Available Elasticsearch index: wazuh-alerts-demo

Critical field names (use EXACTLY as written):
  @timestamp          - event timestamp (use for all time filters)
  rule.level          - integer severity 0-15 (>=10 = high, >=14 = critical)
  rule.description    - text description of alert
  rule.groups         - array of category strings
  rule.id             - rule identifier string
  event_type          - event type: failed_login, malware_detection, vpn_login,
                        mfa_event, privilege_escalation, port_scan, brute_force,
                        suspicious_powershell, file_integrity, lateral_movement,
                        data_exfiltration, successful_login
  agent.name          - hostname of the monitored machine
  agent.ip            - IP of monitored machine
  user.name           - username involved in event
  user.domain         - user domain
  data.srcip          - source IP address
  data.dstip          - destination IP address
  data.win.eventdata.subjectUserName - Windows username
  data.vpn.user       - VPN username
  data.vpn.server     - VPN server
  data.vpn.protocol   - VPN protocol
  data.vpn.location   - VPN connection country
  data.mfa.user       - MFA username
  data.mfa.method     - MFA method (TOTP, Push, SMS)
  data.mfa.success    - MFA success boolean
  data.network.bytes_out      - bytes transferred outbound
  data.network.destination_country - destination country
  data.syscheck.path  - modified file path
  data.syscheck.event - file event: modified, added, deleted
  data.audit.command  - command executed
  data.technique      - attack technique name
  geo.country         - source country
  geo.city            - source city

Date math examples:
  now-1d/d to now/d   = yesterday
  now-7d to now       = last 7 days  
  now-30d to now      = last 30 days
  now-1h to now       = last hour
  now/d to now        = today

Rule groups values:
  authentication_failed, authentication_success, malware, attack,
  vpn, mfa, 2fa, privilege_escalation, network_scan, recon,
  brute_force, authentication_failures, powershell, syscheck,
  lateral_movement, data_exfiltration, credential_access
"""

DSL_SYSTEM_PROMPT = f"""You are an expert Elasticsearch query engineer specializing in SIEM security analytics.

Your task: Convert natural language security questions into valid Elasticsearch DSL queries.

{SCHEMA_CONTEXT}

RULES:
1. Always output ONLY valid JSON. No explanation. No markdown. No code blocks.
2. Always include a time range filter on @timestamp in the filter clause
3. Use "filter" clause (not "must") for exact matches and ranges — it's faster
4. Use "must" clause only for full-text search on rule.description
5. Use "terms" (plural) for matching against arrays like rule.groups
6. Use "term" (singular) for exact keyword matches (user.name, agent.name, etc.)
7. For reports/summaries, include "aggs" with relevant aggregations
8. Default time range when not specified: now-24h to now
9. Default size: 50 (use 0 for aggregation-only queries)
10. Always sort by @timestamp descending

Output format:
{{
  "index": "wazuh-alerts-demo",
  "body": {{
    "query": {{ "bool": {{ "must": [], "filter": [], "must_not": [] }} }},
    "size": 50,
    "sort": [{{"@timestamp": {{"order": "desc"}}}}],
    "aggs": {{}}
  }}
}}
"""

# ── Few-shot examples for Llama 3.1 8B ────────────────────────────────────────
# These are essential. Llama 3.1 8B benefits significantly from examples.
# Format: (user_question, correct_dsl_json_string)

FEW_SHOT_EXAMPLES = [
    (
        "show failed login attempts yesterday",
        json.dumps({
            "index": "wazuh-alerts-demo",
            "body": {
                "query": {"bool": {
                    "must": [],
                    "filter": [
                        {"terms": {"rule.groups": ["authentication_failed"]}},
                        {"range": {"@timestamp": {"gte": "now-1d/d", "lte": "now/d"}}}
                    ]
                }},
                "size": 50,
                "sort": [{"@timestamp": {"order": "desc"}}],
                "aggs": {}
            }
        })
    ),
    (
        "what malware was detected this week, generate a report with charts",
        json.dumps({
            "index": "wazuh-alerts-demo",
            "body": {
                "query": {"bool": {
                    "filter": [
                        {"terms": {"rule.groups": ["malware", "attack"]}},
                        {"range": {"rule.level": {"gte": 10}}},
                        {"range": {"@timestamp": {"gte": "now-7d", "lte": "now"}}}
                    ]
                }},
                "size": 50,
                "sort": [{"@timestamp": {"order": "desc"}}],
                "aggs": {
                    "by_type": {"terms": {"field": "rule.description", "size": 10}},
                    "by_agent": {"terms": {"field": "agent.name", "size": 10}},
                    "over_time": {"date_histogram": {"field": "@timestamp", "calendar_interval": "day"}}
                }
            }
        })
    ),
    (
        "show brute force attacks from external IPs last month on SSH service",
        json.dumps({
            "index": "wazuh-alerts-demo",
            "body": {
                "query": {"bool": {
                    "filter": [
                        {"terms": {"rule.groups": ["brute_force", "authentication_failures"]}},
                        {"term": {"data.service": "ssh"}},
                        {"range": {"@timestamp": {"gte": "now-30d", "lte": "now"}}}
                    ]
                }},
                "size": 50,
                "sort": [{"@timestamp": {"order": "desc"}}],
                "aggs": {
                    "by_src_ip": {"terms": {"field": "data.srcip", "size": 10}}
                }
            }
        })
    ),
    (
        "VPN logins from Russia or China last 7 days",
        json.dumps({
            "index": "wazuh-alerts-demo",
            "body": {
                "query": {"bool": {
                    "filter": [
                        {"terms": {"rule.groups": ["vpn"]}},
                        {"terms": {"geo.country": ["Russia", "China"]}},
                        {"range": {"@timestamp": {"gte": "now-7d", "lte": "now"}}}
                    ]
                }},
                "size": 50,
                "sort": [{"@timestamp": {"order": "desc"}}],
                "aggs": {
                    "by_country": {"terms": {"field": "geo.country", "size": 5}},
                    "by_user": {"terms": {"field": "user.name", "size": 10}}
                }
            }
        })
    ),
    (
        "failed MFA attempts this week",
        json.dumps({
            "index": "wazuh-alerts-demo",
            "body": {
                "query": {"bool": {
                    "filter": [
                        {"terms": {"rule.groups": ["mfa", "2fa"]}},
                        {"term": {"data.mfa.success": False}},
                        {"range": {"@timestamp": {"gte": "now-7d", "lte": "now"}}}
                    ]
                }},
                "size": 50,
                "sort": [{"@timestamp": {"order": "desc"}}],
                "aggs": {
                    "by_user": {"terms": {"field": "data.mfa.user", "size": 10}},
                    "by_method": {"terms": {"field": "data.mfa.method", "size": 5}}
                }
            }
        })
    ),
]


def build_few_shot_messages() -> list[dict]:
    """Build the few-shot examples as alternating user/assistant messages."""
    messages = []
    for user_q, assistant_dsl in FEW_SHOT_EXAMPLES:
        messages.append({"role": "user", "content": user_q})
        messages.append({"role": "assistant", "content": assistant_dsl})
    return messages


def generate_dsl(
    user_query: str,
    schema_context: str = "",
    conversation_summary: str = "",
) -> dict | None:
    """
    Use Llama 3.1 8B to generate Elasticsearch DSL from natural language.

    Args:
        user_query:           Natural language security question
        schema_context:       Additional schema fields from RAG (optional)
        conversation_summary: Summary of previous query for context (optional)

    Returns:
        Parsed DSL dict with "index" and "body" keys, or None on failure
    """
    # Build messages with few-shot examples
    messages = build_few_shot_messages()

    # Add context if this is a follow-up
    if conversation_summary:
        messages.append({
            "role": "user",
            "content": f"[CONTEXT: Previous query was about {conversation_summary}. "
                       f"Apply this context to the following query if relevant.]"
        })
        messages.append({
            "role": "assistant",
            "content": "Understood. I will apply the previous query context."
        })

    # Add current query
    messages.append({"role": "user", "content": user_query})

    # Add RAG schema context to system prompt if available
    system = DSL_SYSTEM_PROMPT
    if schema_context:
        system += f"\n\nAdditional relevant fields for this query:\n{schema_context}"

    raw = ollama.chat(
        messages=messages,
        system=system,
        temperature=0.05,    # very low — DSL must be deterministic
        max_tokens=800,
        json_mode=True,
    )

    if raw.startswith("ERROR:"):
        return None

    # Parse and validate
    try:
        # Strip any accidental markdown fences
        clean = raw.replace("```json", "").replace("```", "").strip()
        dsl = json.loads(clean)

        # Basic structure check
        if "body" not in dsl or "query" not in dsl.get("body", {}):
            return None

        # Ensure index is set
        if "index" not in dsl:
            dsl["index"] = "wazuh-alerts-demo"

        return dsl

    except json.JSONDecodeError:
        return None


def generate_narrative(
    intent_description: str,
    results_sample: list[dict],
    total_count: int,
    time_range: str,
    aggregations: dict = None,
) -> str:
    """
    Generate a 3-4 sentence analyst narrative summary using Llama 3.1 8B.
    """
    # Build aggregation summary — handle over_time specially to find peak day
    agg_summary = ""
    if aggregations:
        lines = []
        for agg_name, agg_data in aggregations.items():
            buckets = agg_data.get("buckets", [])
            if not buckets:
                continue

            if agg_name == "over_time":
                # Buckets are chronological — sort by count to find actual peak
                sorted_b = sorted(buckets, key=lambda b: b.get("doc_count", 0), reverse=True)
                peak = sorted_b[0]
                peak_date = peak.get("key_as_string", str(peak.get("key", "?")))
                # Trim to date only (strip time component if present)
                peak_date = peak_date[:10] if len(peak_date) > 10 else peak_date
                total_days = sum(b.get("doc_count", 0) for b in buckets)
                lines.append(
                    f"Timeline: peak activity on {peak_date} "
                    f"({peak.get('doc_count', 0)} events). "
                    f"Top 3 days: "
                    + ", ".join(
                        f"{b.get('key_as_string','?')[:10]} ({b.get('doc_count',0)})"
                        for b in sorted_b[:3]
                    )
                )
            else:
                label = agg_name.replace("by_", "").replace("_", " ").title()
                top = [
                    f"{b.get('key', '?')} ({b.get('doc_count', 0)})"
                    for b in buckets[:3]
                ]
                lines.append(f"Top {label}: {', '.join(top)}")

        agg_summary = "\n".join(lines)

    # Use up to 5 samples, extracting the most useful fields for the narrative
    sample_fields = []
    for hit in results_sample[:5]:
        sample_fields.append({
            "time":        hit.get("@timestamp", ""),
            "type":        hit.get("event_type", ""),
            "description": hit.get("rule", {}).get("description", ""),
            "severity":    hit.get("rule", {}).get("level", ""),
            "user":        hit.get("user", {}).get("name", ""),
            "host":        hit.get("agent", {}).get("name", ""),
            "src_ip":      hit.get("data", {}).get("srcip", ""),
            "country":     hit.get("geo", {}).get("country", ""),
        })

    prompt = f"""You are a senior security analyst writing an executive summary for a SIEM report.

Query: {intent_description}
Time range: {time_range}
Total events found: {total_count}

Aggregation breakdown:
{agg_summary if agg_summary else "No aggregation data available."}

Sample events (most recent first):
{json.dumps(sample_fields, indent=2, default=str)}

Write exactly 3-4 sentences covering:
1. What was found, how many events, and over what time period
2. The most notable or suspicious pattern from the aggregations or samples
3. Specific top offenders: name the actual users, IPs, hosts, or countries from the data
4. A concrete risk assessment and one specific recommended action

Rules:
- Be specific — use actual values from the data, not generic statements
- Plain text only, no bullet points, no markdown, no headers
- Do not start with "I" or refer to yourself"""

    result = ollama.generate(prompt, temperature=0.3, max_tokens=350)
    if result.startswith("ERROR:"):
        return f"Found {total_count} events in {time_range}."
    return result


# classify_intent() has moved to llm/intent_classifier.py
# Import from there: from llm.intent_classifier import classifier


def filter_hits_with_llm(hits: list[dict], follow_up_query: str) -> list[dict] | None:
    """
    Use Llama to filter a list of hits based on a complex follow-up query.

    Used when _filter_in_memory() can't handle the query — null/missing field
    checks, negations, relative comparisons, "not available", "unknown", etc.

    Strips hits to relevant fields before sending to keep token count low.
    With 50 hits × ~300 tokens each = ~15K tokens, fits in Llama's 8K context
    if we extract only the key fields (not the full raw doc).

    Returns:
        Filtered list of hits (subset of input), or None if LLM call failed.
    """
    if not hits:
        return []

    # Strip each hit to the fields most useful for filtering
    # Keeps token count manageable — full docs would overflow context
    stripped = []
    for i, h in enumerate(hits):
        stripped.append({
            "_idx": i,   # keep original index so we can map back
            "event_type":    h.get("event_type", ""),
            "rule_level":    h.get("rule", {}).get("level", ""),
            "rule_desc":     h.get("rule", {}).get("description", ""),
            "user":          h.get("user", {}).get("name", ""),
            "src_ip":        h.get("data", {}).get("srcip", ""),
            "dst_ip":        h.get("data", {}).get("dstip", ""),
            "country":       h.get("geo", {}).get("country", ""),
            "host":          h.get("agent", {}).get("name", ""),
            "service":       h.get("data", {}).get("service", ""),
            "dst_country":   h.get("data", {}).get("network", {}).get("destination_country", ""),
            "technique":     h.get("data", {}).get("technique", ""),
            "bytes_out":     h.get("data", {}).get("network", {}).get("bytes_out", ""),
            "timestamp":     h.get("@timestamp", "")[:10],
        })

    prompt = f"""You are a security data analyst. Filter this list of security events.

User request: "{follow_up_query}"

Events (JSON array, each has an _idx field):
{json.dumps(stripped, indent=2)}

Rules:
- Return ONLY a JSON array of _idx values for events that match the request
- Empty values ("", null, None) count as "not available" / "unknown" / "missing"
- For "not available" or "unknown" — include events where that field is empty or null
- For negations like "not from X" — exclude events where field equals X
- Be inclusive — if ambiguous, include the event
- Return ONLY the JSON array, nothing else. Example: [0, 3, 7, 12]"""

    raw = ollama.generate(prompt, temperature=0.0, max_tokens=500)

    if raw.startswith("ERROR:"):
        return None

    try:
        clean = raw.replace("```json", "").replace("```", "").strip()
        # Extract just the array part if there's extra text
        import re
        match = re.search(r'\[[\d,\s]*\]', clean)
        if not match:
            return None
        indices = json.loads(match.group())
        if not isinstance(indices, list):
            return None
        # Map indices back to original hits
        valid = set(range(len(hits)))
        return [hits[i] for i in indices if i in valid]
    except (json.JSONDecodeError, IndexError):
        return None


def refine_dsl(previous_dsl: dict, follow_up_query: str) -> dict | None:
    """
    Modify an existing DSL based on a follow-up query.

    Takes the ACTUAL previous DSL and asks the LLM to modify it surgically.
    Key rule: when the follow-up changes event TYPE (e.g. "show brute force"),
    REPLACE the existing rule.groups filter rather than stacking a second one.
    Stacking creates an AND condition that can never be satisfied when the two
    event types don't share rule.groups values.

    Returns modified DSL dict, or None on failure (pipeline falls back to generate_dsl).
    """
    prev_body = json.dumps(previous_dsl.get("body", {}), indent=2)

    system = """You are an Elasticsearch DSL editor for a SIEM security assistant.

You receive an EXISTING DSL body and a follow-up instruction.
Return the COMPLETE modified DSL with "index" and "body" keys.

CRITICAL RULES:
1. Output ONLY valid JSON. No explanation. No markdown. No code fences.
2. Always include "index": "wazuh-alerts-demo" at the top level.
3. Never change the @timestamp range unless explicitly asked.
4. Keep size, sort, and aggs unless the follow-up changes them.

FILTER RULES — read carefully:
- "show X out of these" where X is an EVENT TYPE (brute force, malware, VPN, MFA, etc.):
    → REPLACE the existing rule.groups filter with the new event type's groups.
    → Do NOT stack two rule.groups filters — that creates an impossible AND condition.
    → brute force  → ["brute_force", "authentication_failures"]
    → failed login → ["authentication_failed", "win_authentication"]
    → malware      → ["malware", "attack"]
    → vpn          → ["vpn", "authentication", "network"]
    → mfa          → ["mfa", "authentication", "2fa"]
    → powershell   → ["attack", "powershell"]
    → lateral      → ["lateral_movement", "attack"]
    → exfiltration → ["data_exfiltration", "attack"]
- "filter by user X" / "only user X"  → ADD {"term": {"user.name": "X"}}
- "filter by IP X"                     → ADD {"term": {"data.srcip": "X"}}
- "filter by host X"                   → ADD {"term": {"agent.name": "X"}}
- "filter by country X"                → ADD {"term": {"geo.country": "X"}}
- "only high severity"     → ADD {"range": {"rule.level": {"gte": 10}}}
- "only critical severity" → ADD {"range": {"rule.level": {"gte": 14}}}
- "critical"               → ADD {"range": {"rule.level": {"gte": 14}}}
- "exclude X" / "remove X" → REMOVE the matching filter clause"""

    messages = [
        # Example 1: event type change — REPLACE rule.groups
        {
            "role": "user",
            "content": (
                "Previous DSL body:\n"
                '{"query":{"bool":{"filter":['
                '{"terms":{"rule.groups":["authentication_failed","win_authentication"]}},'
                '{"range":{"@timestamp":{"gte":"now-30d","lte":"now"}}}]}},'
                '"size":50,"sort":[{"@timestamp":{"order":"desc"}}],'
                '"aggs":{"by_user":{"terms":{"field":"user.name","size":10}},'
                '"by_src_ip":{"terms":{"field":"data.srcip","size":10}}}}\n\n'
                "Follow-up: show brute force out of these"
            )
        },
        {
            "role": "assistant",
            "content": json.dumps({
                "index": "wazuh-alerts-demo",
                "body": {
                    "query": {"bool": {"filter": [
                        {"terms": {"rule.groups": ["brute_force", "authentication_failures"]}},
                        {"range": {"@timestamp": {"gte": "now-30d", "lte": "now"}}}
                    ]}},
                    "size": 50,
                    "sort": [{"@timestamp": {"order": "desc"}}],
                    "aggs": {
                        "by_user":   {"terms": {"field": "user.name",  "size": 10}},
                        "by_src_ip": {"terms": {"field": "data.srcip", "size": 10}}
                    }
                }
            })
        },
        # Example 2: add user filter — KEEP rule.groups, ADD term
        {
            "role": "user",
            "content": (
                "Previous DSL body:\n"
                '{"query":{"bool":{"filter":['
                '{"terms":{"rule.groups":["vpn","authentication","network"]}},'
                '{"range":{"@timestamp":{"gte":"now-7d","lte":"now"}}}]}},'
                '"size":50,"sort":[{"@timestamp":{"order":"desc"}}],'
                '"aggs":{"by_user":{"terms":{"field":"user.name","size":10}}}}\n\n'
                "Follow-up: filter those by user alice"
            )
        },
        {
            "role": "assistant",
            "content": json.dumps({
                "index": "wazuh-alerts-demo",
                "body": {
                    "query": {"bool": {"filter": [
                        {"terms": {"rule.groups": ["vpn", "authentication", "network"]}},
                        {"term": {"user.name": "alice"}},
                        {"range": {"@timestamp": {"gte": "now-7d", "lte": "now"}}}
                    ]}},
                    "size": 50,
                    "sort": [{"@timestamp": {"order": "desc"}}],
                    "aggs": {"by_user": {"terms": {"field": "user.name", "size": 10}}}
                }
            })
        },
        # Example 3: add severity filter
        {
            "role": "user",
            "content": (
                "Previous DSL body:\n"
                '{"query":{"bool":{"filter":['
                '{"terms":{"rule.groups":["brute_force","authentication_failures"]}},'
                '{"range":{"@timestamp":{"gte":"now-7d","lte":"now"}}}]}},'
                '"size":50,"sort":[{"@timestamp":{"order":"desc"}}],'
                '"aggs":{"by_src_ip":{"terms":{"field":"data.srcip","size":10}}}}\n\n'
                "Follow-up: only show critical severity ones"
            )
        },
        {
            "role": "assistant",
            "content": json.dumps({
                "index": "wazuh-alerts-demo",
                "body": {
                    "query": {"bool": {"filter": [
                        {"terms": {"rule.groups": ["brute_force", "authentication_failures"]}},
                        {"range": {"rule.level": {"gte": 14}}},
                        {"range": {"@timestamp": {"gte": "now-7d", "lte": "now"}}}
                    ]}},
                    "size": 50,
                    "sort": [{"@timestamp": {"order": "desc"}}],
                    "aggs": {"by_src_ip": {"terms": {"field": "data.srcip", "size": 10}}}
                }
            })
        },
        # Actual query
        {
            "role": "user",
            "content": f"Previous DSL body:\n{prev_body}\n\nFollow-up: {follow_up_query}"
        },
    ]

    raw = ollama.chat(
        messages=messages,
        system=system,
        temperature=0.0,
        max_tokens=900,
        json_mode=True,
    )

    if raw.startswith("ERROR:"):
        return None

    try:
        clean = raw.replace("```json", "").replace("```", "").strip()
        dsl = json.loads(clean)

        # Accept body-only response — LLM sometimes omits the index key
        if "body" not in dsl and "query" in dsl:
            dsl = {"index": "wazuh-alerts-demo", "body": dsl}

        if "body" not in dsl or "query" not in dsl.get("body", {}):
            return None

        if "index" not in dsl:
            dsl["index"] = "wazuh-alerts-demo"

        # Ensure size is never 0
        if dsl["body"].get("size", 50) == 0:
            dsl["body"]["size"] = 50

        return dsl

    except json.JSONDecodeError:
        return None