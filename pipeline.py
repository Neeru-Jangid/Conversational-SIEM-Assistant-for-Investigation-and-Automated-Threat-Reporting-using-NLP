"""
pipeline.py

Main orchestrator. On RTX 4060 + Llama 3.1 8B, runs in HYBRID mode:

  1. IntentClassifier — single LLM call handles ALL routing:
       · Non-SIEM (greeting / thanks / help / OOS) → instant guard response
       · SIEM query → core_query extracted, report_requested, event_type_hint
  2. RAG — retrieve relevant schema fields for DSL generation
  3. Llama 3.1 8B generates DSL from core_query (not raw user input)
  4. Validator checks field names and structure
  5. If invalid → template engine rebuilds using event_type_hint
  6. Execute against SIEM with retry/widening logic
  7. Format results as table + chart + narrative

This is a meaningful upgrade over the template-only v1 approach.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config.settings import settings
from memory.context import ConversationMemory
from llm.intent_classifier import classifier
from llm.dsl_generator import generate_dsl, generate_narrative, refine_dsl, filter_hits_with_llm
from rag.store import retrieve_fields
from engine.templates import build_from_template, validate_dsl
from siem.connector import SIEMConnector
from reports.generator import format_report


# ── In-memory follow-up filter ─────────────────────────────────────────────────

def _build_no_match_explanation(
    core_query: str,
    classification,
    stored_hits: list,
    stored_facets: dict,
) -> str:
    """
    Build a specific, data-aware explanation for why in-memory filter returned
    no results. Uses facets to tell the user exactly what IS available vs what
    they asked for — like a real analyst would.
    """
    entities  = classification.entities or {}
    hint      = classification.event_type_hint or "all_events"
    n         = len(stored_hits)
    lines     = []

    _HINT_TO_EVENT_TYPES = {
        "failed_logins":         ["failed_login"],
        "malware_detection":     ["malware_detection"],
        "vpn_activity":          ["vpn_login"],
        "mfa_events":            ["mfa_event"],
        "brute_force":           ["brute_force"],
        "privilege_escalation":  ["privilege_escalation"],
        "port_scan":             ["port_scan"],
        "suspicious_powershell": ["suspicious_powershell"],
        "file_integrity":        ["file_integrity"],
        "lateral_movement":      ["lateral_movement"],
        "data_exfiltration":     ["data_exfiltration"],
    }

    # Severity check — most common case
    severity_min = entities.get("severity_min")
    if hint == "high_severity" and severity_min is None:
        severity_min = 10
    if severity_min is not None:
        available_levels = sorted(stored_facets.get("severity_levels", []), reverse=True)
        max_level = available_levels[0] if available_levels else 0
        if max_level < severity_min:
            label = "critical" if severity_min >= 14 else "high"
            lines.append(
                f"None of the {n} cached results meet {label} severity "
                f"(level ≥ {severity_min}). Highest level in cache: {max_level}."
            )

    # Event type check
    event_types = _HINT_TO_EVENT_TYPES.get(hint, [])
    if event_types:
        available_et = stored_facets.get("event_types", [])
        missing = [et for et in event_types if et not in available_et]
        if missing:
            lines.append(
                f"Event type '{hint.replace('_', ' ')}' not found in cache. "
                f"Cache contains: {', '.join(available_et) or 'unknown'}."
            )

    # Service check
    services = [s.lower() for s in entities.get("services", []) if s]
    if services:
        available_svc = stored_facets.get("services", [])
        missing_svc = [s for s in services if s not in available_svc]
        if missing_svc:
            lines.append(
                f"Service '{', '.join(missing_svc)}' not in cache. "
                f"Services found: {', '.join(available_svc) or 'none'}."
            )

    # Country check
    countries = [c.lower() for c in entities.get("countries", []) if c]
    if countries:
        available_c = [c.lower() for c in stored_facets.get("countries", [])]
        missing_c = [c for c in countries if c not in available_c]
        if missing_c:
            lines.append(
                f"Country '{', '.join(missing_c)}' not in cache. "
                f"Countries found: {', '.join(stored_facets.get('countries', [])[:5]) or 'none'}."
            )

    # User check
    users = [u.lower() for u in entities.get("users", []) if u]
    if users:
        available_u = [u.lower() for u in stored_facets.get("users", [])]
        missing_u = [u for u in users if u not in available_u]
        if missing_u:
            lines.append(
                f"User '{', '.join(missing_u)}' not in cache. "
                f"Users found: {', '.join(stored_facets.get('users', [])[:5]) or 'none'}."
            )

    if lines:
        explanation = " ".join(lines)
    else:
        explanation = f"No matches for '{core_query}' in the {n} cached results."

    return f"{explanation} Search the full index instead?"


def _filter_in_memory(hits: list[dict], classification, facets: dict) -> list[dict]:
    """
    Filter already-retrieved hits using classifier output validated against
    actual facet values from the data.

    facets: dict from QueryState.last_facets — the ground truth of what
            values exist in the cached hits. Entity values from the classifier
            are cross-checked against this before filtering so we never filter
            on values that don't exist in the data.

    Returns:
        Filtered list, or empty list to trigger confirmation flow.
    """
    if not hits:
        return []

    _HINT_TO_EVENT_TYPES = {
        "failed_logins":         ["failed_login"],
        "malware_detection":     ["malware_detection"],
        "vpn_activity":          ["vpn_login"],
        "mfa_events":            ["mfa_event"],
        "brute_force":           ["brute_force"],
        "privilege_escalation":  ["privilege_escalation"],
        "port_scan":             ["port_scan"],
        "suspicious_powershell": ["suspicious_powershell"],
        "file_integrity":        ["file_integrity"],
        "lateral_movement":      ["lateral_movement"],
        "data_exfiltration":     ["data_exfiltration"],
        "high_severity":         [],
        "all_events":            [],
    }

    hint        = classification.event_type_hint or "all_events"
    entities    = classification.entities or {}
    event_types = _HINT_TO_EVENT_TYPES.get(hint, [])

    # Cross-check classifier entity values against actual facet values
    # Only keep values that genuinely exist in the cached hits
    available_event_types = set(facets.get("event_types", []))
    available_services    = set(facets.get("services", []))
    available_users       = set(u.lower() for u in facets.get("users", []))
    available_countries   = set(c.lower() for c in facets.get("countries", []))
    available_hosts       = set(h.lower() for h in facets.get("hosts", []))
    available_ips         = set(facets.get("src_ips", []))
    available_techniques  = set(t.lower() for t in facets.get("techniques", []))

    # Filter event_types to only those present in data
    event_types = [et for et in event_types if et in available_event_types]

    # Entity values from classifier — validated against facets
    users      = [u.lower() for u in entities.get("users", [])
                  if u and u.lower() in available_users]
    ips        = [ip for ip in entities.get("ips", [])
                  if ip and ip in available_ips]
    countries  = [c.lower() for c in entities.get("countries", [])
                  if c and c.lower() in available_countries]
    hosts      = [h.lower() for h in entities.get("hosts", [])
                  if h and h.lower() in available_hosts]
    services   = [s.lower() for s in entities.get("services", [])
                  if s and s.lower() in available_services]
    techniques = [t.lower() for t in entities.get("techniques", [])
                  if t and t.lower() in available_techniques]

    severity_min = entities.get("severity_min")
    if hint == "high_severity" and severity_min is None:
        severity_min = 10

    # Check if any validated constraint exists
    any_constraint = bool(
        event_types or users or ips or countries or hosts
        or services or techniques or severity_min is not None
    )

    # What the classifier asked for — before facet validation
    classifier_asked_for_entities = bool(
        entities.get("users") or entities.get("ips") or entities.get("countries")
        or entities.get("hosts") or entities.get("services") or entities.get("techniques")
    )

    if not any_constraint:
        # If classifier asked for entities but none validated against facets,
        # the requested values don't exist in cached data → trigger confirmation
        # If classifier asked for nothing specific → also trigger confirmation
        return []

    # Apply validated filters
    filtered = list(hits)

    if event_types:
        filtered = [h for h in filtered if h.get("event_type") in event_types]

    if severity_min is not None:
        filtered = [h for h in filtered
                    if int(h.get("rule", {}).get("level", 0) or 0) >= severity_min]

    if users:
        filtered = [h for h in filtered
                    if h.get("user", {}).get("name", "").lower() in users]

    if ips:
        filtered = [h for h in filtered
                    if h.get("data", {}).get("srcip", "") in ips
                    or h.get("data", {}).get("dstip", "") in ips]

    if countries:
        filtered = [h for h in filtered
                    if h.get("geo", {}).get("country", "").lower() in countries]

    if hosts:
        filtered = [h for h in filtered
                    if h.get("agent", {}).get("name", "").lower() in hosts]

    if services:
        def _hit_services(h):
            return {
                h.get("data", {}).get("service", "").lower(),
                h.get("data", {}).get("vpn", {}).get("protocol", "").lower(),
                h.get("data", {}).get("network", {}).get("protocol", "").lower(),
            } - {""}
        filtered = [h for h in filtered
                    if _hit_services(h) & set(services)]

    if techniques:
        filtered = [h for h in filtered
                    if h.get("data", {}).get("technique", "").lower() in techniques]

    return filtered


class SIEMPipeline:
    """
    Full NLP → SIEM → Report pipeline. One instance per user session.
    """

    def __init__(self):
        self.memory = ConversationMemory()
        self.connector = SIEMConnector()
        self.dsl_mode = settings.dsl_mode  # hybrid | llm | template

    def run(self, user_input: str, force_full_search: bool = False,
            allow_widen: bool = False, on_step=None) -> dict:
        """
        Process a natural language security query end to end.
        on_step: optional callable(message: str) called at each pipeline stage.
        """
        def _step(msg: str):
            if on_step:
                on_step(msg)

        # ── Step 1: Classify intent ────────────────────────────────────────────
        _step("Classifying intent…")
        classification = classifier.classify(user_input, memory=self.memory)

        # Non-SIEM query — return guard response immediately, no DSL call needed
        if not classification.is_siem:
            return classification.build_guard_response(user_input)

        # SIEM query — use classifier outputs for all downstream routing
        core_query       = classification.core_query
        report_requested = classification.report_requested
        is_follow_up     = classification.is_follow_up or self.memory.is_follow_up(user_input)

        llm_query = core_query
        if report_requested and "report" not in llm_query.lower():
            llm_query = f"{llm_query}, generate a report with aggregations"

        context_summary = self.memory.get_context_summary()

        # ── Step 2: RAG — retrieve relevant schema fields ──────────────────────
        _step("Retrieving schema context…")
        try:
            schema_context = retrieve_fields(core_query, n=8)
        except Exception:
            schema_context = ""

        # ── Step 3: Follow-up — try in-memory first ───────────────────────────
        _step("Checking cached results…" if is_follow_up else "Preparing query…")
        if is_follow_up and not self.memory.query_state.is_empty() and not force_full_search:
            stored_hits   = self.memory.query_state.last_results_sample
            stored_facets = self.memory.query_state.last_facets
            if stored_hits:
                memory_hits = _filter_in_memory(stored_hits, classification, stored_facets)

                # If rule-based filter returned nothing, try LLM filter before
                # giving up — handles null checks, negations, complex conditions
                # that the rule-based system can't express
                if not memory_hits:
                    _step("Trying LLM filter on cached results…")
                    llm_hits = filter_hits_with_llm(stored_hits, core_query)
                    if llm_hits is not None and len(llm_hits) > 0:
                        memory_hits = llm_hits
                if memory_hits:
                    # Found matches — return immediately, no OpenSearch call
                    event_type = memory_hits[0].get("event_type", "default")
                    time_range = self.memory.query_state.last_time_range or "cached"
                    report = format_report(
                        hits=memory_hits,
                        aggregations={},
                        event_type=event_type,
                        time_range=time_range,
                        total=len(memory_hits),
                        narrative=(
                            f"Filtered {len(memory_hits)} records from "
                            f"{len(stored_hits)} cached results in memory."
                        ),
                        dsl=self.memory.query_state.last_dsl,
                    )
                    # IMPORTANT: update state to the filtered subset so
                    # chained follow-ups filter from here, not the original 50
                    self.memory.update_state(
                        intent=event_type,
                        dsl=self.memory.query_state.last_dsl,
                        results=memory_hits,
                        query=user_input,
                        time_range=time_range,
                    )
                    self.memory.log_query(
                        natural_query=user_input,
                        intent=event_type,
                        dsl=self.memory.query_state.last_dsl,
                        time_range=time_range,
                        result_count=len(memory_hits),
                        is_follow_up=True,
                        dsl_source="memory_filter",
                    )
                    return {
                        "success": True,
                        "user_input": user_input,
                        "dsl": self.memory.query_state.last_dsl,
                        "dsl_source": "memory_filter",
                        "classification": classification.to_dict(),
                        "validation": {"valid": True, "errors": [], "warnings": []},
                        "report": report,
                        "_raw_hits": memory_hits,
                        "is_follow_up": True,
                        "report_requested": report_requested,
                        "siem_meta": {
                            "total": len(memory_hits),
                            "took_ms": 0,
                            "warning": None,
                            "attempts": 0,
                        },
                        "clarification": None,
                        "error": None,
                    }
                else:
                    # Nothing in cached data matches — explain WHY using facets
                    smart_msg = _build_no_match_explanation(
                        core_query, classification, stored_hits, stored_facets
                    )
                    return {
                        "success": True,
                        "user_input": user_input,
                        "dsl": None,
                        "dsl_source": "pending_confirmation",
                        "classification": classification.to_dict(),
                        "validation": {"valid": True, "errors": [], "warnings": []},
                        "report": {
                            "dataframe": None, "chart": None, "kql": "",
                            "narrative": smart_msg,
                            "metadata": {},
                        },
                        "is_follow_up": True,
                        "report_requested": report_requested,
                        "pending_confirmation": True,
                        "pending_query": user_input,
                        "siem_meta": {"total": 0, "took_ms": 0, "warning": None, "attempts": 0},
                        "clarification": None,
                        "error": None,
                    }

        # ── Step 4: Generate DSL ──────────────────────────────────────────────
        dsl = None
        dsl_source = "none"
        validation = {"valid": False, "errors": ["Not yet validated"], "warnings": []}

        if is_follow_up and not self.memory.query_state.is_empty():
            _step("Refining previous query…")
            prev_dsl = self.memory.query_state.last_dsl
            dsl = refine_dsl(previous_dsl=prev_dsl, follow_up_query=core_query)
            if dsl:
                validation = validate_dsl(dsl)
                dsl_source = "llm_followup"

        if dsl is None and self.dsl_mode in ("hybrid", "llm"):
            _step("Generating DSL query…")
            dsl = generate_dsl(
                user_query=llm_query,
                schema_context=schema_context,
                conversation_summary="",
            )
            if dsl:
                validation = validate_dsl(dsl)
                if validation["valid"]:
                    dsl_source = "llm"
                else:
                    dsl = None

        if dsl is None and self.dsl_mode in ("hybrid", "template"):
            _step("Using template fallback…")
            dsl = build_from_template(
                intent=classification.template_intent,
                filters={},
                time_range=classification.time_range_hint or "last 24 hours",
                include_aggs=report_requested,
            )
            validation = validate_dsl(dsl)
            dsl_source = "template"

        if dsl is None:
            return self._error_response(
                "Could not generate a valid query. Please rephrase your question.",
                user_input
            )

        # ── Step 4: Size guard ─────────────────────────────────────────────────
        # Never allow size: 0 — we always want hits returned
        if dsl.get("body", {}).get("size", 50) == 0:
            dsl["body"]["size"] = 50

        # Strip aggs from main query — run them separately after hits come back
        # This is lazy aggregation: hits first (fast), aggs only if hits > 0
        import copy as _copy
        dsl_for_hits = _copy.deepcopy(dsl)
        dsl_for_hits["body"].pop("aggs", None)

        # ── Step 5: Execute against SIEM ──────────────────────────────────────
        _step("Fetching data from OpenSearch…")
        result = self.connector.execute(dsl_for_hits, allow_widen=allow_widen)

        # If no results in original range — ask user whether to widen
        if result.get("no_results_in_range"):
            orig_range = self._extract_time_range(dsl)
            return {
                "success": True,
                "user_input": user_input,
                "dsl": dsl,
                "dsl_source": "pending_confirmation",
                "classification": classification.to_dict(),
                "validation": validation,
                "report": {
                    "dataframe": None, "chart": None, "kql": "",
                    "narrative": (
                        f"No results found for '{core_query}' in the {orig_range} range. "
                        f"Widen the search to 30 days?"
                    ),
                    "metadata": {"time_range": orig_range},
                },
                "is_follow_up": is_follow_up,
                "report_requested": report_requested,
                "pending_confirmation": True,
                "pending_query": f"__widen__:{user_input}",
                "siem_meta": {"total": 0, "took_ms": 0, "warning": None, "attempts": 1},
                "clarification": None,
                "error": None,
            }

        if not result["success"]:
            return self._error_response(result["error"], user_input)

        # ── Step 6: Determine event type and actual time range ─────────────────
        event_type = "default"
        if result["hits"]:
            event_type = result["hits"][0].get("event_type", "default")

        actual_range       = result.get("actual_time_range")
        display_time_range = actual_range or self._extract_time_range(dsl)

        # ── Step 6b: Lazy aggregations — run agg query now that we have hits ───
        # Build agg DSL from template matching the detected event type,
        # scoped to the same time range that returned results.
        aggregations = {}
        if result["total"] > 0:
            _step("Building aggregations…")
            # Use the DSL that actually returned results (may have widened time)
            agg_dsl = _copy.deepcopy(dsl)
            # Use template aggs for this event type — covers all useful fields
            template_dsl = build_from_template(
                classification.template_intent, {}, "last 24 hours", include_aggs=True
            )
            agg_dsl["body"]["aggs"] = template_dsl["body"].get("aggs", {})
            # If time was widened, apply the same widening to the agg query
            if actual_range:
                widen_map = {"7 days": "now-7d", "30 days": "now-30d"}
                if actual_range in widen_map:
                    agg_dsl = self.connector._widen_time(agg_dsl, widen_map[actual_range])
            aggregations = self.connector.execute_aggs(agg_dsl)

        # ── Step 7: Generate narrative ─────────────────────────────────────────
        narrative = ""
        if result["total"] > 0:
            _step("Generating analyst narrative…")
            narrative = generate_narrative(
                intent_description=user_input,
                results_sample=result["hits"][:5],
                total_count=result["total"],
                time_range=display_time_range,
                aggregations=aggregations,
            )

        # ── Step 8: Format report ──────────────────────────────────────────────
        _step("Formatting report…")
        report = format_report(
            hits=result["hits"],
            aggregations=aggregations,
            event_type=event_type,
            time_range=display_time_range,
            total=result["total"],
            narrative=narrative,
            dsl=dsl,
        )

        # ── Step 9: Update memory ──────────────────────────────────────────────
        self.memory.add_exchange(
            user_input,
            f"Found {result['total']} {event_type.replace('_', ' ')} events. {narrative[:100]}"
        )
        self.memory.update_state(
            intent=event_type,
            dsl=dsl,
            results=result["hits"],
            query=user_input,
            time_range=display_time_range,
        )
        self.memory.log_query(
            natural_query=user_input,
            intent=event_type,
            dsl=dsl,
            time_range=display_time_range,
            result_count=result["total"],
            is_follow_up=is_follow_up,
            dsl_source=dsl_source,
        )

        return {
            "success": True,
            "user_input": user_input,
            "dsl": dsl,
            "dsl_source": dsl_source,
            "classification": classification.to_dict(),
            "validation": validation,
            "report": report,
            "_raw_hits": result["hits"],   # used by interactive chart builder in UI
            "is_follow_up": is_follow_up,
            "report_requested": report_requested,
            "siem_meta": {
                "total":      result["total"],
                "took_ms":    result["took_ms"],
                "warning":    result.get("warning"),
                "attempts":   result.get("attempts", 1),
                "time_range": display_time_range,
            },
            "clarification": None,
            "error": None,
        }

    def reset(self):
        self.memory.clear()

    def health(self) -> dict:
        from llm.client import ollama
        return {
            "elasticsearch": self.connector.status(),
            "ollama": ollama.health_check(),
            "dsl_mode": self.dsl_mode,
        }

    def stats(self) -> dict:
        return self.memory.stats()

    @staticmethod
    def _extract_time_range(dsl: dict) -> str:
        """Pull time range string from DSL for display."""
        try:
            filters = dsl["body"]["query"]["bool"]["filter"]
            for clause in filters:
                if "range" in clause and "@timestamp" in clause["range"]:
                    gte = clause["range"]["@timestamp"].get("gte", "now-24h")
                    range_map = {
                        "now-1d/d": "yesterday", "now-7d": "last 7 days",
                        "now-30d": "last 30 days", "now-24h": "last 24 hours",
                        "now-1h": "last hour", "now/d": "today",
                        "now-3d": "last 3 days", "now-14d": "last 14 days",
                    }
                    return range_map.get(gte, gte)
        except Exception:
            pass
        return "last 24 hours"

    @staticmethod
    def _error_response(message: str, user_input: str = "") -> dict:
        return {
            "success": False, "user_input": user_input,
            "dsl": None, "dsl_source": "none",
            "validation": None, "report": None,
            "is_follow_up": False, "report_requested": False,
            "siem_meta": None, "clarification": None,
            "error": message,
        }