"""
memory/context.py

Dual memory system:
  1. session_log     — full structured log of every query this session
  2. query_state     — last DSL + results for programmatic follow-ups
  3. history         — plain text exchanges for LLM context injection
"""

from dataclasses import dataclass, field
from collections import deque
from datetime import datetime
from typing import Optional
import copy


@dataclass
class QueryRecord:
    """One entry in the session log — full record of a single query."""
    index: int
    natural_query: str
    intent: str
    dsl: dict
    time_range: str
    result_count: int
    executed_at: datetime
    is_follow_up: bool = False
    dsl_source: str = "llm"

    def to_summary(self) -> str:
        """Short string for LLM injection."""
        return (
            f"Query {self.index}: '{self.natural_query}' "
            f"[{self.intent}] returned {self.result_count} results "
            f"over {self.time_range}"
        )


@dataclass
class QueryState:
    """Tracks the most recent query for programmatic follow-ups."""
    last_intent: Optional[str] = None
    last_dsl: Optional[dict] = None
    last_natural_query: Optional[str] = None
    last_results_sample: list = field(default_factory=list)
    last_facets: dict = field(default_factory=dict)   # values that exist in retrieved hits
    last_time_range: Optional[str] = None
    result_count: int = 0
    executed_at: Optional[datetime] = None

    def update(self, intent: str, dsl: dict, results: list,
               natural_query: str, time_range: str = "last 24 hours"):
        self.last_intent = intent
        self.last_dsl = copy.deepcopy(dsl)
        self.last_natural_query = natural_query
        self.last_results_sample = results  # store ALL hits for in-memory filtering
        self.last_facets = self._build_facets(results)
        self.last_time_range = time_range
        self.result_count = len(results)
        self.executed_at = datetime.now()

    @staticmethod
    def _build_facets(hits: list) -> dict:
        """
        Extract every filterable value that actually exists in the retrieved hits.
        This is the ground truth injected into the classifier so it knows what
        values are available to filter on — no guessing from sentence text.
        """
        facets: dict = {
            "event_types":     set(),
            "users":           set(),
            "src_ips":         set(),
            "countries":       set(),
            "hosts":           set(),
            "services":        set(),
            "severity_levels": set(),
            "techniques":      set(),
            "rule_groups":     set(),
        }
        for h in hits:
            if v := h.get("event_type"):
                facets["event_types"].add(v)
            if v := h.get("user", {}).get("name"):
                facets["users"].add(v)
            if v := h.get("data", {}).get("srcip"):
                facets["src_ips"].add(v)
            if v := h.get("geo", {}).get("country"):
                facets["countries"].add(v)
            if v := h.get("agent", {}).get("name"):
                facets["hosts"].add(v)
            if v := h.get("data", {}).get("service"):
                facets["services"].add(str(v).lower())
            if v := h.get("data", {}).get("vpn", {}).get("protocol"):
                facets["services"].add(str(v).lower())
            if v := h.get("data", {}).get("network", {}).get("protocol"):
                facets["services"].add(str(v).lower())
            if v := h.get("rule", {}).get("level"):
                try:
                    facets["severity_levels"].add(int(v))
                except (ValueError, TypeError):
                    pass
            if v := h.get("data", {}).get("technique"):
                facets["techniques"].add(v)
            for g in h.get("rule", {}).get("groups", []):
                facets["rule_groups"].add(g)
        # Convert sets to sorted lists for JSON serialisability
        return {k: sorted(v) for k, v in facets.items()}

    def facets_summary(self) -> str:
        """
        Human-readable summary of available facet values for LLM injection.
        Only includes non-empty facets. Truncates large sets to top 20.
        """
        if not self.last_facets:
            return ""
        lines = ["Available values in current cached results:"]
        labels = {
            "event_types":     "event types",
            "users":           "users",
            "src_ips":         "source IPs",
            "countries":       "countries",
            "hosts":           "hosts",
            "services":        "services/protocols",
            "severity_levels": "severity levels",
            "techniques":      "attack techniques",
            "rule_groups":     "rule groups",
        }
        for key, label in labels.items():
            values = self.last_facets.get(key, [])
            if values:
                display = values[:20]
                suffix = f" … (+{len(values)-20} more)" if len(values) > 20 else ""
                lines.append(f"  {label}: {', '.join(str(v) for v in display)}{suffix}")
        return "\n".join(lines)

    def is_empty(self) -> bool:
        return self.last_dsl is None

    def to_summary(self) -> str:
        if self.is_empty():
            return ""
        return (
            f"previous query: '{self.last_natural_query}', "
            f"time range: {self.last_time_range}, "
            f"returned {self.result_count} results"
        )

    def get_modified_dsl(self, additional_filters: list) -> dict:
        if self.is_empty():
            return None
        dsl = copy.deepcopy(self.last_dsl)
        filter_list = (dsl["body"].get("query", {})
                                  .get("bool", {})
                                  .setdefault("filter", []))
        filter_list.extend(additional_filters)
        return dsl


@dataclass
class ConversationMemory:
    history: deque = field(default_factory=lambda: deque(maxlen=12))
    query_state: QueryState = field(default_factory=QueryState)
    session_log: list = field(default_factory=list)  # full structured log
    session_start: datetime = field(default_factory=datetime.now)
    total_queries: int = 0

    def add_exchange(self, user_msg: str, assistant_summary: str):
        """Add plain text exchange to LLM history."""
        self.history.append({"role": "user", "content": user_msg})
        self.history.append({"role": "assistant", "content": assistant_summary})
        self.total_queries += 1

    def log_query(self, natural_query: str, intent: str, dsl: dict,
                  time_range: str, result_count: int,
                  is_follow_up: bool = False, dsl_source: str = "llm"):
        """Add a full structured record to session log."""
        record = QueryRecord(
            index=len(self.session_log) + 1,
            natural_query=natural_query,
            intent=intent,
            dsl=copy.deepcopy(dsl),
            time_range=time_range,
            result_count=result_count,
            executed_at=datetime.now(),
            is_follow_up=is_follow_up,
            dsl_source=dsl_source,
        )
        self.session_log.append(record)
        return record

    def update_state(self, intent: str, dsl: dict, results: list,
                     query: str, time_range: str = "last 24 hours"):
        self.query_state.update(intent, dsl, results, query, time_range)

    def get_history(self) -> list:
        return list(self.history)

    def get_context_summary(self) -> str:
        """
        Returns facet summary of current cached results for LLM injection.
        Previously returned a useless one-liner; now returns ground-truth
        values that actually exist in the data.
        """
        return self.query_state.facets_summary()

    def get_session_log_summary(self) -> str:
        """
        Returns a multi-query summary string for LLM injection.
        Used when user asks about multiple previous queries.
        e.g. "generate report for above three"
        """
        if not self.session_log:
            return ""
        lines = ["Session query log:"]
        for record in self.session_log[-10:]:
            lines.append(f"  {record.to_summary()}")
        return "\n".join(lines)

    def get_recent_records(self, n: int = 3) -> list:
        """Get last n QueryRecord objects."""
        return self.session_log[-n:] if self.session_log else []

    def is_follow_up(self, text: str) -> bool:
        if self.query_state.is_empty():
            return False
        signals = [
            "filter", "those", "these", "that", "them", "it", "only", "just",
            "also", "now show", "narrow", "refine", "from those", "from these",
            "out of those", "out of these", "of those", "of these",
            "how many", "count", "total", "add", "within these", "within those",
            "exclude", "remove", "limit", "from here", "from above",
            "from the above", "from that", "from this",
        ]
        lower = text.lower()
        return any(s in lower for s in signals)

    def is_multi_query_request(self, text: str) -> bool:
        """Detect if user is referencing multiple previous queries."""
        signals = [
            "above", "previous", "last two", "last three", "last 2",
            "last 3", "all queries", "all of them", "combine",
            "combined", "together", "all three", "all above",
        ]
        lower = text.lower()
        return any(s in lower for s in signals)

    def clear(self):
        self.history.clear()
        self.query_state = QueryState()
        self.session_log = []
        self.total_queries = 0
        self.session_start = datetime.now()

    def stats(self) -> dict:
        return {
            "total_queries": self.total_queries,
            "session_minutes": (datetime.now() - self.session_start).seconds // 60,
            "last_intent": self.query_state.last_intent,
            "history_length": len(self.history),
            "session_log_count": len(self.session_log),
        }