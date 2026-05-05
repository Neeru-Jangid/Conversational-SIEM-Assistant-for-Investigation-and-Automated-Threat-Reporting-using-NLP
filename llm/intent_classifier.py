"""
llm/intent_classifier.py
Single-call intent classifier for the SIEM NLP assistant.
Architecture two layers:

  Layer 1 Keyword pre-check (no LLM, <1ms)
    Handles obvious greetings, thanks, help, and OOS queries instantly.
    Uses token-level matching so "hey how are you" still hits the greeting
    bucket without needing to enumerate every variant.

  Layer 2 LLM classification (single Llama call, ~1-3s)
    For anything that passes Layer 1, one structured LLM call returns
    everything pipeline.py needs:
      · Is this a SIEM query or conversational?
      · Report requested? (catches all phrasings naturally)
      · Is it a follow-up on previous results?
      · What is the clean core security question? (strips meta-instructions)
      · Event type hint → maps directly to template fallback keys
      · Time range hint (natural language)
      · Named entities: users, IPs, countries, hosts

Usage:
    from llm.intent_classifier import classifier

    result = classifier.classify(user_input, memory=self.memory)

    if not result.is_siem:
        # return guard response no LLM DSL call needed
        return result.build_guard_response(user_input)

    # SIEM query use result fields directly
    core_query       = result.core_query
    report_requested = result.report_requested
    is_follow_up     = result.is_follow_up
    template_intent  = result.template_intent   # maps to engine/templates.py keys
"""

import json
import os
import sys
from dataclasses import dataclass, field
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from llm.client import classifier_ollama


# ── Layer 1: keyword sets ─────────────────────────────────────────────────────
# Token-level matching — any word in the input hits the bucket.
# Deliberately small and high-precision to avoid false positives on SIEM queries.

_L1_GREETING_TOKENS = {
    "hi", "hello", "hey", "howdy", "hiya", "sup", "yo", "greetings",
}

_L1_GREETING_PHRASES = {
    "good morning", "good afternoon", "good evening", "good day",
    "how are you", "how do you do",
}

_L1_THANKS_TOKENS = {
    "thanks", "thx", "ty", "cheers",
}

_L1_THANKS_PHRASES = {
    "thank you", "thank you so much", "appreciate it", "great job",
    "well done", "good job", "nice work",
}

_L1_HELP_PHRASES = {
    "help", "what can you do", "what do you do", "how do you work",
    "what are you", "who are you", "show examples", "what can i ask",
    "list commands", "capabilities",
}

# OOS: only truly unambiguous non-security topics
_L1_OOS_TOKENS = {
    "weather", "forecast", "recipe", "football", "cricket", "basketball",
    "bitcoin", "crypto", "ethereum", "translate", "lyrics",
}

_L1_OOS_PHRASES = {
    "tell me a joke", "what time is it", "date today", "capital of",
    "what is love", "meaning of life",
}

# Words that strongly indicate a SIEM query — presence of ANY of these
# overrides an OOS or unclear match from Layer 1.
_SIEM_OVERRIDE_TOKENS = {
    "login", "logon", "failed", "brute", "malware", "attack", "threat",
    "alert", "event", "security", "scan", "port", "vpn", "mfa", "auth",
    "privilege", "escalation", "lateral", "exfiltration", "powershell",
    "syscheck", "integrity", "wazuh", "siem", "incident", "breach",
    "firewall", "intrusion", "exploit", "ransomware", "phishing",
    "credential", "hash", "mimikatz", "psexec", "smb", "ssh", "rdp",
    "report", "show", "find", "detect", "investigate", "query",
    "yesterday", "today", "week", "month", "last", "recent", "hour",
    "high", "critical", "severity", "agent", "host", "user", "ip",
    "suspicious", "anomaly", "russia", "china", "country",
}


# ── Canned responses for non-SIEM intents ─────────────────────────────────────

_RESPONSES = {
    "greeting": (
        "Hello! I'm your SIEM Intelligence Assistant, ready to help you "
        "investigate security events.\n\n"
        "Ask me about failed logins, malware detections, brute force attacks, "
        "VPN activity, or any security event in your Wazuh deployment. "
        "What would you like to investigate?"
    ),
    "thanks": (
        "You're welcome! Let me know if you need to investigate anything else."
    ),
    "help": (
        "I'm your SIEM Intelligence Assistant. I can help you investigate "
        "security events in your Wazuh deployment.\n\n"
        "Try asking me things like:\n"
        "· \"Show failed logins from admin user yesterday\"\n"
        "· \"Brute force attacks this week\"\n"
        "· \"Malware detected on any host last 7 days\"\n"
        "· \"VPN logins from Russia or China — generate a report\"\n"
        "· \"High severity events from external IPs last month\"\n"
        "· \"Filter those results by source IP\"\n\n"
        "I understand natural language so just describe what you want to investigate."
    ),
    "oos": (
        "I'm focused on security event analysis and can't help with that. "
        "Try asking me about security events — like failed logins, malware "
        "detections, or brute force attacks."
    ),
    "unclear": (
        "I didn't quite understand that. I'm a SIEM analyst assistant — "
        "try asking about security events like failed logins or malware detections."
    ),
}


# ── Event type → template key mapping ─────────────────────────────────────────
# These match the keys in engine/templates.py TEMPLATES dict exactly.

_EVENT_TYPE_TO_TEMPLATE = {
    "failed_logins":        "failed_logins",
    "malware_detection":    "malware_detection",
    "vpn_activity":         "vpn_activity",
    "mfa_events":           "mfa_events",
    "brute_force":          "brute_force",
    "privilege_escalation": "privilege_escalation",
    "port_scan":            "port_scan",
    "suspicious_powershell":"suspicious_powershell",
    "file_integrity":       "file_integrity",
    "lateral_movement":     "lateral_movement",
    "data_exfiltration":    "data_exfiltration",
    "high_severity":        "high_severity",
    "all_events":           "all_events",
}


# ── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class IntentResult:
    """
    Everything pipeline.py needs from classification, in one object.

    Fields set by Layer 1 (keyword pre-check):
        category, source="layer1"
        is_siem=False, core_query="", report_requested=False, etc.

    Fields set by Layer 2 (LLM):
        All fields populated from structured LLM output.
    """
    # Routing
    category: str               # siem | greeting | thanks | help | oos | unclear
    source: str                 # layer1 | llm | fallback

    # SIEM query fields (populated by LLM for category=="siem")
    report_requested: bool = False
    is_follow_up: bool = False
    core_query: str = ""        # meta-instructions stripped, pure security question
    event_type_hint: str = "all_events"   # maps to template key
    time_range_hint: str = ""
    entities: dict = field(default_factory=dict)  # {users, ips, countries, hosts}
    confidence: str = "medium"

    @property
    def is_siem(self) -> bool:
        return self.category == "siem"

    @property
    def template_intent(self) -> str:
        """Returns the engine/templates.py key for this event type."""
        return _EVENT_TYPE_TO_TEMPLATE.get(self.event_type_hint, "all_events")

    def build_guard_response(self, user_input: str) -> dict:
        """
        Build the pipeline result dict for a non-SIEM query.
        Matches the exact structure pipeline.py returns for guard hits
        so the UI renders it identically.
        """
        message = _RESPONSES.get(self.category, _RESPONSES["unclear"])
        return {
            "success": True,
            "user_input": user_input,
            "dsl": None,
            "dsl_source": "guard",
            "guard_type": self.category,
            "classification": {
                "category": self.category,
                "intent_type": "guard",
                "source": self.source,
            },
            "validation": {"valid": True, "errors": [], "warnings": []},
            "report": {
                "dataframe": None,
                "chart": None,
                "narrative": message,
                "kql": None,
                "metadata": {},
            },
            "is_follow_up": False,
            "report_requested": False,
            "siem_meta": {"total": 0, "took_ms": 0, "warning": None, "attempts": 0},
            "error": None,
        }

    def to_dict(self) -> dict:
        """Serialisable dict for inclusion in pipeline result (used by app.py)."""
        return {
            "category": self.category,
            "intent_type": "report" if self.report_requested else "investigation",
            "report_requested": self.report_requested,
            "is_follow_up": self.is_follow_up,
            "core_query": self.core_query,
            "event_type_hint": self.event_type_hint,
            "time_range_hint": self.time_range_hint,
            "entities": self.entities,
            "confidence": self.confidence,
            "source": self.source,
        }


# ── LLM system prompt ─────────────────────────────────────────────────────────

_LLM_SYSTEM = """You are an intent classifier for a SIEM security assistant.

Your job: analyse the user's message and return a single JSON object.

CATEGORY values:
  "siem"      — any security investigation or analysis request
  "greeting"  — hello, hi, how are you, etc.
  "thanks"    — thank you, great job, appreciate it, etc.
  "help"      — asking what the assistant can do, examples, capabilities
  "oos"       — clearly off-topic: weather, jokes, recipes, sports, crypto, etc.
  "unclear"   — too short or ambiguous to classify

EVENT_TYPE_HINT values (use the closest match for SIEM queries):
  failed_logins | malware_detection | vpn_activity | mfa_events |
  brute_force | privilege_escalation | port_scan | suspicious_powershell |
  file_integrity | lateral_movement | data_exfiltration | high_severity | all_events

CORE_QUERY rules:
  Strip ALL meta-instructions and return only the pure security question.
  Meta-instructions include phrases like:
    "generate report for", "generate report for:", "create a report about",
    "show me a summary of", "can you make a report on", "give me a report of",
    "i want a report about", "report on", "summarize", "show me", "find me",
    "can you show", "please show", "tell me about"
  If there are no meta-instructions, core_query equals the original message.
  For non-SIEM categories, core_query is an empty string.

REPORT_REQUESTED is true when user wants: report, chart, summary, aggregation,
  graph, visualization, breakdown, or overview — regardless of phrasing.

IS_FOLLOW_UP is true when the query references previous results using words like:
  "those", "that", "them", "these", "filter those", "narrow down", "from those",
  "from above", "those results", "add filter", "also show", "now show only",
  "out of those", "out of these", "give me the ones where", "only show",
  "where service", "where user", "where ip", "just the"

ENTITIES — extract ALL specific constraint values mentioned:
  users:        usernames (e.g. "admin", "alice")
  ips:          IP addresses (e.g. "192.168.1.1")
  countries:    country names (e.g. "Russia", "China")
  hosts:        hostnames (e.g. "srv-01", "db-42")
  services:     network services or protocols (e.g. "ssh", "rdp", "http", "ftp", "smtp")
  severity_min: minimum severity integer if mentioned (e.g. 10 for "high", 14 for "critical")
  techniques:   attack technique names (e.g. "Pass-the-Hash", "WMI")

Output ONLY valid JSON, no explanation, no markdown:
{
  "category": "siem",
  "report_requested": true,
  "is_follow_up": false,
  "core_query": "the pure security question",
  "event_type_hint": "vpn_activity",
  "time_range_hint": "last 7 days",
  "entities": {
    "users":        [],
    "ips":          [],
    "countries":    ["Russia", "China"],
    "hosts":        [],
    "services":     [],
    "severity_min": null,
    "techniques":   []
  },
  "confidence": "high"
}"""

_LLM_EXAMPLES = [
    # report prefix — button injection
    ("generate report for: VPN logins from Russia or China last 7 days",
     '{"category":"siem","report_requested":true,"is_follow_up":false,'
     '"core_query":"VPN logins from Russia or China last 7 days",'
     '"event_type_hint":"vpn_activity","time_range_hint":"last 7 days",'
     '"entities":{"users":[],"ips":[],"countries":["Russia","China"],"hosts":[]},'
     '"confidence":"high"}'),

    # natural report phrasing
    ("can you make me a report about brute force attacks this week",
     '{"category":"siem","report_requested":true,"is_follow_up":false,'
     '"core_query":"brute force attacks this week",'
     '"event_type_hint":"brute_force","time_range_hint":"this week",'
     '"entities":{"users":[],"ips":[],"countries":[],"hosts":[]},'
     '"confidence":"high"}'),

    # plain investigation
    ("show failed logins from admin yesterday",
     '{"category":"siem","report_requested":false,"is_follow_up":false,'
     '"core_query":"show failed logins from admin yesterday",'
     '"event_type_hint":"failed_logins","time_range_hint":"yesterday",'
     '"entities":{"users":["admin"],"ips":[],"countries":[],"hosts":[]},'
     '"confidence":"high"}'),

    # follow-up
    ("filter those by source IP 192.168.1.1",
     '{"category":"siem","report_requested":false,"is_follow_up":true,'
     '"core_query":"filter by source IP 192.168.1.1",'
     '"event_type_hint":"all_events","time_range_hint":"",'
     '"entities":{"users":[],"ips":["192.168.1.1"],"countries":[],"hosts":[]},'
     '"confidence":"high"}'),

    # summary phrasing
    ("give me a summary of high severity events last month",
     '{"category":"siem","report_requested":true,"is_follow_up":false,'
     '"core_query":"high severity events last month",'
     '"event_type_hint":"high_severity","time_range_hint":"last month",'
     '"entities":{"users":[],"ips":[],"countries":[],"hosts":[],'
     '"services":[],"severity_min":null,"techniques":[]},'
     '"confidence":"high"}'),

    # greeting
    ("hello there",
     '{"category":"greeting","report_requested":false,"is_follow_up":false,'
     '"core_query":"","event_type_hint":"","time_range_hint":"",'
     '"entities":{},"confidence":"high"}'),

    # OOS
    ("what is the weather in London",
     '{"category":"oos","report_requested":false,"is_follow_up":false,'
     '"core_query":"","event_type_hint":"","time_range_hint":"",'
     '"entities":{},"confidence":"high"}'),

    # service filter follow-up
    ("out of those give the ones where service used was ssh",
     '{"category":"siem","report_requested":false,"is_follow_up":true,'
     '"core_query":"filter by service ssh",'
     '"event_type_hint":"all_events","time_range_hint":"",'
     '"entities":{"users":[],"ips":[],"countries":[],"hosts":[],'
     '"services":["ssh"],"severity_min":null,"techniques":[]},'
     '"confidence":"high"}'),

    # severity filter follow-up
    ("from those show only critical severity",
     '{"category":"siem","report_requested":false,"is_follow_up":true,'
     '"core_query":"filter by critical severity",'
     '"event_type_hint":"high_severity","time_range_hint":"",'
     '"entities":{"users":[],"ips":[],"countries":[],"hosts":[],'
     '"services":[],"severity_min":14,"techniques":[]},'
     '"confidence":"high"}'),

    # multi-query report
    ("generate a combined report for above three queries",
     '{"category":"siem","report_requested":true,"is_follow_up":true,'
     '"core_query":"combined report for above three queries",'
     '"event_type_hint":"all_events","time_range_hint":"",'
     '"entities":{"users":[],"ips":[],"countries":[],"hosts":[],'
     '"services":[],"severity_min":null,"techniques":[]},'
     '"confidence":"high"}'),
]


# ── Classifier ────────────────────────────────────────────────────────────────

class IntentClassifier:
    """
    Two-layer intent classifier.

    Layer 1: instant keyword pre-check — no LLM call.
    Layer 2: single structured LLM call for all SIEM routing needs.
    """

    def classify(self, user_input: str, memory=None) -> IntentResult:
        """
        Classify user_input and return an IntentResult.

        Args:
            user_input: raw text from the user
            memory:     ConversationMemory instance (optional, used to
                        provide conversation context to the LLM)
        """
        # Layer 1 — instant keyword check
        layer1 = self._layer1(user_input)
        if layer1 is not None:
            return layer1

        # Layer 2 — LLM
        return self._llm_classify(user_input, memory)

    # ── Layer 1 ───────────────────────────────────────────────────────────────

    def _layer1(self, text: str) -> Optional[IntentResult]:
        """
        Keyword pre-check. Returns IntentResult if matched, None otherwise.

        Never intercepts a query that contains SIEM override tokens — those
        always pass through to the LLM regardless of other keyword matches.
        """
        t = text.lower().strip().rstrip("?!.")
        tokens = set(t.split())

        # SIEM override — if ANY siem keyword present, skip Layer 1 entirely
        if tokens & _SIEM_OVERRIDE_TOKENS:
            return None

        # Exact phrase checks (highest precision)
        if t in _L1_GREETING_TOKENS or any(p in t for p in _L1_GREETING_PHRASES):
            return self._l1_result("greeting")

        if t in _L1_THANKS_TOKENS or any(p in t for p in _L1_THANKS_PHRASES):
            return self._l1_result("thanks")

        if any(p in t for p in _L1_HELP_PHRASES):
            return self._l1_result("help")

        if tokens & _L1_OOS_TOKENS or any(p in t for p in _L1_OOS_PHRASES):
            return self._l1_result("oos")

        # Very short queries with no SIEM keywords at all
        if len(tokens) <= 2:
            return self._l1_result("unclear")

        # Can't determine from keywords alone — pass to LLM
        return None

    @staticmethod
    def _l1_result(category: str) -> IntentResult:
        return IntentResult(category=category, source="layer1")

    # ── Layer 2: LLM ─────────────────────────────────────────────────────────

    def _llm_classify(self, text: str, memory) -> IntentResult:
        """Single structured LLM call. Returns IntentResult."""
        messages = self._build_messages(text, memory)

        raw = classifier_ollama.chat(
            messages=messages,
            system=_LLM_SYSTEM,
            temperature=0.0,
            max_tokens=200,
            json_mode=True,
        )

        if raw.startswith("ERROR:"):
            return self._fallback(text)

        try:
            data = json.loads(raw.replace("```json", "").replace("```", "").strip())
            return self._parse_llm_output(data, text)
        except (json.JSONDecodeError, KeyError):
            return self._fallback(text)

    def _build_messages(self, text: str, memory) -> list[dict]:
        """Build few-shot messages, with facets context injected for follow-ups."""
        messages = []

        # Few-shot examples
        for user_q, assistant_json in _LLM_EXAMPLES:
            messages.append({"role": "user", "content": user_q})
            messages.append({"role": "assistant", "content": assistant_json})

        # Inject facets context if available — gives LLM ground truth values
        # from the actual retrieved data instead of guessing from the sentence.
        # Guard with hasattr for backward compatibility with old session state objects.
        if memory and not memory.query_state.is_empty():
            facets = ""
            if hasattr(memory.query_state, "facets_summary"):
                facets = memory.query_state.facets_summary()
            if facets:
                messages.append({
                    "role": "user",
                    "content": (
                        f"{facets}\n\n"
                        f"Previous query: '{memory.query_state.last_natural_query}' "
                        f"({memory.query_state.result_count} results)\n\n"
                        f"Classify this follow-up: {text}"
                    )
                })
            else:
                messages.append({"role": "user", "content": text})
        else:
            messages.append({"role": "user", "content": text})

        return messages

    @staticmethod
    def _parse_llm_output(data: dict, original_text: str) -> IntentResult:
        """Parse and validate LLM JSON output into an IntentResult."""
        category = data.get("category", "siem")
        if category not in ("siem", "greeting", "thanks", "help", "oos", "unclear"):
            category = "siem"  # safe default — better to query than to block

        # core_query fallback: if LLM returns empty for a SIEM query, use original
        core_query = data.get("core_query", "").strip()
        if category == "siem" and not core_query:
            core_query = original_text

        return IntentResult(
            category=category,
            source="llm",
            report_requested=bool(data.get("report_requested", False)),
            is_follow_up=bool(data.get("is_follow_up", False)),
            core_query=core_query,
            event_type_hint=data.get("event_type_hint", "all_events") or "all_events",
            time_range_hint=data.get("time_range_hint", ""),
            entities=data.get("entities", {}),
            confidence=data.get("confidence", "medium"),
        )

    @staticmethod
    def _fallback(text: str) -> IntentResult:
        """
        Safe fallback when LLM call fails or returns unparseable output.
        Assumes SIEM query so we don't accidentally block a real query.
        """
        return IntentResult(
            category="siem",
            source="fallback",
            report_requested="report" in text.lower() or "summary" in text.lower(),
            is_follow_up=False,
            core_query=text,
            event_type_hint="all_events",
            time_range_hint="",
            entities={},
            confidence="low",
        )


# Singleton — import this everywhere
classifier = IntentClassifier()