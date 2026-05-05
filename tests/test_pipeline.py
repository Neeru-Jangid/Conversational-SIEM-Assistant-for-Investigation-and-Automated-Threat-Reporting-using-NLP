"""
tests/test_pipeline.py

Test suite for SIEM NLP Assistant v2.

Run:
    pytest tests/ -v                          # unit tests only
    pytest tests/ -v -m integration          # needs Elasticsearch
    pytest tests/ -v -m e2e                  # needs ES + Ollama
"""

import pytest
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.templates import (
    build_from_template, validate_dsl, parse_time_range, TEMPLATES
)
from memory.context import ConversationMemory, QueryState
from reports.generator import build_dataframe, dsl_to_kql


# ─────────────────────────────────────────────────────────────────────────────
# UNIT TESTS
# ─────────────────────────────────────────────────────────────────────────────

class TestDateMath:

    def test_yesterday(self):
        gte, lte = parse_time_range("yesterday")
        assert gte == "now-1d/d"
        assert lte == "now/d"

    def test_last_week(self):
        gte, _ = parse_time_range("last week")
        assert "7d" in gte

    def test_dynamic_last_n_days(self):
        gte, _ = parse_time_range("last 14 days")
        assert "14d" in gte

    def test_dynamic_last_n_hours(self):
        gte, _ = parse_time_range("last 6 hours")
        assert "6h" in gte

    def test_unknown_falls_back(self):
        gte, _ = parse_time_range("three moons ago")
        assert "24h" in gte


class TestTemplateEngine:

    @pytest.mark.parametrize("intent", list(TEMPLATES.keys()))
    def test_all_templates_build_without_error(self, intent):
        result = build_from_template(intent, {}, "last 24 hours")
        assert result is not None
        assert "body" in result
        assert "query" in result["body"]

    def test_user_filter_applied(self):
        result = build_from_template("failed_logins", {"user": "admin"}, "yesterday")
        body_str = json.dumps(result["body"])
        assert "admin" in body_str

    def test_time_range_in_query(self):
        result = build_from_template("failed_logins", {}, "last week")
        filters = result["body"]["query"]["bool"]["filter"]
        has_time = any("range" in f and "@timestamp" in f.get("range", {}) for f in filters)
        assert has_time

    def test_aggs_included_when_requested(self):
        result = build_from_template("malware_detection", {}, "last week", include_aggs=True)
        assert "aggs" in result["body"]

    def test_aggs_excluded_by_default(self):
        result = build_from_template("failed_logins", {}, "yesterday", include_aggs=False)
        assert "aggs" not in result["body"]

    def test_unknown_filter_key_ignored(self):
        result = build_from_template("failed_logins", {"nonexistent": "value"}, "yesterday")
        body_str = json.dumps(result["body"])
        assert "nonexistent" not in body_str

    def test_max_results_respected(self):
        result = build_from_template("failed_logins", {}, "yesterday", max_results=10)
        assert result["body"]["size"] == 10


class TestDSLValidator:

    def test_valid_query_passes(self):
        query = build_from_template("failed_logins", {}, "yesterday")
        result = validate_dsl(query)
        assert result["valid"] is True

    def test_missing_index_fails(self):
        result = validate_dsl({"body": {"query": {}}})
        assert result["valid"] is False
        assert any("index" in e.lower() for e in result["errors"])

    def test_missing_body_fails(self):
        result = validate_dsl({"index": "test"})
        assert result["valid"] is False

    def test_oversized_query_capped(self):
        query = build_from_template("failed_logins", {}, "yesterday", max_results=1000)
        query["body"]["size"] = 1000
        result = validate_dsl(query)
        assert result["valid"] is True
        assert any("500" in w or "large" in w.lower() for w in result["warnings"])

    def test_llm_generated_valid_dsl(self):
        """Test that a well-formed LLM-style DSL passes validation."""
        query = {
            "index": "wazuh-alerts-demo",
            "body": {
                "query": {"bool": {
                    "filter": [
                        {"terms": {"rule.groups": ["authentication_failed"]}},
                        {"range": {"@timestamp": {"gte": "now-24h", "lte": "now"}}},
                    ]
                }},
                "size": 50,
                "sort": [{"@timestamp": {"order": "desc"}}],
            }
        }
        result = validate_dsl(query)
        assert result["valid"] is True


class TestMemory:

    def test_initial_empty(self):
        mem = ConversationMemory()
        assert mem.query_state.is_empty()
        assert len(mem.history) == 0

    def test_add_exchange(self):
        mem = ConversationMemory()
        mem.add_exchange("show failed logins", "Found 10 events")
        assert len(mem.history) == 2
        assert mem.total_queries == 1

    def test_history_maxlen(self):
        mem = ConversationMemory()
        for i in range(20):
            mem.add_exchange(f"query {i}", f"result {i}")
        assert len(mem.history) <= 12

    def test_update_state(self):
        mem = ConversationMemory()
        mem.update_state("failed_logins", {"index": "x", "body": {}}, [{"x": 1}], "failed logins", "yesterday")
        assert mem.query_state.last_intent == "failed_logins"
        assert mem.query_state.result_count == 1

    def test_follow_up_detection(self):
        mem = ConversationMemory()
        mem.update_state("failed_logins", {}, [{}], "test", "yesterday")
        assert mem.is_follow_up("filter those by admin") is True
        assert mem.is_follow_up("show all malware events this week") is False

    def test_context_summary(self):
        mem = ConversationMemory()
        mem.update_state("failed_logins", {}, [], "failed logins yesterday", "yesterday")
        ctx = mem.get_context_summary()
        assert "failed logins yesterday" in ctx

    def test_clear(self):
        mem = ConversationMemory()
        mem.add_exchange("test", "response")
        mem.clear()
        assert len(mem.history) == 0
        assert mem.total_queries == 0


class TestReportGenerator:

    SAMPLE_HITS = [
        {
            "@timestamp": "2024-01-15T10:30:00Z",
            "event_type": "failed_login",
            "user": {"name": "admin"},
            "data": {"srcip": "1.2.3.4"},
            "agent": {"name": "workstation-01"},
            "rule": {"description": "Failed login", "level": 8},
        }
    ]

    def test_build_dataframe_not_empty(self):
        df = build_dataframe(self.SAMPLE_HITS, "failed_login")
        assert not df.empty
        assert len(df) == 1

    def test_build_dataframe_empty_hits(self):
        df = build_dataframe([], "failed_login")
        assert df.empty

    def test_kql_conversion(self):
        dsl = build_from_template("failed_logins", {"user": "admin"}, "yesterday")
        kql = dsl_to_kql(dsl)
        assert isinstance(kql, str)
        assert len(kql) > 0


# ─────────────────────────────────────────────────────────────────────────────
# INTEGRATION TESTS — requires running Elasticsearch
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.integration
class TestSIEMConnector:

    @pytest.fixture(autouse=True)
    def setup(self):
        from siem.connector import SIEMConnector
        self.conn = SIEMConnector()
        if not self.conn.ping():
            pytest.skip("Elasticsearch not running")

    def test_ping(self):
        assert self.conn.ping()

    def test_status(self):
        s = self.conn.status()
        assert s.get("connected")

    def test_execute_basic_query(self):
        from engine.templates import build_from_template
        q = build_from_template("all_events", {}, "last 30 days", max_results=5)
        result = self.conn.execute(q)
        assert "success" in result
        assert isinstance(result["hits"], list)

    def test_error_on_bad_index(self):
        q = {"index": "nonexistent_index_xyz_abc", "body": {"query": {"match_all": {}}}}
        result = self.conn.execute(q)
        assert result["success"] is False


# ─────────────────────────────────────────────────────────────────────────────
# END-TO-END TESTS — requires Elasticsearch + Ollama
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.e2e
class TestFullPipeline:

    QUERIES = [
        "show failed login attempts yesterday",
        "what malware was detected this week",
        "brute force attacks last month",
        "VPN logins from Russia last 7 days",
        "failed MFA attempts this week",
        "privilege escalation attempts last 7 days",
        "suspicious PowerShell activity today",
        "generate a malware report for last month",
        "port scans from external IPs",
        "high severity events last 24 hours",
    ]

    @pytest.fixture(autouse=True)
    def setup(self):
        from pipeline import SIEMPipeline
        from siem.connector import SIEMConnector
        from llm.client import ollama

        if not SIEMConnector().ping():
            pytest.skip("Elasticsearch not running")
        if not ollama.health_check()["connected"]:
            pytest.skip("Ollama not running")

        self.p = SIEMPipeline()

    @pytest.mark.parametrize("query", QUERIES)
    def test_query_does_not_crash(self, query):
        result = self.p.run(query)
        assert "success" in result
        assert result.get("error") is None or isinstance(result.get("error"), str)

    def test_multi_turn_follow_up(self):
        r1 = self.p.run("show failed logins last week")
        assert "success" in r1
        r2 = self.p.run("filter those by user admin")
        assert r2.get("is_follow_up") is True

    def test_report_has_narrative(self):
        result = self.p.run("generate a report of malware detections last month")
        if result["success"] and result.get("report"):
            narrative = result["report"].get("narrative", "")
            assert len(narrative) > 20

    def test_dsl_source_tracking(self):
        result = self.p.run("show failed logins yesterday")
        assert result.get("dsl_source") in ("llm", "template", "template_follow_up", "none")

    def test_session_reset(self):
        self.p.run("show failed logins yesterday")
        self.p.reset()
        assert self.p.stats()["total_queries"] == 0
