"""
siem/connector.py

OpenSearch connector with intelligent error recovery and
runtime mapping-aware DSL repair.

DSL Repair Logic:
  - Fetches index mapping once and caches it in memory
  - For term/terms filters: appends .keyword if field is text type with keyword sub-field
  - For aggregations: same .keyword logic
  - Never appends .keyword to numeric, date, boolean, or ip fields
  - Never appends .keyword if field already ends in .keyword
"""

import copy
import os
import sys
from opensearchpy import OpenSearch, NotFoundError, RequestError, ConnectionError

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.settings import settings


class SIEMConnector:

    def __init__(self):
        self.es = OpenSearch(
            hosts=[{"host": settings.es_host, "port": settings.es_port}],
            http_auth=(settings.es_user, settings.es_password),
            use_ssl=True,
            verify_certs=False,
            ssl_show_warn=False,
            timeout=30,
            max_retries=2,
            retry_on_timeout=True,
        )
        # Cache index mapping so we only fetch it once per session
        self._mapping_cache: dict = {}

    def ping(self) -> bool:
        try:
            return self.es.ping()
        except Exception:
            return False

    def status(self) -> dict:
        if not self.ping():
            return {"connected": False, "message": "Elasticsearch not reachable"}
        try:
            health = self.es.cluster.health()
            count = self.es.count(index=settings.es_index).get("count", 0)
            return {
                "connected": True,
                "cluster_status": health["status"],
                "cluster_name": health["cluster_name"],
                "document_count": count,
                "index": settings.es_index,
            }
        except Exception as e:
            return {"connected": True, "message": str(e)}

    # ── Mapping cache ──────────────────────────────────────────────────────────

    def _get_field_types(self, index: str) -> dict:
        """
        Returns flat dict of {field_name: field_info} where field_info is:
          {"type": "text", "has_keyword": True/False}

        Fetches from OpenSearch once, then caches for the session.
        """
        if index in self._mapping_cache:
            return self._mapping_cache[index]

        try:
            raw = self.es.indices.get_mapping(index=index)
            properties = {}
            for idx_data in raw.values():
                properties.update(idx_data.get("mappings", {}).get("properties", {}))

            field_types = {}
            self._flatten_mapping(properties, "", field_types)
            self._mapping_cache[index] = field_types
            return field_types
        except Exception:
            return {}

    def _flatten_mapping(self, properties: dict, prefix: str, result: dict):
        """Recursively flatten nested mapping properties."""
        for field, config in properties.items():
            full_field = f"{prefix}.{field}" if prefix else field
            field_type = config.get("type", "object")
            has_keyword = "keyword" in config.get("fields", {})

            result[full_field] = {
                "type": field_type,
                "has_keyword": has_keyword,
            }

            if "properties" in config:
                self._flatten_mapping(config["properties"], full_field, result)

    # ── DSL repair ─────────────────────────────────────────────────────────────

    def _needs_keyword(self, field: str, field_types: dict) -> bool:
        """
        Returns True if field should have .keyword appended.
        Rules:
          - Already ends in .keyword → False
          - Not in mapping → False (don't guess)
          - Type is text AND has .keyword sub-field → True
          - Type is keyword, long, integer, float, date, boolean, ip → False
        """
        if field.endswith(".keyword"):
            return False
        info = field_types.get(field)
        if not info:
            return False
        return info["type"] == "text" and info["has_keyword"]

    def _repair_dsl(self, query: dict) -> dict:
        """
        Walk through DSL and append .keyword where needed based on live mapping.
        Repairs:
          - term filter field names
          - terms filter field names
          - terms aggregation field names
          - cardinality aggregation field names
        Does NOT touch:
          - range filters (numeric/date fields never need .keyword)
          - match queries (text search, .keyword would break it)
          - sort fields (usually fine as-is)
        """
        index = query.get("index", settings.es_index)
        field_types = self._get_field_types(index)

        if not field_types:
            return query  # can't repair without mapping, return as-is

        q = copy.deepcopy(query)
        body = q.get("body", {})

        # Repair query filters
        filters = body.get("query", {}).get("bool", {}).get("filter", [])
        for clause in filters:
            self._repair_clause(clause, field_types)

        # Repair must/should clauses too
        for clause_type in ("must", "should", "must_not"):
            for clause in body.get("query", {}).get("bool", {}).get(clause_type, []):
                self._repair_clause(clause, field_types)

        # Repair aggregations
        aggs = body.get("aggs", {})
        self._repair_aggs(aggs, field_types)

        q["body"] = body
        return q

    def _repair_clause(self, clause: dict, field_types: dict):
        """Repair a single query clause in-place."""
        # term: {"term": {"user.name": "admin"}}
        if "term" in clause:
            for field in list(clause["term"].keys()):
                if self._needs_keyword(field, field_types):
                    clause["term"][f"{field}.keyword"] = clause["term"].pop(field)

        # terms: {"terms": {"rule.groups": ["auth_failed"]}}
        elif "terms" in clause:
            for field in list(clause["terms"].keys()):
                if field == "boost":
                    continue
                if self._needs_keyword(field, field_types):
                    clause["terms"][f"{field}.keyword"] = clause["terms"].pop(field)

    def _repair_aggs(self, aggs: dict, field_types: dict):
        """Recursively repair aggregation field names in-place."""
        for agg_name, agg_body in aggs.items():
            for agg_type in ("terms", "cardinality", "avg", "sum", "min", "max"):
                if agg_type in agg_body:
                    field = agg_body[agg_type].get("field", "")
                    if field and self._needs_keyword(field, field_types):
                        agg_body[agg_type]["field"] = f"{field}.keyword"

            # Recurse into sub-aggregations
            if "aggs" in agg_body:
                self._repair_aggs(agg_body["aggs"], field_types)

    # ── Query execution ────────────────────────────────────────────────────────

    def execute(self, query: dict, allow_widen: bool = True) -> dict:
        """
        Execute a DSL query against OpenSearch.

        allow_widen: if True (default), automatically try wider time ranges
                     when original returns 0 results.
                     if False, return immediately with no results and
                     no_results_in_range=True so the caller can ask the user.
        """
        if not self.ping():
            return self._err("Cannot connect to Elasticsearch. Is Wazuh running? Run: docker-compose up -d")

        # Repair DSL field names based on live mapping
        query = self._repair_dsl(query)
        warning = None
        actual_time_range = None   # tracks the time range that actually returned results
        current_query = copy.deepcopy(query)

        widen_steps = [None, "now-7d", "now-30d"] if allow_widen else [None]

        for attempt, new_gte in enumerate(widen_steps):
            if new_gte:
                current_query = self._widen_time(current_query, new_gte)
                label = "7 days" if attempt == 1 else "30 days"
                warning = f"No results in original time range. Widened search to {label}."
                actual_time_range = label

            try:
                resp = self.es.search(
                    index=current_query["index"],
                    body=current_query["body"],
                )
                hits  = [h["_source"] for h in resp["hits"]["hits"]]
                total = resp["hits"]["total"]["value"]

                if total == 0 and attempt < len(widen_steps) - 1:
                    continue

                return {
                    "success":          True,
                    "hits":             hits,
                    "total":            total,
                    "took_ms":          resp.get("took", 0),
                    "aggregations":     resp.get("aggregations", {}),
                    "warning":          warning,
                    "error":            None,
                    "attempts":         attempt + 1,
                    "actual_time_range": actual_time_range,   # None = original range used
                    "no_results_in_range": False,
                }

            except NotFoundError:
                return self._err(
                    f"Index '{current_query.get('index')}' not found. "
                    f"Run: python data/generate_dummy_data.py"
                )
            except RequestError as e:
                reason = e.info.get("error", {}).get("reason", str(e))
                return self._err(f"Query error: {reason}. Check field names.")
            except ConnectionError:
                return self._err("Connection lost mid-query. Check Docker.")
            except Exception as e:
                return self._err(str(e))

        # Exhausted all attempts with 0 results
        return {
            "success":          True,
            "hits":             [],
            "total":            0,
            "took_ms":          0,
            "aggregations":     {},
            "warning":          None,
            "error":            None,
            "attempts":         len(widen_steps),
            "actual_time_range": None,
            "no_results_in_range": True,
        }

    def execute_aggs(self, query: dict) -> dict:
        """
        Run aggregations only against an existing query — no hits returned.
        Uses size:0 so it's fast. Used to populate charts after the main
        query has already returned hits.

        Takes the same DSL dict as execute(), injects size:0 and strips
        existing size to keep it clean.

        Returns aggregations dict, or empty dict on failure.
        """
        try:
            query = self._repair_dsl(query)
            import copy as _copy
            agg_query = _copy.deepcopy(query)
            agg_query["body"]["size"] = 0
            # Remove sort — irrelevant for agg-only queries
            agg_query["body"].pop("sort", None)

            resp = self.es.search(
                index=agg_query["index"],
                body=agg_query["body"],
            )
            return resp.get("aggregations", {})
        except Exception:
            return {}

    def get_mappings(self, index: str = None) -> dict:
        try:
            return self.es.indices.get_mapping(index=index or settings.es_index)
        except Exception:
            return {}

    def count(self, index: str = None) -> int:
        try:
            return self.es.count(index=index or settings.es_index)["count"]
        except Exception:
            return 0

    @staticmethod
    def _widen_time(query: dict, new_gte: str) -> dict:
        q = copy.deepcopy(query)
        filters = (q["body"].get("query", {})
                             .get("bool", {})
                             .get("filter", []))
        for clause in filters:
            if "range" in clause and "@timestamp" in clause["range"]:
                clause["range"]["@timestamp"]["gte"] = new_gte
                clause["range"]["@timestamp"]["lte"] = "now"
        return q

    @staticmethod
    def _err(msg: str) -> dict:
        return {
            "success": False, "hits": [], "total": 0,
            "took_ms": 0, "aggregations": {}, "warning": None,
            "error": msg, "attempts": 0,
        }