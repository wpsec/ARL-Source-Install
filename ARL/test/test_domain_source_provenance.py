import unittest
from unittest.mock import patch

from app.modules import DomainInfo
from app.repositories import DomainRepository
from app.services.collection_query_service import normalize_domain_source_query
from app.tasks.domain import DomainTask


class _Collection(object):
    def __init__(self):
        self.calls = []

    def update_many(self, *args, **kwargs):
        self.calls.append(("update_many", args, kwargs))
        return "merged"

    def update_one(self, *args, **kwargs):
        self.calls.append(("update_one", args, kwargs))
        return "upserted"


class _QueryPluginResult(list):
    def __init__(self, values):
        super().__init__(values)
        self.metrics = {}


class TestDomainSourceProvenance(unittest.TestCase):
    def test_domain_task_merges_sources_before_domain_deduplication(self):
        task = DomainTask(
            base_domain="example.com",
            task_id="task-1",
            options={"port_scan_type": "test"},
        )

        with patch.object(DomainRepository, "add_sources_by_domains") as merge_sources:
            task.add_domain_source_names(["A.Example.com.", "a.example.com"], "fofa")
            task.add_domain_source_names(["a.example.com"], "hunter_how")

        self.assertEqual(task.domain_source_map["a.example.com"], {"fofa", "hunter_how"})
        self.assertEqual(merge_sources.call_count, 2)

    def test_save_uses_one_upsert_with_all_sources(self):
        task = DomainTask(
            base_domain="example.com",
            task_id="task-1",
            options={"port_scan_type": "test"},
        )
        task.domain_source_map = {"a.example.com": {"fofa", "hunter_how"}}
        info = DomainInfo(
            domain="a.example.com",
            record=["a.example.com"],
            type="CNAME",
            ips=[],
        )

        with patch.object(DomainRepository, "upsert_discovered_domain") as upsert:
            task.save_domain_info_list([info], source="fofa")

        self.assertEqual(upsert.call_count, 1)
        self.assertEqual(upsert.call_args.kwargs["primary_source"], "fofa")
        self.assertEqual(upsert.call_args.kwargs["sources"], ["fofa", "hunter_how"])

    def test_repository_upsert_writes_compatibility_and_complete_source_fields(self):
        collection = _Collection()
        info = {
            "domain": "A.Example.com.",
            "type": "A",
            "record": ["1.1.1.1"],
            "ips": ["1.1.1.1"],
        }

        with patch("app.repositories.domain_repository.utils.conn_db", return_value=collection):
            DomainRepository.upsert_discovered_domain(
                task_id="task-1",
                domain_info=info,
                primary_source="certspotter",
                sources=["certspotter", "fofa", "certspotter"],
            )

        operation = collection.calls[0]
        self.assertEqual(operation[0], "update_one")
        self.assertEqual(operation[1][0], {"task_id": "task-1", "domain": "a.example.com"})
        update = operation[1][1]
        self.assertEqual(update["$setOnInsert"], {"source": "certspotter"})
        self.assertEqual(update["$addToSet"], {
            "sources": {"$each": ["certspotter", "fofa"]},
        })
        self.assertTrue(operation[2]["upsert"])

    def test_domain_source_filter_matches_legacy_and_aggregated_fields(self):
        query = {"task_id": "task-1", "source": {"$regex": "fofa", "$options": "i"}}

        normalized = normalize_domain_source_query("domain", query)

        self.assertNotIn("source", normalized)
        self.assertEqual(normalized["$or"], [
            {"source": {"$regex": "fofa", "$options": "i"}},
            {"sources": {"$regex": "fofa", "$options": "i"}},
        ])

    def test_asset_domain_source_filter_matches_legacy_and_aggregated_fields(self):
        query = {"scope_id": "scope-1", "source": {"$regex": "fofa", "$options": "i"}}

        normalized = normalize_domain_source_query("asset_domain", query)

        self.assertNotIn("source", normalized)
        self.assertEqual(len(normalized["$or"]), 2)

    def test_dns_query_plugin_builds_each_domain_once_and_keeps_all_sources(self):
        task = DomainTask(
            base_domain="example.com",
            task_id="task-1",
            options={"port_scan_type": "test", "dns_query_plugin": True},
        )
        infos = [
            DomainInfo(
                domain="a.example.com",
                record=["1.1.1.1"],
                type="A",
                ips=["1.1.1.1"],
            ),
            DomainInfo(
                domain="b.example.com",
                record=["2.2.2.2"],
                type="A",
                ips=["2.2.2.2"],
            ),
        ]

        def query_plugin(_target, sources):
            values = []
            if "fofa" in sources:
                values.extend([
                    {"domain": "a.example.com", "source": "fofa"},
                    {"domain": "b.example.com", "source": "fofa"},
                ])
            if "hunter_how" in sources:
                values.append({"domain": "a.example.com", "source": "hunter_how"})
            return _QueryPluginResult(values)

        with patch.object(task, "_resolve_dns_query_sources", return_value=["fofa", "hunter_how"]), \
                patch("app.tasks.domain.run_query_plugin", side_effect=query_plugin), \
                patch.object(task, "build_domain_info", return_value=infos) as build_info, \
                patch.object(task, "clear_domain_info_by_record", side_effect=lambda value: value), \
                patch.object(task, "save_domain_info_list") as save_info, \
                patch.object(DomainRepository, "add_sources_by_domains"):
            task.dns_query_plugin()

        self.assertEqual(build_info.call_count, 1)
        self.assertEqual(
            set(build_info.call_args.args[0]),
            {"a.example.com", "b.example.com"},
        )
        self.assertEqual(task.domain_source_map["a.example.com"], {"fofa", "hunter_how"})
        self.assertEqual(task.domain_source_map["b.example.com"], {"fofa"})
        self.assertEqual(len(task.domain_info_list), 2)
        self.assertEqual(save_info.call_count, 1)
        self.assertEqual(save_info.call_args.kwargs["source"], "fofa")
        self.assertEqual(len(save_info.call_args.args[0]), 2)
        self.assertEqual(task._last_dns_query_metrics["unique_domain_count"], 2)
        self.assertEqual(task._last_dns_query_metrics["domain_dedup_count"], 1)

    def test_domain_task_passes_shared_dns_policy_cache_to_builder(self):
        task = DomainTask(
            base_domain="example.com",
            task_id="task-1",
            options={"port_scan_type": "test"},
        )

        with patch("app.tasks.domain.services.build_domain_info", return_value=[]) as build_info:
            task.build_domain_info(["a.example.com"])

        self.assertIs(build_info.call_args.kwargs["dns_policy_cache"], task._dns_policy_cache)


if __name__ == "__main__":
    unittest.main()
