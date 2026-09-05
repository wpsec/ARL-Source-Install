import unittest
from app.routes.policy import add_policy_fields, gen_model_policy_keys, change_policy_dict


class TestWebInfoHunter(unittest.TestCase):
    def test_gen_policy_keys(self):
        keys = gen_model_policy_keys(add_policy_fields["policy"])
        self.assertTrue("web_info_hunter" in keys)
        self.assertTrue(len(keys) > 0)

    def test_gen_policy_keys_include_full_strategy_options(self):
        keys = set(gen_model_policy_keys(add_policy_fields["policy"]))
        expected_keys = {
            "alt_dns",
            "dns_query_plugin",
            "arl_search",
            "port_scan",
            "service_detection",
            "os_detection",
            "ssl_cert",
            "skip_scan_cdn_ip",
            "site_identify",
            "search_engines",
            "site_spider",
            "site_capture",
            "nuclei_scan",
            "afrog_scan",
            "web_info_hunter",
            "smart_skip_waf",
            "file_leak",
        }
        self.assertTrue(expected_keys.issubset(keys))

    def test_change_policy_dict(self):
        item = {
            "domain_config": {
                "domain_brute": True,
                "domain_brute_type": "test",
                "alt_dns": False,
                "arl_search": False,
                "dns_query_plugin": False,
            },
            "ip_config": {
                "port_scan": True,
                "port_scan_type": "top100",
                "service_detection": False,
                "os_detection": False,
                "ssl_cert": False,
                "skip_scan_cdn_ip": True,
                "host_timeout": 0,
                "port_parallelism": 32,
                "port_min_rate": 60
            },
            "site_config": {
                "site_identify": False,
                "site_capture": False,
                "search_engines": False,
                "site_spider": False,
                "nuclei_scan": False,
                "afrog_scan": False,
                "waf_bypass": False,
                "smart_skip_waf": False,
            },
            "file_leak": False,
            "npoc_service_detection": False,
            "scope_config": {
                "scope_id": "643cf62215906b51d3159f9e"
            },
            "poc_config": [],
            "brute_config": []
        }

        item = {
            "name": "test",
            "desc": "old desc",
            "policy": item
        }
        policy_data = {
            "domain_config": {"domain_brute": True, "alt_dns": False, "arl_search": True, "dns_query_plugin": False,
                              "domain_brute_type": "big"},
            "ip_config": {
                "port_scan": True,
                "port_scan_type": "custom",
                "service_detection": True,
                "os_detection": True,
                "ssl_cert": True,
                "skip_scan_cdn_ip": False,
                "port_custom": "80,443,8443",
            },
            "site_config": {
                "site_identify": True,
                "site_capture": True,
                "search_engines": True,
                "site_spider": True,
                "nuclei_scan": True,
                "afrog_scan": True,
                "web_info_hunter": True,
                "waf_bypass": True,
                "smart_skip_waf": True,
                "not_exist": True,
            },
            "file_leak": True,
            "npoc_service_detection": True,
        }

        policy_data = {
            "name": "update-name",
            "desc": "test",
            "policy": policy_data
        }

        allow_keys = gen_model_policy_keys(add_policy_fields["policy"])
        allow_keys.extend(["name", "desc", "policy"])

        item = change_policy_dict(item, policy_data, allow_keys)

        self.assertTrue(item["name"] == "update-name")
        self.assertTrue(item["desc"] == "test")

        item = item["policy"]

        self.assertTrue(item["site_config"]["site_identify"])
        self.assertTrue(item["site_config"]["web_info_hunter"])
        self.assertTrue(item["site_config"]["search_engines"])
        self.assertTrue(item["site_config"]["site_spider"])
        self.assertTrue(item["site_config"]["nuclei_scan"])
        self.assertTrue(item["site_config"]["afrog_scan"])
        self.assertTrue(item["site_config"]["smart_skip_waf"])
        # 计划1收口:waf_bypass 旧策略键已随渗透链路删除,不再被模型接受——
        # 请求里携带的 True 值必须被丢弃,原 item 的 False 保持不变。
        self.assertFalse(item["site_config"].get("waf_bypass", False))
        self.assertTrue(item["domain_config"]["arl_search"])
        self.assertTrue(item["ip_config"]["service_detection"])
        self.assertTrue(item["ip_config"]["os_detection"])
        self.assertTrue(item["ip_config"]["ssl_cert"])
        self.assertTrue(item["ip_config"]["port_scan_type"] == "custom")
        self.assertTrue(item["ip_config"]["port_custom"] == "80,443,8443")
        self.assertTrue(item["ip_config"]["port_scan"])
        self.assertTrue(item["file_leak"])
        self.assertTrue(item["npoc_service_detection"])

        self.assertTrue(item["scope_config"]["scope_id"] == "643cf62215906b51d3159f9e")

        self.assertTrue(item["site_config"].get("not_exist") is None)
