#!/usr/bin/env python3
"""把 ARL-NPoC 的 40 个漏洞验证插件迁移为 YAML 规则。

这些 YAML 与旧 Python 插件共用稳定 ID。迁移工具只生成等价候选和待验证清单；
只有离线正反向 fixture 验证通过后，运行时才会用 YAML 覆盖同名 Python fallback。
"""

import argparse
import hashlib
import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT_ROOT = ROOT / "xing" / "pocs"


def _info(name, finger, tags):
    return {"name": name, "finger": finger, "severity": "info", "tags": ["legacy", *tags]}


def _http(rule_id, name, finger, paths, expression, tags, **extra):
    request = {
        "method": "GET",
        "paths": paths,
        "expression": expression,
    }
    request.update(extra.pop("request", {}))
    requests = extra.pop("requests", None)
    rule = {
        "id": rule_id,
        "info": _info(name, finger, tags),
        "transport": "http",
        "requests": requests or [request],
    }
    rule.update(extra)
    return rule


def _tcp(rule_id, name, finger, expressions, tags, **extra):
    request = {"expression": expressions}
    request.update(extra.pop("request", {}))
    rule = {
        "id": rule_id,
        "info": _info(name, finger, tags),
        "transport": "tcp",
        "tcpRequests": [request],
    }
    rule.update(extra)
    return rule


def legacy_rules():
    identify = "identify"
    noauth = "noauth"
    poc = "poc"
    return [
        _http("Adminer_PHP_Identify", "发现 Adminer.php", "Adminer.php",
              ["/admin/adminer.php", "/adminer.php", "/adminer/adminer.php"],
              'contains(body, ">Login - Adminer<")', [identify],
              request={"headers": {"Accept-Language": "en"}}),
        _http("Any800_Identify", "发现 Any800全渠道智能客服云平台", "Any800",
              ["/any800/echatManager.do", "/ump/umpLogin/login"],
              'matches(body, "new Date\\(nowtime_time\\+offset\\+offset_b\\)|>Any800v")', [identify]),
        _http("Apache_Apereo_CAS_Identify", "发现 Apache Apereo Cas", "Apache Apereo",
              "/cas/login", 'contains(body, "Apereo") && contains(body, "cas")', [identify]),
        _http("Apache_Ofbiz_Identify", "发现 Apache Ofbiz", "Apache Ofbiz",
              "/webtools/control/main", 'contains(header, "OFBiz.Visitor=") or contains(body, ">OFBiz")', [identify]),
        _http("Clickhouse_REST_API_Identify", "发现 Clickhouse REST API", "Clickhouse",
              "/ping", 'contains(header, "read_rows") && contains(body, "Ok.")', [identify]),
        _http("Finereport_Identify", "发现帆软 FineReport", "FineReport",
              [
                  "/webroot/ReportServer?op=resource&resource=/com/fr/web/jquery.js",
                  "/WebReport/ReportServer?op=resource&resource=/com/fr/web/jquery.js",
                  "/seeyonreport/ReportServer?op=resource&resource=/com/fr/web/jquery.js",
              ], 'contains(body, "jQuery=") && !contains(body, "<title>")', [identify]),
        _http("FinereportV10_Identify", "发现帆软 FineReport V10", "FineReport",
              ["/webroot/decision/system/info", "/decision/system/info"],
              'contains(body, "frontSeed") && contains(body, "name")', [identify]),
        _http("Grafana_Identify", "发现 Grafana", "Grafana",
              ["/login", "/grafana/login", "/monitor/login"],
              'contains(body, "Grafana</title>")', [identify]),
        _http("Graphql_Identify", "发现 Graphql 接口", "Graphql",
              ["/graphql", "/v2/graphql", "/v1/graphql"],
              'status_code == 400 && contains(body, "query missing") && !contains(body, "<")', [identify],
              request={"headers": {"Accept": "*/*"}}),
        _http("Harbor_Identify", "发现 Harbor API", "Harbor",
              ["/api/systeminfo", "/harbor/api/systeminfo"],
              r'''status_code == 200 && contains(body, '"harbor_version"') && !contains(body, "<")''', [identify]),
        _http("Hystrix_Dashboard_Identify", "发现 Hystrix Dashboard", "Hystrix",
              ["/hystrix", "/", "/api/hystrix", "/actuator/hystrix"],
              'contains(body, ">Hystrix Dashboard<")', [identify]),
        _http("Nacos_Identify", "发现 Nacos", "Nacos", ["/", "/nacos/"],
              'contains(body, "<title>Nacos</title>")', [identify]),
        _http("Oracle_Weblogic_Console_Identify", "发现 Oracle Weblogic 控制台", "weblogic",
              ["/#/console/css/test.css", "/#/../console/css/test.css", "/#/../../console/css/test.css",
               "/console/css/test.css;/../../../"],
              'contains(body, "WLS Administration Console")', [identify],
              request={"disable_normal": True}),
        _http("Shiro_Identify", "发现 Apache Shiro", "Shiro", "/",
              'contains(header, "rememberMe=deleteMe")', [identify],
              request={"headers": {"Cookie": "rememberMe=1"}}),
        _http("Swagger_Json_Identify", "发现 Swagger 文档接口", "Swagger",
              ["/swagger.json", "/api/swagger.json", "/swagger/v1/swagger.json", "/v2/api-docs",
               "/api/v2/api-docs", "/api/v2/swagger.json"],
              'status_code == 200 && starts_with(trim(body), "{") && ends_with(trim(body), "}") && contains(body, "paths") && contains(body, "swagger")',
              [identify]),
        _http("vcenter_identify", "发现VMware vCenter", "vCenter", "/sdk",
              'status_code == 200 && matches(body, "<fullName>[^<]+</fullName>")', [identify],
              request={
                  "method": "POST",
                  "data": "<env:Envelope xmlns:env=\"http://schemas.xmlsoap.org/soap/envelope/\"><env:Body><RetrieveServiceContent xmlns=\"urn:vim25\"><_this type=\"ServiceInstance\">ServiceInstance</_this></RetrieveServiceContent></env:Body></env:Envelope>",
              }),
        _http("Weaver_Ecology_Identify", "发现泛微 Ecology", "Ecology", ["/help/sys/help.html", "/js"],
              'contains(body, "$(this).attr(\\\"src\\\",\\\"image/btn_help_click") or contains(header, "ecology_JSessionid")', [identify]),
        _http("XXL_Job_Admin_Identify", "发现 xxl-job-admin", "xxl-job-admin",
              ["/toLogin", "/xxl-job/toLogin", "/xxl-job-admin/toLogin", "/xxl/toLogin", "/xxljob/toLogin"],
              'contains(body, "<b>XXL</b>JOB")', [identify]),

        _http("Actuator_httptrace_noauth", "Actuator httptrace API 未授权访问", "Actuator",
              ["/actuator/httptrace", "/jeecg-boot/actuator/httptrace", "/actuator;/httptrace",
               "/api/actuator;/httptrace", "/api/actuator/httptrace", "/actuator/httptrace;.css"],
              'contains(body, "{\\\"traces\\\"") && contains(content_type, "actuator")', [noauth]),
        _http("Actuator_noauth_bypass_waf", "Actuator API 未授权访问 (绕过WAF)", "Actuator",
              ["/actuator;/env;.css", "/api/actuator;/env;.css", "/api;/env;.css", "/;/env;.css"],
              'contains(body, "java.runtime.version")', [noauth]),
        _http("Actuator_noauth", "Actuator API 未授权访问", "Actuator",
              ["/env", "/actuator/env", "/manage/env", "/management/env", "/api/env", "/api/actuator/env"],
              'contains(body, "java.runtime.version")', [noauth]),
        _http("Apollo_Adminservice_noauth", "apollo-adminservice 未授权访问", "apollo-adminservice", "/apps",
              r'''!contains(body, "<") && contains(body, '"ownerEmail"') && contains(body, '"ownerName"')''', [noauth]),
        _http("DockerRemoteAPI_noauth", "Docker Remote API 未授权访问", "Docker", "/version",
              r'''contains(body, '"ApiVersion"') && !contains(body, "<")''', [noauth]),
        _http("Druid_noauth", "Druid 未授权访问", "Druid", "/druid/webapp.json",
              r'''!contains(body, "<") && contains(body, '"ResultCode"') && contains(body, '"RequestCount"')''', [noauth]),
        _http("Elasticsearch_noauth", "Elasticsearch 未授权访问", "Elasticsearch", "/_cat",
              'contains(body, "/_cat/master") && !contains(body, "<")', [noauth]),
        _tcp("Hadoop_YARN_RPC_noauth", "Hadoop YARN RCP 未授权访问漏洞", "Hadoop YARN",
             [
                 'conn.WriteStr(base64_decode("aHJwYwkAAAAAAF8aCAIQABgFIhArOwdm0CFF2Ym70jxlutaBKAFDEgkKB2ZyZWVtYW4aNm9yZy5hcGFjaGUuaGFkb29wLnlhcm4uYXBpLkFwcGxpY2F0aW9uQ2xpZW50UHJvdG9jb2xQQgAAAGgaCAIQABgAIhArOwdm0CFF2Ym70jxlutaBKABLCg9nZXRBcHBsaWNhdGlvbnMSNm9yZy5hcGFjaGUuaGFkb29wLnlhcm4uYXBpLkFwcGxpY2F0aW9uQ2xpZW50UHhgBAA=="))',
                 "conn.ReadStr()",
                 'contains(res, "Exception*") == false && starts_with(res, "\\x00\\x00") && contains(res, "+;\\x07f\\xd0!E")',
             ], [noauth], scheme="hrpc"),
        _http("Headless_remote_API_noauth", "Headless Remote API 未授权访问", "Headless", "/json/version",
              r'''contains(body, '"Protocol-Version"') && !contains(body, "<")''', [noauth]),
        _http("Kibana_noauth", "Kibana 未授权访问", "Kibana", "/app/kibana",
              'contains(body, ".kibanaWelcomeView")', [noauth]),
        _tcp("Memcached_noauth", "Memcached 未授权访问", "Memcached",
             ['conn.WriteStr("stats\\r\\n")', "conn.ReadStr()", 'contains(res, "STAT version")'], [noauth], scheme="memcached"),
        _tcp("Mongodb_noauth", "Mongodb 未授权访问", "Mongodb",
             [
                 'conn.WriteStr(hex_decode("430000000400000000000000d40700000000000061646d696e2e24636d640000000000ffffffff1c000000016c69737444617461626173657300000000000000f03f00"))',
                 "conn.ReadStr()",
                 'contains(res, "sizeOnDisk") && !contains(res, "Unauthorized")',
             ], [noauth], scheme="mongodb"),
        _http("Nacos_noauth", "Nacos 未授权访问", "Nacos",
              ["/v1/auth/users?pageNo=1&pageSize=10", "/nacos/v1/auth/users?pageNo=1&pageSize=10"],
              r'''!contains(body, "<") && contains(body, '"pageNumber"') && contains(body, '"password"')''', [noauth],
              request={"headers": {"User-Agent": "Nacos-Server"}}),
        _http("Onlyoffice_noauth", "Onlyoffice 未授权漏洞", "Onlyoffice", "/ConvertService.ashx",
              'contains(body, "<Error>-7</Error>") && contains(body, "<?xml")', [noauth]),
        _tcp("Redis_noauth", "Redis 未授权访问", "Redis",
             ['conn.WriteStr("info\\r\\n")', "conn.ReadStr()", 'starts_with(res, "$") && contains(res, "redis_version:")'], [noauth], scheme="redis"),
        _http("Solr_noauth", "Apache solr 未授权访问", "solr",
              ["/solr/admin/cores?wt=json&indexInfo=false", "/admin/cores?wt=json&indexInfo=false"],
              '!contains(body, "<") && contains(body, "responseHeader")', [noauth]),
        _tcp("ZooKeeper_noauth", "ZooKeeper 未授权访问", "ZooKeeper",
             ['conn.WriteStr("envi")', "conn.ReadStr()", 'contains(res, "zookeeper.version=")'], [noauth], scheme="zookeeper"),

        _http("Django_Debug_Info", "Django 开启调试模式", "Django", ["/lljfafd", "/api/lljfafd"],
              'status_code == 404 && contains(body, "Django") && contains(body, "DEBUG = True") && contains(body, "<title>Page not found at") && contains(body, "lljfafd</title>")', [poc]),
        _http("Gitlab_Username_Leak", "Gitlab 用户名泄漏", "Gitlab", "/explore/projects",
              'contains(body, "GitLab") && contains(body, "authenticity_token")', [poc],
              requests=[
                  {"method": "GET", "path": "/explore/projects",
                   "expression": 'contains(body, "GitLab") && contains(body, "authenticity_token")'},
                  {"method": "GET", "path": "/api/v4/users/1",
                   "expression": r'''matches(body, '"(message|username)"\s*:')'''},
              ]),
        _http("Ueditor_SSRF", "Ueditor SSRF 漏洞", "Ueditor",
              ["/ueditor/php/controller.php?action=catchimage&source%5b%5d=http://127.0.0.1:6981/?1.png",
               "/Public/ueditor/php/controller.php?action=catchimage&source%5b%5d=http://127.0.0.1:6981/?1.png",
               "/js/ueditor/php/controller.php?action=catchimage&source%5b%5d=http://127.0.0.1:6981/?1.png",
               "/statics/ueditor/php/controller.php?action=catchimage&source%5b%5d=http://127.0.0.1:6981/?1.png",
               "/module/ueditor/php/controller.php?action=catchimage&source%5b%5d=http://127.0.0.1:6981/?1.png"],
              r'''!contains(body, "<") && contains(body, "\\u94fe\\u63a5\\u4e0d\\u53ef\\u7528")''', [poc]),
        _http("Ueditor_Store_XSS", "Ueditor 存储 XSS 漏洞", "Ueditor",
              ["/ueditor/php/controller.php", "/Public/ueditor/php/controller.php", "/js/ueditor/php/controller.php",
               "/statics/ueditor/php/controller.php", "/module/ueditor/php/controller.php", "/ueditor/jsp/controller.jsp"],
              r'''!contains(body, "<") && (contains(body, "\\u8bf7\\u6c42\\u5730\\u5740\\u51fa\\u9519") or contains(body, "upload method not exists"))''', [poc]),
        _http("WEB_INF_WEB_xml_leak", "WEB-INF/web.xml 文件泄漏", "Java", ["/%2e/WEB-INF/web.xml", "/WEB-INF/web.xml.", "/static?/%2557EB-INF/web.xml"],
              'status_code == 200 && contains(body, "</web-app>")', [poc],
              request={"disable_normal": True}),
    ]


def _canonical_hash(rule):
    data = json.dumps(rule, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def migrate(output_root=DEFAULT_OUTPUT_ROOT):
    output_root = Path(output_root).expanduser().resolve()
    yaml_root = output_root / "yaml" / "legacy"
    yaml_root.mkdir(parents=True, exist_ok=True)
    entries = []
    for rule in legacy_rules():
        rule_id = rule["id"]
        target = yaml_root / (rule_id + ".yaml")
        text = yaml.safe_dump(rule, allow_unicode=True, sort_keys=False, default_flow_style=False)
        target.write_text(text, encoding="utf-8")
        entries.append({
            "rule_id": rule_id,
            "canonical_path": str(Path("yaml") / "legacy" / target.name),
            "canonical_sha256": _canonical_hash(rule),
            "canonical_file_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
            "engine": "yaml",
            "source": "legacy-python",
            "status": "pending_fixture",
            "fallback": "python",
            "reason": "等待旧 Python 插件正反向 fixture 等价验证",
        })
    manifest = {
        "schema_version": 1,
        "source": "legacy-python",
        "rule_count": len(entries),
        "ready_count": 0,
        "pending_count": len(entries),
        "entries": entries,
    }
    (output_root / "legacy_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", default=str(DEFAULT_OUTPUT_ROOT))
    args = parser.parse_args(argv)
    manifest = migrate(args.output_root)
    print(json.dumps({"rule_count": manifest["rule_count"], "pending_count": manifest["pending_count"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
