import json
from xing.conf import Conf
from xing.core.BasePlugin import BasePlugin
from xing.core.const import PluginType
from xing.utils.file import append_file
from xing.core.ServiceBrutePlugin import ServiceBrutePlugin


def save_result(plg, msg):
    if not isinstance(plg, BasePlugin):
        raise TypeError("BasePlugin is required")

    text_msg = ""
    if msg and isinstance(plg, ServiceBrutePlugin) and isinstance(msg, dict):
        username = list(msg)[0]
        password = msg[username]
        msg = {
            "username": username,
            "password": password
        }
        text_msg = "{} {}:{}".format(plg.target, username, password)

    yaml_fields = msg if getattr(plg, "poc_engine", "") == "yaml" and isinstance(msg, dict) else {}
    item = {
        "plg_name": getattr(plg, "_plugin_name", ""),
        "plg_type": plg.plugin_type,
        "vul_name": plg.vul_name,
        "app_name": plg.app_name,
        "target": plg.target,
        "verify_data": yaml_fields.get("verify_data", msg),
    }
    if yaml_fields:
        for key in (
            "result_status", "poc_engine", "poc_id", "poc_source", "severity", "tags",
            "request_index", "match_summary", "evidence", "error_type", "error",
        ):
            if key in yaml_fields:
                item[key] = yaml_fields[key]
    else:
        item["poc_engine"] = "python"
        item["poc_source"] = "npoc"
        item["result_status"] = "matched"
        if plg.plugin_type == PluginType.POC:
            # Python POC 没有统一的请求证据对象，保留字段形状但不复制可能含敏感信息的原始响应。
            item["poc_id"] = getattr(plg, "_plugin_name", "")
            item["severity"] = str(getattr(plg, "severity", "info") or "info").lower()
            tags = getattr(plg, "tags", []) or []
            item["tags"] = list(tags) if isinstance(tags, (list, tuple, set)) else [str(tags)]
            item["request_index"] = -1
            item["match_summary"] = ""
            item["evidence"] = {}

    if Conf.SAVE_JSON_RESULT_FILENAME:
        data = json.dumps(item)
        append_file(Conf.SAVE_JSON_RESULT_FILENAME, [data])

    if Conf.SAVE_TEXT_RESULT_FILENAME:
        data = str(msg)
        if text_msg:
            msg = text_msg

        if plg.plugin_type == PluginType.SNIFFER:
            pass

        elif plg.vul_name:
            if isinstance(msg, str) and "://" in msg:
                data = "{}----{}".format(plg.vul_name, msg)
            else:
                data = "{}----{}----{}".format(plg.vul_name, plg.target, msg)

        append_file(Conf.SAVE_TEXT_RESULT_FILENAME, [data])
