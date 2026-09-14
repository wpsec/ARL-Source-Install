"""
网络协议探测和识别
"""
import os
import json
try:
    from pymongo import UpdateOne
except ImportError:
    UpdateOne = None
from urllib.parse import urlparse
from xing.core import PluginType, PluginRunner
from xing.utils import load_plugins
from xing.yaml_poc import load_yaml_aliases, load_yaml_plugins
from xing.conf import Conf as npoc_conf
from app import utils
from app.modules import PoCCategory
from app.config import Config
from app.utils.log_safety import safe_error_text

logger = utils.get_logger()


class NPoC(object):
    """docstring for ClassName"""

    def __init__(self, concurrency=6, tmp_dir="./"):
        super(NPoC, self).__init__()
        self._plugins = None
        self._poc_info_list = None
        self.concurrency = concurrency
        self._plugin_name_list = None
        self.plugin_name_set = set()
        self._db_plugin_name_list = None
        self.tmp_dir = tmp_dir
        self.runner = None
        self.result = []
        self.brute_plugin_name_set = set()
        self.poc_plugin_name_set = set()
        self.sniffer_plugin_name_set = set()
        self.poc_alias_map = {}
        npoc_conf.TLS_VERIFY = bool(getattr(Config, "SCAN_TLS_VERIFY", True))

    @property
    def plugin_name_list(self) -> list:
        """ xing 中插件名称列表 """

        if self._plugin_name_list is None:
            # 触发下调用
            x = self.poc_info_list
            self._plugin_name_list = list(self.plugin_name_set)

        return self._plugin_name_list

    @property
    def db_plugin_name_list(self) -> list:
        """ 数据库中插件名称列表 """
        if self._db_plugin_name_list is None:
            self._db_plugin_name_list = []
            for item in utils.conn_db('poc').find({}):
                self._db_plugin_name_list.append(item["plugin_name"])

        return self._db_plugin_name_list

    @property
    def plugins(self) -> list:
        """ xing 中插件实例列表 """
        if self._plugins is None:
            self._plugins = self.load_all_poc()

        return self._plugins

    @property
    def poc_info_list(self) -> list:
        """ xing 中插件信息列表 """
        if self._poc_info_list is None:
            self._poc_info_list = self.gen_poc_info()

        return self._poc_info_list

    def load_all_poc(self):
        # 迁移完成的 YAML 先占用稳定 ID，旧 Python 只作为未完成迁移规则的 fallback。
        plugins = load_yaml_plugins()
        self.poc_alias_map = load_yaml_aliases()
        plugins.extend(load_plugins(os.path.join(npoc_conf.PROJECT_DIRECTORY, "plugins")))
        pocs = []
        loaded_names = set()
        for plugin in plugins:
            plugin_name = getattr(plugin, "_plugin_name", "")
            if plugin_name and plugin_name in loaded_names:
                logger.info("skip duplicate plugin fallback {}".format(plugin_name))
                continue
            if plugin_name:
                loaded_names.add(plugin_name)
            if plugin.plugin_type == PluginType.POC:
                pocs.append(plugin)

            if plugin.plugin_type == PluginType.BRUTE:
                pocs.append(plugin)

            if plugin.plugin_type == PluginType.SNIFFER:
                pocs.append(plugin)

        return pocs

    def gen_poc_info(self):
        info_list = []
        for p in self.plugins:
            info = dict()
            info["plugin_name"] = getattr(p, "_plugin_name", "")
            if p.plugin_type == PluginType.SNIFFER:
                self.sniffer_plugin_name_set.add(info["plugin_name"])
                continue

            info["app_name"] = p.app_name
            info["scheme"] = ",".join(p.scheme)
            info["vul_name"] = p.vul_name
            info["plugin_type"] = p.plugin_type
            info["engine"] = getattr(p, "poc_engine", "python")
            info["source"] = getattr(p, "poc_source", "npoc")
            info["status"] = getattr(p, "status", "ready")
            info["severity"] = getattr(p, "severity", "")
            info["tags"] = getattr(p, "tags", [])
            info["finger"] = getattr(p, "finger", info["app_name"])

            if p.plugin_type == PluginType.POC:
                info["category"] = PoCCategory.POC
                self.poc_plugin_name_set.add(info["plugin_name"])

            if p.plugin_type == PluginType.BRUTE:
                self.brute_plugin_name_set.add(info["plugin_name"])
                if "http" in info["scheme"]:
                    info["category"] = PoCCategory.WEBB_RUTE
                else:
                    info["category"] = PoCCategory.SYSTEM_BRUTE

            if info["plugin_name"] in self.plugin_name_set:
                logger.warning("plugin {} already exists".format(info["plugin_name"]))
                continue
            self.plugin_name_set.add(info["plugin_name"])
            info_list.append(info)

        return info_list

    def sync_to_db(self):
        documents = []
        for old in self.poc_info_list:
            new = old.copy()
            new["update_date"] = utils.curr_date()
            documents.append(new)

        info_by_name = {item["plugin_name"]: item for item in self.poc_info_list}
        for alias, target in getattr(self, "poc_alias_map", {}).items():
            target_info = info_by_name.get(target)
            if not target_info:
                logger.warning("skip POC alias without target {} -> {}".format(alias, target))
                continue
            alias_info = target_info.copy()
            alias_info["plugin_name"] = alias
            alias_info["alias_of"] = target
            alias_info["update_date"] = utils.curr_date()
            documents.append(alias_info)

        collection = utils.conn_db("poc")
        # 大批量同步使用 ordered=False，避免单条慢写放大同步耗时；小型测试替身和旧驱动继续走兼容路径。
        if len(documents) > 50 and callable(getattr(collection, "bulk_write", None)) and UpdateOne:
            for offset in range(0, len(documents), 500):
                operations = [
                    UpdateOne(
                        {"plugin_name": item["plugin_name"]},
                        {"$set": item},
                        upsert=True,
                    )
                    for item in documents[offset:offset + 500]
                ]
                collection.bulk_write(operations, ordered=False)
        else:
            for item in documents:
                collection.update_one(
                    {"plugin_name": item["plugin_name"]},
                    {"$set": item},
                    upsert=True,
                )

        logger.info("sync POC metadata documents:{} aliases:{}".format(
            len(self.poc_info_list), len(documents) - len(self.poc_info_list)))

        return True

    def delete_db(self):
        poc_alias_map = getattr(self, "poc_alias_map", {})
        for name in self.db_plugin_name_list:
            if name not in set(self.plugin_name_list) | set(poc_alias_map):
                query = {"plugin_name": name}
                utils.conn_db('poc').delete_one(query)

        return True

    def run_poc(self, plugin_name_list, targets):
        self.result = []
        npoc_conf.SAVE_TEXT_RESULT_FILENAME = ""
        random_file = os.path.join(self.tmp_dir, "npoc_result_{}.txt".format(utils.random_choices()))
        npoc_conf.SAVE_JSON_RESULT_FILENAME = random_file
        runner = self.runner or self.prepare_runner(plugin_name_list, targets)

        try:
            runner.run()
        except Exception as exc:
            self.result.append({
                "plg_name": "__runner__",
                "target": "",
                "result_status": "partial",
                "error_type": type(exc).__name__,
                "error": safe_error_text(exc, max_length=500),
            })

            for error_item in list(getattr(runner, "errors", []) or []):
                self.result.append({
                    "plg_name": error_item.get("plugin_name", ""),
                    "target": error_item.get("target", ""),
                    "result_status": "partial",
                    "error_type": error_item.get("error_type", "PluginError"),
                    "error": safe_error_text(error_item.get("error", ""), max_length=500),
                })

            if not os.path.exists(random_file):
                return self.result

            for item in utils.load_file(random_file):
                try:
                    self.result.append(json.loads(item))
                except (TypeError, ValueError) as exc:
                    self.result.append({
                        "plg_name": "__result__",
                        "target": "",
                        "result_status": "partial",
                        "error_type": type(exc).__name__,
                        "error": safe_error_text(exc, max_length=500),
                    })
        finally:
            if os.path.exists(random_file):
                try:
                    os.unlink(random_file)
                except OSError as exc:
                    logger.warning("remove NPoC result file failed path:{} error_type:{}".format(
                        random_file, type(exc).__name__))

        return self.result

    def prepare_runner(self, plugin_name_list, targets):
        """在线程启动前建立 runner，避免进度读取和执行初始化发生竞态。"""
        plugins = self.filter_plugin_by_name(plugin_name_list)
        self.runner = PluginRunner.PluginRunner(
            plugins=plugins,
            targets=targets,
            concurrency=self.concurrency,
        )
        return self.runner

    def run_all_poc(self, targets):
        return self.run_poc(self.plugin_name_list, targets)

    def filter_plugin_by_name(self, plugin_name_list):
        requested = {str(name).strip() for name in (plugin_name_list or []) if str(name).strip()}
        requested.update(
            self.poc_alias_map.get(name)
            for name in list(requested)
            if self.poc_alias_map.get(name)
        )
        plugins = []
        for plugin in self.plugins:
            curr_name = getattr(plugin, "_plugin_name", "")
            if not curr_name:
                continue
            if curr_name in requested:
                plugins.append(plugin)
        return plugins


def sync_to_db(del_flag=False):
    n = NPoC()
    n.sync_to_db()
    if del_flag:
        n.delete_db()
    return True


def run_risk_cruising(plugins, targets):
    n = NPoC(tmp_dir=Config.TMP_PATH, concurrency=Config.NPOC_POC_CONCURRENCY)
    return n.run_poc(plugins, targets)


def run_sniffer(targets, skip_common_http_ports=True):
    n = NPoC(concurrency=Config.NPOC_SNIFFER_CONCURRENCY, tmp_dir=Config.TMP_PATH)
    new_targets = []
    target_set = set()
    skip_port_set = set()
    if skip_common_http_ports:
        skip_port_set = {"80", "443"}

    # 兼容旧逻辑：默认跳过80/443；需要全端口识别时可关闭该开关
    for t in targets:
        t = str(t).strip()
        if not t:
            continue

        if ":" not in t:
            continue

        host, port = t.rsplit(":", 1)
        if not host or not port:
            continue

        if port in skip_port_set:
            continue

        if t in target_set:
            continue
        target_set.add(t)
        new_targets.append(t)

    items = n.run_poc(n.sniffer_plugin_name_set, new_targets)
    ret = []
    for result in items:
        target = str(result.get("verify_data", "")).strip()
        if "://" not in target:
            continue

        parsed = urlparse(target)
        scheme = str(parsed.scheme or "").strip().lower()
        host = str(parsed.hostname or "").strip()
        port = parsed.port

        if not scheme or not host or port is None:
            continue

        item = {
            "scheme": scheme,
            "host": host,
            "port": str(port),
            "target": target
        }
        ret.append(item)

    return ret
