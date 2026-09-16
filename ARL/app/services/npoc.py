"""
网络协议探测和识别
"""
import os
import json
import multiprocessing
import time
try:
    from pymongo import UpdateOne
except ImportError:
    UpdateOne = None
from urllib.parse import urlparse
from xing.core import PluginType, PluginRunner
from xing.core.request_context import RequestExecutionContext
from xing.utils import load_plugins
from xing.yaml_poc import load_yaml_aliases, load_yaml_plugins
from xing.conf import Conf as npoc_conf
from app import utils
from app.modules import PoCCategory
from app.config import Config
from app.utils.log_safety import safe_error_text

logger = utils.get_logger()


class NPoCScanResult(list):
    """兼容旧 list 返回值，同时携带扫描阶段的完整性指标。"""

    def __init__(self, values=None, metrics=None):
        super(NPoCScanResult, self).__init__(values or [])
        self.metrics = dict(metrics or {})


def _normalize_text_values(value):
    if value is None:
        return []
    if isinstance(value, dict):
        values = [value.get("name"), value.get("value"), value.get("product")]
    elif isinstance(value, (list, tuple, set)):
        values = []
        for item in value:
            values.extend(_normalize_text_values(item))
        return values
    else:
        values = [value]
    return [str(item or "").strip().lower() for item in values if str(item or "").strip()]


def _normalize_fingerprint(value):
    names = set()
    for item in _normalize_text_values(value):
        normalized = " ".join(item.split())
        if not normalized:
            continue
        names.add(normalized)
        for token in normalized.replace("/", " ").replace("_", " ").split():
            if len(token) >= 3:
                names.add(token)
    return names


def _profile_for_target(target_profiles, target):
    profiles = target_profiles or {}
    text = str(target or "").strip()
    if text in profiles:
        return profiles[text]
    try:
        parsed = urlparse(text if "://" in text else "//" + text)
        host = str(parsed.hostname or "").strip().lower().rstrip(".")
    except ValueError:
        host = ""
    return profiles.get(host, {}) if host else {}


def _new_target_profile():
    return {
        "schemes": set(),
        "fingerprints": set(),
        "services": set(),
        "cdn": False,
    }


def _merge_target_profile(target_profiles, key, profile):
    if not key:
        return
    target_profiles.setdefault(key, _new_target_profile())
    current = target_profiles[key]
    for field in ("schemes", "fingerprints", "services"):
        current.setdefault(field, set()).update(profile.get(field, set()) or set())
    current["cdn"] = bool(current.get("cdn") or profile.get("cdn"))


def build_npoc_target_profiles(task_id, targets):
    """读取已完成的站点/服务画像，减少无效的插件-目标组合。"""
    target_list = [str(item or "").strip() for item in targets or [] if str(item or "").strip()]
    profiles = {}
    if not target_list:
        return profiles

    exact_targets = set(target_list)
    try:
        site_query = {"task_id": task_id, "site": {"$in": list(exact_targets)}}
        fields = {
            "site": 1,
            "finger": 1,
            "http_server": 1,
            "cdn_name": 1,
            "is_cdn": 1,
        }
        for item in utils.conn_db("site").find(site_query, fields):
            site = str(item.get("site", "") or "").strip()
            if not site:
                continue
            profile = _new_target_profile()
            scheme = str(urlparse(site).scheme or "").strip().lower()
            if scheme:
                profile["schemes"].add(scheme)
            profile["fingerprints"].update(_normalize_fingerprint(item.get("finger", [])))
            profile["fingerprints"].update(_normalize_fingerprint(item.get("http_server", "")))
            profile["cdn"] = bool(item.get("is_cdn") or item.get("cdn_name"))
            _merge_target_profile(profiles, site, profile)
            try:
                host = str(urlparse(site).hostname or "").strip().lower().rstrip(".")
            except ValueError:
                host = ""
            _merge_target_profile(profiles, host, profile)
    except Exception as exc:
        logger.warning(
            "build NPoC site profiles failed task_id:{} error_type:{}".format(
                task_id, type(exc).__name__
            )
        )

    try:
        service_query = {"task_id": task_id, "target": {"$in": list(exact_targets)}}
        fields = {"target": 1, "scheme": 1, "service": 1, "finger": 1, "fingerprints": 1}
        for item in utils.conn_db("npoc_service").find(service_query, fields):
            target = str(item.get("target", "") or "").strip()
            if not target:
                continue
            profile = _new_target_profile()
            scheme = str(item.get("scheme", "") or "").strip().lower()
            if scheme:
                profile["schemes"].add(scheme)
            profile["services"].update(_normalize_fingerprint(item.get("service", "")))
            profile["fingerprints"].update(_normalize_fingerprint(item.get("finger", [])))
            profile["fingerprints"].update(_normalize_fingerprint(item.get("fingerprints", [])))
            _merge_target_profile(profiles, target, profile)
    except Exception as exc:
        logger.warning(
            "build NPoC service profiles failed task_id:{} error_type:{}".format(
                task_id, type(exc).__name__
            )
        )
    return profiles


def _waf_guard_context(guard):
    if guard is None:
        return None
    try:
        return {
            "enabled": bool(getattr(guard, "enabled", False)),
            "smart_skip_enabled": bool(getattr(guard, "smart_skip_enabled", False)),
            "task_id": str(getattr(guard, "task_id", "") or ""),
            "scope_sites": sorted(getattr(guard, "scope_hosts", set()) or []),
            "weak_block_threshold": int(getattr(guard, "weak_block_threshold", 3) or 3),
            "timeout_block_threshold": int(
                getattr(guard, "timeout_block_threshold", 3) or 3
            ),
            "summary": guard.summary(include_all=True),
        }
    except Exception as exc:
        logger.warning("build NPoC WAF context failed error_type:{}".format(type(exc).__name__))
        return None


def _build_child_waf_guard(context):
    if not isinstance(context, dict) or not context.get("enabled"):
        return None
    from app.services.waf_guard import WAFSmartSkipGuard

    guard = WAFSmartSkipGuard(
        enabled=True,
        smart_skip_enabled=bool(context.get("smart_skip_enabled", True)),
        task_id=str(context.get("task_id", "") or ""),
        scope_sites=list(context.get("scope_sites") or []),
        weak_block_threshold=int(context.get("weak_block_threshold", 3) or 3),
        timeout_block_threshold=int(context.get("timeout_block_threshold", 3) or 3),
    )
    guard.merge_summary(context.get("summary") or {})
    return guard


class NPoC(object):
    """docstring for ClassName"""

    def __init__(
        self,
        concurrency=6,
        tmp_dir="./",
        waf_guard=None,
        target_profiles=None,
        plugin_timeout_sec=None,
        target_timeout_sec=None,
        stage_timeout_sec=None,
    ):
        super(NPoC, self).__init__()
        self._plugins = None
        self._poc_info_list = None
        self.concurrency = concurrency
        self._plugin_name_list = None
        self.plugin_name_set = set()
        self._db_plugin_name_list = None
        self.tmp_dir = tmp_dir
        self.runner = None
        self.result = NPoCScanResult()
        self.metrics = {}
        self.waf_guard = waf_guard
        self.target_profiles = target_profiles or {}
        self.request_context = None
        self.plugin_timeout_sec = self._config_timeout(
            plugin_timeout_sec, "NPOC_PLUGIN_TIMEOUT_SEC", 60
        )
        self.target_timeout_sec = self._config_timeout(
            target_timeout_sec, "NPOC_TARGET_TIMEOUT_SEC", 300
        )
        self.stage_timeout_sec = self._config_timeout(
            stage_timeout_sec, "NPOC_STAGE_TIMEOUT_SEC", 1800
        )
        self.brute_plugin_name_set = set()
        self.poc_plugin_name_set = set()
        self.sniffer_plugin_name_set = set()
        self.poc_alias_map = {}
        npoc_conf.TLS_VERIFY = bool(getattr(Config, "SCAN_TLS_VERIFY", True))

    @staticmethod
    def _config_timeout(value, name, default):
        try:
            result = float(getattr(Config, name, default) if value is None else value)
        except (TypeError, ValueError):
            result = float(default)
        return max(0.0, result)

    @staticmethod
    def _target_scheme(target):
        try:
            parsed = urlparse(str(target or "").strip())
        except ValueError:
            return ""
        if parsed.scheme:
            return parsed.scheme.lower()
        return ""

    @staticmethod
    def _plugin_schemes(plugin):
        values = _normalize_text_values(getattr(plugin, "scheme", []))
        schemes = set()
        for value in values:
            if value in {"http/https", "https/http", "http|https", "https|http"}:
                schemes.update({"http", "https"})
            else:
                schemes.update(item.strip() for item in value.split(",") if item.strip())
        if not schemes:
            fallback = str(getattr(plugin, "target_scheme", "") or "").strip().lower()
            if fallback:
                schemes.add(fallback)
        return schemes

    @staticmethod
    def _is_generic_fingerprint(value):
        return str(value or "").strip().lower() in {
            "", "*", "all", "any", "generic", "web", "http", "https", "tcp",
        }

    def _fingerprints_match(self, plugin, profile):
        target_fingerprints = set(profile.get("fingerprints", set()) or set())
        target_fingerprints.update(profile.get("services", set()) or set())
        target_fingerprints = {
            item for item in target_fingerprints if not self._is_generic_fingerprint(item)
        }
        if not target_fingerprints:
            return True

        plugin_fingerprints = _normalize_fingerprint(getattr(plugin, "finger", ""))
        plugin_fingerprints.update(_normalize_fingerprint(getattr(plugin, "app_name", "")))
        plugin_fingerprints = {
            item for item in plugin_fingerprints if not self._is_generic_fingerprint(item)
        }
        if not plugin_fingerprints:
            return True

        for plugin_finger in plugin_fingerprints:
            for target_finger in target_fingerprints:
                if (
                    plugin_finger == target_finger
                    or plugin_finger in target_finger
                    or target_finger in plugin_finger
                ):
                    return True
        return False

    def _pair_is_eligible(self, plugin, target):
        profile = _profile_for_target(self.target_profiles, target)
        target_scheme = self._target_scheme(target)
        plugin_schemes = self._plugin_schemes(plugin)
        if target_scheme and plugin_schemes:
            normalized_plugin_schemes = {"web": "http"}
            normalized_plugin_schemes = {
                normalized_plugin_schemes.get(item, item)
                for item in plugin_schemes
            }
            if target_scheme not in normalized_plugin_schemes and "all" not in normalized_plugin_schemes:
                return False
        return self._fingerprints_match(plugin, profile)

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
        self.result = NPoCScanResult()
        target_list = []
        seen_targets = set()
        for target in targets or []:
            target_text = str(target or "").strip()
            if not target_text or target_text in seen_targets:
                continue
            seen_targets.add(target_text)
            target_list.append(target_text)
        self.targets = target_list
        npoc_conf.SAVE_TEXT_RESULT_FILENAME = ""
        random_file = os.path.join(self.tmp_dir, "npoc_result_{}.txt".format(utils.random_choices()))
        npoc_conf.SAVE_JSON_RESULT_FILENAME = random_file
        waf_skipped_count = 0
        runner = self.runner
        runner_was_prepared = runner is not None
        runner_targets = list(getattr(runner, "targets", []) or []) if runner else target_list
        if self.waf_guard is not None:
            target_list, waf_skipped_count = self.waf_guard.filter_targets(
                runner_targets,
                module="npoc",
                preclassify=True,
            )
            if runner is not None:
                runner.targets = target_list
        if not target_list:
            requested_pair_count = len(plugin_name_list or []) * len(runner_targets)
            metrics = {
                "status": "partial" if waf_skipped_count else "success",
                "end_reason": "waf_circuit_breaker" if waf_skipped_count else "completed",
                "requested_pair_count": requested_pair_count,
                "eligible_pair_count": 0,
                "filtered_pair_count": requested_pair_count,
                "waf_skipped_count": int(waf_skipped_count),
                "output_count": 0,
                "metrics_complete": True,
            }
            self.metrics = metrics
            self.result.metrics = metrics
            npoc_conf.SAVE_JSON_RESULT_FILENAME = ""
            return self.result
        runner = runner or self.prepare_runner(plugin_name_list, target_list)
        runner_error = None

        try:
            runner.run()
        except Exception as exc:
            runner_error = exc

        if runner_error is not None:
            self.result.append({
                "plg_name": "__runner__",
                "target": "",
                "result_status": "partial",
                "error_type": type(runner_error).__name__,
                "error": safe_error_text(runner_error, max_length=500),
            })

        for error_item in list(getattr(runner, "errors", []) or []):
            self.result.append({
                "plg_name": error_item.get("plugin_name", ""),
                "target": error_item.get("target", ""),
                "result_status": "partial",
                "error_type": error_item.get("error_type", "PluginError"),
                "error": safe_error_text(error_item.get("error", ""), max_length=500),
            })

        if os.path.exists(random_file):
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

        if os.path.exists(random_file):
            try:
                os.unlink(random_file)
            except OSError as exc:
                logger.warning("remove NPoC result file failed path:{} error_type:{}".format(
                    random_file, type(exc).__name__))

        runner_metrics = getattr(runner, "request_context", None)
        context_metrics = runner_metrics.snapshot() if runner_metrics is not None else {}
        requested_pair_count = int(
            getattr(
                runner,
                "requested_pair_count",
                len(plugin_name_list or []) * len(runner_targets),
            )
            or 0
        )
        if not runner_was_prepared:
            requested_pair_count += waf_skipped_count * len(plugin_name_list or [])
        eligible_pair_count = int(getattr(runner, "eligible_pair_count", 0) or 0)
        filtered_pair_count = max(requested_pair_count - eligible_pair_count, 0)
        timeout_count = int(context_metrics.get("timeout_count", 0) or 0)
        plugin_timeout_count = int(context_metrics.get("plugin_timeout_count", 0) or 0)
        target_timeout_count = int(context_metrics.get("target_timeout_count", 0) or 0)
        stage_timeout = bool(
            runner_metrics is not None and runner_metrics.deadline_reached()
        )
        partial = bool(
            runner_error
            or getattr(runner, "errors", None)
            or waf_skipped_count
            or timeout_count
            or plugin_timeout_count
            or target_timeout_count
            or stage_timeout
            or any(item.get("result_status") == "partial" for item in self.result)
        )
        if stage_timeout:
            end_reason = "stage_timeout"
        elif target_timeout_count:
            end_reason = "target_timeout"
        elif plugin_timeout_count:
            end_reason = "plugin_timeout"
        elif timeout_count:
            end_reason = "request_timeout"
        elif waf_skipped_count:
            end_reason = "waf_circuit_breaker"
        elif runner_error:
            end_reason = "runner_error"
        else:
            end_reason = "completed"

        metrics = dict(context_metrics)
        metrics.update({
            "status": "partial" if partial else "success",
            "end_reason": end_reason,
            "requested_pair_count": requested_pair_count,
            "eligible_pair_count": eligible_pair_count,
            "filtered_pair_count": filtered_pair_count,
            "waf_skipped_count": int(waf_skipped_count),
            "output_count": len(self.result),
            "metrics_complete": True,
        })
        self.metrics = metrics
        self.result.metrics = metrics
        return self.result

    def prepare_runner(self, plugin_name_list, targets):
        """在线程启动前建立 runner，避免进度读取和执行初始化发生竞态。"""
        plugins = self.filter_plugin_by_name(plugin_name_list)
        self.request_context = RequestExecutionContext(
            guard=self.waf_guard,
            module="npoc",
            plugin_timeout_sec=self.plugin_timeout_sec,
            target_timeout_sec=self.target_timeout_sec,
            stage_timeout_sec=self.stage_timeout_sec,
        )
        self.runner = PluginRunner.PluginRunner(
            plugins=plugins,
            targets=targets,
            concurrency=self.concurrency,
            pair_filter=self._pair_is_eligible,
            request_context=self.request_context,
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


def _write_npoc_ipc_payload(path, payload):
    temp_path = "{}.tmp".format(path)
    try:
        with open(temp_path, "w", encoding="utf-8") as output:
            json.dump(payload, output, ensure_ascii=False, default=str)
        os.replace(temp_path, path)
        return True
    except (OSError, TypeError, ValueError) as exc:
        logger.warning(
            "write NPoC IPC payload failed path:{} error_type:{}".format(
                path, type(exc).__name__
            )
        )
        try:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
        except OSError as cleanup_exc:
            logger.debug(
                "remove NPoC IPC temp payload failed error_type:{}".format(
                    type(cleanup_exc).__name__
                )
            )
        return False


def _read_npoc_ipc_payload(path):
    try:
        with open(path, "r", encoding="utf-8") as source:
            return json.load(source)
    except (OSError, TypeError, ValueError) as exc:
        logger.warning(
            "read NPoC IPC payload failed path:{} error_type:{}".format(
                path, type(exc).__name__
            )
        )
        return None


def _cleanup_npoc_ipc_payload(path):
    for candidate in (path, "{}.tmp".format(path)):
        try:
            if os.path.exists(candidate):
                os.unlink(candidate)
        except OSError as exc:
            logger.warning(
                "remove NPoC IPC payload failed path:{} error_type:{}".format(
                    candidate, type(exc).__name__
                )
            )


def _run_npoc_child(
    connection,
    plugins,
    targets,
    concurrency,
    target_profiles,
    waf_context,
    result_path,
):
    """隔离 NPoC 的失控插件，子进程只负责网络探测和结果回传。"""
    try:
        guard = _build_child_waf_guard(waf_context)
        instance = NPoC(
            tmp_dir=Config.TMP_PATH,
            concurrency=concurrency,
            waf_guard=guard,
            target_profiles=target_profiles,
        )
        result = instance.run_poc(plugins, targets)
        payload = {
            "result": list(result),
            "metrics": dict(getattr(result, "metrics", {}) or {}),
            "waf_summary": guard.summary(include_all=True) if guard else None,
        }
        if _write_npoc_ipc_payload(result_path, payload):
            connection.send({"result_path": result_path})
        else:
            connection.send({
                "result": [{
                    "plg_name": "__npoc_child__",
                    "target": "",
                    "result_status": "partial",
                    "error_type": "NPoCIPCWriteError",
                    "error": "NPoC child result could not be persisted",
                }],
                "metrics": {
                    "status": "partial",
                    "end_reason": "child_ipc_error",
                    "metrics_complete": False,
                },
                "waf_summary": None,
            })
    except Exception as exc:
        payload = {
            "result": [{
                "plg_name": "__npoc_child__",
                "target": "",
                "result_status": "partial",
                "error_type": type(exc).__name__,
                "error": safe_error_text(exc, max_length=500),
            }],
            "metrics": {
                "status": "partial",
                "end_reason": "child_error",
                "metrics_complete": True,
            },
            "waf_summary": None,
        }
        try:
            if _write_npoc_ipc_payload(result_path, payload):
                connection.send({"result_path": result_path})
            else:
                connection.send(payload)
        except (BrokenPipeError, EOFError, OSError) as send_exc:
            logger.warning(
                "send NPoC child error failed error_type:{}".format(type(send_exc).__name__)
            )
    finally:
        try:
            connection.close()
        except OSError as exc:
            logger.debug("close NPoC child pipe failed error_type:{}".format(type(exc).__name__))


def run_risk_cruising(
    plugins,
    targets,
    waf_guard=None,
    target_profiles=None,
    isolate=None,
):
    """执行 PoC；默认以独立进程承载阶段硬超时。"""
    target_list = list(targets or [])
    plugin_list = list(plugins or [])
    if target_profiles is None:
        target_profiles = {}
    if isolate is None:
        isolate = bool(getattr(Config, "NPOC_PROCESS_ISOLATION_ENABLE", True))
    stage_timeout = NPoC._config_timeout(None, "NPOC_STAGE_TIMEOUT_SEC", 1800)
    if not isolate or stage_timeout <= 0:
        instance = NPoC(
            tmp_dir=Config.TMP_PATH,
            concurrency=Config.NPOC_POC_CONCURRENCY,
            waf_guard=waf_guard,
            target_profiles=target_profiles,
        )
        return instance.run_poc(plugin_list, target_list)
    waf_context = _waf_guard_context(waf_guard)
    try:
        process_context = multiprocessing.get_context("fork")
    except ValueError:
        process_context = multiprocessing.get_context()
        logger.warning("NPoC fork 不可用，使用当前平台 multiprocessing context")
    parent_conn, child_conn = process_context.Pipe(duplex=False)
    result_path = os.path.join(
        Config.TMP_PATH,
        "npoc_ipc_{}.json".format(utils.random_choices()),
    )
    process = process_context.Process(
        target=_run_npoc_child,
        args=(
            child_conn,
            plugin_list,
            target_list,
            Config.NPOC_POC_CONCURRENCY,
            target_profiles,
            waf_context,
            result_path,
        ),
        name="arl-npoc-stage",
    )
    process.daemon = True
    started = time.monotonic()
    try:
        process.start()
    except Exception as exc:
        parent_conn.close()
        child_conn.close()
        _cleanup_npoc_ipc_payload(result_path)
        logger.warning(
            "start isolated NPoC failed error_type:{}, fallback in process".format(
                type(exc).__name__
            )
        )
        instance = NPoC(
            tmp_dir=Config.TMP_PATH,
            concurrency=Config.NPOC_POC_CONCURRENCY,
            waf_guard=waf_guard,
            target_profiles=target_profiles,
        )
        return instance.run_poc(plugin_list, target_list)
    child_conn.close()
    payload = None
    deadline = time.monotonic() + stage_timeout

    def receive_child_payload():
        try:
            message = parent_conn.recv()
        except (EOFError, OSError) as exc:
            logger.warning(
                "receive NPoC child result failed error_type:{}".format(
                    type(exc).__name__
                )
            )
            return None
        if (
            isinstance(message, dict)
            and message.get("result_path")
            and str(message.get("result_path")) == result_path
        ):
            return _read_npoc_ipc_payload(result_path)
        return message

    while process.is_alive() and time.monotonic() < deadline:
        remaining = max(0.05, deadline - time.monotonic())
        if parent_conn.poll(min(0.5, remaining)):
            payload = receive_child_payload()
            break
        process.join(min(0.5, remaining))
    if payload is None and parent_conn.poll(0.1):
        payload = receive_child_payload()
    if payload is not None and process.is_alive():
        process.join(2.0)
    if process.is_alive() and payload is None:
        process.terminate()
        grace = NPoC._config_timeout(None, "NPOC_PROCESS_KILL_GRACE_SEC", 5)
        process.join(grace)
        if process.is_alive():
            kill = getattr(process, "kill", None)
            if callable(kill):
                kill()
                process.join(grace)
        parent_conn.close()
        _cleanup_npoc_ipc_payload(result_path)
        elapsed = time.monotonic() - started
        logger.warning(
            "NPoC stage hard timeout after {:.1f}s, child terminated".format(elapsed)
        )
        return NPoCScanResult(
            [{
                "plg_name": "__npoc_stage__",
                "target": "",
                "result_status": "partial",
                "error_type": "NPoCStageTimeout",
                "error": "NPoC stage deadline exceeded",
            }],
            metrics={
                "status": "partial",
                "end_reason": "stage_timeout",
                "stage_timeout_sec": stage_timeout,
                "metrics_complete": False,
            },
        )
    if process.is_alive():
        # 结果已完整收到；子进程只剩收尾线程时不再把正常结果误判为阶段超时。
        process.terminate()
        grace = NPoC._config_timeout(None, "NPOC_PROCESS_KILL_GRACE_SEC", 5)
        process.join(grace)
        if process.is_alive():
            kill = getattr(process, "kill", None)
            if callable(kill):
                kill()
                process.join(grace)
    if payload is None and parent_conn.poll(2.0):
        payload = receive_child_payload()
    parent_conn.close()
    _cleanup_npoc_ipc_payload(result_path)
    if not isinstance(payload, dict):
        return NPoCScanResult(
            [{
                "plg_name": "__npoc_child__",
                "target": "",
                "result_status": "partial",
                "error_type": "NPoCChildNoResult",
                "error": "NPoC child exited without a result",
            }],
            metrics={
                "status": "partial",
                "end_reason": "child_no_result",
                "metrics_complete": False,
            },
        )
    if waf_guard is not None and payload.get("waf_summary"):
        waf_guard.merge_summary(payload.get("waf_summary"))
    return NPoCScanResult(
        payload.get("result") or [],
        metrics=payload.get("metrics") or {},
    )


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
