import time

from xing.core.BaseThread import BaseThread
from xing.core.BasePlugin import BasePlugin
from xing.core import PluginType
from xing.core.request_context import RequestExecutionContext
from xing.utils import get_logger, append_file
from xing.utils.save_result import save_result


class PluginRunner(object):
    def __init__(self, plugins, targets, concurrency=6, pair_filter=None,
                 request_context=None):
        self.plugins = list(plugins or [])
        self.targets = list(targets or [])
        self.concurrency = max(1, int(concurrency or 1))
        self.pair_filter = pair_filter if callable(pair_filter) else None
        self.request_context = request_context
        self.logger = get_logger()
        self.runner_cnt = 0
        self.errors = []
        self.requested_pair_count = len(self.plugins) * len(self.targets)
        self.eligible_pair_count = 0
        self.filtered_pair_count = 0
        self._target_deadline = None
        self._eligible_plugins_by_target = {}
        self._eligible_targets_by_plugin = {}

    def _is_eligible(self, plugin, target):
        if self.pair_filter is None:
            return True
        try:
            return bool(self.pair_filter(plugin, target))
        except Exception as exc:
            self.logger.warning("plugin target filter failed plugin:%s error:%s",
                                getattr(plugin, "_plugin_name", ""), exc)
            return False

    def _eligible_plugins(self, target):
        if target in self._eligible_plugins_by_target:
            return self._eligible_plugins_by_target[target]
        eligible = [plugin for plugin in self.plugins if self._is_eligible(plugin, target)]
        self._eligible_plugins_by_target[target] = eligible
        return eligible

    def _eligible_targets(self, plugin):
        plugin_key = id(plugin)
        if plugin_key in self._eligible_targets_by_plugin:
            return self._eligible_targets_by_plugin[plugin_key]
        eligible = [target for target in self.targets if self._is_eligible(plugin, target)]
        self._eligible_targets_by_plugin[plugin_key] = eligible
        return eligible

    def plan(self):
        self._eligible_plugins_by_target = {}
        self._eligible_targets_by_plugin = {
            id(plugin): [] for plugin in self.plugins
        }
        eligible = 0
        for target in self.targets:
            target_plugins = self._eligible_plugins(target)
            eligible += len(target_plugins)
            for plugin in target_plugins:
                self._eligible_targets_by_plugin[id(plugin)].append(target)
        self.eligible_pair_count = eligible
        self.filtered_pair_count = max(self.requested_pair_count - eligible, 0)
        return self.eligible_pair_count

    def _target_deadline_for(self):
        timeout_sec = 0.0
        context = self.request_context
        if isinstance(context, RequestExecutionContext):
            timeout_sec = context.target_timeout_sec
        return time.monotonic() + timeout_sec if timeout_sec > 0 else None

    def run(self):
        self.plan()
        if len(self.plugins) > len(self.targets):
            cnt = 0
            count = len(self.targets)
            for target in self.targets:
                if self.request_context and self.request_context.deadline_reached():
                    break
                cnt += 1
                self.logger.info("[%s/%s] PluginRunner %s", cnt, count, target)
                eligible_plugins = self._eligible_plugins(target)
                if not eligible_plugins:
                    continue
                self._target_deadline = self._target_deadline_for()
                runner = ConcurrentByPlugin(
                    plugins=eligible_plugins,
                    target=target,
                    runner=self,
                    concurrency=self.concurrency,
                    request_context=self.request_context,
                    target_deadline=self._target_deadline,
                )
                runner.run()
                self.errors.extend(runner.errors)
        else:
            cnt = 0
            count = len(self.plugins)
            for plugin in self.plugins:
                if self.request_context and self.request_context.deadline_reached():
                    break
                cnt += 1
                self.logger.info("[%s/%s] PluginRunner %s", cnt, count, plugin)
                eligible_targets = self._eligible_targets(plugin)
                if not eligible_targets:
                    continue
                runner = ConcurrentByTarget(
                    targets=eligible_targets,
                    plugin=plugin,
                    runner=self,
                    concurrency=self.concurrency,
                    request_context=self.request_context,
                )
                runner.run()
                self.errors.extend(runner.errors)


def plugin_runner(plugins, targets, concurrency=6):
    runner = PluginRunner(plugins=plugins, targets=targets, concurrency=concurrency)
    return runner.run()


class Mixin(object):
    def __init__(self, *args, **kwargs):
        self.result_map = {
            PluginType.SNIFFER: [],
            PluginType.POC: []
        }

    def put_result(self, plg, target, ret):
        if plg.plugin_type == PluginType.SNIFFER:
            self.result_map[PluginType.SNIFFER].append(ret)
        else:
            if isinstance(ret, str) and "://" in ret:
                msg = ret
            else:
                msg = "{}----{}".format(target, ret)

            self.result_map[PluginType.POC].append(msg)


class ConcurrentByPlugin(BaseThread, Mixin):
    def __init__(self, plugins, target, runner, concurrency=6, request_context=None,
                 target_deadline=None):
        def cancel_check():
            if request_context and request_context.deadline_reached():
                return True
            return target_deadline is not None and time.monotonic() >= target_deadline

        super(ConcurrentByPlugin, self).__init__(
            targets=plugins,
            concurrency=concurrency,
            cancel_check=cancel_check if request_context else None,
        )
        Mixin.__init__(self)
        self.target = target
        self.runner = runner if isinstance(runner, PluginRunner) else None
        self.request_context = request_context
        self.target_deadline = target_deadline

    def work(self, plg):
        if self.request_context:
            with self.request_context.bind(
                getattr(plg, "_plugin_name", ""), self.target, self.target_deadline
            ):
                self.runner.runner_cnt += 1
                ret = run(plg=plg, target=self.target)
        else:
            self.runner.runner_cnt += 1
            ret = run(plg=plg, target=self.target)
        if not ret:
            return
        self.put_result(plg, self.target, ret)

    def run(self):
        self._run()


class ConcurrentByTarget(BaseThread, Mixin):
    def __init__(self, targets, plugin, runner, concurrency=6, request_context=None):
        super(ConcurrentByTarget, self).__init__(
            targets=targets,
            concurrency=concurrency,
            cancel_check=(request_context.deadline_reached if request_context else None),
        )
        Mixin.__init__(self)
        self.plugin = plugin
        self.runner = runner if isinstance(runner, PluginRunner) else None
        self.request_context = request_context

    def work(self, target):
        if self.request_context:
            with self.request_context.bind(
                getattr(self.plugin, "_plugin_name", ""), target
            ):
                self.runner.runner_cnt += 1
                ret = run(plg=self.plugin, target=target)
        else:
            self.runner.runner_cnt += 1
            ret = run(plg=self.plugin, target=target)
        if not ret:
            return
        self.put_result(self.plugin, target, ret)

    def run(self):
        self._run()


def run(plg, target, copy_flag=True):
    if not isinstance(plg, BasePlugin):
        raise Exception("{} not xing plugin".format(plg))

    new_plg = plg
    if copy_flag:
        try:
            obj = plg.__class__(rule_path=getattr(plg, "_rule_path", None))
        except TypeError:
            obj = plg.__class__()
        name = getattr(plg, '_plugin_name', "")
        setattr(obj, '_plugin_name', name)
        new_plg = obj

        setattr(obj, 'password_file', getattr(plg, 'password_file'))
        setattr(obj, 'username_file', getattr(plg, 'username_file'))
        for attr in (
            "poc_engine", "poc_source", "status", "severity", "tags", "finger",
            "app_name", "vul_name", "scheme", "target_scheme", "plugin_type",
        ):
            if hasattr(plg, attr):
                setattr(obj, attr, getattr(plg, attr))

    new_plg.set_target(target)
    result = new_plg.run()
    if result and not should_skip_web_brute_result(new_plg):
        save_result(new_plg, result)

    return result


def should_skip_web_brute_result(plg):
    login_fun = getattr(plg, "login", None)
    if not login_fun:
        return False

    if not callable(login_fun):
        return False

    service_brute_fun = getattr(plg, "service_brute", None)
    if service_brute_fun and callable(service_brute_fun):
        return False

    if plg.plugin_type == PluginType.BRUTE:
        return True
    else:
        return False
