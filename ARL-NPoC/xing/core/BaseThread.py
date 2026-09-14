import threading
import collections
import requests.exceptions
import time
import random
from lxml import etree
from xing.utils import get_logger


class BaseThread(object):
    def __init__(self, targets, concurrency=6):
        self.concurrency = concurrency
        self.semaphore = threading.Semaphore(concurrency)
        self._targets = targets
        # 子线程异常不能只写日志，否则上层会把不完整结果当作成功。
        # 由 PluginRunner 汇总后以 partial 结果回传，仍允许其它规则继续执行。
        self.errors = []
        self._errors_lock = threading.Lock()
        self.shuffle_targets = False
        self.logger = get_logger()

    def work(self, site):
        raise NotImplementedError()

    def _work(self, url):
        try:
            self.work(url)
        except requests.exceptions.RequestException as e:
            self.logger.debug("error on {} {}".format(url, e))
            self._record_error(url, e)

        except etree.Error as e:
            self.logger.debug("error on {} {}".format(url, e))
            self._record_error(url, e)

        except Exception as e:
            self.logger.warning("error on {}".format(url))
            self.logger.exception(e)
            self._record_error(url, e)

        except BaseException as e:
            self.logger.warning("BaseException on {}".format(url))
            self.semaphore.release()
            raise e

        self.semaphore.release()

    def _record_error(self, value, error):
        plugin = value if isinstance(value, BasePlugin) else getattr(self, "plugin", None)
        target = getattr(self, "target", None) if isinstance(value, BasePlugin) else value
        item = {
            "plugin_name": str(getattr(plugin, "_plugin_name", "") or "").strip(),
            "target": str(target or "").strip(),
            "error_type": type(error).__name__,
            "error": str(error or "")[:500],
        }
        with self._errors_lock:
            self.errors.append(item)

    def _run(self):
        deque = collections.deque(maxlen=2000)
        cnt = 0

        if self.shuffle_targets:
            random.shuffle(self._targets)

        for target in self._targets:
            if isinstance(target, str):
                target = target.strip()

            cnt += 1
            self.logger.debug("[{}/{}] work on {}".format(cnt, len(self._targets), target))

            if not target:
                continue

            self.semaphore.acquire()
            t1 = threading.Thread(target=self._work, args=(target,))
            # 可以快速结束程序
            t1.setDaemon(True)
            t1.start()
            deque.append(t1)

        for t in list(deque):
            while t.is_alive():
                time.sleep(0.2)

