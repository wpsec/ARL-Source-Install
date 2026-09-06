"""搜索引擎页面候选登记回归（Review 20260905 P0.2）。

只测登记语义与降级路径：`search_engines` 的抓取接线由
`page_fetch(discovery_context=..., traffic_class="crawler")` 参数强制，
本文件锁定晚到候选显影口径——获取成功不显影、失败保持可领取。
"""

import sys
import unittest
from pathlib import Path

ARL_ROOT = Path(__file__).resolve().parents[1]
if str(ARL_ROOT) not in sys.path:
    sys.path.insert(0, str(ARL_ROOT))


def _ensure_app_package():
    """真实 app 包优先：app/__init__ 轻量（仅 warnings 配置），独立进程直接
    真实导入即可——旧实现注入 ModuleType 假包且 py3.10 该路径下 tearDownModule
    不会执行（hygiene 容器重扫实锤 polluted=app=fake-file）。

    槽位被既有用例换成无 __path__ 的 fake 时，只补路径防御、不换对象——
    真污染归因回肇事文件，不在本文件兜底还原他人不还原的桩。
    """
    app = sys.modules.get("app")
    if app is None:
        import app  # noqa: F401  真实轻量 __init__
    elif not hasattr(app, "__path__"):
        app.__path__ = [str(ARL_ROOT / "app")]


_ensure_app_package()

from app.services.discovery_context import DiscoveryContext  # noqa: E402
from app.tasks.domain import DomainTask  # noqa: E402

_OK_URL = "https://blog.example.com/post/1"
_FAIL_URL = "https://www.example.com/news/2"


class _Stub(object):
    def __init__(self, context):
        self.discovery_context = context


class SearchPageCandidateTest(unittest.TestCase):
    def test_fetched_success_marks_non_open_state(self):
        context = DiscoveryContext(task_id="se-1")
        DomainTask._register_search_page_candidates(
            _Stub(context), [_OK_URL, _FAIL_URL], {_OK_URL: {"title": "x"}})
        by_url = {
            item.candidate: item for item in context.candidate_registry.values()
        }
        ok = by_url.get(_OK_URL)
        self.assertIsNotNone(ok)
        self.assertEqual(ok.status, "fetched", "已获取页面不得留在晚到显影开放态")
        self.assertEqual(ok.sources, {"search_engine"})

    def test_fetch_failure_stays_discovered_for_url_probe(self):
        context = DiscoveryContext(task_id="se-2")
        DomainTask._register_search_page_candidates(
            _Stub(context), [_FAIL_URL], {})
        failed = next(
            item for item in context.candidate_registry.values()
            if item.candidate == _FAIL_URL)
        self.assertEqual(failed.status, "discovered", "获取失败必须保持可被后续阶段领取")

    def test_no_context_is_noop(self):
        # 无上下文路径（禁用共享发现的部署）不得抛错。
        DomainTask._register_search_page_candidates(
            _Stub(None), [_OK_URL], {_OK_URL: {}})

    def test_candidate_event_published_once_per_created(self):
        context = DiscoveryContext(task_id="se-3")
        DomainTask._register_search_page_candidates(
            _Stub(context), [_OK_URL], {_OK_URL: {}})
        DomainTask._register_search_page_candidates(
            _Stub(context), [_OK_URL], {_OK_URL: {}})
        self.assertEqual(context.event_counts.get("UrlCandidateDiscovered", 0), 1)
        self.assertEqual(context.metrics["candidate_source_merge_count"], 0)
        self.assertEqual(context.metrics["candidate_discovered_count"], 1)


if __name__ == "__main__":
    unittest.main()
