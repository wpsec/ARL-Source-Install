"""计划 6 API 统一测试共用 bootstrap（Review P2-13）。

背景：app/services/__init__.py 在包级导入全部重依赖服务子模块（npoc → xing 等），
轻测试环境里任何 from app.services import X 顶层形式都会在收集期 ImportError。
旧做法（test_api_unified_models 永久注入空壳桩包）违反 test_api_unified_shadow
的头注红线：残留的 app.services 空壳会让同进程后续用例（task_orchestrator 等）
的 `from app.services import X` 不可还原地拿到空壳。

本模块提供"临时桩加载"：
1. 若 sys.modules 中 app / app.services 缺失或为无 __path__ 的 fake，
   临时安装带正确 __path__ 的桩包（桩必须带 __path__，否则子模块内的相对导入
   from .api_unified_models import ... 与 from app.services import api_doc_scan
   都无法解析）；
2. 在桩窗口内 import 目标子模块；
3. 完成后把 app / app.services 两个槽位还原到收集前状态（原本不存在则删除）。

子模块缓存条目（app.utils、app.services.api_doc_scan 等）保留：测试文件的运行期
懒导入均为 `from app.services.X import Y` 直接形式，命中 sys.modules 缓存条目即
可工作，不会触发包 __init__。捕获到的模块对象以返回值交付，测试文件用模块级
常量持有真实引用，免疫其它用例注入 fake 不还原的污染。
"""

import importlib
import sys
import types as _types
from pathlib import Path

ARL_ROOT = Path(__file__).resolve().parents[1]

_STUB_PATHS = {
    "app": str(ARL_ROOT / "app"),
    "app.services": str(ARL_ROOT / "app" / "services"),
}


def _install_stub_package(name: str) -> _types.ModuleType:
    module = _types.ModuleType(name)
    module.__path__ = [_STUB_PATHS[name]]
    sys.modules[name] = module
    return module


def _restore_slot(name: str, previous):
    if previous is None:
        sys.modules.pop(name, None)
    else:
        sys.modules[name] = previous


def load_modules(*fullnames: str):
    """在临时桩窗口内加载 app.* 子模块，返回 {fullname: module}。

    fullnames 支持 app.utils / app.modules / app.services.X。真实包槽位若已
    存在（含被其它用例合法导入过），直接复用不覆盖；仅对缺失或无 __path__
    的槽位安装桩，且无论加载成败都在 finally 还原，避免空壳残留。
    """
    for name in fullnames:
        if name != "app" and not name.startswith("app.") and not name.startswith("app.services."):
            raise ValueError(f"仅支持 app / app.services 子模块，收到: {name!r}")
    saved_app = sys.modules.get("app")
    saved_services = sys.modules.get("app.services")
    try:
        if saved_app is None or not hasattr(saved_app, "__path__"):
            _install_stub_package("app")
        services = sys.modules.get("app.services")
        if services is None or not hasattr(services, "__path__"):
            _install_stub_package("app.services")
        return {name: importlib.import_module(name) for name in fullnames}
    finally:
        _restore_slot("app.services", saved_services)
        _restore_slot("app", saved_app)


# 四件 api 统一测试共用的预载闭包。除各文件头部直接 import 的子模块外，
# 还必须包含 service 子模块**函数体内的懒导入**目标，否则槽位还原后、运行期
# 相对导入（如 api_candidate_registry._bridge_parse_result 的
# `from .api_unified_parser import url_has_template`、api_unified_parser 与
# registry 的 `from .web_info_intel_utils import safe_site/fetch_text`）会因
# app.services 缓存条目缺失而回到真实 __init__ 并 ImportError。
# app.modules / url_candidate_filter 等由各文件顶层导入链在桩窗口内自动带入缓存。
UNIFIED_SERVICE_MODULES = (
    "app.utils",
    "app.services.api_unified_models",
    "app.services.api_unified_parser",
    "app.services.api_unified_shadow",
    "app.services.discovery_context",
    "app.services.web_info_intel_utils",
    "app.services.api_doc_scan",
    "app.services.api_candidate_registry",
    "app.services.wih_endpoint_probe",
)


def load_unified_modules():
    """加载 api 统一测试面的完整依赖闭包，返回 {fullname: module}。"""

    return load_modules(*UNIFIED_SERVICE_MODULES)


def assert_no_shell_pollution():
    """污染回归：app.services 槽位不得是跳过真实 __init__ 的空壳桩。

    真实 __init__ 在包级重导出 run_api_doc_scan 等服务函数，空壳桩没有该属性；
    槽位不存在视为已干净还原（等同从未安装过桩）。发现残留说明某条加载路径
    跳过了还原步骤，会让同进程后续 `from app.services import X` 全部拿到空壳。
    """
    services = sys.modules.get("app.services")
    if services is None:
        return
    if not hasattr(services, "run_api_doc_scan"):
        raise AssertionError(
            "sys.modules['app.services'] 残留空壳桩包：bootstrap 加载后必须还原"
            " app / app.services 槽位，否则同进程后续 from app.services import X"
            " 的用例（task_orchestrator 等）将不可还原地拿到空壳"
        )
