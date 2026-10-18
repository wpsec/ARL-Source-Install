"""以注册表生成清单，避免人工统计在路由变化后失效。"""

import ast
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ROUTES_DIR = ROOT / "ARL" / "app" / "routes"
MAIN_FILE = ROOT / "ARL" / "app" / "main.py"
MODULE_FILE = ROOT / "ARL" / "docker" / "frontend-src" / "src" / "config" / "modules.ts"
OUTPUT = ROOT / "docs" / "testing" / "test-inventory.md"
HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}

API_DOMAIN_COVERAGE = [
    (
        "任务与用户权限",
        "test_high_risk_api_contracts.py, test_task_repository.py, test_task_pipeline.py, test_task_terminal_status_mapping.py, test_semantics_and_recovery.py, test_legacy_owner_migration.py",
        "任务创建/所有者归属、IDOR、状态恢复、历史所有者兼容；系统测试另验证 worker 与 API 的真实隔离闭环。",
    ),
    (
        "资产与范围",
        "test_high_risk_api_contracts.py, test_asset_scope.py, test_asset_site_update.py, test_asset_site_monitor.py, test_asset_wih_monitor.py, test_asset_wih_task.py",
        "范围输入校验、删除目标、资产同步及监控逻辑；provider 和扫描命令使用 mock/fixture。",
    ),
    (
        "风险与验证",
        "test_high_risk_api_contracts.py, test_risk_cruising.py, test_nuclei_result_verify.py, test_controlled_verification_policy.py",
        "风险记录删除边界、风险巡检、验证策略和结果处理。",
    ),
    (
        "策略与计划任务",
        "test_high_risk_api_contracts.py, test_policy_edit.py, test_scheduler.py, test_task_schedule_query_args.py, test_wih_adaptive_scheduler.py",
        "策略字段收敛、计划任务输入/持久化 ID、查询过滤与调度逻辑。",
    ),
    (
        "导出",
        "test_high_risk_api_contracts.py, test_batch_export.py, test_export_repository.py, test_waf_export.py",
        "跨用户任务导出拒绝、批量导出、仓储分页和结果组装。",
    ),
    (
        "ICP",
        "test_icp_query_routes.py, test_icp_query.py, test_icp_fixtures.py, test_icp_config_templates.py",
        "路由认证/错误脱敏、输入校验、固定 provider 响应、任务生命周期、取消/导出及历史清理；不访问真实 provider。",
    ),
    (
        "配置与集成",
        "test_high_risk_api_contracts.py, test_config_domain_service.py, test_config_file_store.py, test_scan_config_service.py, test_service_api_config_service.py, test_ai_config_service.py, test_dingtalk_api_sensitive.py",
        "配置校验、原子持久化、脱敏字段保护及敏感值 reveal 边界；外部服务调用使用 mock。",
    ),
    (
        "GitHub 任务",
        "test_high_risk_api_contracts.py, test_github_task.py, test_github_search.py, test_github_cron.py",
        "输入校验、固定队列适配、搜索和周期任务逻辑；不访问 GitHub。",
    ),
    (
        "系统监控",
        "test_system_monitor_processes.py, test_console_dashboard_trend.py, test_api_route_contract_inventory.py",
        "容器进程快照、过期数据聚合、趋势逻辑及接口认证；不读取宿主机生产状态。",
    ),
]


def literal_string(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def decorator_name(node):
    if isinstance(node, ast.Call):
        node = node.func
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return ""


def registered_namespaces():
    tree = ast.parse(MAIN_FILE.read_text(encoding="utf-8"))
    return {
        node.args[0].attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "add_namespace"
        and node.args
        and isinstance(node.args[0], ast.Attribute)
        and isinstance(node.args[0].value, ast.Name)
        and node.args[0].value.id == "routes"
    }


def namespace_imports():
    tree = ast.parse((ROUTES_DIR / "__init__.py").read_text(encoding="utf-8"))
    result = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom) or not node.module:
            continue
        for item in node.names:
            alias = item.asname or item.name
            if alias.endswith("_ns") and item.name == "ns":
                result[alias] = node.module.rsplit(".", 1)[-1]
    return result


def route_inventory():
    registered = registered_namespaces()
    imports = namespace_imports()
    operations = []

    for alias in sorted(registered):
        module_name = imports.get(alias)
        if not module_name:
            raise RuntimeError("无法解析已注册命名空间：" + alias)
        path = ROUTES_DIR / (module_name + ".py")
        tree = ast.parse(path.read_text(encoding="utf-8"))
        namespace_name = None
        namespace_path = None
        for node in tree.body:
            if not isinstance(node, ast.Assign) or not any(
                isinstance(target, ast.Name) and target.id == "ns"
                for target in node.targets
            ):
                continue
            call = node.value
            if not isinstance(call, ast.Call):
                continue
            namespace_name = literal_string(call.args[0]) if call.args else None
            for keyword in call.keywords:
                if keyword.arg == "path":
                    namespace_path = literal_string(keyword.value)
        if not namespace_name:
            raise RuntimeError("无法解析 Namespace 名称：" + str(path))
        prefix = namespace_path or "/" + namespace_name
        prefix = "/" + prefix.strip("/") if prefix != "/" else ""

        for node in tree.body:
            if not isinstance(node, ast.ClassDef):
                continue
            route = None
            for decorator in node.decorator_list:
                if (
                    isinstance(decorator, ast.Call)
                    and isinstance(decorator.func, ast.Attribute)
                    and decorator.func.attr == "route"
                    and isinstance(decorator.func.value, ast.Name)
                    and decorator.func.value.id == "ns"
                    and decorator.args
                ):
                    route = literal_string(decorator.args[0])
            if route is None:
                continue
            route_path = "/" + route.lstrip("/") if route else "/"
            full_path = "/api" + prefix + route_path
            for method in node.body:
                if not isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                verb = method.name.lower()
                if verb not in HTTP_METHODS:
                    continue
                authenticated = any(
                    decorator_name(decorator) == "auth"
                    for decorator in method.decorator_list
                )
                operations.append({
                    "namespace": namespace_name,
                    "module": module_name,
                    "resource": node.name,
                    "path": full_path,
                    "method": verb.upper(),
                    "authenticated": authenticated,
                    "source": "ARL/app/routes/{}.py:{}".format(module_name, node.lineno),
                })

    operations.sort(key=lambda item: (item["path"], item["method"], item["resource"]))
    return len(registered), operations


def frontend_modules():
    source = MODULE_FILE.read_text(encoding="utf-8")
    section_start = source.index("export const modules:")
    section_end = source.index("export const TASK_DETAIL_TABS", section_start)
    lines = source[section_start:section_end].splitlines()
    modules = []
    index = 0
    while index < len(lines):
        if not re.match(r"^  \{(?:\s|$)", lines[index]):
            index += 1
            continue
        start = index
        depth = 0
        in_string = None
        escaped = False
        while index < len(lines):
            for char in lines[index]:
                if in_string:
                    if escaped:
                        escaped = False
                    elif char == "\\":
                        escaped = True
                    elif char == in_string:
                        in_string = None
                    continue
                if char in ("'", '"', "`"):
                    in_string = char
                elif char == "{":
                    depth += 1
                elif char == "}":
                    depth -= 1
            index += 1
            if depth == 0:
                break
        block = "\n".join(lines[start:index])
        match = re.search(r"(?:^|\n)\s{4}id:\s*'([^']+)'", block)
        if not match:
            match = re.search(r"^\s*\{\s*id:\s*'([^']+)'", block)
        if match and not re.search(r"(?:^|\n)\s{4}hidden:\s*true", block):
            module_id = match.group(1)
            modules.append({
                "id": module_id,
                "label": module_label(block),
                "path": "/dashboard" if module_id == "dashboard" else "/modules/" + module_id.replace("_", "-"),
            })
    return modules


def module_label(block):
    match = re.search(r"(?:^|\n)\s{4}label:\s*'([^']+)'", block)
    if match:
        return match.group(1)
    match = re.search(r"^\s*\{\s*id:\s*'[^']+'\s*,\s*label:\s*'([^']+)'", block)
    return match.group(1) if match else ""


def render():
    namespace_count, operations = route_inventory()
    modules = frontend_modules()
    test_files = len(list((ROOT / "ARL" / "test").glob("test_*.py")))
    frontend_root = ROOT / "ARL" / "docker" / "frontend-src"
    frontend_tests = len(
        list((frontend_root / "src").rglob("*.test.ts"))
        + list((frontend_root / "src").rglob("*.test.tsx"))
        + list((frontend_root / "e2e").glob("*.spec.ts"))
    )
    lines = [
        "# 自动化测试覆盖清单",
        "",
        "本清单由 `python3 scripts/generate_test_inventory.py` 生成。API 行来自 Flask 已注册 Namespace 和 `@ns.route`；页面行来自前端模块注册表。",
        "",
        "## 盘点基线",
        "",
        "- Python 测试文件：{} 个。".format(test_files),
        "- Flask 已注册 Namespace：{} 个；HTTP 操作：{} 个。".format(namespace_count, len(operations)),
        "- 前端测试文件：{} 个；可见业务页面：{} 个。".format(frontend_tests, len(modules)),
        "- 每个 API 操作都有路由注册及对应基础响应契约：受保护操作检查缺少 Token 的统一响应包络，公开登录/登出分别检查失败与成功响应；高风险业务行为由域级测试补充。",
        "",
        "## API 操作",
        "",
        "| 方法 | 路径 | Namespace | 资源 | 认证 | API 基础契约 | 源码 |",
        "|---|---|---|---|---|---|---|",
    ]
    for item in operations:
        auth = "Token" if item["authenticated"] else "公开（显式 allowlist）"
        if item["authenticated"]:
            operation_contract = "注册 + 缺 Token 响应包络"
        elif item["path"] == "/api/user/login":
            operation_contract = "注册 + 错误登录响应"
        else:
            operation_contract = "注册 + 登出成功响应包络"
        lines.append("| {} | `{}` | `{}` | `{}` | {} | {} | `{}` |".format(
            item["method"], item["path"], item["namespace"], item["resource"], auth,
            operation_contract, item["source"]
        ))
    lines += ["", "## 前端业务页面", "", "| 页面 ID | 名称 | 直接访问路径 | 基础覆盖 |", "|---|---|---|---|"]
    for item in modules:
        lines.append("| `{}` | {} | `{}` | Vitest 路由注册；Playwright 页面 smoke |".format(
            item["id"], item["label"], item["path"]
        ))
    lines += [
        "",
        "## 高风险业务域覆盖映射",
        "",
        "此表列出业务域的主要单测/API 合同测试。它说明测试范围，不代表列出的每个用例都会访问生产 provider；真实扫描、真实 provider 和生产数据均不在自动化测试范围。",
        "",
        "| 业务域 | 主要测试文件 | 覆盖边界 |",
        "|---|---|---|",
    ]
    for domain, tests, boundary in API_DOMAIN_COVERAGE:
        lines.append("| {} | {} | {} |".format(
            domain,
            ", ".join("`{}`".format(name) for name in tests.split(", ")),
            boundary,
        ))
    lines += [
        "",
        "## 端到端工作流",
        "",
        "| 工作流 | 覆盖方式 |",
        "|---|---|",
        "| 登录、深层链接返回、导航、刷新、浏览器历史 | Playwright 固定 API fixture |",
        "| 任务名筛选、同名任务查看、Task ID 与详情 tab 绑定 | Vitest 组件测试与 Playwright 固定 fixture |",
        "| 真实 API 创建任务、隔离 worker 执行、任务列表/详情/异常对话框查看 | Playwright 通过本地端口代理到隔离 Compose API；固定 Celery 测试任务 |",
        "| 查询/分页/筛选 URL 恢复、主题、窄屏无溢出 | Vitest 路由测试与 Playwright 固定 fixture |",
        "| API 路由注册及受保护接口缺少 Token 的响应 | Flask 测试客户端逐操作检查 |",
        "| 高风险任务/用户/资产/风险/策略/计划任务/导出/配置/GitHub API 的输入、权限和副作用合同 | `test_high_risk_api_contracts.py`，扫描队列与外部 provider 使用 mock |",
        "| RabbitMQ 投递/重试/撤销/重试耗尽、worker 重启、Mongo 状态落库、Redis 数据隔离 | 隔离 Compose 系统测试 |",
        "| 外部 provider / 扫描器真实网络行为 | 默认排除；通过固定响应测试 ARL 适配层 |",
        "",
    ]
    return "\n".join(lines)


def main():
    output = render()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(output, encoding="utf-8")
    print("生成 {}".format(OUTPUT.relative_to(ROOT)))


if __name__ == "__main__":
    main()
