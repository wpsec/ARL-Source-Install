#!/usr/bin/env python3
"""API 契约静态冻结取证（docs/04 Step 1；重构期间契约只读的基准文档）。

为什么脚本生成而不是手抄：路由 40+ 文件、端点 200+，手抄必漏；
AST 提取保证与代码同源。输出 markdown 表供 UI 重构逐项对照。
"""
import ast
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ROUTES_DIR = ROOT / "ARL" / "app" / "routes"
MAIN_PY = ROOT / "ARL" / "app" / "main.py"
APP_TSX = ROOT / "ARL" / "docker" / "frontend-src" / "src" / "App.tsx"

HTTP_METHODS = {"get": "GET", "post": "POST", "put": "PUT", "delete": "DELETE", "patch": "PATCH"}
MODULE_RE = re.compile(r"^\s*module\s*=\s*\"([^\"]+)\"|^\s*module\s*=\s*'([^']+)'", re.M)


def ns_name_for(path: Path) -> str:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == "ns" and isinstance(node.value, ast.Call):
                    fn = node.value.func
                    fname = getattr(fn, "id", None) or getattr(fn, "attr", None)
                    if fname == "Namespace" and node.value.args:
                        a = node.value.args[0]
                        if isinstance(a, ast.Constant):
                            return str(a.value)
    return ""


def main_routes_prefixes() -> dict:
    """main.py 中 api.add_namespace 的显式 path= 前缀；无 path 则默认 /<ns名>。"""
    tree = ast.parse(MAIN_PY.read_text(encoding="utf-8"))
    explicit = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, "attr", "") == "add_namespace":
            if not node.args:
                continue
            alias = ast.unparse(node.args[0]).split(".")[-1]
            for kw in node.keywords:
                if kw.arg == "path":
                    explicit[alias] = ast.literal_eval(kw.value)
    return explicit


def extract_endpoints():
    rows = []
    for path in sorted(ROUTES_DIR.glob("*.py")):
        if path.name == "__init__.py":
            continue
        name = ns_name_for(path)
        if not name:
            continue
        src = path.read_text(encoding="utf-8")
        tree = ast.parse(src)
        # 类名 -> 路由表达式（装饰器）
        cls_routes: dict[str, list[str]] = {}
        # 记录每个 route 表达式对应类里的 handler 与解析器
        for node in ast.walk(tree):
            if isinstance(node, (ast.ClassDef, ast.FunctionDef)):
                for dec in node.decorator_list:
                    call = dec if isinstance(dec, ast.Call) else (dec if isinstance(dec, ast.Attribute) else None)
                    if call is None:
                        continue
                    target = call.func if isinstance(call, ast.Call) else dec
                    if getattr(getattr(target, "value", None), "id", "") == "ns" and getattr(target, "attr", "") == "route":
                        expr = ast.unparse(call.args[0]) if isinstance(call, ast.Call) and call.args else "''"
                        cls_routes.setdefault(node.name, []).append(expr)
        # 变量 -> 字符串路由表达式
        var_routes: dict[str, list[str]] = {}
        for vname, exprs in cls_routes.items():
            var_routes[vname] = exprs
        # 遍历每个带 @ns.route 的类，收集 on_*/get/post 与 parser 引用
        for node in ast.walk(tree):
            if not isinstance(node, (ast.ClassDef, ast.FunctionDef)):
                continue
            rexprs = var_routes.get(node.name)
            if rexprs is None:
                continue
            methods = []
            expect = ""
            body_nodes = node.body
            for sub in body_nodes:
                if isinstance(sub, ast.FunctionDef) and sub.name in HTTP_METHODS:
                    methods.append(HTTP_METHODS[sub.name])
                    for dec in sub.decorator_list:
                        m = re.search(r"expect\(([^)]+)\)", ast.unparse(dec))
                        if m and not expect:
                            expect = m.group(1).strip()
                    if not expect:
                        # parser 类属性模式：self.parser.parse_args
                        if re.search(r"self\.parser\b", ast.unparse(sub)):
                            expect = "self.parser"
            if not methods and isinstance(node, ast.ClassDef):
                continue
            methods = sorted(set(methods), key=lambda x: ["GET", "POST", "PUT", "DELETE", "PATCH"].index(x))
            rows.append({
                "ns": name,
                "file": path.name,
                "route": " | ".join(repr(e) for e in rexprs),
                "methods": ",".join(methods) or "?",
                "expect": expect,
                "doc": (ast.get_docstring(node) or "").strip().splitlines()[0] if ast.get_docstring(node) else "",
            })
    return rows


def frontend_endpoints():
    """App.tsx 中 UI 消费的 /api/... 端点（requestApi 第二参静态串 + 模板串归一）。"""
    src = APP_TSX.read_text(encoding="utf-8")
    found = set()
    for m in re.finditer(r"requestApi\([^,]+,\s*(['\"`])([^'\"`]+)\1", src):
        u = m.group(2)
        if u.startswith("/"):
            found.add(u)
    for m in re.finditer(r"requestApi\([^,]+,\s*`([^`]+)`", src):
        found.add(re.sub(r"\$\{[^}]+\}", "{var}", m.group(1)))
    # listPath/exportPath 与 action path 也属消费面
    for pat in (r"listPath: '([^']+)'", r"exportPath: '([^']+)'", r"path: '(/[^']+)'"):
        for m in re.finditer(pat, src):
            found.add(m.group(1))
    return sorted(found)


def frontend_modules():
    """modules 配置的字段消费契约：id/label/listPath/columns/actions。

    行级状态机解析（配置为规整 TS 对象字面量），只取冻结所需的键。
    """
    src = APP_TSX.read_text(encoding="utf-8")
    start = src.index("const modules: ModuleConfig[] = [")
    end = src.index("\n];", start)
    mods = []
    cur = None
    nested = None  # 当前嵌套对象所属数组名（actions/searchFields/...）
    pending_arr = None
    for line in src[start:end].splitlines():
        s = line.strip()
        indent = len(line) - len(line.lstrip())
        if indent == 2 and s == "{":
            cur = {"id": "", "label": "", "description": "", "group": "", "columns": [],
                   "actions": [], "listPath": "", "exportPath": "", "rowIdKey": "", "searchKeys": []}
            nested = None
            pending_arr = None
            mods.append(cur)
            continue
        if cur is None:
            continue
        if indent == 2 and re.match(r"^\},?$", s):
            cur = None
            continue
        if indent >= 6:
            if s == "{":
                nested = pending_arr
                if nested == "actions":
                    obj = {"id": ""}
                    cur["actions"].append(obj)
                    nested = obj
                continue
            if re.match(r"^\},?$", s):
                nested = None
                continue
            if isinstance(nested, dict):
                mk = re.match(r"^(id|method|path): '([^']*)',?$", s)
                if mk:
                    nested[mk.group(1)] = mk.group(2)
                continue
            if nested == "searchFields":
                mk = re.match(r"^key: '([^']+)',?$", s)
                if mk:
                    cur["searchKeys"].append(mk.group(1))
                continue
            continue
        if indent == 4:
            mk = re.match(r"^(\w+): \[$", s)
            if mk:
                pending_arr = mk.group(1)
                continue
            mk = re.match(r"^id: '([a-zA-Z0-9_]+)',?$", s)
            if mk:
                cur["id"] = mk.group(1)
                continue
            for key in ("label", "description", "group", "rowIdKey", "quickFilterKey",
                        "defaultOrder", "listPath", "exportPath"):
                mk = re.match(rf"^{key}: '([^']*)',?$", s)
                if mk:
                    cur[key] = mk.group(1)
                    break
            else:
                mk = re.match(r"^columns: \[([^\]]*)\],?$", s)
                if mk:
                    cur["columns"] = re.findall(r"'([^']+)'", mk.group(1))
    return [m for m in mods if m["id"]]


def export_module_hints():
    hints = {}
    for path in ROUTES_DIR.glob("*.py"):
        mm = MODULE_RE.search(path.read_text(encoding="utf-8"))
        if mm:
            hints[path.name] = mm.group(1) or mm.group(2)
    return hints


OUT_DOC = ROOT / "docs" / "plan" / "04-附录A-API契约冻结清单.md"


def render():
    import subprocess
    rev = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT,
                         capture_output=True, text=True).stdout.strip()
    rows = extract_endpoints()
    mods = frontend_modules()
    by_ns: dict[str, list] = {}
    for r in rows:
        by_ns.setdefault(r["ns"], []).append(r)
    ns_paths = {"/" + ns for ns in by_ns}
    consumed_ns = set()
    fe_all = frontend_endpoints()
    fe = []
    for u in fe_all:
        seg = "/" + u.strip("/").split("/")[0] if u.startswith("/") else ""
        if seg in ns_paths:
            fe.append(u)
            consumed_ns.add(seg)
        elif seg:
            print("WARN 非本系统命名空间（外部 URL，不入冻结面）:", u)

    out = []
    out.append("# 04 附录A · API 契约冻结清单（Step 1 取证，UI 重构期间只读）\n")
    out.append(f"- 生成命令：`python3 scripts/freeze-api-contract.py`（本文件即脚本输出，禁止手改；代码变更后重跑刷新）")
    out.append(f"- 基线 rev：`{rev}`，生成时间：{__import__('datetime').datetime.now():%F %T}")
    out.append(f"- 规模：{len(rows)} 端点 / {len(by_ns)} 命名空间；UI 消费端点 {len(fe)} 条；modules 配置 {len(mods)} 页\n")
    out.append("""
## 冻结规则

1. 本清单是 UI 重构（Phase 0-4）期间的行为基准：重构只允许改渲染与请求组织方式，**端点路径、方法、请求参数、响应字段、状态枚举、导出下载行为不得变化**。
2. 列表接口标准信封（`ARLResource.build_data` → `collection_query_service.build_collection_data`）：
   `{ page, size, total, items, query, code: 200 }`；缓存受 `API_LIST_CACHE_EXPIRE` 控制，`_refresh=1` 强制穿透。
3. 认证：请求头 `Token: <token>`（flask_restx ApiKeyAuth），失败 401。
4. 任务状态枚举：`waiting/running/done/stop/error`；任务类型：`domain/ip/risk_cruising/fofa/asset_site_add` 等。
5. 若后端契约确需变更，必须先改本清单来源（代码）并重跑脚本，再改 UI——顺序不可反。

## UI 消费的端点全表（requestApi/listPath/exportPath/action.path 去重）

说明：`/api` 前缀由前端 `API_BASE` 统一拼接；`<img>` 直连资源（截图 `/image/{task_id}/{path}`）不经 requestApi，但同样属冻结面。

| 端点 |
|---|""")
    for u in fe:
        out.append(f"| `{u}` |")
    out.append("\n## modules 配置：字段与动作消费契约\n")
    out.append("| 模块 | 名称 | listPath | 行键 | 消费列 |")
    out.append("|---|---|---|---|---|")
    for m in mods:
        cols = ", ".join(m["columns"]) or "-"
        out.append(f"| `{m['id']}` | {m.get('label', '')} | `{m['listPath'] or '-'}` | `{m.get('rowIdKey') or '_id'}` | {cols} |")
    out.append("\n### 动作（action id → method + path）\n")
    out.append("| 模块 | 动作 | 方法 | 路径 |")
    out.append("|---|---|---|---|")
    for m in mods:
        for a in m["actions"]:
            if a.get("path"):
                out.append(f"| `{m['id']}` | `{a['id']}` | {a.get('method', 'GET')} | `{a['path']}` |")
    out.append("\n## 后端端点全表（AST 提取自 ARL/app/routes/）\n")
    for ns, rs in sorted(by_ns.items()):
        out.append(f"\n### /api/{ns}  （`{rs[0]['file']}`）\n")
        out.append("| 路由 | 方法 | 参数模型 | 摘要 |")
        out.append("|---|---|---|---|")
        for r in sorted(rs, key=lambda x: x["route"]):
            route = r["route"].replace("'", "").replace('"', "")
            expect = r["expect"] or "-"
            expect = expect.replace("|", "\\|")
            doc = r["doc"].replace("|", "\\|")
            out.append(f"| {route} | {r['methods']} | `{expect}` | {doc} |")
    out.append("")
    OUT_DOC.write_text("\n".join(out), encoding="utf-8")
    print(f"written: {OUT_DOC} ({len(rows)} endpoints, {len(fe)} consumed, {len(mods)} modules)")
    unconsumed = sorted(ns_paths - consumed_ns)
    if unconsumed:
        print("INFO UI 未消费的命名空间（后端独有，属 CLI/兼容面）:", [p[1:] for p in unconsumed])


if __name__ == "__main__":
    render()
