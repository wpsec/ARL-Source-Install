# ARL-NPoC YAML POC 统一导入与执行器改造计划

> 当前状态：[已归档]。YAML 导入、受限执行器、旧插件等价迁移、任务/API/UI 接入和本地验收已完成；真实授权目标的端到端验证由后续 review/test 在部署环境执行。

## 1. 目标与边界

将 `/Users/eric.sy.wu/Documents/tmp1/dt` 中的 YAML POC 纳入 ARL-NPoC，YAML 作为 NPoC 漏洞验证规则的标准源码格式，并通过兼容适配器接入现有 `poc_config -> NPoC -> vuln` 链路。

本次不改造为 Nuclei 或 Afrog 模板，也不改变 Nuclei/Afrog 的目录、开关和执行器。爆破、sniffer、listener 继续使用 Python；复杂或尚未完成等价验证的旧漏洞插件保留 Python fallback。

任务新建时增加 NPoC 漏洞验证总开关，默认关闭。打开后只执行用户搜索并勾选的 POC，不因风险标签自动关闭规则；高风险信息只用于展示和结果标记。

## 2. 已确认的数据基线

- dt 数据源为 `data/ARL_POC.zip`，包含 `rules/*.yaml` 共 4,420 条规则。
- 当前快照 4,418 条可直接解析，2 条已知 YAML 语法问题由导入器修复。
- 18 条缺少 `info.finger`，该字段允许为空。
- 初始检查未发现重复；导入器完成规范化后发现 1 组同内容不同 ID，按精确内容去重并记录为 alias，不做语义合并。
- ARL-NPoC 当前有 40 个漏洞验证类 Python 插件，其中 35 个 HTTP、5 个 TCP；brute、sniffer、listener 不纳入 YAML 化。

## 3. 仓库布局

```text
ARL-NPoC/
  xing/
    pocs/
      yaml/              # 规范化 YAML 源码
      manifest.json       # 导入状态、哈希、alias、隔离原因
    yaml_poc.py           # 运行时适配器与受限表达式执行器
  tools/
    import_dt_pocs.py     # 支持 zip 或 rules 目录，可重复执行
```

只纳入 `rules/*.yaml`。原始 zip、`raw/*.json`、`index.sqlite`、清单 CSV 和鉴权信息不进入仓库。

## 4. 导入与规范化

导入器执行 YAML 解析、已知语法修复、字段别名归一化、静态校验、规范化 YAML 输出和 manifest 生成。固定 ID；`info.finger` 允许为空；仅在结构明确时修复 `mehod`、`methpd`、`variabels` 等拼写，否则进入隔离清单。未知字段不得静默丢弃。

每条 manifest 记录至少包含源文件哈希、规范文件哈希、规则 ID、规范路径、`ready/quarantine/duplicate` 状态、处理原因和 alias。失败规则不进入运行时加载清单。精确去重按规范化内容哈希执行，不按产品名、漏洞名或 CVE 做语义合并。

## 5. YAML 执行器

`YamlPocPlugin` 兼容 `BasePlugin`，由现有 PluginRunner 调用。执行器支持当前数据集实际使用的 HTTP GET/POST/PUT/DELETE/PATCH/OPTIONS/MOVE、TCP 原始数据、多请求顺序、请求间变量传递、headers/data/raw/files/redirect/timeout，以及 `status_code/body/header/title/raw/duration` 响应变量。

表达式使用白名单 AST 解释器，不调用 `eval`。支持 `contains`、`matches`、`regex_find`、`compare_versions`、`random_int`、`random_str`、`md5`、`base64`、`hex_decode`、`&&`、`||`、`!` 和比较表达式。请求路径只能基于当前任务目标拼接，禁止 YAML 规则任意访问外部目标。

单条规则或请求失败不阻断其它规则，记录规则 ID、目标、请求阶段、错误类型和脱敏错误信息。成功结果保留既有 vuln 字段，并增加 `poc_engine`、`poc_id`、`poc_source`、`severity`、`tags`、`request_index`、`match_summary`、限长脱敏 `evidence`。

## 6. NPoC、API、数据库和前端

NPoC 加载 Python 与 YAML POC，稳定名称优先使用旧 Python 插件名；已完成等价验证后才删除重复 Python 实现。YAML POC 的数据库信息增加 `engine=yaml`、`source=dt`、`status`、`severity`、`tags`、`finger` 等字段。

任务新增：

```json
{
  "npoc_poc_scan": false,
  "poc_config": [{"plugin_name": "poc-yaml-example", "enable": true}]
}
```

缺少总开关时兼容旧配置：按 `poc_config` 中是否存在启用项推导；总开关为 false 时保留选择但不执行；总开关为 true 且无选择时明确显示未选择 POC，禁止默认全量执行。

`/poc/` 提供服务端分页、关键字和 ID/漏洞名称/指纹/标签/严重等级/engine/source/status 查询；只有 `ready` 规则进入可执行列表。新建任务 UI 提供默认关闭的总开关、服务端搜索、多选、筛选结果全选/清空和跨页保留选择。

## 7. 测试与上线

导入测试覆盖 4,420 条规则、2 条已知修复、ID 唯一、规范哈希去重、finger 缺失和 manifest 完整性。执行器测试覆盖 HTTP/TCP mock、单请求、多请求变量、表达式、重定向、超时、raw、文件上传、正向/反向 fixture、单条失败隔离和目标范围校验。

旧 Python 漏洞插件逐项建立 YAML 等价规则，至少完成正向和反向 fixture；等价验证通过后删除重复 Python。上线顺序为导入器与 manifest、离线执行器、旧插件迁移、NPoC 接入、API/UI、回归验证、生产启用（总开关仍默认关闭）、最后清理已验证的重复 Python。

## 8. 当前实施原则

迁移阶段先交付可重复导入、静态门禁、YAML 运行时基础能力和现有链路接入；等价验证完成前，旧 Python 漏洞插件保留 fallback。任何规则不支持或失败都必须可观测，不得静默丢弃；不得执行未被用户选中的 POC。

## 9. 已实施与验收记录（2026-09-14）

### 9.1 导入与清单

- 已新增 `ARL-NPoC/tools/import_dt_pocs.py`，支持 `ARL_POC.zip` 和 `rules/` 目录，可重复执行。
- 已导入 4,420 条规则：4,419 条 `ready`、1 条精确内容重复 alias、0 条隔离；规范化内容哈希无重复执行实体。
- 实际重复规则为 `poc-yaml-PigCMS-file-arbitrary-upload`，alias 到 `poc-yaml-PigCMS-action_flashUpload-arbitrary-upload`，两个 ID 都保留在 manifest/数据库兼容层。
- 已修复并记录 2 条已知 YAML 问题：GWT 规则的字面制表符、Elber Wayber 规则的 `\x3a` 和字面制表符。
- 已补充文件上传字段 `name/data` 到 `filename/content` 的结构归一化；未知结构不猜测，进入隔离。
- `ARL-NPoC/tools/validate_yaml_manifest.py` 已验证：ready 文件 4,419 个全部存在，路径未越界，哈希一致，未引用 dt 文件为 0。
- 运行能力静态分类为 `full=4,401`、`partial=19`。其中 14 条使用 Java DNS gadget，5 条使用 TCP 专项检查；这些规则仍在可执行清单中，运行失败会返回 `partial` 并落入 `poc_scan_error`，不会静默丢失。

### 9.2 YAML 执行器与 NPoC 链路

- 已新增 `ARL-NPoC/xing/yaml_poc.py` 的 `YamlPocPlugin` 和受限 AST DSL，未使用 `eval/exec`。
- 已接入 HTTP/TCP、多请求顺序、变量传递、raw、files、redirect、timeout、rawPath、响应字段、逻辑运算和实际数据集中出现的函数/对象方法。
- 目标校验限制规则只能使用当前任务目标的协议和主机；YAML 路径不会导致执行器访问规则指定的外部主机。
- YAML 结果已携带 `poc_engine`、`poc_id`、`poc_source`、`severity`、`tags`、`request_index`、`match_summary` 和限长脱敏 `evidence`。
- Python POC 结果补齐相同字段形状；未统一的 Python 请求证据不复制原始响应，使用空证据对象。
- NPoC 已按 YAML 优先、Python fallback 加载；alias 请求会映射到唯一规范执行实体。
- 当前加载结果为 4,459 条 YAML POC（4,419 条 dt + 40 条 legacy），名称唯一；brute、sniffer、listener 源码未纳入 YAML 化。

### 9.3 40 个旧漏洞插件迁移

- 已新增 `migrate_legacy_pocs.py` 和 `verify_legacy_pocs.py`，生成 40 个稳定 ID 的 YAML 规则及 `legacy_manifest.json`。
- 40 个规则均完成正向/反向 mock fixture 等价验证，清单状态为 `verified`，并记录 `python-plugin-before-removal` 作为对照来源。
- 等价验证完成后已删除 40 个重复的 identify/noauth/poc Python 漏洞实现；brute、sniffer、listener 保留。

### 9.4 API、任务和前端

- `/poc/` 已支持服务端分页、关键字、ID、漏洞名称、指纹、标签、严重等级、engine、source、status 等查询。
- 任务和策略增加 `npoc_poc_scan`；新建任务默认关闭，具体 POC 默认不选中。总开关关闭时保留选择配置，但不执行；开启且未选择时 UI 明确提示且不会全量执行。
- 选择列表只请求 `status=ready` 的 POC，支持跨页保留选择、当前筛选结果全选/清空，并展示严重等级、引擎、指纹和标签。
- 任务范围校验、超时、并发、WAF 过滤和现有 Nuclei/Afrog 独立开关保持不变。
- 单条 YAML 失败会写入 `poc_scan_error`，不会使其它 POC 或任务整体异常终止；任务删除会一并清理该集合。

### 9.5 已执行检查

- 导入器和 manifest 校验：4,420 条通过，隔离 0 条。
- 40 条 legacy 规则正反向等价快照：40/40 通过。
- Python 定向回归：11 个测试通过；统一指纹既有回归：18 个测试通过。
- 前端 Vitest：22 个测试文件、137 个测试通过。
- ICP 完整协议 fixture：令牌、验证码、查询顺序和凭证传递测试通过；ICP 定向回归 49 项通过、1 项因本机缺少 Pillow/numpy 跳过。
- 前端 TypeScript lint 和生产构建均通过。
- 变更 Python 文件已通过 `py_compile`，`git diff --check` 无空白错误。

### 9.6 上线前保留项

- 当前环境缺少 `dnslib`、`requests_ntlm`、`Cryptodome`，因此本地动态加载时会提示少量既有 brute/listener 可选依赖缺失；未修改这些非本次范围的插件。生产镜像需按原依赖清单安装。
- 真实授权目标上的 HTTP/TCP fixture 尚未执行，本轮已完成 mock、静态门禁、目标边界和结果链路验收；生产开启前仍应使用授权测试资产执行一次端到端验证，结果补充到本归档文档。
