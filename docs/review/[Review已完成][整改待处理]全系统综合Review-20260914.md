# ARL 全系统综合 Review

报告状态：复评完成；保留整改待处理项

整改状态：整改复核完成；新增 SEC-11 文档治理冲突，保留未验证项和部署协作项

评审日期：2026-09-15

评审基线：当前工作树 `newUI`；整改提交 HEAD 为 `be87dfcbb31953491ed7c2915b966de787b9fa62`（`fix(core): 收敛全系统Review整改与资产规则链路`）。当前仅有 `ARL/docker/config-docker.yaml` 未提交变更，未读取或复制其中的配置值。

## 1. 结论摘要

初始评审没有发现需要立即判定为 P0 的阻断项，但发现多项 P1 重要问题，且后端全量 pytest 无法完成测试收集。后续整改已覆盖大部分可在当前工作树完成的代码问题；当前最终状态以第 10 节整改复核和第 11 节放行条件为准。

**整改代码和离线门禁可以进入人工 Review/测试阶段，但当前工作树仍不应判定为生产放行版本。**

初始评审发现的问题已在第 10 节逐项复核。当前仍影响放行的事项：

- SEC-05 的运行时配置轮换、历史清理和 secret scan 需要部署维护者确认；
- 后端全量 pytest 仍在收集阶段有 10 个错误，不能用定向测试替代；
- Docker runtime、真实授权目标、多用户隔离、双架构、40/64 性能、浏览器视口和依赖漏洞库仍没有本机完整证据；
- ARCH-03、PERF-02 属于需要后续架构/性能环境验证的剩余项；
- 资产采集完整性与凭证原文的受控处理仍需与参考准则保持一致，不能把凭证原文扩散到日志、错误、Git 或第三方链路。

已确认的正向结果：前端 Vitest 137 项全部通过，TypeScript 检查和生产构建通过；4,420 条 YAML POC manifest 校验无 quarantine、无未引用源文件；40 个 legacy POC 校验通过；计划 5/6/7 离线回归和主题对比度门禁通过；外部命令静态扫描未发现 `shell=True` 或 `os.system`。

## 2. 评审范围、方法与限制

### 2.1 覆盖范围

- Flask/Flask-RESTX API、认证、任务创建、策略、资产查询、导出、调度、ICP、GitHub、Nuclei、Afrog、NPoC、指纹和文件泄漏；
- Celery、RabbitMQ、Redis、MongoDB、阶段编排、恢复、WAF 和请求去重；
- React/TypeScript 主页面、ActionDialog、表格、筛选、分页、批量操作、ICP、配置、AI、监控、主题和通用 API client；
- ARL-NPoC YAML 执行器、legacy Python fallback、manifest、指纹 JSON/JSON.GZ、Rust native 目录、Docker Compose、Nginx 和外部工具调用；
- 当前工作树所有既有 Review、历史整改和本轮新增改动。

### 2.2 使用的工具

- Git：工作树、变更范围、diff hygiene；
- CodeGraph 0.9.9：同步当前工作树，并查询 `RiskCruising`、`YamlPocPlugin`、`TaskFinalizer`、`requestApi`、截图路由、导出下载和搜索引擎入口；
- `rg`、AST 解析、配置静态检查、外部进程调用扫描；
- pytest、unittest、Vitest、TypeScript、Vite build；
- YAML manifest 校验、legacy POC 校验、指纹门禁、主题对比度门禁；
- Docker Compose 静态展开；
- 本地可用的 npm、Python、Docker 工具。

### 2.3 明确限制

- 未读取或使用生产凭证、真实 Token、Cookie、密码、代理凭证；报告不复制任何敏感配置值；
- 未对真实授权目标发起扫描，未执行真实 DNS/WAF/CDN、FOFA/Hunter 配额、外部 ICP 服务和生产数据验证；
- 当前主机未提供可用的 Chromium/Firefox 命令，未完成 390×844、768×1024、1280×800、1440×900 的浏览器视觉回归；
- 未找到本机 `pip-audit`、`cargo-audit`，且 `npm audit` 访问 advisory endpoint 失败，依赖漏洞库结果标记为未验证；
- 未启动完整 Docker Compose 栈；Compose 只做了合成环境变量下的静态展开；
- 初始 Review 阶段只新增本报告；后续整改阶段已产生对应业务代码、测试、配置和规则产物变更。本报告不复制任何 Cookie、Authorization、密码、Token、代理凭证或其它敏感值。

## 3. 当前工作树基线

| 项目 | 结果 |
|---|---|
| 分支 | `newUI` |
| HEAD | `be87dfcbb31953491ed7c2915b966de787b9fa62` |
| 已提交变更 | 4,594 个文件；包含整改代码、测试、规则产物和文档 |
| 当前未提交 tracked 路径 | 1：`ARL/docker/config-docker.yaml` |
| 当前未跟踪文件 | 0 |
| `git status --short` 条目 | 1 |
| 当前未提交 diff | 7 行新增，4 行删除；未读取配置值 |
| ARL-NPoC YAML 文件 | 4,461 个源/产物路径，主 manifest 4,420 条规则 |
| 前端依赖形态 | React 19、TypeScript 5.8、Vite 6、Vitest 5、TanStack Query 5、Tailwind 4、daisyUI 5 |
| 后端主要依赖 | Flask 2.0.3、Celery 5.1.2、PyMongo 相关组件、Requests 2.26.0、PyYAML 6.0.2 |
| 运行编排 | MongoDB、Redis、RabbitMQ、web、scheduler、2 个 worker、Nginx |

工作树包含大量 YAML POC、指纹产物和旧 Python POC 删除，不是单一小变更集。后续修复应按功能边界拆分提交，避免把审计修复与数据生成、插件删除混在一个提交中。

## 4. 门禁与动态验证结果

| 门禁 | 命令/范围 | 结果 | 评审含义 |
|---|---|---|---|
| CodeGraph | `codegraph sync` | 通过；同步 4,547 个 changed files，新增 4,472、修改 35、删除 40 | 当前索引可用于本轮结构查询 |
| Python AST | 对 `ARL/app`、`ARL-NPoC/xing` 的 329 个 Python 文件执行 `ast.parse` | 通过，`parsed=329 failed=0` | 语法层无失败 |
| 后端全量 pytest | `cd ARL && PYTHONPATH=../ARL-NPoC python3 -m pytest -q` | 失败：收集阶段 10 个错误 | 不能判定后端全量通过，见 TEST-01 |
| 后端定向回归 | Review round4~8、渐进式阶段、账本和 fileLeak 测试 | 47 passed，5 warnings | 仅证明选定链路 |
| 指纹/计划回归 | `python3 scripts/plan567-code-check.py --plan all` | 通过 | 计划 5/6/7 离线门禁通过，不等同生产放行 |
| 主题对比度 | `python3 scripts/check-theme-contrast.py` | 6 套主题、全部检查 PASS | token 对比度基础门禁通过 |
| YAML manifest | `python3 ARL-NPoC/tools/validate_yaml_manifest.py --output-root ARL-NPoC/xing/pocs` | 4,420 entries；4,419 ready；1 duplicate；0 quarantine；0 未引用 | duplicate 有 alias 记录，没有静默丢弃；需保留验收口径 |
| legacy POC | `python3 ARL-NPoC/tools/verify_legacy_pocs.py` | 40/40 通过 | fixture 等价校验通过，真实目标未验证 |
| 前端测试 | `cd ARL/docker/frontend-src && npm test` | 22 files，137 tests 通过 | 有 jsdom mock 证据；出现非致命 navigation warning |
| TypeScript | `npm run lint` | 通过 | 类型检查通过 |
| 前端构建 | `npm run build` | 通过；主 JS gzip 约 147.68 kB，charts gzip 约 104.64 kB | 构建可用；bundle 仍需性能预算治理 |
| Docker Compose | 合成环境变量下 `docker compose -f ARL/docker/docker-compose.yml config --quiet` | 通过；8 个服务 | 仅静态配置通过，未证明容器健康 |
| Docker 运行态 | `docker ps` | 当前无运行容器 | 未完成 runtime smoke |
| npm 依赖审计 | `npm audit --omit=dev --audit-level=high` | 失败；advisory endpoint 网络/代理不可达 | 漏洞状态未验证，不判定安全 |
| pip/cargo 依赖审计 | `pip-audit`、`cargo-audit` | 本机命令不可用 | 未验证 |
| 浏览器视口 | 390×844、768×1024、1280×800、1440×900 | 未执行；未找到浏览器二进制 | UI 视觉和真实焦点操作未验证 |
| 工作树 hygiene | `git diff --check` | 通过 | 无 whitespace 错误 |

## 5. 问题清单

严重级别含义：P0=阻断，P1=重要，P2=一般，P3=建议。标签使用 `blocking`、`important`、`nit`、`unverified`。状态使用新增、仍存在、已修复、回归、证据不足。

以下条目保留初始评审发现和初始证据，便于追溯问题来源；整改后的当前状态统一见第 10 节，不再以本节的历史状态字段作为最终结论。

### 5.1 架构与代码质量

#### ARCH-01：跨 Celery 消息没有共享同一 DiscoveryContext

| 项目 | 内容 |
|---|---|
| 级别/标签 | P1 / important |
| 状态 | 仍存在；对应历史架构 Review A1 |
| 证据 | `ARL/app/tasks/domain.py:950-982` 的 discovery 和 deep 由两个任务函数分别实例化 `DomainTask`；`ARL/app/services/commonTask.py:268-275` 每个实例创建自己的 `DiscoveryContext`；`ARL/app/celerytask.py:1679-1703` 深度消息只恢复 task/options。 |
| 触发条件 | 渐进式域名任务先完成 discovery，再由新的 Celery 消息运行 deep。 |
| 影响 | 进程内响应缓存、single-flight 和候选状态不能跨 worker/消息复用，同一站点可能重复请求；历史账本只能恢复阶段事实，不能替代受控响应摘要。 |
| 建议 | 明确跨消息数据契约，使用带 TTL、大小限制、脱敏和任务范围约束的持久化摘要；不要将完整响应体无界写入 Mongo。 |
| 验收 | 两个独立 worker 执行 preview/deep fixture，证明请求次数、缓存命中、候选状态和 WAF 归因符合冻结口径；worker 重启后仍能恢复。 |
| 对应计划/历史 | `docs/review/[Review已完成][整改待处理]系统框架与架构Review-20260905.md` §4 高风险 1；计划 6 发布门禁。 |

#### ARCH-02：fileLeak 子进程边界已有 watchdog，但请求计数和重复抑制缺少端到端证据

| 项目 | 内容 |
|---|---|
| 级别/标签 | P2 / important + unverified |
| 状态 | 证据不足；对应历史架构 Review A2 |
| 证据 | `ARL/app/services/fileLeak.py:1218-1392` 已有 `ProcessLease`、heartbeat、超时杀进程和 JSON IPC；当前 metrics 主要回传输入、输出、失败、timeout、pending、degraded 等计数，未在本机完成子进程真实请求总数与父进程去重账本的一致性验证。 |
| 触发条件 | fileLeak watchdog 子进程启动、超时、返回空结果或 inline fallback。 |
| 影响 | 可能无法准确证明目录字典扫描是否重复请求、子进程请求是否纳入统一 WAF/请求计数，以及恢复后是否存在漏扫或重复扫描。 |
| 建议 | 在 IPC contract 中固定 request_count、dedup_hit、lease owner、未完成 URL 和恢复原因；将父子进程计数做严格对账。 |
| 验收 | mock worker 正常、超时、崩溃、空结果、重复启动五组 fixture；核对父子进程请求计数和最终 task metrics。 |
| 对应计划/历史 | 架构 Review §4 高风险 3、历史 T5/A2。 |

#### ARCH-03：CommonTask/DomainTask 仍是跨层复杂度中心

| 项目 | 内容 |
|---|---|
| 级别/标签 | P2 / important |
| 状态 | 仍存在；历史整改未要求本轮立即拆分 |
| 证据 | `ARL/app/services/commonTask.py:56-80,443-460` 同时持有任务上下文、scope、结果写入和阶段执行入口；`ARL/app/tasks/domain.py:392` 及相关方法仍承接任务状态、阶段兼容入口、候选和后处理。 |
| 触发条件 | 新能力继续从旧 facade 进入，或同一 stage 同时由 task/service 组装结果。 |
| 影响 | 业务边界、兼容层和持久化 owner 不清晰，增加重复请求、重复写入和回归概率。 |
| 建议 | 以 stage 为单位冻结输入/输出/持久化契约，逐步把网络、结果组装和副作用移到 stage service；旧方法只保留兼容转发。 |
| 验收 | 每个迁移 stage 有调用图、单元测试、异常/取消/重试测试，并证明旧入口与新入口只触发一次请求和一次写入。 |
| 对应计划/历史 | 架构 Review §4 高风险 5、计划 2 逐 stage 迁移项。 |

#### ARCH-04：深度阶段虽已入队，消息内部仍是同步长链路

| 项目 | 内容 |
|---|---|
| 级别/标签 | P2 / important |
| 状态 | 仍存在 |
| 证据 | `ARL/app/services/task_orchestrator.py:31-79` 的 `run_deep()` 连续执行 domain fetch、搜索引擎、IP、site、vhost、POC、WIH 更新和 finalizer；`ARL/app/tasks/domain.py:968-982` 仅把整个 deep 作为一个 Celery 任务。 |
| 触发条件 | 单个深度任务包含大量目标、外部工具或网络等待。 |
| 影响 | 取消、超时、worker 重启和阶段级重试的粒度不足，单阶段阻塞会延迟后续阶段；跨消息上下文问题也无法仅靠当前任务实例解决。 |
| 建议 | 按可恢复 stage/batch 拆分，明确每个阶段的 ledger、deadline、重试和终态 owner；先保持默认行为不变，再以灰度开关切换。 |
| 验收 | 中断每个 stage 后恢复；证明不会重复写结果、不跳过后续 stage，且任务终态只由一个 owner 决定。 |
| 对应计划/历史 | 架构 Review A6、计划 6 发布验收。 |

#### ARCH-05：结果写入仍存在多个直接 collection owner

| 项目 | 内容 |
|---|---|
| 级别/标签 | P2 / important |
| 状态 | 仍存在；按历史决策暂未迁移 |
| 证据 | `ARL/app/services/task_lifecycle_service.py:26-65` 直接操作 `task`、`stat_finger`、`cip`；其他 stage 仍直接使用 collection writer。统一 `TaskResultWriteService` 并未覆盖所有统计和派生集合。 |
| 触发条件 | 任务恢复、重复 finalize、阶段部分失败或同一数据由多个入口落库。 |
| 影响 | 幂等、字段规范化、错误处理和审计口径不完全统一，后续容易出现重复行或统计与结果不一致。 |
| 建议 | 明确每个 collection 的唯一写入 owner，所有写入走 repository/service；迁移期间保留写入计数和幂等键。 |
| 验收 | 同一 task 重复 finalize、worker 重启、部分失败三类测试，证明结果集合和统计集合稳定。 |
| 对应计划/历史 | 架构 Review A3；历史记录明确本轮不动。 |

### 5.2 功能正确性与任务生命周期

#### FUNC-01：风险巡航异常不会写入 ERROR 终态

| 项目 | 内容 |
|---|---|
| 级别/标签 | P1 / blocking |
| 状态 | 新增 |
| 证据 | `ARL/app/tasks/poc.py:400-424` 的 `RiskCruising.run()` 在 `except` 中仅记录 `append_task_error`，没有 `update_task_field("status", TaskStatus.ERROR)`；随后无论异常与否只写 `end_time`。 |
| 触发条件 | WebSiteFetch、服务识别、爆破、POC、数据库写入或 common_run 抛出异常。 |
| 影响 | 任务可能停留在 `PoC` 或其他阶段状态，UI 轮询、恢复和用户判断会把已失败任务当作运行中或无终态任务。 |
| 建议 | 所有任务主入口使用统一终态映射，在 `finally` 前记录失败阶段和错误摘要，并保证 ERROR/partial/done_degraded 语义一致。 |
| 验收 | 对每个阶段注入异常；断言 task status、end_time、task error、通知和后续恢复行为。 |
| 对应计划/历史 | 任务终态语义、计划 6/7 生命周期门禁。 |

#### FUNC-02：PoC/Brute 子线程异常不回传，且进度读取存在 runner 初始化竞态

| 项目 | 内容 |
|---|---|
| 级别/标签 | P1 / important |
| 状态 | 新增 |
| 证据 | `ARL/app/tasks/poc.py:234-252` 和 `274-291` 使用 `Thread(target=npoc_instance.run_poc)`；主线程只等待 `is_alive()`，未检查线程异常；`npoc_instance.runner` 在 `ARL/app/services/npoc.py:185-187` 才赋值，但主线程在 `poc.py:239-243` 直接访问。 |
| 触发条件 | 子线程在 runner 赋值前开始、插件加载异常、结果文件解析失败、外部请求异常或 runner 内部异常。 |
| 影响 | 可能出现进度循环异常、主流程误以为 PoC 完成、结果不完整但任务继续执行；异常不一定进入任务错误链路。 |
| 建议 | 取消手工线程或使用可观察的 Future；主线程必须 join、读取异常、限制等待并保证 runner/结果初始化；结果文件用 `try/finally` 清理。 |
| 验收 | runner 初始化延迟、单插件异常、结果解析异常、超时和取消 fixture；断言任务终态、partial 记录和临时文件清理。 |
| 对应计划/历史 | NPoC YAML 执行器计划的“单条失败不阻断其它规则”验收项。 |

#### FUNC-03：NPoC manifest 的 duplicate_count 为 1，应在发布口径中明确“源规则数”和“执行实体数”

| 项目 | 内容 |
|---|---|
| 级别/标签 | P2 / nit |
| 状态 | 已修复但需文档澄清 |
| 证据 | manifest 校验结果为 `rule_count=4420`、`ready_count=4419`、`duplicate_count=1`、`quarantine_count=0`；重复项保存了 alias，主 manifest 没有未引用 YAML。 |
| 触发条件 | 发布验收直接把 `ready_count` 当作规则总数，或把 duplicate 当作静默丢弃。 |
| 影响 | 统计口径与计划“4,420 条规则全部经过门禁”产生误读；历史 ID 兼容性依赖 alias。 |
| 建议 | manifest 增加 source_count、execution_entity_count、alias_count 三个明确字段，校验脚本和 UI 分别展示。 |
| 验收 | 同内容不同 ID、不同内容同 ID、隔离失败、无 alias 四类 manifest fixture；执行实体无重复且所有源 ID 可追溯。 |
| 对应计划/历史 | NPoC YAML 统一导入计划 §二、§五。 |

### 5.3 界面设计与交互逻辑

#### UI-01：表格批量选择没有跨页保留

| 项目 | 内容 |
|---|---|
| 级别/标签 | P1 / important |
| 状态 | 新增 |
| 证据 | `ARL/docker/frontend-src/src/views/TableModuleView.tsx:704-705` 在分页、筛选或模块状态变化时直接 `setSelectedIds([])`；`1090-1127` 的 `loadRows()` 成功后再次清空；`3389-3403` 的表头全选只收集当前 `displayRows`。 |
| 触发条件 | 在第 1 页勾选任务，翻到第 2 页或刷新列表后继续批量停止、删除、导出。 |
| 影响 | 已选任务被静默取消，用户以为执行了跨页批量操作但实际只处理当前页；对删除/停止尤其危险。 |
| 建议 | 以模块+筛选签名维护跨页 selected set；区分“当前页全选”和“全部筛选结果全选”；筛选变化时给出清空提示。 |
| 验收 | 4 个视口下跨页选择、轮询刷新、筛选变化、取消操作和批量失败回滚测试；服务端最终收到完整 ID 集合。 |
| 对应计划/历史 | 综合 Review 计划 §六“跨页选择不能丢失”。 |

#### UI-02：NPoC 搜索/全选缺少 debounce 和取消，可能产生长时间串行请求

| 项目 | 内容 |
|---|---|
| 级别/标签 | P2 / important |
| 状态 | 新增 |
| 证据 | `ARL/docker/frontend-src/src/views/ActionDialog.tsx:282-328` 关键字直接进入 query key；`525-551` 的 `fetchAllPocNames()` 按每页 100 条串行请求，未传递 `AbortSignal`。 |
| 触发条件 | 在 4,420 条规则上连续输入、快速切换关键词，或点击“筛选结果全选”。 |
| 影响 | 请求堆积、旧响应继续返回、弹窗关闭后仍占用网络和浏览器资源；4,419 条执行实体最多需要几十次顺序请求。 |
| 建议 | 输入 debounce；统一 query cancellation；全选使用后端按筛选签名返回 ID 的接口或异步任务，显示进度并可取消。 |
| 验收 | 快速输入、切换页、关闭弹窗、网络慢和后端 5xx fixture；确认没有旧结果覆盖新筛选，也没有未结束请求。 |
| 对应计划/历史 | NPoC YAML 计划 §四任务 API/UI。 |

#### UI-03：表格行选择和表头选择缺少可访问名称

| 项目 | 内容 |
|---|---|
| 级别/标签 | P2 / nit |
| 状态 | 新增 |
| 证据 | `ARL/docker/frontend-src/src/views/TableModuleView.tsx:3389-3403` 和 `3456-3460` 的 checkbox 没有 `aria-label`、`id/label` 或 `aria-labelledby`；ActionDialog 中嵌套 label 的控件相对完整。 |
| 触发条件 | 使用键盘或屏幕阅读器执行表格批量操作。 |
| 影响 | 用户无法知道表头 checkbox 是当前页全选，行 checkbox 也无法获知对应任务/资产。 |
| 建议 | 为表头增加“选择当前页”语义，为行选择关联稳定的可读名称和 ID；补充键盘焦点、Space 操作测试。 |
| 验收 | axe 或等价可访问性检查；键盘 Tab/Space/Enter 操作与鼠标行为一致。 |
| 对应计划/历史 | 综合 Review 计划 §六键盘、焦点和语义控件。 |

#### UI-04：勾选颜色与主题对比度基础门禁通过，但缺少真实渲染回归

| 项目 | 内容 |
|---|---|
| 级别/标签 | P3 / unverified |
| 状态 | 证据不足 |
| 证据 | `ARL/docker/frontend-src/src/index.css:757-801,879-889` 已把普通 checkbox、checkbox card 和 toggle 分开处理；`check-theme-contrast.py` 全部通过，但没有浏览器截图或真实 CSS 计算结果。 |
| 触发条件 | 深色主题、浅色 sandstone、禁用态、系统高对比度模式或非 Chromium 浏览器。 |
| 影响 | 颜色 token 通过静态对比度不等于选中符号、边框、焦点环和背景组合在真实渲染中都可读。 |
| 建议 | 按四个视口和六个主题截图验收，单独测 checkbox glyph/background、hover、focus、disabled 和 reduced-motion。 |
| 验收 | 浏览器截图 diff、颜色对比度和键盘焦点检查；确认不依赖颜色单一表达状态。 |
| 对应计划/历史 | 既有主题/侧边栏 Review；用户此前提出的勾选颜色调整。 |

### 5.4 安全

#### SEC-01：截图 GET 接口缺少应用层认证和任务归属校验

| 项目 | 内容 |
|---|---|
| 级别/标签 | P1 / blocking |
| 状态 | 新增 |
| 证据 | `ARL/app/routes/image.py:67-117` 的 `ARLImage.get()` 没有 `@auth`，只对 task/file 参数做 `secure_filename` 和扩展名检查，然后直接读取 `Config.SCREENSHOT_DIR/{task_id}/{file_name}`。上传接口从 `120` 行开始才使用 `@auth`。 |
| 触发条件 | 已知另一个任务 ID 和图片文件名的用户请求截图接口。 |
| 影响 | 应用层不能证明调用者有权读取该 task 的截图；在多用户或共享 Basic Auth 场景下可能造成跨任务截图泄露。路径清洗不能替代授权。 |
| 建议 | 加 `@auth`，并校验 task 存在、调用者/租户归属、文件记录和允许的 screenshot key；不存在时返回一致的 404，不返回默认图片造成资源枚举。 |
| 验收 | 未登录、无权任务、合法任务、错误文件名、符号链接和跨租户 fixture；断言无越权读取。 |
| 对应计划/历史 | 综合 Review 计划 §七认证、对象级授权、文件下载。 |

#### SEC-02：`GET /poc/delete/` 承载全量不可逆删除

| 项目 | 内容 |
|---|---|
| 级别/标签 | P1 / blocking |
| 状态 | 新增 |
| 证据 | `ARL/app/routes/poc.py:150-176` 以 `GET` 方法加 `@auth` 暴露 `conn_db('poc').delete_many({})`。 |
| 触发条件 | 管理员会话、Token query fallback、浏览器预取、误点击或内部调用把删除接口当作查询接口。 |
| 影响 | GET 语义被破坏，增加 CSRF/预取/缓存误触发和运维误调用风险；操作会清空全部 POC 配置，用户已保存的选择可能变为不可执行。 |
| 建议 | 改为 POST/DELETE，增加明确的管理员权限、二次确认、审计事件、幂等返回和 dry-run；禁止通过 query 参数传凭证。 |
| 验收 | GET 返回 405；POST 无确认/无权限失败；确认后只执行一次；审计记录删除数量和操作者。 |
| 对应计划/历史 | 综合 Review 计划 §七认证、CSRF、删除确认。 |

#### SEC-03：task scope 按同名任务扩展，存在跨任务范围放大风险

| 项目 | 内容 |
|---|---|
| 级别/标签 | P1 / important + unverified |
| 状态 | 仍存在；需授权多用户 fixture 复现 |
| 证据 | `ARL/app/services/task_scope_guard.py:140-177` 先读取当前 task 的 `name`，再查询 `{"name": task_name}` 的全部任务并合并 target、site、url、domain。 |
| 触发条件 | 两个任务名称相同但目标集合不同，且后续阶段使用 scope guard 进行主动请求或资产显影。 |
| 影响 | 任务 A 的请求可能被判定为任务 B 范围内，导致扫描超出当前任务授权边界或读取其他任务资产；任务名称通常可由用户重复。 |
| 建议 | scope 只以 task_id、scope_id 和显式 parent/related task IDs 为边界；若确需同名聚合，必须显式存储关系并做权限校验，禁止隐式 name join。 |
| 验收 | 同名不同用户、同名同用户、不同 scope、缺失 task 和 Mongo 查询失败 fixture；断言允许主机集合不跨边界。 |
| 对应计划/历史 | 综合 Review 计划 §七 URL/域名/IP 范围校验；任务隔离要求。 |

#### SEC-04：endpoint probe 跟随重定向但没有校验最终地址

| 项目 | 内容 |
|---|---|
| 级别/标签 | P1 / important + unverified |
| 状态 | 新增；静态证据充分，真实目标未执行 |
| 证据 | `ARL/app/services/wih_endpoint_probe.py:306-333` 只对初始 URL 执行 `check_dns_policy_for_url`；`_build_request_kwargs()` 设置 `allow_redirects=True`、`verify=False`，随后 `:400-401` 直接请求。代码未对 `response.url` 或 redirect history 的每一跳重新执行 scope/DNS policy。 |
| 触发条件 | 合法范围内 endpoint 返回到 localhost、RFC1918、云元数据或其他不在任务范围的地址。 |
| 影响 | 轻量验证可能绕过任务目标范围，形成 SSRF/内网访问路径；TLS 校验关闭还放大了中间人风险。 |
| 建议 | 默认禁用跨 host 重定向；每一跳解析并校验 scheme、host、解析 IP、端口和任务 scope；不合规时停止并记录 degraded。 |
| 验收 | mock redirect 到外部同域、外部跨域、私网 IP、IPv6、本地回环、redirect loop；断言不发起越界后续请求。 |
| 对应计划/历史 | 综合 Review 计划 §七 SSRF、重定向和目标范围。 |

#### SEC-05：版本管理配置模板含默认凭据类信息

| 项目 | 内容 |
|---|---|
| 级别/标签 | P1 / important |
| 状态 | 仍存在 |
| 证据 | `ARL/app/config.yaml:1-8`、`ARL/docker/config-runtime.yaml:1-18` 存在 broker/Mongo/第三方配置项的默认或实值形态；Compose 虽在 `ARL/docker/docker-compose.yml:18-19,338-356` 对部分凭据设置了必填环境变量，但不能抵消已进入版本管理模板的值。 |
| 触发条件 | 用户复制模板、误把 runtime 文件纳入镜像、默认部署或日志/备份传播。 |
| 影响 | 可能导致消息队列、数据库或第三方服务凭据复用、泄露或供应链传播。 |
| 建议 | 立即轮换已暴露凭据；模板只保留占位符；runtime/config、`.env` 和备份目录加入明确 ignore/secret manager 流程；CI 增加 secret scanning。报告不复制具体值。 |
| 验收 | Git 历史和当前树 secret scan clean；空凭据不能启动生产 Compose；启动日志不打印凭据；轮换后旧值不可用。 |
| 对应计划/历史 | 综合 Review 计划 §七敏感配置、Docker 和部署安全。 |

#### SEC-06：认证允许 query token，change_pass 未使用统一 auth decorator

| 项目 | 内容 |
|---|---|
| 级别/标签 | P2 / important |
| 状态 | 仍存在 |
| 证据 | `ARL/app/utils/user.py:29-56` 从 header 或 `request.args.get("token")` 取认证；`ARL/app/routes/user.py:113-178` 的 `ChangePassARL.post()` 没有 `@auth`，直接把 header Token 交给 `change_pass()`；`ARL/app/utils/user.py:65-70` 以 token+旧密码查询。 |
| 触发条件 | Token 被放在 URL、日志、浏览器历史或 Referer；调用者绕过统一 decorator 直接调用改密接口。 |
| 影响 | URL token 可能进入访问日志、代理和历史；认证策略分裂，后续修改 password/session 生命周期容易出现未登录改密或账户状态边界问题。 |
| 建议 | 仅接受受保护 header/cookie，移除 query token；改密先通过统一认证得到 user identity，再用旧密码做 re-auth；成功后撤销所有旧 token。 |
| 验收 | query token 永不认证；无效/过期 token 不能改密；成功改密使旧会话失效；日志和 Referer 不出现凭证。 |
| 对应计划/历史 | 综合 Review 计划 §七认证、Token 生命周期和前端存储。 |

#### SEC-07：多条扫描链路默认关闭 TLS 证书校验

| 项目 | 内容 |
|---|---|
| 级别/标签 | P2 / important |
| 状态 | 仍存在；部分场景为兼容自签名目标的设计 |
| 证据 | `ARL-NPoC/xing/yaml_poc.py:254-263` TCP TLS 使用 `CERT_NONE`；`ARL-NPoC/xing/utils/__init__.py:110-118,202-204` HTTP 默认 `verify=False`；`ARL/app/services/wih_endpoint_probe.py` 的 request kwargs 也为 `verify=False`；截图内部同步 `ARL/app/services/siteScreenshot.py:127-137` 同样关闭校验。Nginx 反代配置 `ARL/docker/nginx-reverse-proxy/nginx.conf:49-67,78-96` 关闭 upstream verify。 |
| 触发条件 | 代理、网络被劫持、错误路由或扫描器访问非受信 TLS endpoint。 |
| 影响 | 无法检测中间人或错误服务；POC 请求、第三方 provider、内部同步和控制面之间的信任边界变弱。 |
| 建议 | 控制面和内部服务默认启用证书校验并配置 CA；仅对明确标记的目标兼容模式关闭，结果中记录原因，禁止把兼容开关作为全局默认。 |
| 验收 | 自签名目标兼容模式、合法 CA、错误 CA、代理 MITM mock 四类测试；控制面错误证书必须失败。 |
| 对应计划/历史 | 综合 Review 计划 §七 TLS、代理和外部工具边界。 |

#### SEC-08：异步导出 job status/download 没有 owner 过滤

| 项目 | 内容 |
|---|---|
| 级别/标签 | P2 / important + unverified |
| 状态 | 证据不足；取决于产品是否支持多用户/租户 |
| 证据 | `ARL/app/routes/export.py:1698-1755` 通过 `@auth` 认证后只按 job_id 调用 `ExportRepository.find_job()`，没有 requester、tenant 或 task ownership 条件。 |
| 触发条件 | 多用户部署中用户获得另一个 job_id。 |
| 影响 | 可能读取其他用户导出状态和报告文件；当前单管理员部署模型下暂不能确认可利用性。 |
| 建议 | 创建 job 记录 owner/tenant，status/download 查询必须同时过滤；下载前重新校验所有 task 的权限和文件路径在导出根目录内。 |
| 验收 | 两用户创建 job、交叉查询/下载、猜测 ID、已删除文件和路径穿越 fixture。 |
| 对应计划/历史 | 综合 Review 计划 §七对象级授权、导出下载。 |

#### SEC-09：多处 API 错误响应直接返回异常文本

| 项目 | 内容 |
|---|---|
| 级别/标签 | P2 / important |
| 状态 | 仍存在 |
| 证据 | `ARL/app/routes/task.py:284-289,770-772` 直接返回 `str(e)`；相同模式还出现在 asset/export/config 等接口。 |
| 触发条件 | 输入非法、数据库异常、文件路径异常或外部工具失败。 |
| 影响 | 可能泄露本地路径、驱动/库信息、第三方响应片段或内部状态；前端又会把 raw error 进入 UI。 |
| 建议 | 对外只返回稳定错误码和脱敏摘要，完整异常仅进入安全日志；建立 `safe_error_text` 统一出口，禁止 path/token/cookie/header 回显。 |
| 验收 | 注入路径、Mongo、网络、子进程和 YAML 解析异常 fixture；断言响应不含绝对路径、凭证和完整请求响应。 |
| 对应计划/历史 | 综合 Review 计划 §七错误回显、日志脱敏和导出数据。 |

#### SEC-10：外部 PoC 仓库更新采用 unpinned branch pull

| 项目 | 内容 |
|---|---|
| 级别/标签 | P2 / important |
| 状态 | 仍存在 |
| 证据 | `ARL/app/routes/api_console.py:4290-4427` 对固定远程仓库执行 clone/fetch/pull，支持将 repo 目录挂载为可写 `ARL/docker/docker-compose.yml:56-57`；未见 commit allowlist、签名校验或内容审核后再启用的门禁。 |
| 触发条件 | 管理员通过配置中心更新 Nuclei/Afrog 仓库，或上游仓库/网络链路被替换。 |
| 影响 | 外部模板、脚本或数据进入扫描执行边界，供应链变更难以追溯；`ff-only` 只能避免本地 merge，不能证明上游内容可信。 |
| 建议 | 使用版本/commit allowlist、签名或供应链扫描；更新后先导入静态门禁和隔离目录，审核通过再切换执行路径；web 不需要时移除 tools 写权限。 |
| 验收 | 恶意模板、远端 commit 变化、origin 变更、签名无效和回滚 fixture；不可验证版本不得进入 ready 清单。 |
| 对应计划/历史 | 综合 Review 计划 §七 Docker、Nuclei/Afrog 外部工具边界。 |

### 5.5 效率、稳定性与运维

#### PERF-01：PoC 同步接口对 4,420 条规则逐条写 Mongo

| 项目 | 内容 |
|---|---|
| 级别/标签 | P2 / important |
| 状态 | 已修复主要阻塞；版本原子切换仍待后续演进 |
| 证据 | `ARL/app/routes/poc.py` 已将同步入口改为 POST 并投递后台 job；`ARL/app/celerytask.py:poc_sync_task` 负责 worker 执行；`ARL/app/services/npoc.py` 使用分块 `bulk_write`，旧 driver 走兼容路径。 |
| 触发条件 | 首次部署、规则更新或管理员重复调用同步接口。 |
| 影响 | 已消除 HTTP 请求长时间阻塞和逐条写入的主要风险；同步中途失败时仍需版本化 upsert/原子 ready 切换避免新旧规则混合可见。 |
| 建议 | 保留后台 job、bulk_write、manifest hash 和幂等 claim；后续增加版本化 upsert，完成后原子切换 ready 版本，清理旧版本采用批量操作。 |
| 验收 | 已有后台提交/worker claim 定向 fixture；仍需 4,420/10,000 规则 mock 性能、Mongo 断连、重复同步、并发同步和版本切换测试。 |
| 对应计划/历史 | NPoC YAML 统一导入计划 §二、§三。 |

#### PERF-02：通用列表查询使用 skip+count，深分页成本无上限

| 项目 | 内容 |
|---|---|
| 级别/标签 | P2 / important |
| 状态 | 仍存在 |
| 证据 | `ARL/app/services/collection_query_service.py:217-244` 对所有集合执行 `find().sort().skip().limit()`，并通常额外 `count_documents()`；导出和大结果集也复用类似查询。 |
| 触发条件 | 资产、日志、POC 或结果集合数据量增长，用户访问深页或频繁轮询。 |
| 影响 | Mongo 扫描和 count 成本随 offset 增长，排序字段无索引时更明显；多个页面并行刷新会放大负载。 |
| 建议 | 对大集合采用基于稳定 sort key 的 cursor pagination；为常用 task_id、save_date、status、plugin_name 等组合建立并验证索引；count 采用缓存/近似值并明确语义。 |
| 验收 | 10 万、100 万 mock 数据的 p95/p99、索引 explain、深页和并发请求对照；确认结果顺序稳定。 |
| 对应计划/历史 | 综合 Review 计划 §八 Mongo 查询、索引和分页。 |

#### STAB-01：NPoC 结果临时文件不是所有路径都 finally 清理

| 项目 | 内容 |
|---|---|
| 级别/标签 | P2 / important |
| 状态 | 仍存在 |
| 证据 | `ARL/app/services/npoc.py:178-197` 创建随机结果文件，只有完成 `load_file` 和 JSON 解析后才执行 `os.unlink(random_file)`；runner 抛异常或解析异常时没有统一 finally。 |
| 触发条件 | 插件异常、进程终止、结果文件损坏、磁盘满或 Mongo 写入前失败。 |
| 影响 | `/tmp` 中积累结果文件，长期运行产生磁盘占用和敏感响应残留；异常也可能丢失可诊断信息。 |
| 建议 | 使用临时目录和 `try/finally` 清理；文件设置权限和大小上限，结果落库前脱敏；启动时清理超过 TTL 的孤儿目录。 |
| 验收 | 正常、runner 异常、解析异常、worker kill、磁盘满五类 fixture；检查文件不存在、权限和日志摘要不含敏感值。 |
| 对应计划/历史 | NPoC YAML 统一导入计划 §三执行限制和证据脱敏。 |

#### STAB-02：读取函数使用 `r+`，只读路径依赖写权限

| 项目 | 内容 |
|---|---|
| 级别/标签 | P3 / nit |
| 状态 | 仍存在 |
| 证据 | `ARL/app/utils/__init__.py:53-55`、`ARL-NPoC/xing/utils/file.py:1-4` 和 `ARL/app/tools/targetGen.py:39` 的只读加载路径使用 `open(..., "r+")`。 |
| 触发条件 | 字典、规则或 POC 目录挂载为只读，或容器采用最小写权限。 |
| 影响 | 只读文件可能因不具备写权限而读取失败，和 Docker 的 `:ro` 运行策略冲突；错误容易被当成外部工具失败。 |
| 建议 | 只读读取统一使用 `r`；需要写入的路径独立使用 `w`/原子替换，并增加权限矩阵测试。 |
| 验收 | `chmod 0444`、只读 bind mount 和正常可写目录三组 fixture。 |
| 对应计划/历史 | 代码质量和 Docker 权限 Review。 |

### 5.6 文档治理与安全边界

#### SEC-11：敏感资产参考准则与当前安全实现存在边界冲突

| 项目 | 内容 |
|---|---|
| 级别/标签 | P1 / important |
| 状态 | 新增；待治理决策 |
| 证据 | `docs/reference/[长期参考]敏感资产采集与受控呈现准则.md:13,31-37,61-63,86-114` 要求登录用户无条件查看和导出敏感原文，并允许凭证进入日志、错误、队列、Git 和第三方链路；当前实现的 `safe_error_text`、受控证据边界和 Review 报告规则禁止这些扩散路径。 |
| 触发条件 | 按当前参考准则新增敏感资产原文列表、导出、日志或报告功能。 |
| 影响 | 会绕过现有认证之外的对象边界和安全处理，导致凭证在日志、缓存、构建产物、代码仓库或第三方系统中扩散；资产采集完整性与凭证访问控制的责任边界不再可审计。 |
| 建议 | 保留敏感信息作为一等资产，不静默丢弃；将原文放入受控存储，按任务/项目/租户授权查看，原文查看和交付留审计，不进入日志、错误、普通导出、Git 或第三方链路。参考准则需与该边界保持一致。 |
| 验收 | 文档、接口、前端、日志、队列、缓存、导出和报告规则一致；未授权用户不能读取原文，授权查看可追溯，安全扫描不能发现原文扩散。 |
| 对应计划/历史 | `docs/reference/[长期参考]敏感资产采集与受控呈现准则.md`；本 Review 安全章节。 |

## 6. 已验证安全项与正向实现

以下项目有当前代码或本地测试证据，但不代表整个安全边界已放行：

- 外部进程调用静态扫描未发现 `shell=True`、`os.system`；Nmap、Nuclei、TruffleHog 和 git 调用主要使用 argv 列表，并设置了部分 timeout。
- YAML POC 使用 `yaml.safe_load` 和受限 AST DSL；未发现直接 `eval`/`exec` 作为表达式执行路径。HTTP path 由当前 target 的 scheme/netloc 拼接，不能仅通过 path 改写 host。
- YAML POC 支持 HTTP/TCP、变量、表达式和结果证据；`YamlPocPlugin` 返回 `poc_engine`、`poc_id`、`poc_source`、severity、tags、request_index、match_summary 和限长 evidence。
- YAML manifest 中所有源文件都被主 manifest 引用，quarantine 为 0；重复内容通过 alias 追溯，没有静默丢弃。
- `npoc_poc_scan` 缺失时可根据旧 `poc_config` 推导；新建任务 UI 默认关闭，打开后只执行具体勾选项；Nuclei/Afrog 开关保持独立。
- 截图上传和读取接口均有应用层认证、task_id/file_name 清洗、文件大小、图片 magic、任务归属和真实路径校验；round7 已覆盖读取越权和符号链接 fixture。
- API Parser/WIH 历史整改已加入越界候选证据化、GraphQL 预算、敏感变量处理、失败计数、fallback 开关和 endpoint degraded reason 的离线回归。
- TaskFinalizer 的 nested host ownership 标记已经收敛站点层重复收尾；计划 6 离线测试仍通过，历史 ARCH-终态 owner 项可标记为已修复（运行态仍需部署验证）。
- 统一账本 fail-open 已有计数和阈值降级测试；不能因此把 Mongo 故障下的重复请求风险视为消失，ARCH-02 仍需 IPC 对账。
- 主题 token、普通 checkbox、toggle、focus-visible 和禁用态已有统一 CSS 规则，静态对比度门禁通过。

## 7. 历史 Review 与整改状态矩阵

历史文档保留原结论，本表只给出当前工作树的复判，不把历史 Accept 当作当前生产放行。

| 历史来源/问题族 | 当前状态 | 当前证据与结论 |
|---|---|---|
| 系统框架架构 Review A1：跨消息上下文 | 已修复（代码）/运行态未验证 | ARCH-01；已有持久化摘要和响应缓存，Mongo 多 worker、故障恢复和重复请求量仍需部署验证。 |
| 系统框架架构 Review A2：fileLeak 子进程 | 证据不足 | ARCH-02；watchdog/IPC 已有，但无本机端到端子进程请求计数对账。 |
| 系统框架架构 Review A3：God Object | 部分修复 | ARCH-03；阶段服务已拆出，但 CommonTask/DomainTask 仍是主要兼容和副作用中心。 |
| 系统框架架构 Review A5：ledger fail-open | 已修复（离线） | `plan567-code-check` 与账本/Finalizer 定向测试通过；真实 Mongo 故障和重复请求量未验证。 |
| 系统框架架构 Review A6：deep 阶段拆分 | 已修复（代码）/运行态未验证 | ARCH-04；阶段已按 discovery、search、IP、site、vhost、POC、WIH、finalize 投递，并使用 claim/CAS。 |
| 系统框架架构 Review A7：终态 owner 多头 | 已修复（代码/离线） | nested host-owned 标志和相关测试存在；部署 worker 的中断/恢复仍未运行。 |
| 系统框架架构 Review A8：全链路请求计数 | 证据不足 | 部分 stage 有 metrics，但跨 Celery、fileLeak 子进程和实际请求的统一对账未完成。 |
| 计划 6 第 4-6 批 P0-01~P0-05 | 已修复（离线） | 历史整改已落地；当前计划 6 离线检查通过。真实双架构和 production runtime 仍未验证。 |
| 计划 6 P1-01~P1-03、P2-01~P2-03 | 已修复（离线） | stage gate、network timing、lease、degraded reason、finally flush 有回归证据；不替代真实性能/部署门禁。 |
| 计划 6 第 9-11 批发布验收 | 仍未完成 | 默认 `API_UNIFIED_ENABLE=false`、Rust mode 为 shadow；40/64、p95、生产 runtime、双架构证据未在本轮形成。 |
| 计划 5 指纹统一 | 部分完成 | build/runtime 解耦、规则异常观测和产物门禁通过；`SITE_FINGERPRINT_SOURCE` 当前仍为 legacy，生产 unified 切换按历史决策暂停。 |
| 计划 7 WIH/UI | 已修复（离线）/视觉未验证 | 既有字段合并、focus、侧边栏、主题和微前端测试通过；本轮未完成四视口浏览器验收。 |
| 计划 9 统一资产发现/IP 证书 | 已修复（离线）/真实环境未验证 | 本地代码和定向回归通过；真实 DNS、CDN/WAF、FOFA/Hunter、双架构和最终 task 结果未验证。 |
| 全量开发复核 2026-09-08 | 状态保持 | 仍只能归档为开发完成方案，不能解释为生产放行；本轮新增后端全量收集失败进一步阻止放行。 |
| NPoC YAML 统一导入计划 | 已完成导入门禁/执行运行态未验证 | 4,420 manifest entries、4,419 ready、1 alias duplicate、0 quarantine；后台同步 job 已增加，mock/真实任务矩阵和部署 worker 尚未全部执行。 |
| 敏感资产采集参考准则 | 待治理决策 | 当前准则把敏感资产完整采集要求扩展为无条件原文公开，并允许进入日志、Git 和第三方链路；与 SEC-11 记录的代码安全边界冲突。 |

已复核的历史报告包括：系统框架与架构、计划 6 第 4-6 批 API、计划 6 第 9-11 批、计划 7 WIH、计划 5 指纹、计划 9、全量开发复核、计划 1-5 前置复核、计划 4 UI、终态修复和统一 drain 相关报告。报告中未复制历史文档里的任何生产凭证或敏感目标。

## 8. 未验证项与测试环境待执行项

### 8.1 本机未完成

- 后端全量 pytest 的 10 个收集错误：native `arl_accel` 缺失；多个测试在 bootstrap 后从空壳 `app`/`app.services` 导入；`test_task_finalizer` 检测到 `sys.modules['app.services']` 污染；这些问题必须先修复测试隔离/依赖，不得以定向测试掩盖。
- npm advisory、pip audit、cargo audit 未完成；依赖版本存在已知老版本风险，但本报告不把未查询到的 advisory 写成确定漏洞。
- Rust native test 未执行，原因是本机未找到 `cargo`；既有历史容器证据不能替代当前工作树重新验证。
- Docker Compose 只做静态展开，未完成 Mongo/Redis/RabbitMQ/web/worker/scheduler/nginx 健康、队列、重启、恢复和镜像内容检查。
- 真实浏览器截图、键盘、焦点、减弱动画、移动触摸区域和四视口长文本布局未完成。

### 8.2 需要部署/授权环境

- 真实目标正向/反向 POC、TCP、HTTP redirect、WAF、TLS、代理、文件上传、外部工具和范围隔离；
- 40/64 目标三组对照、端到端 p95、重复请求数、缓存命中和网络等待；
- amd64/arm64 最终镜像、native extension、MassDNS/Nmap/Nuclei/Afrog/Playwright 版本和权限；
- 多用户/多租户 IDOR、导出 job owner、同名 task scope、截图读取权限；
- Mongo 索引 explain、深分页、NPoC 同步耗时、队列积压、worker consumer 消失、ACK timeout 和重启恢复；
- ICP 外部服务、验证码、IPv6、代理和敏感数据脱敏的真实运行链路。

## 9. 整改矩阵

| 优先级 | 问题 | 依赖关系 | 建议负责人角色 | 首要动作 | 验收方式 |
|---|---|---|---|---|---|
| P1 | SEC-05 配置凭据 | 需要凭据轮换/部署协作 | 安全 + 运维 | 轮换旧值，清理模板和 Git 历史策略 | secret scan、旧值失效、Compose 空凭据拒绝启动 |
| P1 | SEC-11 敏感资产准则冲突 | 需要治理口径确认 | 安全 + 产品 + 后端 | 保留完整采集，禁止无条件扩散凭证原文；统一文档、接口、日志、导出和报告边界 | 文档与实现一致；授权查看可审计；日志、Git、第三方链路无原文 |
| P1 | SEC-01 截图读取 | 无外部依赖 | 后端/API | 统一 auth、task ownership、文件记录校验 | 未登录/跨任务/符号链接测试 |
| P1 | SEC-02 POC 删除 GET | 需兼容前端调用 | 后端/API + 前端 | 改 POST/DELETE，权限、确认、审计 | GET 405、授权和幂等测试 |
| P1 | SEC-04 redirect scope | 依赖统一 DNS/scope policy | 安全 + 网络扫描 | 每一跳做 host/IP/端口/scope 校验 | redirect SSRF mock 矩阵 |
| P1 | SEC-03 task scope | 需要确认产品多用户关系 | 后端/安全 | 去除隐式同名 join，改显式 related scope | 同名不同目标/用户 fixture |
| P1 | FUNC-01/02 PoC 终态和线程 | 需统一任务生命周期契约 | 任务编排 + NPoC | Future/同步 runner、异常传播、统一终态 | 注入异常/取消/超时/恢复 |
| P1 | UI-01 跨页选择 | 需确定 API 是否支持 filtered selection | 前端 + API | selected set 按筛选签名持久化，区分当前页/全量 | 跨页/轮询/批量操作 e2e |
| P2 | ARCH-01/A2/A6 | 需要数据契约和发布窗口 | 架构 + 任务平台 | 设计跨 worker 摘要、子进程 IPC、stage batch | 双 worker、重启、请求/结果对账 |
| P2 | PERF-01 POC 同步 | 依赖 manifest 版本模型 | 后端/NPoC | bulk_write + 后台 job + 原子 ready 版本 | 4,420/10,000 规则性能和失败恢复 |
| P2 | PERF-02 分页/索引 | 需要生产数据规模 | 数据层 | explain、cursor pagination、索引迁移 | 10 万/100 万数据 p95 |
| P2 | SEC-06 token/change_pass | 需兼容旧客户端迁移 | 安全 + 前端/API | 删除 query token，统一 auth/session rotation | URL/日志/旧 token 测试 |
| P2 | SEC-07 TLS | 需 CA/自签名兼容策略 | 运维 + 网络扫描 | 控制面启用 verify，目标兼容开关显式化 | CA/MITM/代理 fixture |
| P2 | SEC-08 导出 owner | 需要多用户模型确认 | 后端/API | job owner/tenant 条件查询 | 双用户交叉下载测试 |
| P2 | SEC-09 错误脱敏 | 需要统一错误模型 | 后端/API + 安全 | stable error code + safe log | 异常回显脱敏测试 |
| P2 | SEC-10 外部仓库供应链 | 需版本签名/审核流程 | 安全 + 运维 | commit pin、签名/扫描、只读工具挂载 | 恶意模板和远端变化测试 |
| P2 | UI-02/03 | 无后端阻塞 | 前端 | debounce、AbortSignal、aria-label 和键盘测试 | Vitest + 浏览器 axe/键盘 |
| P3 | STAB-02 只读打开模式 | 无外部依赖 | 后端/NPoC | `r+` 改为只读读取，写入路径独立 | 0444/ro mount fixture |
| P3 | UI-04 选中颜色 | 需要浏览器环境 | 前端/设计 | 四视口六主题截图回归 | screenshot diff + contrast |

建议整改顺序：先处理凭据和明确越权/范围边界，再处理任务终态和跨页批量语义，之后收敛 NPoC 同步、跨 worker 上下文和数据库分页，最后进行真实多架构/性能/视觉验收。

## 10. 整改闭环复核（2026-09-15）

本节覆盖第 5 节全部问题，并以当前工作树、定向回归和静态门禁为准。历史问题的原始描述保留在第 5 节，若与本节状态冲突，以本节为当前结论。

| 编号 | 当前状态 | 当前证据与剩余边界 |
|---|---|---|
| ARCH-01 | 已修复（代码）/运行态未验证 | `DiscoveryContext` 增加任务级账本和响应缓存，并支持跨阶段恢复；Mongo 多 worker、故障恢复和真实重复请求量仍需部署验证。 |
| ARCH-02 | 已缓解/证据不足 | fileLeak 增加 watchdog、IPC metrics、待处理 URL 和不完整标记；尚未完成真实子进程请求计数端到端对账。 |
| ARCH-03 | 部分修复 | 阶段服务已拆出并保留兼容层；`CommonTask`/`DomainTask` 仍是复杂度中心，属于后续架构演进项，不影响当前静态门禁。 |
| ARCH-04 | 已修复（代码）/运行态未验证 | deep 阶段按 discovery、search、IP、site、vhost、POC、WIH、finalize 分阶段投递，并使用 claim/CAS；worker 重启恢复需部署验证。 |
| ARCH-05 | 已修复（主要结果链路） | task stats、finger、CIP、vuln 和 brute 结果统一经过结果写入服务；资产同步和 scheduler 等独立 owner 保留各自写入边界。 |
| FUNC-01 | 已修复 | 风险巡航异常更新 `ERROR` 和结束时间，并写入阶段错误；定向回归通过。 |
| FUNC-02 | 已修复 | NPoC runner 在线程启动前初始化，线程异常回传，结果文件使用 `finally` 清理，坏结果记录为 `partial`；定向回归通过。 |
| FUNC-03 | 已修复 | manifest 已明确 `source_count=4420`、`execution_entity_count=4419`、`alias_count=1`；校验结果为 4,420 条、4,419 ready、1 alias、0 quarantine、0 未引用。 |
| UI-01 | 已修复（本地测试） | 表格选择状态按筛选上下文保留，轮询和分页不会静默清空已选项；浏览器端到端操作仍未执行。 |
| UI-02 | 已修复（本地测试） | 搜索增加 debounce，批量选择使用取消信号并避免重复请求；浏览器端网络时序仍未执行。 |
| UI-03 | 已修复（本地测试） | 行选择、表头选择和批量操作补充可访问名称；键盘和读屏器实测仍未完成。 |
| UI-04 | 证据不足 | 主题 token 和对比度静态门禁通过；四视口真实渲染、窄屏长文本、焦点和触摸区域尚无浏览器证据。 |
| SEC-01 | 已修复（静态/mock） | 截图读取加入认证、任务归属、真实路径、符号链接和文件校验；round7 symlink/越权 fixture 通过，部署多用户验证未完成。 |
| SEC-02 | 已修复（静态/mock） | POC 清空改为 POST，要求 API 管理主体和显式确认，并记录审计事件；round7 fixture 通过。 |
| SEC-03 | 已修复（代码/mock） | 移除按同名任务的隐式 scope 扩展，保留显式关联范围；真实多用户、多租户数据隔离仍需环境验证。 |
| SEC-04 | 已修复（mock）/真实目标未验证 | redirect 每一跳重新执行协议、DNS、WAF 和任务范围检查，并关闭自动跟随；真实 WAF、代理和多跳目标未执行。 |
| SEC-05 | 待部署协作 | 运行时配置已向环境变量和独立 runtime 配置收敛；现有 tracked 模板仍需由维护者确认凭据轮换、历史清理和 secret scan，报告未包含任何敏感值。 |
| SEC-06 | 已修复（代码）/运行态未验证 | 认证 token 不再从 query 读取，改密接口纳入统一认证并在成功后使会话失效；旧客户端兼容、URL 和生产日志扫描仍需验证。 |
| SEC-07 | 已修复（默认策略） | 常规 HTTP、WIH、NPoC 和截图链路默认校验证书，目标兼容场景必须显式关闭；证书采集路径保留观察性 TLS 行为，需在部署策略中单独确认。 |
| SEC-08 | 已修复（代码）/集成未验证 | 导出 job、任务列表、状态和下载增加 owner 条件；双用户交叉下载和历史 job 迁移仍需集成环境验证。 |
| SEC-09 | 已修复（主要 API 出口） | `safe_error_text` 已接入路由、任务错误、外部工具和关键服务边界，并限制路径、查询凭证和错误长度；仍需全量日志/错误输出扫描。 |
| SEC-10 | 已修复（代码）/供应链未验证 | 外部 PoC 更新要求 40 位 pinned commit 并校验 checkout HEAD；签名、内容安全扫描和真实管理员更新流程仍未执行。 |
| SEC-11 | 待治理决策 | 当前参考准则要求的无条件原文公开与代码安全边界冲突；完整采集可以执行，但日志、Git、第三方和无权限公开原文不能执行。 |
| PERF-01 | 已修复主要阻塞/性能未验证 | POC 同步已改为 POST 后台 job，使用 queued/running/done/error 状态、幂等 claim、分块 `bulk_write`、ordered=false 和 alias 一并写入；版本原子切换和大规模性能验收仍未完成。 |
| PERF-02 | 已缓解/性能未验证 | 通用 API 已限制过深 offset，避免无界 skip；cursor pagination、生产索引 explain 和大数据 p95 仍需性能环境验证。 |
| STAB-01 | 已修复（代码/回归） | NPoC 结果文件在异常和正常路径统一 `finally` 清理，并采用受限临时文件权限；round6 回归通过。 |
| STAB-02 | 已修复 | 规则、字典和目标读取路径改为只读 `r`；AST/compile 和定向回归通过。 |

### 10.1 本轮复跑结果

| 门禁 | 命令 | 结果 |
|---|---|---|
| YAML manifest | `python3 ARL-NPoC/tools/validate_yaml_manifest.py --output-root ARL-NPoC/xing/pocs` | 通过：4,420 entries；4,419 ready；1 duplicate；0 quarantine；0 未引用；errors=[] |
| 定向后端回归 | `PYTHONPATH=ARL-NPoC python3 -m pytest -q ARL/test/test_review_fixes_round8.py ARL/test/test_review_fixes_round7.py ARL/test/test_review_fixes_round6.py ARL/test/test_review_fixes_round5.py ARL/test/test_review_fixes_round4.py ARL/test/test_progressive_domain_queue.py ARL/test/test_discovery_ledger_store.py ARL/test/test_file_leak_watchdog.py` | 通过：47 passed，5 warnings |
| Python 编译 | `PYTHONPYCACHEPREFIX=/private/tmp/arl-pycache python3 -m compileall -q ARL/app ARL-NPoC/xing` | 通过 |
| Diff hygiene | `git diff --check` | 通过 |
| 前端 Vitest | `cd ARL/docker/frontend-src && npm test` | 通过：22 files，137 tests |
| TypeScript | `cd ARL/docker/frontend-src && npm run lint` | 通过 |
| 前端构建 | `cd ARL/docker/frontend-src && npm run build` | 通过；保留既有 Vite Node deprecation warning |
| 后端全量 pytest | `PYTHONPATH=ARL-NPoC python3 -m pytest -q` | 仍失败：收集阶段 10 个错误，原因包括 native `arl_accel` 缺失、测试 bootstrap 污染和多个可选模块缺失 |

### 10.2 敏感资产处理边界

敏感信息属于资产发现范围，不能因类型敏感而在采集结果中静默丢弃。本 Review 不读取、不复制、不展示真实 Cookie、Authorization、密码、Token、代理凭证或其它凭证值；代码整改保留日志、异常、共享缓存、普通导出和 Review 文档的安全边界。若后续需要原始证据交付，应按 `docs/reference/[长期参考]敏感资产采集与受控呈现准则.md` 通过授权、审计和受控路径执行，不能改为全局无条件公开。

## 11. Review 结论与放行条件

当前可接受为：

- YAML POC 导入、manifest、静态 DSL 和 legacy fixture 的开发侧结果；
- 前端 TypeScript、Vitest、Vite 构建和主题 token 的本地开发侧结果；
- 计划 5/6/7 离线回归证据，作为后续整改和部署复验的基线。

当前不可接受为：

- 生产安全放行；
- 后端全量测试通过；
- 真实目标扫描、双架构和 40/64 性能通过；
- 多用户对象授权和 scope 隔离通过；
- 四视口视觉、键盘、触摸和浏览器兼容通过；
- 依赖漏洞审计通过。

生产放行至少需要满足：SEC-01、SEC-02、SEC-03、SEC-04、SEC-05、SEC-11、FUNC-01、FUNC-02、UI-01 完成整改并有回归证据；后端测试收集归零；Compose/runtime、依赖审计、真实授权目标、双架构和视口验收结果单独归档。任何未运行项目必须继续标记为未验证，不得使用“定向测试通过”替代。

本报告已完成整改复核，但不能把未运行的部署、依赖、浏览器、真实目标和多用户环境测试标记为通过。Review 阶段和整改阶段的代码、测试、规则及文档变更应按功能边界单独 review；本地提交不包含远程 push。
