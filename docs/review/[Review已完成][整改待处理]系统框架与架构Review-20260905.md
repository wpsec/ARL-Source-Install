# 当前系统框架与架构 Review

项目：ARL-Source-Install
报告状态：已完成（本轮 Review 已完成）
整改状态：待处理（第 4 节问题清单和 P0/P1/P2 项尚未全部修复）
说明：文件名中的“Review已完成”仅表示报告完成，不表示 Review 发现的问题已经完成整改。
日期：2026-09-05
范围：当前工作区代码、运行时配置模板、任务编排、发现上下文、API 解析、指纹体系、Docker/Rust 边界和前端骨架。
结论性质：只读审查。本轮不修改业务代码、不重启容器、不提交代码。

## 1. 结论摘要

当前系统已经从“任务类直接串联工具”演进为“API 层 + Celery 编排 + 阶段服务 + 任务级发现上下文 + 统一结果写入”的过渡架构，方向正确，主要基础设施已经具备：

- `StageExecutor` 统一阶段状态、耗时、预算、失败原因和指标回写；
- `TaskFinalizer` 统一处理有限 drain、残余队列和 `done/done_pending/done_degraded`；
- `DiscoveryContext` 已包含响应缓存、候选注册、账本、请求调度和 WAF 流量分类；
- URLFinder、页面抓取、WIH endpoint、文件泄漏已经有不同程度的上下文接入；
- Rust 被限制在 URL/HTML/JS 等无副作用批量处理层，没有越界接管数据库、网络或任务生命周期；
- React + TypeScript + Vite 前端骨架和 TanStack Query 已形成统一入口。

但当前还不能称为“架构完全收口”。最关键的缺口不是新增工具，而是以下四条链路还不一致：

1. `DiscoveryContext` 主要是进程内对象，预览阶段、深度阶段和部分域名阶段没有共享同一实例；
2. 搜索引擎页面获取、文件泄漏子进程仍有统一请求层之外的网络路径；
3. 统一 API 解析虽然已接入 WIH 条件分支，但默认配置仍关闭，legacy 顺序仍是默认行为；
4. 站点、域名、IP 三层编排器都可能执行 `TaskFinalizer`，终态所有权不够单一。

因此本轮建议结论为：**架构方向通过，当前实现需要整改后再宣称“统一发现架构完成”；不建议在此状态继续扩大新工具或继续拆分目录。**

本轮没有发现已被静态证据确认的新增高危安全漏洞；但 SSRF、越权、外部 URL 范围校验和运行时敏感信息输出仍需独立安全门禁，不能由本架构 Review 代替。

## 2. 当前系统架构

### 2.1 总体调用链

```text
浏览器 / API Client
        │
        ▼
Nginx / Flask + Flask-RESTX
        │  /api/*
        ▼
Routes / Namespace
        │
        ▼
Celery Task Entry
        │  RabbitMQ broker，Redis 运行时状态/缓存，Mongo 结果与任务事实
        ▼
DomainTaskOrchestrator / IPTaskOrchestrator
        │
        ├─ discovery：基础域名、预览结果、深度任务投递
        └─ deep：域名、IP、站点、外部工具、WIH、收尾
                         │
                         ▼
              WebSiteFetchOrchestrator
                         │
        ┌────────────────┼─────────────────┐
        ▼                ▼                 ▼
   Discovery        External Scan       Intel
   fetch/spider     file leak/nuclei    WIH/API/JS
   identify         afrog                endpoint
        │                │                 │
        └────────────────┴─────────────────┘
                         ▼
        DiscoveryContext / StageExecutor / TaskFinalizer
                         │
                         ▼
        TaskResultWriteService / TaskLifecycleService
                         │
                         ▼
        Mongo 业务结果、任务阶段、账本、统计与导出
```

### 2.2 分层与目录职责

| 层 | 主要目录/文件 | 当前职责 | 评价 |
|---|---|---|---|
| Web/API | `ARL/app/main.py`、`ARL/app/routes/` | Flask-RESTX 应用、认证、API namespace、参数和响应 | 边界清晰 |
| 异步入口 | `ARL/app/celerytask.py`、`ARL/app/tasks/` | Celery 消息、任务恢复、域名/IP/GitHub/PoC 任务入口 | 入口清晰，但深度阶段仍偏同步 |
| 高层编排 | `task_orchestrator.py`、`web_site_fetch_orchestrator.py` | 阶段顺序、任务收尾、兼容旧任务入口 | 已拆出，但存在多头收尾 |
| 阶段服务 | `*_stage_services.py` | 组合单个扫描能力和阶段边界 | 多数仍调用 `CommonTask` 兼容方法 |
| 任务兼容层 | `commonTask.py`、`tasks/domain.py` | 旧公共函数、业务状态、部分结果组装、网络/工具调用 | 仍是主要复杂度中心 |
| 发现上下文 | `discovery_context.py`、`discovery_queue.py`、`discovery_ledger_store.py` | 响应、候选、事件、WAF、请求类别和恢复账本 | 设计完整，跨消息持久化不完整 |
| 结果持久化 | `task_result_write_service.py`、`task_result_item_service.py`、`repositories/` | 结果字段组装、幂等写入、部分查询 | 已有边界，但旧路径仍直接写 Mongo |
| 资产能力 | `domain.py`、`ip.py`、`fetchSite.py`、`fileLeak.py`、WIH services | 域名、DNS、端口、站点、文件泄漏、情报和风险扫描 | 能力完整，调用入口尚未完全统一 |
| 外部工具 | `tools/` | WIH、Nuclei、afrog、massdns、TruffleHog、Playwright 等 | 应保持供应链/进程边界，不应混入业务层 |
| 数据字典 | `ARL/app/dicts/`、`ARL/docker/dicts/` | 域名、目录、服务和站点指纹等 JSON/压缩产物 | 规范化在推进，运行时仍有 legacy 默认路径 |
| Rust 加速层 | `ARL/native/arl_accel/` | PyO3/maturin 批量文本、URL、候选处理 | 边界正确，最终性能门禁尚未在本轮确认 |
| 前端 | `ARL/docker/frontend-src/` | React、TypeScript、Vite、TanStack Query、虚拟列表、daisyUI/Tailwind | 骨架基本统一，部署/视觉/测试门禁仍有挂账 |

## 3. 已形成的架构优点

### 3.1 生命周期与阶段观测已统一

`StageExecutor` 负责阶段开始、状态、耗时、预算、结果数量、失败原因和阶段指标；业务函数不再需要重复实现全部生命周期逻辑。`TaskPipeline` 也已经把阶段调用抽成可复用入口。

### 3.2 发现上下文的抽象方向正确

`DiscoveryContext` 已定义：

- `ResponseRegistry`：按 URL、method、request profile 保存响应；
- `CandidateRegistry`：保存页面、主机、接口、目录等候选及来源；
- `DiscoveryLedger`：保存阶段状态、幂等键和恢复元数据；
- `RequestScheduler`：按 `normal/crawler/wih/directory/browser` 分类调度；
- `WafPolicy`：按流量类别隔离熔断，避免目录扫描弱证据影响正常爬虫和 WIH。

这套抽象符合“一个任务级上下文、多个独立策略”的目标，且没有把 Mongo、Redis、Celery 或外部工具迁移到 Rust。

### 3.3 结果和降级语义比旧链路明确

当前阶段已经使用 `success/partial/pending/error/timeout/skipped` 等结果状态，并在文件泄漏、WIH、Nuclei 等路径记录降级、失败或待处理数量，方向上解决了“失败被当成空结果”的问题。

### 3.4 Rust 边界合理

Rust 目前定位为批量、无副作用、CPU 密集型数据层；Python 继续负责 HTTP、DNS/WAF、Playwright、Celery、Mongo、预算和 `WihRecord`。这比直接重写 WIH 或网络工具更容易验证结果一致性和回滚。

## 4. Review 问题清单

| 等级 | 文件/模块 | 问题 | 影响 | 最小修复建议 |
|---|---|---|---|---|
| 高风险 | `ARL/app/tasks/domain.py:2623`、`ARL/app/celerytask.py:1358` | 发现预览创建独立 `WebSiteFetch`；深度阶段由新的 Celery 消息重新创建 `DomainTask`，因此不会共享预览阶段的进程内 `DiscoveryContext` 和响应体 | 同一站点可能在预览和深度阶段再次请求；响应缓存无法跨 worker/消息复用，当前“任务级一次请求”只对单实例成立 | 明确跨消息上下文策略：同一进程注入同一实例；跨 worker 用受限、脱敏、带 TTL 的持久化响应摘要/缓存恢复，不能只恢复状态账本 |
| 高风险 | `ARL/app/tasks/domain.py:2537` | `search_engines()` 直接调用 `services.page_fetch(urls)`，没有把当前任务的 `DiscoveryContext` 传入；`DomainTask` 本身也没有统一持有站点上下文 | 搜索引擎页面请求绕过响应注册、请求类别和 WAF 隔离，后续站点/WIH 可能重复取同一页面；来源和指标不完整 | 将搜索结果先登记为统一候选，再由站点上下文领取和获取；至少保证 `page_fetch` 使用当前 task context 和明确的 `search_engine` 流量类别 |
| 高风险 | `ARL/app/services/fileLeak.py:939-1159`、`1401-1492` | 文件泄漏虽然有上下文快照、账本和 WAF 回流，但真正的目录字典请求在 watchdog 子进程内由 `HTTPReq` 直接发出，未经过 `RequestScheduler`；当前代码已将其标记为 `external_network_file_leak_directory` | 目录请求仍可能与爬虫/WIH重复；统一请求数不能代表真实总请求；目录并发和 WAF 控制无法完全由任务上下文收敛 | 将子进程改成受控 HTTP worker/可注入请求适配器，或明确把它作为外部边界并实现可验证的候选领取、响应回流、请求计数和重复抑制门禁 |
| 高风险 | `ARL/app/services/web_site_fetch_orchestrator.py:35`、`ARL/app/services/task_orchestrator.py:55/92` | 站点编排器、域名编排器和 IP 编排器都构造并运行 `TaskFinalizer`；同时域名/IP路径还执行 `TaskLifecycleService.run_finalize()` | drain、pending 账本、统计和终态可能被多次执行；同一 Task ID 的终态所有权不单一，排障时难以判断哪一层决定了最终状态 | 只保留一个宿主层拥有最终终态；站点编排器只输出阶段结果和发现证据，域名/IP宿主统一执行一次 finalizer/lifecycle finalize，并为嵌套调用增加幂等测试 |
| 高风险 | `ARL/app/services/commonTask.py:52`、`ARL/app/tasks/domain.py:622` | `CommonTask` 和 `DomainTask` 仍同时承担业务状态、阶段兼容入口、网络调用、外部工具、结果组装和部分持久化；阶段服务目前多为薄 facade | 新需求容易继续堆到 God Object；同一能力会出现新服务路径和旧兼容路径两套行为，增加重复请求及回归风险 | 以 stage 为单位逐步迁移：先固定输入/输出契约，再把一个 stage 的网络、结果组装和持久化移出；旧方法只保留薄兼容转发，禁止继续增加横向职责 |
| 高风险 | `ARL/app/tasks/domain.py:1303-1456,1613,2285-2541`、`ARL/app/tasks/asset_wih.py:129` | 已有 `TaskResultWriteService` 和 repository 边界，但域名、WIH 等旧路径仍直接 `utils.conn_db(...).insert/update/delete` | 幂等键、来源聚合、失败回写和字段组装可能因入口不同而不一致；审计和重试无法只依赖一个写入边界 | 按 collection 建立唯一写入 owner；先迁移高频结果 `domain/ip/service/url/wih/vuln`，保留旧公共函数签名，禁止新代码直接调用 `conn_db` |
| 高风险 | `ARL/app/services/wih_orchestrator.py:276-330`、`ARL/app/config.py:775` | 统一 API 队列已在 WIH 中挂接，但仅在 `API_UNIFIED_ENABLE` 为真时运行；默认仍走 legacy，legacy 顺序为 `wih_api_doc` 在 `wih_js_intel` 之前 | 默认配置下，JS 新发现的 API 文档不能在同一轮进入统一文档队列；计划 6 的“发现即回流”不是默认生产语义 | 完成真实加载、结果对比和回滚门禁后，切换默认入口；在切换前至少对 legacy 分支明确记录“跨轮回流”，避免日志看起来像已完成实时回流 |
| 一般 | `ARL/app/services/api_candidate_registry.py:329-346`、`125-151` | API 文档账本 key 使用空的 `input_signature`；文档注册表以规范化 URL 作为唯一键，不保留 request profile/body signature 的并列实例 | 文档内容或认证 profile 变化时可能错误复用旧的 `covered` 状态；同 URL 不同请求语义的来源和状态会被合并 | 文档获取前先确定请求 profile，成功后以正文摘要和请求上下文形成稳定 key；若设计上 URL 必须唯一，应在契约中明确“URL唯一、正文变化强制重验”并增加测试 |
| 一般 | `ARL/app/services/discovery_ledger_store.py:5,160`、`discovery_context.py:788` | 账本和请求调度故障采用 fail-open，优先保证继续扫描；这是有意设计，但当前缺少强制告警/任务状态升级和重复执行上限的统一门禁 | Mongo/账本故障时可能重复请求，WAF 风险和耗时放大；仅靠 debug/低级日志不足以让用户识别数据一致性降级 | fail-open 继续执行时必须累计 `ledger_unavailable`、`dedup_degraded` 和重复请求指标；超过阈值将阶段标为 `degraded`，并把恢复范围写入 pending 账本 |
| 一般 | `ARL/app/services/fetchSite.py:43-101`、`ARL/app/config.py:775-776` | 站点统一指纹链已经实现，但 `SITE_FINGERPRINT_SOURCE` 默认仍为 `legacy`；`site_fingerprint_registry.py:27` 运行时依赖构建脚本模块 | 计划 5 的规范产物尚未成为默认运行事实；构建脚本与运行时耦合，生产导入路径或构建依赖缺失时可能降级；规则异常目前返回 false 且没有独立计数 | 将编译/运行模型拆成稳定运行时 parser；完成真实加载和召回一致性后切换默认；规则解析异常必须有阶段、规则 ID 和计数指标 |
| 一般 | `ARL/app/services/task_orchestrator.py:25-60`、`ARL/app/celerytask.py:1347-1394` | 当前已拆成 discovery/deep 两条消息，但 `run_deep()` 内部仍按域名、搜索、端口、站点、外部工具、WIH 顺序同步执行，不是完整的阶段队列 | 首批预览能提前展示，但深度阶段中一个慢 provider/端口批次仍可能阻塞后续；worker 重启只能按较大阶段恢复 | 下一阶段先把深度阶段拆为可恢复 stage/batch 消息，使用统一幂等键；不要直接提高全局并发，先以指标证明瓶颈和公平调度收益 |
| 建议 | `ARL/app/services/browser_intel_scan.py`、`ARL/app/services/wih_orchestrator.py` | 浏览器运行时 API 采集有实现和测试，但没有成为当前主 WIH 编排中的标准策略节点 | 对 SPA、动态导入、运行时拼装 URL 的覆盖依赖配置或其他解析器，能力入口不统一 | 将 browser intel 注册为可选策略，统一产出 `ApiCandidateRegistry`/`CandidateRegistry` 事件；必须有预算、浏览器并发和失败状态 |
| 建议 | `ARL/app/services/wih_orchestrator.py`、`fileLeak.py`、`siteUrlSpider.py` | 当前有多种响应缓存、镜像 profile 和 child response 回流规则，但没有一个全链路门禁验证“同一 URL、同一 profile 只请求一次” | 代码结构看似已经统一，实际重复请求率、跨策略复用率和缓存截断重取率还不能从静态代码确认 | 增加任务级 request ledger 测试和运行指标：总请求、唯一请求、缓存命中、重复请求、profile 差异、截断重取、策略来源 |

## 5. 重点链路审查

### 5.1 站点爬虫、URLFinder、WIH、目录扫描

当前站点链路已经具备部分协同：

- `fetchSite.py`、`pageFetch.py`、`siteUrlSpider.py` 可以使用 `DiscoveryContext` 的 `html_get` 和 singleflight；
- 爬虫发现的 URL 会进入候选图，并由后续 `page_fetch` 获取；
- WIH endpoint 会登记为 endpoint candidate，后续有 follow-up probe；
- 文件泄漏命中会把响应回登记到 `file_leak_get` profile，并记录目录类 WAF 信号；
- 新主机队列和 `TaskFinalizer` 能处理部分晚到候选。

但这还不是完整的“一个请求，多方消费”：

1. 预览和深度跨 Celery 消息时，内存响应注册表不在同一实例；
2. 搜索引擎页面获取没有注入上下文；
3. 目录字典的实际请求在子进程内进行，统一 scheduler 只能看到快照和回流；
4. 爬虫请求、页面二次处理和截断响应重取之间，缺少按 profile/完整性标记验证的端到端测试；
5. `Info_Hunter` 开关会改变 URLFinder/page intel 的执行位置，策略行为依赖配置而非统一候选事件图。

因此，当前应称为“共享发现上下文的渐进接入版”，不能称为“所有 Web 发现策略已统一”。

### 5.2 WIH 与统一 API 解析

统一 API 模块的设计包括 API 文档候选注册、来源聚合、深度/数量/大小/时间预算、文档解析、Endpoint 注册和旧链路 fallback。当前 `services/__init__.py` 已导出 `run_api_document_pipeline`，WIH 也已在 JS 情报之后按开关调用它，这是本轮重要进展。

当前仍有两个边界：

- 默认 `API_UNIFIED_ENABLE=False`，生产默认仍为 legacy；
- 统一层的文档账本 key 仍使用空 `input_signature`，不能完整兑现接口契约声明的幂等键。

这意味着计划 6 第 3 批的“代码已具备入口”和“生产默认已切换”不能混为一谈。必须分别记录：代码存在、shadow 指标存在、统一入口可选、默认生效、结果一致性通过。

### 5.3 任务终态和恢复

发现阶段已由 Celery 单独投递深度阶段，并有 orphan recovery、深度状态和 `TaskFinalizer`，这解决了旧链路单消息长时间无首批结果的问题。

但当前恢复粒度仍主要是“阶段/目标账本”，而非“每个候选/请求批次队列”。另外站点编排器和宿主编排器均执行 finalizer，最终状态的 owner 需要收敛。正式验收前必须证明：

- worker 在任意阶段退出后，任务不会回到裸 `done`；
- 已完成候选不重复写入；
- 未完成候选会进入 `pending` 或 `degraded`；
- 一个 Task ID 只由一个最终收尾 owner 写终态。

## 6. 数据和依赖边界

### 6.1 Mongo、Redis、RabbitMQ

- Mongo 是任务结果、资产、统计和恢复账本的主要持久化事实源；
- RabbitMQ 是 Celery 消息 broker，不应作为结果事实源；
- Redis 可承载运行时缓存、锁或会话类数据，但不能替代 Mongo 结果和阶段账本；
- 当前直接 `conn_db` 与服务化写入并存，说明持久化边界尚未完全收口。

### 6.2 外部工具

WIH、Nuclei、afrog、massdns、TruffleHog、Playwright 等应继续作为外部能力。业务层需要统一记录命令 profile、输入规模、退出码、超时、结果数和降级原因；不应把外部工具的内部数据模型扩散到 Mongo 公共字段。

### 6.3 Rust

Rust 的职责保持为：

- HTML/JS/URL 批量解析；
- URL 归一化、范围过滤和去重；
- 候选排序、指纹和规范化记录计算。

Rust 不应直接访问 Mongo、Redis、Celery、HTTP、DNS、Playwright、LLM 或外部扫描器。当前设计满足这一边界，但本轮未执行 64 目标 Rust/Python 对照，因此不能对性能门禁作通过结论。

## 7. 测试与审查证据

本轮执行：

- 使用 CodeGraph 查询关键类和调用关系；
- 使用 `rg` 核对 API 统一入口、上下文接入、直接 Mongo 写入、finalizer 调用和指纹默认路径；
- 对 `api_candidate_registry.py`、`discovery_context.py`、`wih_orchestrator.py`、`task_orchestrator.py`、`commonTask.py`、`domain.py` 执行 AST 解析，结果为 `ast-ok`；
- 执行 `git diff --check`，未发现空白错误。

本轮未执行：

- 全量 Python 单元测试和容器内运行时导入；
- 40/64 目标真实扫描；
- Rust/Python golden corpus 全量对照；
- amd64/arm64 Docker smoke；
- 真实 Mongo/Redis/RabbitMQ 故障恢复测试；
- 浏览器运行时 API 采集、SSRF 和越权动态测试。

当前工作区存在大量既有改动、文档迁移和未跟踪文件，尤其是 `ARL/app/services/api_candidate_registry.py` 和 `ARL/test/test_task_terminal_status_mapping.py` 尚未纳入 Git 跟踪。该状态不影响本轮静态分析，但意味着不能把当前工作区直接视为单一可发布变更集。

## 8. 整改优先级与下一步计划

### P0：先收口统一请求和终态所有权

1. 让 `DomainTask`、预览 `WebSiteFetch`、深度 `WebSiteFetch` 明确共享策略：同进程注入同一上下文，跨 worker 通过受限持久化上下文恢复；
2. 把 `search_engines` 页面结果纳入候选图和统一获取入口；
3. 为文件泄漏子进程确定正式边界，不能同时宣称“统一请求已完成”又把真实请求留在 scheduler 外；
4. 只保留一个 TaskFinalizer 宿主，补齐嵌套编排器重复收尾测试。

### P1：收口结果写入和 API 统一入口

1. 逐 collection 迁移 `domain.py`、`asset_wih.py` 等直接 Mongo 写入；
2. 修复 API 文档账本 signature/profile 语义，补正文变化、来源合并、同 URL 不同 profile 的测试；
3. 完成统一 API 结果与 legacy golden 对照后，再决定是否把 `API_UNIFIED_ENABLE` 默认切换为 true；
4. 将 browser intel、URLFinder、WIH、目录扫描统一映射为候选事件，而不是仅通过阶段顺序传递列表。

### P2：再做性能和代码结构收敛

1. 将 `run_deep` 拆成可恢复的 stage/batch 队列，幂等键固定为 `task_id + stage + target + scan_profile + input_signature`；
2. 把 `CommonTask`/`DomainTask` 中的单个 stage 逐步下沉到业务服务，兼容方法只保留转发；
3. 建立重复请求和跨策略复用的真实指标；
4. 最后执行 Rust/Python 对照、40 目标定位、64 目标性能门禁和 amd64/arm64 Docker 验收。

## 9. 发布前必须满足的门禁

- 默认生产链路中，所有启用的 Web 发现策略都能说明请求来自哪个 profile、是否命中响应缓存、是否发生重复请求；
- 预览、重试、worker 重启不会造成已完成候选无界重复请求或重复写入；
- 目录扫描 WAF 只能暂停 directory 类流量，主机级封禁才允许暂停站点全部流量；
- JS、浏览器、URLFinder 发现的 API 文档能在当前任务进入统一文档队列，且有深度/数量/大小/时间预算；
- 一个 Task ID 只有一个终态收尾 owner，所有残余都表现为 `pending/degraded/failed`，不能伪装为空结果；
- 所有业务 collection 的写入都经过明确 owner 和幂等策略；
- 统一指纹文件和 API 统一解析切换后，运行时导入不依赖构建脚本；
- Rust 与 Python 输出集合一致，Rust 热点满足 CPU 降低 30% 或吞吐提升 1.5 倍；
- 端到端阶段耗时恶化不超过 5%，并完成 64 目标和 amd64/arm64 同口径验收；
- 动态安全测试确认 URL 范围、认证、SSRF、越权和日志脱敏边界。

## 10. 最终判定

**架构设计：通过。** 分层、阶段服务、发现上下文、候选图、WAF 分类和 Rust 边界均有明确实现方向。
**当前实现：部分通过。** 核心能力已落地，但跨 Celery 的上下文复用、统一网络入口、终态 owner、结果写入边界和默认 API/fingerprint 运行路径仍未完全闭环。
**发布建议：暂缓架构收口声明，先完成 P0；P0 通过后再进行 P1 和最终性能部署门禁。**
