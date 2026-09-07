# 当前系统框架与架构 Review

项目：ARL-Source-Install
报告状态：已完成（本轮 Review 已完成）
整改状态：进行中（第 8 节整改记录：轮 1 已完成 P0.2、P0.4 与 §4 一般项"API 账本 key 契约"处置；轮 2 第一批已完成 fail-open 阈值降级门禁（A5）与指纹运行时/构建解耦+规则异常计数；P0.1、P0.3 及 run_deep 队列化等余项按待处置表推进）
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

## 11. 整改记录

### 轮 1（2026-09-05）

| 问题项 | 处置 | 证据 |
|---|---|---|
| P0.4 终态 owner 多头 | 唯一宿主标记 `terminal_finalize_host_owned`：`DomainSiteStageService`/`IPTaskOrchestrator` 在嵌套 `WebSiteFetch.run()` 前置位，`WebSiteFetchOrchestrator` 置位时整体跳过 TaskFinalizer（不 drain、不记 pending）；独立宿主（预览消息/PoC/资产监控）默认位不变、仍为唯一收尾点 | `test_web_site_fetch_orchestrator.py::test_host_owned_nested_flow_skips_site_finalizer`、`test_task_orchestrator.py` IP 置位断言、`test_domain_stage_services.py::test_site_service_marks_host_owned_terminal_finalize` |
| P0.2 search_engines 绕过统一层 | `services.page_fetch` 注入 `discovery_context` + 显式 `traffic_class="crawler"`（不扩 TRAFFIC_CLASSES 枚举，沿用爬虫类节流口径）；结果登记共享候选图——获取成功 `fetched`（不晚到显影）、失败保持 `discovered`（由 url_probe 阶段按既有协议领取） | `test_domain_search_candidates.py` 4 项 |
| §4 一般项：API 文档账本空 signature / URL 唯一 | 采纳 Review 第二口径显式契约化：文档获取固定单 profile、GET、无认证差异，任务窗口内 URL 唯一、正文变化不重验（漂移由新 task_id 周期覆盖）；键形态与跳过行为由测试锁定；语义变更须改 (profile, body-hash) 组合键并同步修订 06-附录A §4.7 | `test_api_candidate_registry.py::test_ledger_url_unique_contract_locked`、附录A §4.7 契约条款、`api_candidate_registry.py` 契约注释 |

轮 1 验证：api 三件 57 项、编排/收尾四组 39 项、search 候选 4 项全绿；golden `--check` 无漂移。

### 状态圆桌（2026-09-07，T11-0 落地后的全量盘点——不虚报、不假关闭）

| 本 Review 问题项 | 2026-09-07 状态 | 依据 |
|---|---|---|
| §4 高风险1（A1 跨消息上下文）/高风险3（A2 fileLeak 子进程）/建议项全链路计数（A8）/§4 高风险4（A7 终态 owner） | 定案维持（T5 复判）：A1/A2 不入单进程统一事实源、A8 四类口径冻结、A7 已修复 | 紧急修复文档 §九 T5 表；发布门禁按 §4.20 口径出报表 |
| §4 一般项 fail-open 阈值降级 | **已完成（轮 2 第一批）** | ledger sink 计数 + `LEDGER_DEGRADED_THRESHOLD`→done_degraded + pending_backlog\|ledger；测试 11 项 |
| §4 一般项 指纹运行时/构建耦合 + 规则异常计数 | **已完成（轮 2 第一批）** | fp_common 下沉 + 受控枚举 + `site_fingerprint_rule_error_count`；`SITE_FINGERPRINT_SOURCE` 默认切换仍属计划 5 暂停决策 |
| §4 高风险2（search_engines 统一层）/§4 一般项 API 账本契约/§4 高风险4（终态 owner） | 已完成（轮 1/终态修复轮） | 本文件 §11 轮 1/轮 2 表 |
| §4 高风险5（God Object 逐 stage 迁移） | 待专项（计划 2 路线分批）；**A3 逐 collection 写入 owner 迁移经用户 2026-09-07 决策本轮不动**，与 40/64 验收窗口/最终 review 合流 | 计划 2 当前状态行 |
| §4 高风险6 直接 conn_db 收敛 | 同 A3，挂专项 | 同上 |
| §4 高风险7 `API_UNIFIED_ENABLE` 默认切换 | 代码门禁全闭环 + stage 级 rust 硬门禁（附录A §4.20）；默认切换待计划 6 第 11 批发布验收（附录 E runbook） | 计划 6 当前状态行 |
| §4 一般项 run_deep 阶段队列化（A6） | 待专项（紧急修复 T5 定案：后续拆可恢复 stage/batch，不与 P0 混做） | 紧急修复文档 T5 表 |
| 发布前门禁 §9 全部动态项（40/64、双架构、SSRF/越权动态测试） | **未完成——环境/授权依赖**：执行手册固化为 `docs/plan/[未完成]06-附录E-计划6发布验收runbook-双架构与40-64目标.md`；安全动态测试归用户最终阶段安排 | 附录 E §6 完成定义 |

本文"待处置（登记，未开工）"一节中的全部条目状态以本表为准；本文文件名保留 `[整改待处理]` 直至 §9 发布门禁全量通过。

### 待处置（登记，未开工）

- **P0.1** 预览/深度跨 Celery 消息上下文共享：需要受限、脱敏、带 TTL 的持久化响应摘要设计，属独立批次（03 第四轮 (c) 项已决策 Mongo 全量落 body 不可行，摘要面方案未定）。
- **P0.3** fileLeak 子进程正式边界：候选领取/响应回流/请求计数中前两项已有实现，缺子进程请求计数回流与重复抑制门禁的可验证口径，需 fileLeak IPC 协议专项。
- **高风险 5/6**（God Object 迁移、逐 collection 写入 owner）：按计划 2/3 既有路线分批推进。
- **高风险 7**（`API_UNIFIED_ENABLE` 默认切换）：按计划 6 第 4-11 批门禁推进，第 3 批完成记录已区分"代码具备入口"与"默认生效"。
- **一般项：fail-open 强制告警/阈值降级**：**已完成（轮 2 第一批）**。**指纹运行时/构建脚本耦合 + 规则异常计数**：**已完成（轮 2 第一批；`SITE_FINGERPRINT_SOURCE` 默认切换仍属计划 5 暂停决策，未动）**。**run_deep 阶段队列化（A6）**：待专项评估。
- **建议项**（browser intel 策略节点、全链路重复请求门禁）：随计划 6 第 8-9 批与 64 目标基线验收落地。

### 轮 2（2026-09-06，一般项打包第一批）

| 问题项 | 处置 | 证据 |
|---|---|---|
| 一般项：site_fingerprint_registry 运行时依赖构建脚本模块 / 规则异常静默 | `parse_human_rule`/`to_human_rule`/`merge_key`（含 COND_RE、OP 映射、quote/unquote、has_boolean_parentheses）自 `app/tools/build_unified_fingerprints` 下沉 `app/fp_common`（零依赖公共层，05 §零.1 单一实现）；构建模块经 import 保持原名 re-export（`BUILD.<attr>` 审计/测试面不变），运行时 `site_fingerprint_registry` 只 import fp_common——生产指纹链不再被构建脚本层牵动。**不改 `SITE_FINGERPRINT_SOURCE` 默认（legacy）**，计划 5 生产切换仍按用户暂停决策。规则判定异常观测：registry 累计计数 + per-rule-id 首现 warning + 每 1000 汇总；`fetchSite._try_unified_fingerprint` 按差值汇入 `site_fingerprint_rule_error_count` 任务指标（收尾 ctx_ 前缀透出，进 `_BACKLOG_METRIC_KEYS`） | `RuntimeBuildDecouplingTest`（运行时源无 app.tools import 钉 + 同对象单一实现钉 + 行为冒烟）、`SiteFingerprintRuleErrorObservabilityTest`（异常计数/distinct id 节流/行为不变）；指纹族回归合跑：registry 15、build 14、service registry 10、golden、cache_unit 全绿；`build_unified_fingerprints --help` 独立入口与 `fingerprint-baseline.py` 正常（纯函数搬迁零行为变更）；`test_fingerprint_wiring_fetchsite` 3 项宿主 skip（xing），容器回归承接 |
| 一般项：账本/调度 fail-open 无强制告警与阈值降级（待处置节 A5） | `MongoLedgerBackend` 全部 fail-open 路径接入观测：per-op 计数（`ledger_get/upsert/claim/finish/confirm/list/owner_probe/status_probe_failed`）+ 两总量（`ledger_unavailable_total`、`ledger_dedup_degraded_total`=covered 不可确认仍执行的重复扫描证据；`ledger_finish_rejected_total` fencing 单列不计 unavailable）；sink 由 `DiscoveryContext.__init__` 晚绑定 `record_metric`，观测汇故障不得反噬主路径。`TaskFinalizer` 新增阈值门禁：`unavailable+dedup_degraded ≥ LEDGER_DEGRADED_THRESHOLD`（Config 默认 10，类默认 + yaml positive-int + env `ARL_LEDGER_DEGRADED_THRESHOLD` 三处接线）时收尾阶段标 `degraded`、非阻断场景终态升 `done_degraded`（WIH 残余仍优先 `done_pending`，阻断口径不变）、恢复证据落 `pending_backlog|ledger|<task_id>` 账本（每任务一条幂等，payload 带计数与阈值）。`over_limit_request_count`/`actual_duplicate_request_count` 保持既有单列（限流压力面，不并入账本阈值） | `test_discovery_ledger_store.py::LedgerFailOpenObservabilityTests` 6 项（sink 一致性、dedup 判定、covered 仍跳过不加码、坏 sink 反噬防护、多 op 计数、context 绑汇）+ `test_task_finalizer.py::LedgerDegradedFinalizerTest` 5 项（升级/未达阈不变/阻断优先/backend 兜底/阈值 0 禁用）；两文件合跑 52 项全绿；config 相关 5 项、`test_discovery_context` 合跑 69 项全绿。顺带按 P2-13 把 `test_discovery_ledger_store` bootstrap 化（宿主 load-fail 集合 -1） |

### 状态指针（2026-09-06 计划 6 第 8 批后紧急修复轮）

本文件"待处置"清单中的 P0.1（A1）、P0.3（A2）、建议项全链路计数口径（A8）、
建议项 browser intel 策略节点，已在
`docs/plan/[进行中]紧急修复-统一发现系统数据与状态边界收口.md` §九 T5 复判定案：
A1/A2 明确为"不纳入单进程统一事实源 + 外部边界计数"（IPC/摘要恢复仍为专项，
不阻塞、不虚报）；A8 四类计数口径冻结；browser intel 已由第 8 批 T8-4 成为
统一 Registry 摄取通道（双开关+范围闸+观察收口约束）。P0.4（A7）经整改轮
已修复，本表维持原登记。其余"待处置"项状态不变。
