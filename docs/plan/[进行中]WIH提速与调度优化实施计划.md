# WIH提速与调度优化实施计划

## 1. 背景

当前 `ARL` 的 `WIH` 链路已经承担了两类职责：

- `URL / JS / 隐藏页面 / 接口 / 参数` 的发现
- 站点级 runtime、二次敏感扫描、后续 URL 探测等增强编排

实际运行中暴露出两个明显问题：

1. 周期任务下，同一批站点会被反复全量深扫，`WIH` 阶段耗时容易被拉到数小时甚至十几小时。
2. 长时间运行会放大 `worker` 重启、计划任务提前收尾、知识库推送跳过等连锁问题。

此外，WIH 与站点爬虫、URLFinder、目录扫描之间没有共享发现上下文，导致相同页面和路径被重复请求，新 API 和新子域也不能稳定进入后续阶段。

本次方案的目标不是削减 `WIH` 的静态/动态能力，而是在 **不明显降低接口发现能力** 的前提下，把耗时集中收敛到真正发生变化的站点和资源上。

## 2. 目标

### 2.1 主目标

- 保留 `WIH` 现有静态与动态提取能力。
- 优先从 `ARL` 编排层提速，而不是先改 `WIH` 本体语义能力。
- 让周期任务优先复用“上次已确认未变化”的结果，减少重复深扫。
- 给深度阶段增加更保守的分级和止损，砍掉无效等待，不砍发现链路。

### 2.2 非目标

- 不直接关闭 `runtime`。
- 不直接关闭 `urlfinder_sensitive`。
- 不把 `WIH` 退化成仅静态模式。
- 不把“提速”建立在大幅降低结果召回率上。

### 2.3 当前实施状态

- 第一阶段：已完成
  - 周期任务上下文已透传到子任务 `options`
  - 已支持基于站点签名的保守结果复用

- 第二阶段：已完成首版
  - 周期任务 `WIH` 主扫描已支持 `light -> full` 的保守升级
  - `minimal` 回退已改为真正轻量模式，不再默认重复深度 runtime

- 第三阶段：已完成
  - `urlfinder_sensitive` 已接入候选优先级排序
  - 已支持连续无新增批次提前止损

- 第四阶段：已完成首版
  - worker 启动恢复已跳过 Celery inspect 仍存活的任务
  - `task_schedule_run` 已支持终态重查与状态校正
  - 知识库写入已与 `notify_on` 解耦

## 3. 问题拆解

### 3.1 当前主要耗时点

1. `wih_primary_scan`
   - 当前主扫描预算较大。
   - 超时后还会走 `minimal` 回退。
   - 单站点最坏路径可接近 `primary + minimal` 双倍超时。

2. `wih_urlfinder_sensitive`
   - 这是增强链路，不是基础提取动作。
   - 当候选资源多、慢页面多、低价值候选占比高时，容易出现长时间空转。

3. 周期任务缺乏复用
   - 相同 `schedule`、相同 `target` 的任务，即使站点外观和基础指纹没有变化，也会重复执行完整 `WIH` 链路。

### 3.2 已确认的关联问题

- 多 `worker` 环境下，长任务更容易遭遇 `worker_bootstrap` 恢复误判，导致 `task_schedule_run` 提前被结算成 `error`。
- `knowledge base` 推送当前依赖 `notify_on=finished`，一旦 run 被提前判成 `error`，就会被直接跳过。

这不是本次提速方案的主改造点，但会被长任务显著放大，需要在后续阶段一起收口。

### 3.3 当前 AI 分析 / 去噪问题

提速不是当前唯一痛点，`WIH` 结果消费侧还存在明显的“AI 去噪不够像去噪”的问题：

1. `WIH接口` 价值判断曾长期过度依赖 `POST + import/export/admin` 等路径/方法特征。
   - 典型误判：
     - 接口被打成 `高价值`
     - 但 `AI填充` 后的真实 `回复报文` 明确是：
       - `未登录`
       - `权限不足`
       - `没有该资源访问权限`
       - `资源不存在`
       - `参数校验失败`
   - 这类结果本质上只证明“接口存在且受保护”，并不等于“已经成功命中高价值业务能力”。

2. `站点 / 目录扫描 / URL信息 / 风险 / PoC风险` 当前也普遍存在类似问题。
   - 模型或规则很多时候只拿到了：
     - `URL`
     - `标题`
     - `状态码`
     - `模板名称`
     - `风险等级`
   - 但没有优先消费：
     - `verify_data`
     - `detail`
     - `proof_type / proof_strength`
     - `回复报文摘要`
     - `响应语义`

3. 结果是“AI分析”更像“关键词重排”而不是“证据优先去噪”。
   - 明显的 `401/403/404`
   - 登录壳 / 统一认证页
   - 普通错误页 / 占位页
   - 只有模板名、没有利用证据的风险

这些场景本应优先降权，但当前仍需要人工逐条判断。

## 4. 设计原则

### 4.1 先统一发现上下文，再优化 WIH

优先在任务级 `DiscoveryContext` 和统一请求层做：

- 响应注册与任务内复用
- 候选资产图和来源聚合
- 爬虫、URLFinder、WIH、目录扫描事件分发
- 流量类别隔离和 WAF 熔断
- 周期任务上下文透传与历史结果复用
- 调度一致性修复

`WIH` 本体只做配合型增强，例如：

- 暴露更细粒度的预算开关
- 输出更稳定的中间元数据
- 为上层提供更清晰的产出统计

### 4.2 先保守复用，再逐步智能化

第一阶段只允许在“站点签名完全一致”时复用结果。  
先保守，再逐步扩大复用条件，避免一开始就因为激进缓存带来接口漏扫。

### 4.3 先砍重复劳动，不砍发现能力

优先减少：

- 周期任务重复全量深扫
- 低价值候选二次复扫
- 长时间无新增的 runtime / secondary scan 空转

不直接砍：

- `JS` 静态提取
- `runtime` 动态提取
- `endpoint` 恢复
- `URL` 二次敏感发现

### 4.4 跨工具协同规则

- `fetch_site` 获取的页面响应必须先登记到 `ResponseRegistry`，爬虫、URLFinder、WIH 和站点识别按请求 profile 复用。
- URLFinder 不再为提取目的独立重新获取已登记页面；新 JS/API 通过候选事件进入 `CandidateRegistry`。
- WIH 消费候选图中的页面、JS、API 和新子域，不再依赖自身私有结果才能继续探测。
- 目录扫描只对尚未被相同 profile 完成覆盖的路径执行请求；爬虫已经处理过的路径直接消费响应或标记 `covered`。
- 目录扫描、爬虫、WIH 和浏览器请求使用独立流量类别、预算和 WAF 状态；目录扫描降级不能静默影响正常请求。
- 新子域必须经过范围、DNS 和 WAF 校验后，同时分发到站点发现、WIH 和目录扫描队列。

## 5. 分阶段方案

## 5.1 第一阶段：周期任务上下文与保守复用

### 目标

- 为周期任务补齐可追踪上下文。
- 为后续复用建立最小闭环。
- 仅在条件足够严格时复用上一轮结果。

### 设计

1. 在计划任务下发时透传以下上下文到子任务 `options`
   - `task_schedule_id`
   - `task_schedule_name`
   - `task_schedule_run_number`

2. 在 `web_info_hunter` 执行前，尝试查找同一 `schedule_id + target` 的上一轮成功任务。

3. 基于当前任务已落库的 `site` 信息构建站点签名：
   - `site`
   - `title`
   - `status`
   - `http_server`
   - `body_length`
   - `favicon.hash`
   - `finger.name[]`

4. 只有当同一站点在上一轮与当前轮的签名完全一致时，才允许复用：
   - `wih`
   - `wih_endpoint`
   - `url(source = wih_url_probe)`

5. 若任一条件不满足，则立即回退为现有完整扫描流程。

### 第一阶段的边界

- 不做跨站点复用。
- 不做跨 `schedule_id` 复用。
- 不做模糊相似度复用。
- 不做 runtime 局部跳过。

## 5.2 第二阶段：runtime 分级升级

### 目标

保留动态能力，但避免所有站点一开始就进入深度 runtime。

### 设计

1. 先执行轻量 runtime。
2. 命中以下强信号时，再升级到当前深度预算：
   - SPA / Router 痕迹
   - 运行时 API 请求
   - 表单/搜索/筛选行为
   - 复杂 JS 框架或管理后台信号
   - 接口/参数恢复明显增量

3. 对未命中升级条件的普通站点，停留在轻量 runtime。
4. 当前实现中，轻量阶段除了看总记录量，还会额外看 `page_url / path / urlfinder_url / endpoint` 这类高价值信号密度；如果信号已经足够明确，则不再继续升级到完整 runtime。

## 5.3 第三阶段：URLFinder 二次敏感扫描止损

### 目标

保留 `urlfinder_sensitive` 的补充价值，同时减少低价值候选带来的长时间空转。

### 设计

1. 对候选目标进行优先级排序：
   - 同 host 优先
   - 带参数、带动作词、带后台/接口关键词优先
   - HTML / API 文档 / 可疑 JS 优先

2. 增加“连续无新增”止损：
   - 连续若干批无新增有效记录时提前结束

3. 为周期任务加入更严格的总预算约束，但不是直接关闭阶段。

## 5.4 第四阶段：调度一致性修复

### 目标

修复“任务后来完成了，但 `task_schedule_run` 已提前判错”的状态漂移问题。

### 设计

1. 修正 `worker` 启动恢复逻辑，避免多 worker 场景误把正在执行的任务标记为 `error`。
2. 为 `task_schedule_run` 增加二次校正机制。
3. 将知识库推送与 `notify_on=finished` 解耦：
   - 通知策略仍由 `notify_on` 控制
   - 知识库写入以“run 是否已结束”为主

## 5.5 第五阶段：AI 去噪可信度收口

### 目标

- 让 `AI去噪` 先判断“证据是否成立”，再判断“价值是否高”。
- 降低“只是受保护 / 只是路径可疑 / 只是模板命中”却被直接提级的误报。
- 把真正需要人工复核的结果缩到更小，而不是让工程师继续逐条看列表。

### 设计

1. 统一采用“证据优先，关键词只做弱信号”的口径
   - `URL / 标题 / 路径关键字 / 方法` 只能做弱提权
   - `回复报文 / verify_data / proof / 成功业务字段` 才能做强提权

2. `WIH接口` 必须优先消费真实响应
   - 优先级：
     - `ai_fill_response_packet`
     - `verification_response_packet`
     - `response_packet`
   - 需要统一抽取：
     - `status_line`
     - `body_excerpt`
     - `JSON键`
     - `响应语义`
   - 其中：
     - `权限拒绝 / 鉴权失败 / 资源不存在 / 参数校验失败`
       - 默认只能降到 `中价值` 或 `无价值`
     - `业务成功 / 敏感字段返回 / 导出地址 / 用户/租户/权限数据`
       - 才允许提级为 `高价值`

3. `站点 / 目录扫描 / URL信息` 在现有字段不足时，先做保守降权
   - `401/403/404`
   - 登录壳 / 统一认证页
   - 普通错误页
   - 静态资源
   - 只命中 `admin/debug/swagger/token` 等弱关键词
   - 上述场景默认不直接提到 `危险`

4. `风险 / PoC风险` 必须优先看验证证据而不是模板名
   - 必须优先消费：
     - `verify_data`
     - `detail / description`
     - `proof_type`
     - `proof_strength`
     - `proof_summary`
   - 若只体现：
     - `未登录`
     - `权限不足`
     - `404`
     - `网络异常`
     - `参数校验失败`
     - `规则命中但无利用证据`
   - 默认应降权为 `疑似误报`

5. 后续需要补齐更强的证据落库
   - 当前 `site / fileleak / url` 侧仍缺少统一的 `body_excerpt / response_packet_excerpt / semantic_tags`
   - 这意味着本轮可以先把规则和提示词收紧，但更深的“响应报文驱动去噪”仍需要补采集链路

## 6. 配置规划

建议新增以下配置项：

- `WIH_PERIODIC_REUSE_ENABLE`
  - 是否启用周期任务 WIH 结果复用

- `WIH_PERIODIC_REUSE_MAX_BASELINE_TASKS`
  - 查找历史基线时最多回看多少条同目标任务

- `WIH_PERIODIC_REUSE_LOG_DETAIL`
  - 是否输出详细复用日志，便于灰度阶段观察

本轮已落地新增：

- `WIH_ADAPTIVE_RUNTIME_ENABLE`
- `WIH_LIGHT_TIMEOUT_SEC`
- `WIH_LIGHT_RUNTIME_TIMEOUT_SEC`
- `WIH_LIGHT_RUNTIME_MAX_PAGES`
- `WIH_LIGHT_RUNTIME_MAX_ACTIONS`
- `WIH_LIGHT_RUNTIME_MAX_REQUESTS`
- `WIH_MINIMAL_TIMEOUT_SEC`
- `WIH_MINIMAL_RUNTIME_ENABLE`
- `URLFINDER_SENSITIVE_NO_GAIN_BATCH_LIMIT`

### 6.1 超时口径说明

这轮实现里，`WIH` 相关超时分成两类，不能混看：

- `WIH_LIGHT_TIMEOUT_SEC`
  - 作用对象：单批 `WIH` 子进程
  - 含义：轻量阶段这整个 batch 最多允许跑多久
  - 默认值：`120s`
  - 备注：这不是单页超时

- `WIH_LIGHT_RUNTIME_TIMEOUT_SEC`
  - 作用对象：runtime 内部单页探索
  - 含义：`Playwright` 处理单页时的超时预算
  - 默认值：`20s`

- `WIH_MINIMAL_TIMEOUT_SEC`
  - 作用对象：单批 `WIH` 子进程
  - 含义：`minimal` 回退阶段整批最多允许运行多久
  - 默认值：`120s`

- `WIH_RUNTIME_TIMEOUT_SEC`
  - 作用对象：完整 runtime 单页探索
  - 含义：深度 runtime 阶段内部单页预算
  - 默认值：`60s`

设计上，轻量阶段就是为了更激进地止损，所以默认值已经收到了 `120s`。如果现场目标极慢，可以再按需上调；如果主要是周期任务、站点又比较稳定，这个值继续收紧到 `90s` 也可以考虑。

### 6.2 当前默认建议

当前仓库建议默认值如下：

- `ARL.WIH_CONCURRENCY = 8`
- `ARL.WIH_CONCURRENCY_PER_SITE = 2`
- `ARL.WIH_LIGHT_TIMEOUT_SEC = 120`
- `ARL.WIH_LIGHT_RUNTIME_TIMEOUT_SEC = 20`
- `ARL.WIH_MINIMAL_TIMEOUT_SEC = 120`
- `ARL.URLFINDER_SENSITIVE_NO_GAIN_BATCH_LIMIT = 2`
- `tools/wih --concurrency/-c = 4`
- `tools/wih --concurrency-per-site/-P = 3`

这一组的原则是：

- 先提升“站点并发”，不先提升“单站点并发”
- 先收紧轻量阶段和回退阶段的总预算
- 保留完整 runtime 和 secondary scan 能力，但减少无效空转

## 7. 回归与验收

## 7.1 能力回归

每一轮优化都必须对比以下指标：

- `endpoint` 数量
- `parameter` 数量
- `page_url` 数量
- `urlfinder_url / path_url` 数量
- `runtime` 发现的请求数

默认要求：

- 速度有明显改善
- 结果量不出现明显下降
- 若结果减少，必须能解释且有白名单/开关回退方案

## 7.2 运行时指标

重点观察：

- `wih_primary_scan` 耗时
- `wih_urlfinder_sensitive` 耗时
- `web_info_hunter` 总耗时
- 周期任务平均总时长
- 计划任务 `error -> done` 状态漂移次数
- `AI去噪` 中被 `401/403/404/登录壳/错误页` 错提级的占比
- `风险 / PoC风险` 中“无验证证据但被判高可信”的占比

## 7.3 灰度策略

1. 先上线上下文透传与复用骨架。
2. 初期仅对周期任务生效。
3. 通过日志与回归数据确认效果后，再逐步打开更激进的分级与止损。

## 8. 开发顺序

### 第一批

1. 周期任务上下文透传
2. `WIH` 周期复用骨架
3. 站点签名模型
4. 最小回归测试

### 第二批

1. runtime 分级升级
2. secondary scan 候选排序
3. 无新增提前止损

### 第三批

1. `worker_bootstrap` 恢复逻辑修正
2. `task_schedule_run` 二次校正
3. 知识库推送与通知策略解耦

### 第四批：统一发现上下文

状态（2026-09-03）：第 1–4 项首批已完成；账本持久化 backend 与连接池收编待下一增量，第 5 项 Rust 决策继续保持后置。

1. 建立任务级 `DiscoveryContext`、`ResponseRegistry`、`CandidateRegistry` 和持久化账本。
   - 已完成内存实现：注册中心含请求 profile 键、消费者记账、总字节预算；候选图含容量上限（默认 20000，最旧驱逐并计数）；`DiscoveryLedger` 预留 backend 注入接口，恢复语义与深度队列消费方同批落地。
2. 将站点获取、爬虫、URLFinder、WIH URL 探测和目录扫描接入统一请求调度。
   - 已完成：`fetch_site`、站点爬虫、`site_spider_probe`、urlfinder/page_intel/js_intel、URL 探测与目录扫描子进程均按 `html_get` profile 共享响应；目录扫描经 job 文件消费重叠候选的已获取响应。
3. 增加页面、API、JS、新子域和目录候选事件分发。
   - 已完成首批：六类事件发布与候选图登记，候选状态含 `discovered/fetched/covered/failed` 迁移。
4. 增加 `normal/crawler/wih/directory/browser` 流量隔离和独立 WAF 熔断。
   - 已完成：类别配额调度（有界等待后 fail-open，杜绝静默丢结果）；目录字典流量的 WAF 证据只暂停该主机 directory 队列，非目录来源维持主机级阻断口径。
5. 通过请求计数和结果集合回归后，再决定是否启用 Rust 内容解析层。
   - 待执行：以共享上下文观测日志和 64 目标双基线为准入依据。

## 9. 当前实施说明

当前已经完成：

- 计划文档与实施边界收口
- 周期任务上下文透传
- 周期任务 `WIH` 保守复用骨架
- `WIH` 轻量 runtime -> 完整 runtime 的保守升级
- `minimal` 真正轻量回退
- `urlfinder_sensitive` 候选优先级与无新增止损
- 多 worker 启动恢复误判收口
- `task_schedule_run` 终态重查与知识库补写
- `WIH接口` 回复报文语义校正
- `site / fileleak / url / vuln / nuclei_result` 规则层弱证据降权与 AI 上下文补强
- 统一发现上下文首批接线：WIH 情报链共享响应消费、候选图与六类事件、目录流量类别隔离与子进程 WAF 证据回流

下一轮继续优化的重点不再是“有没有能力”，而是更细的性能精修：

1. 基于 `JS/resource hash` 的更细粒度增量缓存
2. 基于产出密度的 runtime 升级信号细化
3. 基于站点画像的自适应 batch / concurrency
4. 周期任务与即时任务分层参数模板
5. `site / fileleak / url` 的响应摘要与语义标签补采集
   - 已完成（2026-09-03）：`page_semantics` 统一派生 `body_excerpt`（≤600 字符、去标签、二进制拒绝）与 `semantic_tags`（auth_wall/not_found/server_error/login_page/error_page/placeholder_page/static_asset/api_json/empty_body，上限 8），在 `fetch_site`、`page_fetch`（含缓存路径）、`fileLeak.Page.dump_json`（子进程序列化出口）三处生产点落库；只新增字段不改旧字段，AI 去噪链按“形态弱证据”消费，价值判断仍由去噪侧决定
