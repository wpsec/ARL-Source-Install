# WIH提速与调度优化实施计划

## 1. 背景

当前 `ARL` 的 `WIH` 链路已经承担了两类职责：

- `URL / JS / 隐藏页面 / 接口 / 参数` 的发现
- 站点级 runtime、二次敏感扫描、后续 URL 探测等增强编排

实际运行中暴露出两个明显问题：

1. 周期任务下，同一批站点会被反复全量深扫，`WIH` 阶段耗时容易被拉到数小时甚至十几小时。
2. 长时间运行会放大 `worker` 重启、计划任务提前收尾、知识库推送跳过等连锁问题。

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

## 4. 设计原则

### 4.1 主改 `ARL`，辅改 `WIH`

优先在 `ARL` 侧做：

- 周期任务上下文透传
- 历史结果复用
- 分级扫描
- 候选打分与止损
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

下一轮继续优化的重点不再是“有没有能力”，而是更细的性能精修：

1. 基于 `JS/resource hash` 的更细粒度增量缓存
2. 基于产出密度的 runtime 升级信号细化
3. 基于站点画像的自适应 batch / concurrency
4. 周期任务与即时任务分层参数模板
