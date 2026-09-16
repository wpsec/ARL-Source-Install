# WAF 联动增强计划：wafw00f 补充识别

状态：已归档。仅完成方案设计，按此前决策暂不实施代码、依赖和配置变更。

本文档路径：`docs/history/[已归档]WAF 联动增强计划：wafw00f 补充识别.md`

## Summary

保留现有 `WAFSmartSkipGuard` 作为唯一 WAF 状态中心和熔断决策中心，新增 wafw00f 作为低频补充指纹源：

- 先使用现有响应头、响应体、DNS、状态码和超时证据。
- 仅对未确认 WAF 且仍存活的 HTTP/HTTPS 站点补充探测。
- wafw00f 结果只联动主动风险链，不影响 WIH、爬虫和目录扫描。
- 仅当任务已开启 `smart_skip_waf` 时执行。
- wafw00f 不直接制造主机级封禁，只增加主动风险阶段的跳过依据。

wafw00f 固定使用 `2.4.2`，该版本要求 Python `>=3.10`，与当前容器环境匹配。[官方版本说明](https://github.com/EnableSecurity/wafw00f/releases) [官方依赖声明](https://github.com/EnableSecurity/wafw00f/blob/master/pyproject.toml)

## Implementation Changes

### 1. 依赖和配置

在 `ARL/requirements.txt` 增加：

```text
wafw00f==2.4.2
```

新增配置：

```text
WAFW00F_TIMEOUT_SEC=7
WAFW00F_CONCURRENCY=2
WAFW00F_MAX_TARGETS=200
WAFW00F_STAGE_TIMEOUT_SEC=900
```

不新增任务级开关，`smart_skip_waf` 作为唯一启用条件。

### 2. wafw00f 适配器

新增独立适配层，使用 Python Library，不调用 CLI：

- 懒加载 `wafw00f.WAFW00F`，避免关闭 WAF 联动时引入运行时依赖问题。
- 使用 `identwaf(findall=False)`，只执行一次标准请求和一次受控主动指纹请求。
- 不调用 `genericdetect()`，避免额外发送多组攻击特征请求。
- `followredirect=False`，防止重定向到范围外主机。
- 不转发 Cookie、Authorization 或其它敏感请求头。
- 复用项目代理配置，但日志中不输出代理凭据、攻击 URL 或响应正文。
- 单目标超时、阶段总预算、并发和最大目标数均受配置限制。
- 所有异常 fail-open：wafw00f 失败不能导致主任务失败，也不能自动跳过目标。

### 3. 调度和联动顺序

在 WebSite 流程中新增 `waf_identify` 阶段：

```text
站点发现
→ WIH/被动情报
→ wafw00f 补充识别
→ 文件泄漏/目录扫描
→ Nuclei
→ Afrog
→ NPoC/PoC
→ 收尾
```

具体规则：

- 插入 `WebSiteIntelStageService` 之后、主动风险阶段之前。
- 通过 `TaskPipeline` 和 `StageExecutor` 运行，具备阶段状态、耗时、异常和降级记录。
- 域名深度任务复用已有 `WebSiteFetch.waf_guard`，不建立第二套 WAF 状态。
- 风险巡航任务、域名任务和独立 PoC 任务统一走同一适配器。
- 同一任务内按 `scheme + host + effective_port` 去重，确保一个站点最多探测一次。
- 高置信度已有 WAF 证据的目标不再调用 wafw00f。
- 已被现有 WAF Guard 阻断的目标不再调用 wafw00f。
- 已识别为 CDN 但尚未确认 WAF 的目标允许补充一次识别。

### 4. WAF Guard 联动规则

新增 wafw00f 结果合并方法，不改变现有 WAF 判定入口。

结果处理规则：

- wafw00f 命名厂商识别成功：
  - 记录为高置信度主动指纹证据。
  - 写入主动风险阻断标记。
  - 跳过 NPoC、PoC、Nuclei、Afrog 的该目标。
  - 不设置主机级 `blocked=true`。
- wafw00f 未识别：
  - 只记录 `not_detected`。
  - 不跳过任何阶段。
- wafw00f 超时或异常：
  - 记录 `timeout/error`。
  - 不跳过任何阶段。
- wafw00f 的 generic 结果：
  - 只作为低置信度观测信息。
  - 不触发主动风险跳过。
- WIH、爬虫、目录扫描、站点识别不受 wafw00f 结果影响。

同时修正主动风险过滤调用：

- Afrog 过滤时显式传递 `module="afrog"`。
- Nuclei 在执行前过滤目标字典，并保留原有指纹字段。
- NPoC 继续复用已有 `module="npoc"` 和 `preclassify` 机制。
- 所有主动风险阶段统计输入数、输出数、跳过数和跳过原因。

### 5. 结果结构和展示

扩展现有 `task.waf_skip_summary`，不新增 Mongo 集合：

```json
{
  "wafw00f_status": "detected",
  "wafw00f_names": ["厂商名称"],
  "wafw00f_confidence": "high",
  "wafw00f_evidence": ["wafw00f:厂商名称"],
  "wafw00f_request_count": 2,
  "wafw00f_elapsed_sec": 1.23,
  "wafw00f_checked_at": "时间",
  "wafw00f_active_risk_blocked": true,
  "detection_sources": ["http", "dns", "wafw00f"]
}
```

约束：

- 不保存攻击探测 URL、请求参数、响应正文。
- 继续维护现有 `waf_name`、`waf_confidence`、`waf_evidence` 聚合字段。
- 新增 `detection_sources`，区分 `http`、`dns`、`wafw00f`。
- WAF 识别 API 改为读取 `detected_hosts`，兼容旧数据时回退到 `blocked_hosts` 和 `class_blocked_hosts`。
- 现有 WAF 页面和导出直接增加识别来源、置信度、边界类型、是否跳过和 wafw00f 状态。
- 不新增独立页面或独立模块。

### 6. 任务内缓存和恢复

缓存键固定为：

```text
scheme://host:effective_port
```

缓存内容写入现有 `waf_skip_summary.detected_hosts`：

- 同一 worker 内不重复探测。
- 跨 Celery 深度阶段恢复时读取已保存的 wafw00f 结果。
- `detected/not_detected/timeout/error` 均视为已检查状态，避免任务重试时重复触发目标。
- 阶段完成后立即保存一次 WAF 摘要，最终收尾阶段继续幂等保存。

### 7. 观测指标

新增以下阶段指标：

```text
wafw00f_checked_total
wafw00f_detected_total
wafw00f_not_detected_total
wafw00f_timeout_total
wafw00f_error_total
wafw00f_skipped_by_passive_total
wafw00f_target_cap_skipped_total
wafw00f_request_total
wafw00f_elapsed_sec
```

日志只输出：

- 任务 ID
- 脱敏主机标识
- 识别状态
- 厂商名称
- 请求数
- 耗时
- 异常类型

不输出攻击载荷、完整 URL、Cookie、Authorization 和代理凭据。

## Test Plan

- `smart_skip_waf=false` 时确认不调用 wafw00f、不增加网络请求。
- 已有高置信度 DNS/HTTP WAF 证据时确认跳过 wafw00f。
- CDN-only 目标只执行一次补充识别，不被误判为 WAF。
- wafw00f 命名厂商识别后，确认 NPoC、PoC、Nuclei、Afrog 被过滤。
- wafw00f 识别后，确认 WIH、爬虫、目录扫描继续执行。
- generic、not-detected、timeout、error 均确认 fail-open。
- 同一 host 不同路径只探测一次；不同端口和协议分别探测。
- 重试或跨 worker 恢复后不重复探测。
- 重定向到范围外主机时不越界。
- Nuclei 目标过滤后指纹字段不丢失。
- WAF API、WAF 页面数据和 XLSX 导出兼容历史 `blocked_hosts` 数据。
- 完成 Python 单元测试、阶段顺序测试、WAF Guard 联动测试和 Docker 镜像依赖安装测试。

## Assumptions

- 允许对用户明确授权的目标发送一次受控主动指纹请求；wafw00f 官方识别流程确实可能发送 XSS、SQLi、LFI 等攻击特征请求。[官方源码](https://raw.githubusercontent.com/EnableSecurity/wafw00f/v2.4.2/wafw00f/main.py)
- 默认低并发为 2，最大补充识别目标数为 200，优先控制 WAF 风险而不是追求全量探测速度。
- wafw00f 只负责补充厂商指纹，不替换现有 WAF Guard、DNS/CDN 判定和分类熔断逻辑。
- 本计划完成后，代码变更、回归测试和真实授权目标验证仍需分开记录。
