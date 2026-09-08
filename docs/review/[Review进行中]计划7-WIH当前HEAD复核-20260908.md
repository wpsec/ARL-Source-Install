# 计划 7 WIH 当前 HEAD 开发复核

## 1. 复核结论

- 复核基线：当前分支 `newUI`，代码基线 `eb6ae6f5`、文档同步提交 `fc7fc380`（计划 5/6/7 离线闭环、EvidenceGraph/主题门禁、监控摘要图标与顶部操作栏布局、监控指标文本防裁切、登录页窄屏修复、服务信息重挂载回归、IP 阶段轻依赖测试、侧边栏布局收口和总计划索引均已提交）；工作区干净。
- 结论：**开发侧复核通过，真实运行验收未完成**。
- 未发现新的 P0/P1 范围越界、凭据进入资产面、默认路径隐式发起验证请求或协议观察无界增长问题。
- 计划 7 已标记为 `[未完成][开发完成]`；计划 5 保持暂停，计划 6/7 的真实 worker、40/64、多架构和发布门禁不以本地测试替代。

默认安全基线仍保持：

- `API_UNIFIED_ENABLE=false`
- `API_UNIFIED_FALLBACK_ENABLE=true`
- 受控 API 验证未注入执行器时只返回 `pending`
- Playwright、Go WIH、TruffleHog 等外部网络边界单独记账

## 2. 已复核通过

### 2.1 资产与范围边界

- TargetProfile 只从已取得的响应/记录摘要生成画像，不触发网络请求；微前端资源适配器支持 qiankun、Wujie、micro-app 的静态关系提取，并执行 host scope 校验。
- HAR/代理事件导入只保留 URL 结构、方法、参数名、body 类型和鉴权类型；代理事件不复制原始 body，Header/Cookie/query 值不进入 Endpoint。
- GraphQL、SOAP、WebSocket、SSE 观察统一进入协议 Registry；协议 Registry 拒绝非 `http/https/ws/wss` scheme。
- 协议 Registry 对观察条目、来源集合和 evidence id 均有上限，达到容量时显式返回 `capacity` 并计量，不静默扩容。
- EvidenceGraph 只消费 Registry/Context 快照，不在同步阶段发起请求。
- EvidenceGraph adapter 已补齐文档/候选/路由到 Endpoint 的 `documents`/`calls` 关系、参数节点和有界 evidence ID 引用；图快照仍只保留不可逆节点 ID 与类别化边证据。

### 2.2 验证与脱敏

- L0/L1/L2 验证协调器只有显式注入 executor 才会执行；默认不创建网络客户端、不读取凭据。
- 验证结果会过滤 request/response body、Header、query、嵌套 token/password/credential 等敏感字段；URL query 敏感值、用户信息和 fragment 不进入认证作业结果。
- 参数证据只保存 `(name, in, evidence_kind)`；重复 Endpoint 合并时证据按 `inferred < literal < template < runtime` 升级，且有数量上限。
- 浏览器运行时事件和 TruffleHog 的外部请求边界均保留 WAF/阶段预算接线，异常路径写 debug 日志，不以空结果伪装成功。

## 3. 本轮 review 发现及处置

| 级别 | 发现 | 处置 |
|---|---|---|
| 重要 | Endpoint 合并时未合并 `parameter_evidence`，后续运行时证据可能丢失 | 已增加按参数位置升级合并，并补回归测试 |
| 重要 | 协议 URL 对未知 scheme 可能原样进入 Registry | 已改为仅接受 `http/https/ws/wss`，非法 URL fail-closed |
| 重要 | 认证作业 URL 可能保留 userinfo/fragment | 已清除 userinfo、fragment，并保留 query 敏感键脱敏 |
| 重要 | 代理事件中间结构会复制原始 body | 已改为只保留 MIME 类型和参数名 |
| 重要 | 验证结果的嵌套 `auth_token/query/password_hash` 可能外流 | 已增加递归敏感键和 query 类字段过滤 |
| 重要 | 协议 Registry 合并来源和条目数量缺少硬上限 | 已增加单条集合上限、Registry 容量和 `capacity` 计量 |
| 一般 | 浏览器 WebSocket/关闭阶段异常处理缺少可追踪日志 | 已补 debug 日志，保持主流程容错 |

## 4. 验证证据

- 定向后端回归：`103` 项通过。
- `python3 scripts/plan567-code-check.py --plan all`：计划 5、6、7 离线回归全部通过。
- `git diff --check`：通过。
- 前端 `npm run lint`：通过。
- 前端 Vitest：`18` 个 test files、`117` 项通过。
- 前端 `npm run build`：Vite 生产构建通过。
- `python3 scripts/check-theme-contrast.py`：6 套主题、12 组对比度全部通过。
- `ARL/test/test_theme_contrast.py`：2 项主题 token/对比度回归通过。
- `ARL/docker/frontend-src/scripts/ui-smoke.sh` 静态模式：入口资产与 SHA-256 清单通过；Docker/Playwright 阶段明确跳过。
- EvidenceGraph 图谱与 adapter 定向回归：14 项通过，覆盖调用链、文档关系、参数节点、认证边界、敏感值脱敏和幂等同步。
- 系统监控摘要定向回归：3 项通过，覆盖资源数据显示、失败态占位值、保留小图标和摘要区域 `shrink-0` 布局约束；状态文字和状态点不再进入界面。
- 顶部操作栏定向回归与监控联动：`App`/监控组件共 11 项通过，覆盖操作栏 `shrink-0` 与监控摘要区域的联合布局约束。
- 服务模块重挂载回归：10 项通过，覆盖 `task_id` 筛选恢复以及 `service_info` 的 IP/端口、服务名和 Product 展示，确认前端重构不会丢失已落库服务信息。
- IP 阶段服务边界回归：2 项通过；测试改用统一轻依赖 bootstrap，宿主机直接运行不再因 `xing` 包级导入失败。

测试中的 Mongo unavailable、pyparsing deprecation、ResourceWarning 和故障注入日志均为既有测试环境/故障路径提示，不构成新增失败；不以这些提示宣称生产运行通过。

## 5. 保持未完成的验收项

以下项目因用户当前决定“不做真实服务器观察期和证据归档”而保持未执行，不应勾选完成：

- 真实 worker/队列运行中验证唯一请求、阶段预算和 WAF 退避；
- 统一前后真实请求数、重复请求、缓存命中、网络等待和新增证据对照；
- 40 目标协同回归、64 目标冷/热性能门禁；
- ARM64/amd64 发布 smoke、完整 production runtime smoke；
- 计划 6 默认开关切换与计划 5 指纹生产切换。

上述内容分别由 `docs/plan/[开发完成]06-附录E-计划6发布验收runbook-双架构与40-64目标.md`、`docs/plan/[开发完成]07-计划7-WIH智能API发现与受控验证可行性分析.md` 和暂停中的计划 5 runbook 管理。

## 6. Review 后结论

开发代码可以进入“边用边修”阶段；默认开关保持关闭，真实扫描中出现问题时继续以脱敏日志和任务状态定位。当前不能把本记录解释为双架构发布验收或真实扫描观察期完成证明。
