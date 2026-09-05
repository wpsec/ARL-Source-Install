# 路由规则

当需要决定某条候选记录该怎么验证时，使用这些路由规则。

## 核心原则

不要只根据 URL 形态决定路由。应综合：
- 来源集合
- 风险类型
- 同目标可补到的上下文
- 目标是动态页面、API 文档，还是静态 JS 资源

## 优先路由

### `sensitive_info`
- 如果目标是 `.js`：先拉取 JS，并判断是“硬编码字面量”还是“变量拼接噪声”
- 如果目标是 HTML/API：先确认疑似 secret/token/key 是否真的以字面量出现
- 只有在发现真实字面量凭据时，才允许明显升级结论

### `api_doc`
- 先探测同目标常见 API 文档端点
- 如果文档真实存在，优先提取 path / method / parameter 结构
- 后续验证优先围绕参数化接口做，而不是盲目变异 payload

### `jwt`
- 先从 header/body/evidence 中提取 token
- 判断 `alg`、签名家族、重放表现、弱密钥线索
- 如果连 token 都不存在，就不要继续规划高阶 JWT 探针

### `websocket`
- 优先验证握手路径和 Upgrade 特征
- `101` 是强证据
- `400/426 + websocket header` 是中等证据

### `idor`
- 只对结构化对象 ID 做变异
- 比较响应哈希 / 结构 / 状态码，而不是只看标题变化
- 若明显依赖登录态，则保持 `needs_manual_review`

### `xss`
- 对服务端页面：优先看回显和响应差异
- 对 `.js`：先做 source -> sink 静态分析，再决定是否升级
- 对纯构建产物且无危险 sink 的情况，应优先降权

### `sqli / cmdi / ssrf`
- 使用小步、低副作用探针
- 要求有响应证据或稳定差异
- 纯时间差通常不应直接升为 `verified`

## 产品画像优先级覆盖

如果标题、指纹、路径、知识命中已经强烈指向某个产品家族，应优先走产品画像路由，而不是只按原始 `risk_type`。

例如：
- `swagger/openapi` -> 优先走 API 文档路由
- `seeyon/oa` -> 优先走产品 playbook
- `_nuxt/*.js` -> 优先走 JS 上下文路由，再判断 `sensitive_info/xss`
