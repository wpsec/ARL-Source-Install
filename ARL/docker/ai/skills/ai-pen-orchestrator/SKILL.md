---
name: ai-pen-orchestrator
description: 当需要改进或扩展 ARL 的 AI+MCP 渗透测试验证链路时使用此 Skill，特别适用于候选路由、上下文补全、证据判定、误报抑制、产品化验证 playbook，以及把 PoC 文库转成验证知识而不是盲目利用。
---

# AI渗透编排器

当你在这个仓库里处理 `AI渗透测试` 相关开发时使用此 Skill，尤其是：
- 提升 `AI渗透测试` 的候选筛选与优先级排序
- 决定在执行 MCP 探针前应该先补哪些上下文
- 在不扩大攻击自动化边界的前提下，提高有效漏洞命中率
- 用结构化证据规则压低误报
- 将 `tools/poc/`、`tools/nuclei/`、`tools/afrog/` 转换成“验证知识”和“产品画像 playbook”

此 Skill 适合的改动范围：
- `ARL/docker/ai/`
- `ARL/app/services/commonTask.py`
- `ARL/docker/ai/sop/default_ai_pen_test.yaml`
- `ARL/test/` 中与 AI 渗透测试相关的测试

此 Skill 不适合做的事：
- 把系统变成盲目的 exploit runner
- 引入不可控的爆破、破坏性利用链
- 直接用历史 PoC 原文替代验证编排逻辑

## 工作流

1. 先从候选记录出发，确定它属于哪条验证路由。  
读 [references/routing.md](references/routing.md)

2. 先补“最小但有价值”的上下文，再决定是否换 payload 策略。  
推荐顺序：
- 同目标 HTTP 重放
- 响应头 / 标题 / Body 摘要
- 若目标是 `.js`，补 JS 静态上下文
- 若目标像 Swagger / OpenAPI，先补 API 文档结构
- 若已命中 `tools/poc` 知识索引，补产品与入口线索

3. 用证据门槛判定结果，不要靠单一信号下结论。  
读 [references/evidence-criteria.md](references/evidence-criteria.md)

4. 在提升结论前，先走误报抑制规则。  
读 [references/false-positive-rules.md](references/false-positive-rules.md)

5. 如果产品/框架身份比较明确，再加载对应产品画像。  
读 [references/product-playbooks.md](references/product-playbooks.md)

6. 如果改了运行时逻辑，至少同步检查这些位置：
- `ARL/app/services/commonTask.py`
- `ARL/docker/ai/sop/default_ai_pen_test.yaml`
- `ARL/test/` 里的相关回归测试

## 设计原则

- 优先“上下文先行，探针随后”，不要只看 URL 直接打 payload。
- 优先“多个弱信号汇总成一个强判断”，不要单点命中就升级为 `verified`。
- PoC 文库的首要用途是知识索引：
  `产品 -> 入口特征 -> 证据模式 -> 推荐验证顺序`
- AI 或 MCP 不可用时必须保持 fail-open，不阻断主链路。
- 始终保留可观测性字段：
  `decision`、`confidence`、`reason`、`evidence_snippet`、`tool_trace`

## 安全边界

- 仅在当前任务 scope 内行动。
- 优先只读或低副作用验证。
- 不引入不可控的口令攻击或破坏性利用动作。
- 若必须依赖登录态，要求显式提供测试账号、Cookie 或 Header，上下文不足时保持 `needs_manual_review`。

## 仓库内关键入口

- AI渗透运行时 SOP：
  `ARL/docker/ai/sop/default_ai_pen_test.yaml`
- 主验证链：
  `ARL/app/services/commonTask.py`
- 设计文档：
  `docs/AI渗透测试与MCP开发规划.md`
  `docs/AI智能匹配PoC执行SOP.md`

## 什么时候读哪个参考文件

- 候选该走哪条验证链不清楚，或多个路由冲突：
  读 [references/routing.md](references/routing.md)

- 需要区分 `verified / likely_false_positive / needs_manual_review`：
  读 [references/evidence-criteria.md](references/evidence-criteria.md)

- 遇到静态 JS、构建产物、Swagger 噪声、弱关键词命中：
  读 [references/false-positive-rules.md](references/false-positive-rules.md)

- 已识别出产品/框架/中间件家族，需要按产品走验证顺序：
  读 [references/product-playbooks.md](references/product-playbooks.md)
