# WIH参数提取系统开发规划

## 1. 背景

当前 `ARL` 的 URL 发现能力已经明显增强，核心来源包括：

- `site_spider`
- `page_intel_scan`
- `urlfinder_extract`
- `urlfinder_url_probe`
- `WIH`

但“参数提取”仍然是明显短板。现状问题主要有：

- `WIH` 本身偏向 `URL / path / secret` 发现，不具备稳定的参数级输出能力。
- `AI渗透测试` 中已经实现了部分接口与参数提取，但能力分散在后验证链路里，和 `WIH` 出现职责重复。
- 当前参数提取主要依赖规则和局部正则，难以覆盖：
  - `GET query`
  - `POST body`
  - `header`
  - `path param`
  - `GraphQL variables`
  - 运行时动态拼接参数
- 结果没有统一参数模型，导致“提取出来的信息”很难复用到：
  - URL信息
  - 站点详情
  - 接口可用性验证
  - 导出
  - 后续 AI 语义分析

因此，本方案的目标不是继续在 `AI渗透测试` 里补碎片能力，而是把“接口与参数发现”前移到 `WIH + 站点爬虫` 主链路中，形成一套稳定、可解释、可评估的参数提取系统。

## 2. 总体目标

建设一套面向 `Web` 资产的统一“接口与参数发现系统”，让 `WIH` 从“只会提 URL”升级为“既会提 URL，也会提参数”。

目标包括：

1. 统一输出“接口 + 参数”数据模型，而不是继续产出零散文本片段。
2. 在不放宽任务边界的前提下，覆盖 `query / path / body / header / graphql` 等主流参数来源。
3. 将静态提取、运行时观察、交互探索、Schema 分析统一归并，给每个参数明确来源与置信度。
4. 把这套能力直接接入普通 `站点爬虫 / URL信息 / WIH` 主链路，不依赖单独的 `AI渗透测试` 模块。
5. 让后续 AI 只做“语义增强与重排序”，而不是做主提取器。

## 2.1 当前已完成情况（截至 2026-04-05 / commit `a22fba91`）

当前这份规划已经不再只是方案，下面这些内容已落地到仓库中：

- 已完成统一结构化模型：
  - `EndpointRecord`
  - `ParameterRecord`
  - `EndpointRequestTemplate`
  - `EndpointTriggerContext`
- 已完成结构化参数画像基础字段：
  - `is_pii`
  - `entropy`
  - `request_template`
  - `request_packet`
  - `page_url`
  - `source_detail`
  - `occurrence_count`
- 已完成 `WIH` 独立工具输出增强：
  - 主 `JSON` 输出直接携带 `endpoints / parameters`
  - 支持独立导出 `endpoint.json / parameter.json`
  - 已接入对应 CLI 参数与自动落盘逻辑
- 已完成 `HTML form` 首版参数提取：
  - `action/method/enctype`
  - `input/select/textarea`
  - `required/default/example/enum`
  - `GET/POST` 请求模板生成
- 已完成 `JS` 静态参数提取过渡版：
  - 当前仍以模式提取为主，不是 AST 主链
  - 已覆盖 `fetch / axios / request({...}) / URLSearchParams / FormData / GraphQL variables`
  - 已能输出 `query/body/header/path/graphql_variable`
- 已完成 runtime external driver 契约与最小样例：
  - `stdin/stdout JSON` 协议
  - 示例输入输出文件
  - external driver 示例脚本
- 已完成内置 `Playwright` runtime MVP：
  - 页面加载期 `fetch/xhr/sendBeacon`
  - `xhr.setRequestHeader`
  - `JSON / GraphQL / form` body 基础解析
  - 同 host 页面浅层探索
  - 低风险交互：
    - 搜索输入
    - `select` 切换
    - `tab` 切换
    - 搜索/筛选/下一页/更多点击
    - 低风险 `GET/搜索表单` 提交
  - `Playwright page.on('request')` 网络请求观测补充
- 已完成 runtime 结果归一化：
  - `endpoint_id` 映射
  - `method/protocol/body_kind/content_type`
  - `request_template/request_packet`
  - `parameter.location/param_type`
  - `parameter.source/source_detail`

当前仍未完成的部分：

- `JS AST` 主链尚未落地
- `schema` 提取尚未开始
- `GraphQL` 仍以基础变量提取与 runtime 观察为主，未进入深层结构分析
- `AI` 语义增强尚未开始

当前更准确的状态应理解为：

- `WIH` 已经具备“可独立运行的接口/参数发现 MVP”
- `runtime + form + JS静态提取` 三条主链已经打通
- 后续工作的重点不再是“从 0 到 1”，而是：
  - 把 runtime 继续做深
  - 把静态 `JS` 从模式提取升级到 `AST`
  - 把 schema / GraphQL 深化补齐

## 3. 非目标

本方案不以“自动攻击”或“自动漏洞利用”为目标，首要目标是提升接口面与参数面的发现质量。

短期内不做：

- 跨 host 扩张发现
- 高风险自动利用
- 复杂登录态自动绕过
- 以 `LLM` 替代 `AST / runtime hook` 做主提取

## 4. 设计原则

### 4.1 主链路不依赖 LLM

参数发现主链路必须基于：

- 静态结构提取
- `AST` 分析
- 浏览器运行时 Hook
- 交互驱动探索

`LLM` 只用于：

- 参数语义补全
- 低置信度候选重排序
- 人类可读解释生成

### 4.2 统一参数模型优先

没有统一参数模型，就没有真正可复用的接口发现能力。

### 4.3 运行时优先于命名猜测

参数置信度排序应明确：

- 运行时观察到 > Schema 明确定义 > AST 推断 > 命名猜测

### 4.4 仍严格限制 scope

所有发现行为必须继续约束在：

- 当前任务目标
- 当前 host
- 当前允许 scope

不通过放宽 host 来换召回率。

### 4.5 WIH 必须保持独立工具完整性

`WIH` 不是只能挂在 `ARL` 里才能工作的内部子模块，而是一个可以独立交付、独立运行的工具。

因此本次参数提取系统建设必须满足：

- 脱离 `ARL` 时，`WIH` 仍然可以单独完成：
  - 页面抓取
  - JS 发现
  - 参数提取
  - 参数归并
  - 结构化输出
- `WIH` 的核心参数提取能力不能依赖：
  - `ARL` 数据库
  - `ARL` 任务调度器
  - `ARL` 前端页面
- `ARL` 对 `WIH` 的定位应是“消费其结果并做展示/验证编排”，而不是反向承载 `WIH` 的核心逻辑。
- 所有新增能力都要优先考虑 `CLI / 文件输出 / JSON 输出` 的独立可用性。

一句话说，`ARL` 可以增强 `WIH` 的消费和展示，但不能让 `WIH` 失去独立工具价值。

## 5. 统一数据模型

建议新增统一的接口与参数对象，而不是继续把参数塞进 `ScanRecord.content` 里。

### 5.1 Endpoint 模型

```json
{
  "task_id": "xxx",
  "site": "https://example.com",
  "page_url": "https://example.com/admin",
  "endpoint_id": "stable_hash",
  "url": "https://example.com/api/user/detail",
  "path": "/api/user/detail",
  "method": "GET",
  "protocol": "http",
  "source_types": ["static_ast", "runtime_hook"],
  "trigger_context": {
    "page": "https://example.com/admin",
    "event": "click/search/pagination/form_submit",
    "dom_hint": "button.search"
  },
  "content_type": "application/json",
  "body_kind": "json|form_urlencoded|multipart|xml|graphql|text|unknown",
  "request_template": {
    "headers": {
      "Accept": "application/json, text/plain, */*",
      "Content-Type": "application/json"
    },
    "query": {
      "page": "<value>"
    },
    "body": {
      "keyword": "<value>"
    }
  },
  "confidence": 0.92
}
```

### 5.2 Parameter 模型

```json
{
  "task_id": "xxx",
  "endpoint_id": "stable_hash",
  "param_name": "keyword",
  "location": "query|path|body|header|cookie|graphql_variable",
  "param_type": "string|number|boolean|object|array|file|unknown",
  "required": true,
  "example": "test",
  "default": "",
  "enum": [],
  "source": "runtime|schema|ast|dom_form|heuristic",
  "source_detail": {
    "page_url": "https://example.com/admin",
    "js_file": "https://example.com/static/app.js",
    "schema_lib": "zod"
  },
  "confidence": 0.96,
  "occurrence_count": 3
}
```

### 5.3 推荐落库方式

建议不要直接复用当前 `wih` 集合的纯文本记录形态。

推荐新增：

- `wih_endpoint`
- `wih_parameter`

并保留 `wih` 文本记录作为兼容层。

理由：

- 当前 `wih` 记录结构太扁平，不适合表达方法、位置、类型、置信度。
- 接口和参数需要独立索引、聚合与去重。
- 后续前台展示、导出、筛选、验证都更自然。

同时需要明确两套输出形态：

#### 独立工具输出

当 `WIH` 单独运行时，应至少支持：

- `stdout json`
- `json/jsonl` 文件输出
- `endpoint + parameter` 结构化导出
- 保留兼容当前 `ScanRecord` 的文本命中结果

推荐输出文件：

- `scan_result.json`
- `endpoint.json`
- `parameter.json`

#### ARL 集成输出

当 `WIH` 由 `ARL` 调用时，再由 `ARL` 负责：

- 入库
- 聚合
- 前台展示
- 与 `URL信息 / 站点 / AI验证` 的联动

这样可以确保：

- `WIH` 独立运行时功能完整
- `ARL` 只做平台层消费，不反向绑定工具核心实现

## 6. 分层提取架构

整体采用五层：

1. 抓取层
2. 静态分析层
3. 浏览器运行时 Hook 层
4. 参数归并层
5. AI 语义增强层

---

### 6.1 抓取层

职责：

- 输入站点种子
- 拉取 HTML / JS / sitemap / robots
- 管理页面、脚本、API 文档等候选资源

输入来源：

- `site_spider`
- `page_intel_scan`
- `urlfinder_extract`
- `urlfinder_url_probe`
- `api_doc_scan`

输出：

- 页面列表
- JS 资源列表
- 站点内接口 URL 候选

建议增强：

- 保留当前同 host 限制
- 默认吃 `robots.txt` 与 `sitemap.xml`
- 对 `script[src]` 资源建立单独抓取队列
- 为每个页面记录“来源页面、发现深度、发现方式”

---

### 6.2 静态分析层

职责：

- 从 HTML / JS / TS / bundle 中提取接口与参数结构

重点覆盖：

- `form / input / select / textarea`
- `fetch`
- `XMLHttpRequest.open/send`
- `axios`
- `ky`
- `apollo client`
- `URLSearchParams`
- `FormData`
- `JSON.stringify`
- 前端路由里的 `path params`
- `GraphQL query/mutation + variables`
- `zod / yup / joi / ajv` 等 schema/校验定义

关键要求：

- 静态分析主链路改用 `AST`
- 正则仅作为补洞手段，不再做主提取器

建议模块拆分：

- `html_form_extractor`
- `js_ast_endpoint_extractor`
- `js_ast_param_extractor`
- `graphql_ast_extractor`
- `schema_extractor`

---

### 6.3 浏览器运行时 Hook 层

职责：

- 捕获运行时真实发出的请求与参数
- 解决“参数是动态拼出来的”问题

核心 Hook 点：

- `window.fetch`
- `XMLHttpRequest.open/send`
- `FormData.append`
- `URLSearchParams.append`
- `navigator.sendBeacon`
- `WebSocket`
- `GraphQL client` 请求发送点

关键输出：

- 请求由哪个页面触发
- 请求由哪个事件触发
- 参数最终落点：
  - `query`
  - `path`
  - `body`
  - `header`
  - `graphql_variable`
- 参数名、示例值、出现次数
- 哪些字段只在某次交互后出现

实现建议：

- 基于 `Playwright + CDP`
- 以低副作用、被动观察为主
- 保留最大页面数、最大交互数、最大请求数预算

实现补充建议：

- Hook 层应直接做一轮内存级请求去重，优先按 `method + normalized_path + param_keys + body_kind` 合并，减少心跳包、埋点和轮询请求对后续归并层与存储层的压力。
- Hook 层必须继续执行严格的 scope 过滤，对非目标 host 的请求直接丢弃，避免第三方 API、地图 SDK、统计脚本等把数据面污染到主结果中。
- 运行时采集强调“稳定、低副作用、可审计”，不引入对抗性指纹隐藏、WAF 规避或自动化痕迹伪装逻辑；遇到拦截时应保守停止，不做绕过。

---

### 6.4 交互驱动探索层

职责：

- 主动触发前端行为，让“运行时 Hook”拿到更多动态参数

建议优先覆盖的交互：

- 搜索框输入
- 筛选器切换
- 分页按钮
- Tab 切换
- 下拉框切换
- 登录弹窗打开
- 表单提交前填充
- 文件上传控件识别

设计要求：

- 不做高风险行为
- 使用固定低风险输入模板
- 保证每个动作可回放、可审计

建议策略：

- 默认探索预算：`5~12` 个动作/页面
- 优先动作：
  - 表单
  - 搜索
  - 分页
  - tab
  - select

实现补充建议：

- 建议维护一套通用“安全输入字典”，仅用于低风险字段填充，例如：
  - `email -> test@example.com`
  - `username -> admin`
  - `keyword -> test`
  - `phone -> 13800000000`
- 事件触发顺序优先考虑：
  - `click`
  - `change`
  - `input`
  这几类对触发 `fetch/xhr` 最有效，且副作用相对可控。

---

### 6.5 参数归并层

职责：

- 将多个来源的碎片合并成“接口 + 参数”统一对象

同一接口的参数可能来自：

- DOM 表单
- JS AST
- runtime hook
- schema
- API 文档

归并规则建议：

1. 先按 `method + normalized_path + host` 聚合 endpoint
2. 再按 `param_name + location` 聚合 parameter
3. 对同名参数保留：
   - 全部来源
   - 最可信类型推断
   - 最优示例值
   - required/default/example/enum 的合并结果

置信度建议：

- 运行时观察到：`0.90 ~ 1.00`
- schema 明确定义：`0.80 ~ 0.95`
- AST 明确调用链：`0.65 ~ 0.85`
- DOM 表单声明：`0.60 ~ 0.80`
- 命名猜测：`0.20 ~ 0.50`

参数模型补充建议：

- 建议新增 `is_pii` 字段，用于标记是否疑似敏感信息，例如：
  - 手机号
  - 身份证
  - 邮箱
  - Token
  - 凭证类字段
- 建议新增 `entropy` 字段，用于辅助判断参数值是否更像：
  - 动态 ID
  - 高熵 Token
  - 固定控制指令

## 7. 与现有 ARL/WIH 的整合建议

### 7.1 WIH 侧

当前 `tools/wih` 输出是：

- `ScanResult`
- `ScanRecord`

建议分两步兼容升级：

#### 第一步：兼容扩展

保留原有 `ScanRecord` 输出能力，同时新增参数化输出文件，例如：

- `endpoint.json`
- `parameter.json`

或者新增结构：

```go
type EndpointRecord struct {}
type ParameterRecord struct {}
```

补充要求：

- `WIH` 独立运行时，结构化输出必须可直接用于离线分析，不要求依赖 `ARL` 二次加工才能看懂。
- 文本输出可继续保留，但 `json/jsonl` 输出要把 `endpoint/parameter` 作为一等结果，而不是附属调试字段。

#### 第二步：ARL 侧消费升级

`ARL` 不再只把 `WIH` 当“文本命中器”，而是把它当“接口面发现器”：

- `URL信息` 继续保留页面 URL
- 新增接口与参数资产层
- 逐步替代原 `AI渗透测试` 中偏接口提取的那部分能力

### 7.2 站点爬虫侧

站点爬虫的职责建议调整为：

- 页面发现
- 脚本发现
- 轻交互
- runtime 请求观察
- 入口数据送入参数提取系统

而不是只做：

- 静态 HTML 链接爬取

静态分析补充建议：

- 针对压缩产物，不追求完整还原业务逻辑，优先锁定：
  - `Object.assign`
  - 模板字符串 URL
  - 对象字面量请求体
  - `axios.post(url, data)` / `fetch(url, init)` 等典型调用特征
- 若站点暴露 `SourceMap`，应优先尝试拉取并参与静态分析，这会显著降低混淆产物下的 AST 解析成本。

### 7.3 AI渗透测试侧

建议将其逐步收口为：

- 接口可用性验证
- 低副作用请求验证
- AI 语义解释与优先级排序

而不是继续承担“参数主提取器”角色。

## 8. 分阶段研发计划

### 阶段 0：模型与链路改造准备

当前状态：`已完成`

目标：

- 定义统一参数模型
- 确定落库结构、索引、导出结构
- 明确兼容旧 `wih` 文本记录的方式
- 明确 `WIH standalone` 与 `ARL integrated` 两种运行模式的输出协议

交付：

- 数据结构定义
- Mongo 集合与索引设计
- `WIH -> ARL` 消费协议说明
- `WIH CLI/JSON` 独立输出协议说明
- 结构化结果索引策略，明确 `stable_hash` / `endpoint_id` / `parameter_id` 的复合索引约束

---

### 阶段 1：运行时 Hook MVP

当前状态：`MVP 已完成，持续增强中`

目标：

- 先把最有召回价值的一层做起来

范围：

- `fetch`
- `xhr`
- `FormData`
- `URLSearchParams`
- `sendBeacon`
- `GraphQL request`

交付：

- 浏览器运行时请求与参数采集
- 页面、事件、参数位置、示例值记录
- 可直接由 `WIH` 独立导出的 `endpoint/parameter` 结构化结果

这是第一优先级，收益最高。

---

### 阶段 2：HTML 表单提取

当前状态：`首版已完成`

目标：

- 把页面里明确定义的参数结构补齐

范围：

- `form action`
- `input/select/textarea`
- `name/value/required/type`
- `hidden/csrf`
- `multipart`

---

### 阶段 3：AST 静态分析

当前状态：`过渡版已落地，AST 主链未完成`

目标：

- 让静态代码里能明确看出来的参数也进入统一模型

优先覆盖：

- `fetch`
- `axios`
- `xhr`
- `URLSearchParams`
- `FormData`
- `JSON.stringify`
- path params

---

### 阶段 4：Schema / GraphQL 深化

当前状态：`未完成`

目标：

- 提升参数类型、required、enum、default 的结构化质量

优先覆盖：

- `zod`
- `yup`
- `joi`
- `ajv`
- `GraphQL variables / operation definitions`

---

### 阶段 5：AI 语义增强

当前状态：`未开始`

目标：

- 在主链路稳定后，用 AI 做解释和排序

适用场景：

- 参数语义补充
- 低置信度参数候选重排
- 面向工程师的“接口说明”生成

## 9. 评估指标

必须引入明确指标，否则参数提取能力无法客观演进。

### 9.1 召回率指标

- 页面级接口发现数
- endpoint 去重后数量
- parameter 去重后数量
- `GET / POST / body / header / graphql` 各位置参数覆盖率

### 9.2 质量指标

- 高置信度参数占比
- 运行时命中参数占比
- 无效请求包比例
- 重复参数合并错误率

### 9.3 成本指标

- 单站点平均抓取时长
- 单站点平均页面数
- 单站点平均 JS 数
- 单站点平均交互动作数
- 浏览器资源消耗

### 9.4 回归样本集

需要准备覆盖以下站点类型的样本集：

- 传统 HTML 表单站
- `Vue/React` SPA
- 后台管理系统
- 学校/政务门户
- GraphQL 站点
- 带复杂搜索/筛选/分页的站点

## 10. 风险与注意事项

### 10.1 运行时 Hook 的性能成本

问题：

- 浏览器探索比纯静态提取重很多

控制建议：

- 限预算
- 限页面数
- 限交互数
- 限请求条数

### 10.2 AST 解析复杂度

问题：

- 现代前端构建产物压缩严重

建议：

- 优先处理源码风格和半压缩产物
- 对高度混淆 bundle 只做运行时补偿

### 10.3 参数污染

问题：

- tracking 参数、埋点参数、框架内部参数很多

建议：

- 单独做参数噪声过滤层
- 区分“业务参数”和“观测噪声参数”

额外建议：

- `wih_parameter` 规模可能远大于当前 `wih` 文本记录，必须尽早设计：
  - `endpoint_id`
  - `param_name`
  - `location`
  - `stable_hash`
  相关复合索引
- 否则在复杂 SPA 站点下，参数对象数量会快速膨胀，影响存储与查询性能。

### 10.4 GraphQL 结构化难度

问题：

- `query` 文本与 `variables` 经常分散

建议：

- runtime hook 优先
- AST/Schema 作为补强

## 11. 推荐落地顺序

如果当前只能优先做一条线，建议严格按下面顺序：

1. `浏览器运行时 Hook`
2. `HTML 表单提取`
3. `AST fetch/xhr/axios/URLSearchParams/FormData`
4. `GraphQL 提取`
5. `Schema 提取`
6. `AI 语义增强`

原因：

- 第 1 步直接解决“参数动态拼装”的核心问题
- 第 2、3 步提升覆盖与可解释性
- 第 4、5 步提升结构质量
- 第 6 步最后做，不会绑架主链路稳定性

## 12. 建议的代码拆分

建议最终拆成这些模块：

- `tools/wih/capture/`
  - 页面与脚本抓取
- `tools/wih/extract/html/`
  - HTML 表单提取
- `tools/wih/extract/ast/`
  - JS/TS AST 接口与参数提取
- `tools/wih/extract/graphql/`
  - GraphQL query/variables 提取
- `tools/wih/extract/schema/`
  - zod/yup/joi/ajv 提取
- `tools/wih/runtime/`
  - Playwright/CDP Hook
- `tools/wih/merge/`
  - endpoint/parameter 归并与置信度
- `tools/wih/output/`
  - 兼容当前 `ScanRecord` 与未来结构化输出

建议 `WIH` 独立工具继续保持清晰主程序分层：

- `main.go`
  - CLI 参数解析与运行模式选择
- `scan/`
  - 扫描与提取主流程
- `runtime/`
  - 浏览器 Hook 与交互探索
- `merge/`
  - endpoint/parameter 归并
- `output/`
  - `text/json/jsonl` 多输出格式
- `factory/`
  - 输入源工厂（url/file/json）

ARL 侧建议新增：

- `app/services/interface_surface_collect.py`
- `app/services/interface_param_merge.py`
- `app/routes/interface_surface.py`

## 13. 最终预期

最终形态不是“AI渗透测试里顺手提一点参数”，而是：

- 普通站点爬虫就能把接口与参数面提出来
- `WIH` 成为统一的接口与参数发现底座
- `AI渗透测试` 可以退化为“验证与解释层”
- `WIH` 在脱离 `ARL` 时仍然可以作为完整工具独立交付与使用

这样整套系统的职责会更清楚：

- `站点爬虫 / WIH`：发现
- `URL信息 / 参数资产`：沉淀
- `AI / MCP / 轻验证`：验证与排序
- `WIH CLI`：独立输出结构化接口与参数结果
- `ARL`：消费、展示、编排与验证

## 14. 当前建议

当前仓库如果只启动一项开发，我建议立刻做：

### `运行时 Hook + 自动交互 MVP`

因为这一步最直接解决：

- 参数是动态拼出来的
- 静态代码里看不到
- 页面初始不触发请求

同时，它也最容易快速证明价值：

- 同一批站点下参数数量显著增加
- `POST/body/graphql` 参数召回率明显提升
- 后续所有静态分析与 AI 语义增强都能围绕它继续叠加
