# 误报抑制规则

在升级结论前，优先检查这些降权规则。

## JS / Sensitive Info

以下情况应优先降权：
- 变量拼接，例如 `token="+x`
- `localStorage/sessionStorage` 写入
- host/title/theme/cache 类逻辑
- placeholder/demo/test 字面量

只有在“真实字面量被直接赋值”时，才考虑升级。

## DOM XSS

以下情况应优先降权：
- 文件明显属于 bundled/framework runtime
- 未出现危险 sink
- 只有通用加载器、组件注册、异步模块代码

以下情况保留 `needs_manual_review`：
- 同时出现用户可控 source
- 同时出现危险 DOM sink

## API Docs

以下情况应优先降权：
- URL 带 `swagger`，但响应里没有真实文档结构
- 接口被拦截，且没有登录态上下文
- 页面只出现品牌词，没有 spec 数据

## 通用差分结果

以下信号不能单独抬高结论：
- 仅长度变化
- 仅标题变化
- 不稳定的时间差
- 短片段关键词命中，但没有上下文

## PoC 知识命中

知识命中只是排序信号，不是漏洞证明。

它应该用来：
- 提高验证优先级
- 提示下一步动作
- 帮助识别产品/入口家族

它不应该单独把结论推到 `verified`。
