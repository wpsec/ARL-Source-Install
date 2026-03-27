# 产品画像 Playbooks

只有在目标产品家族比较明确时，才读这份文件。

## Swagger / OpenAPI / Postman

- 第一步确认文档是否真实存在且可读
- 第二步提取 path / method / parameter 结构
- 优先关注：
  - 鉴权相关接口
  - 对象 ID 风格接口
  - 上传 / 下载接口
  - 调试 / 管理接口

## Nuxt / Webpack / 静态 JS 构建产物

- 这类目标上下文丰富，但噪声也大
- 优先寻找：
  - 硬编码字面量
  - 明确 API Base URL
  - source -> sink 链路
- 需要优先降权的模式：
  - `token + variable`
  - `localStorage/sessionStorage`
  - 框架 bootstrap/runtime 代码

## JWT 型应用

- 先确认 token 存在，再谈 JWT 验证
- 先判断签名家族，再决定后续探针
- 如果 token 存在但签名缺陷未证实，保持 `needs_manual_review`

## 中间件 / OA / 管理后台

- 产品家族优先级高于通用风险标签
- 优先关注：
  - 历史高频管理路径
  - 暴露的服务 / 文档入口
  - 文件上传 / 文件读取 / 认证边界

不要直接把社区 PoC 当成执行模板，而要先抽象成：
- 入口模式
- 预期证据
- 最小验证动作

## Seeyon / 类 OA 家族

- 指纹一旦明确，应优先走产品化验证顺序
- 优先关注：
  - 历史高频接口族
  - 文档/服务暴露
  - 文件处理能力
  - 登录态前后的鉴权边界

目标是“证明问题真实存在”，不是“跑完整利用链”。
