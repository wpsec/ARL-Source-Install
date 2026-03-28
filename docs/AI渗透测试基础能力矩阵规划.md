# AI渗透测试基础能力矩阵规划

## 1. 文档目的

本文件用于明确 `AI+MCP 渗透测试` 的后续能力建设方向：

- 以 `OWASP / PortSwigger(Burp 渗透测试方法论)` 这类基础能力作为主干
- 以 `产品画像` 作为顺序优化层
- 以 `PoC 文库` 作为知识增强层

核心目标不是“多收集一些产品 PoC”，而是让系统具备接近渗透测试工程师基础能力的验证框架。

## 2. 核心原则

### 2.1 基础能力优先，文库能力次之

`AI渗透测试` 的能力建设应遵循：

1. 基础能力层  
2. 场景映射层  
3. 产品画像层  
4. 文库知识层  

不应反过来变成：

1. 产品特判  
2. 文库命中  
3. 再拼基础能力

### 2.2 文库不是主干，只是增强

`tools/poc/POC`、`tools/nuclei/nuclei-templates`、`tools/afrog/afrog-pocs` 的价值主要在于：

- 产品别名补齐
- 历史高频入口补齐
- 常见验证动作补齐
- 风险类型与证据标准参考

而不是让运行时逻辑变成：

- 命中某产品  
- 执行一批历史 PoC  
- 再回头找证据

### 2.3 面向“验证能力”而不是“攻击能力”

AI+MCP 的目标应是：

- 更会找验证点
- 更会补上下文
- 更会判定证据
- 更会压误报

而不是：

- 更会自动利用
- 更会自动爆破
- 更会自动扩大战果

## 3. 建议的能力架构

## 3.1 基础能力层

这是主干，应该先建设。

建议统一成以下 `capability profiles`：

### `api_surface_analysis`

目标：
- 发现并结构化分析接口面

输入来源：
- Swagger / OpenAPI / Postman
- JS 提取接口
- URL 参数线索
- 页面表单

关注点：
- path / method / params
- `securitySchemes`
- 鉴权相关接口
- 上传 / 下载接口
- 对象 ID 风格接口

### `authn_session_analysis`

目标：
- 分析身份认证与会话链路

关注点：
- 登录入口
- 会话保持方式
- Cookie / Header / Token 模式
- 认证前后行为差异

### `authz_object_reference_analysis`

目标：
- 分析授权与对象引用边界

关注点：
- `id / *_id / uid / tenant_id / account_id`
- 路径数字 ID
- 权限 / role / scope 参数
- 同一接口不同对象的响应差异

### `token_jwt_analysis`

目标：
- 分析 token / JWT 鉴权面

关注点：
- token 是否真实存在
- `alg`
- 签名方式
- none-token 重放
- 弱密钥风险

### `client_side_input_flow_analysis`

目标：
- 分析前端输入流与浏览器侧风险

关注点：
- DOM XSS source -> sink
- JS 中接口暴露
- 静态构建产物噪声
- 本地存储与变量拼接误报

### `server_side_injection_analysis`

目标：
- 分析服务端注入面

关注点：
- SQL 注入
- 命令注入
- SSRF
- XXE
- LDAP/模板注入等

### `file_handling_analysis`

目标：
- 分析文件上传 / 下载 / 读取能力

关注点：
- 上传入口
- 下载入口
- 文件路径参数
- 模板 / 导出 / 附件处理能力

### `realtime_channel_analysis`

目标：
- 分析 WebSocket 等实时通道

关注点：
- 握手路径
- Upgrade 特征
- 鉴权方式
- 消息订阅/权限边界

## 3.2 场景映射层

这一层的作用是：

- 把资产扫描结果映射到基础能力

示例：

- `Swagger/OpenAPI`  
  -> `api_surface_analysis`

- `JS 提取接口`  
  -> `api_surface_analysis`

- `JWT 线索 / Bearer / securitySchemes`  
  -> `token_jwt_analysis`

- `ID 参数 / 路径数字 ID`  
  -> `authz_object_reference_analysis`

- `upload / download / file / attachment`  
  -> `file_handling_analysis`

- `WebSocket / socket.io / sockjs`  
  -> `realtime_channel_analysis`

- `innerHTML / eval / source->sink`  
  -> `client_side_input_flow_analysis`

## 3.3 产品画像层

产品画像层不是主干，只用于：

- 调整验证顺序
- 提高优先级
- 增加产品家族特有入口提示

应该优先做“系统家族画像”，而不是“产品名特判”。

建议的画像类型：

- `api_doc_surface`
- `js_bundler_app`
- `token_auth_flow`
- `admin_office_portal`
- `middleware_admin_surface`

这些画像应依赖通用证据：

- path/title/body/finger
- API surface summary
- knowledge hit product labels

而不是直接写死：

- `seeyon`
- `tongda`
- `ecology`
- `ruoyi`

举例：

- 命中 `swagger/openapi` 时，不是因为“产品 = Swagger”，而是因为它属于 `api_doc_surface`
- 命中 `oa/office/workflow` 时，不是因为“产品 = 某 OA”，而是因为它属于 `admin_office_portal`

## 3.4 文库知识层

这一层来自：

- `tools/poc/POC`
- `tools/poc/vulhub`
- `tools/poc/PoC-in-GitHub`
- `tools/nuclei/nuclei-templates`
- `tools/afrog/afrog-pocs`

作用：

- `knowledge_hit_tokens`
- `knowledge_hit_product_labels`
- `knowledge_hit_vuln_types`
- `knowledge_hit_entry_paths`
- `knowledge_hit_verify_actions`
- `knowledge_hit_record_refs`

这层应该：

- 给候选排序加权
- 给 AI planner 补上下文
- 给详情页补可解释性

不应该：

- 直接决定最终结论
- 直接驱动高风险利用动作

## 4. 当前实现与问题

当前仓库已经有这些基础：

- `AI渗透` 结果页
- `AI渗透` 规划器
- `MCP` 验证链
- `API 文档结构化摘要`
- `JS 提取接口结构摘要`
- `PoC 文库结构化知识画像`

但当前仍存在的问题：

### 4.1 容易偏向“产品/文库思维”

如果继续沿“产品名 -> playbook”扩展，容易让系统变成：

- 遇到某产品才会测
- 换一个同类系统就丢能力

### 4.2 基础能力尚未显式建模

虽然代码里已经零散具备一些能力，但还缺：

- 统一的 `capability_profiles`
- 统一的 `capability_hints`
- 统一的“能力 -> 验证顺序”框架

### 4.3 文库命中还没有完全转化为能力输入

当前知识画像已经能展示，但还没有完整作为：

- planner 主输入
- verifier 默认偏置
- 场景能力选择器

## 5. 后续开发建议

## 5.1 第一优先级：引入 `capability_profiles`

建议新增一层能力矩阵，例如：

```python
AI_PEN_CAPABILITY_PROFILES = {
    "api_surface_analysis": {...},
    "authn_session_analysis": {...},
    "authz_object_reference_analysis": {...},
    "token_jwt_analysis": {...},
    "client_side_input_flow_analysis": {...},
    "server_side_injection_analysis": {...},
    "file_handling_analysis": {...},
    "realtime_channel_analysis": {...},
}
```

并新增：

- `capability_hints`
- `capability_profiles`
- `priority_actions`

## 5.2 第二优先级：让 planner 按能力而不是按产品工作

planner 输入里优先给：

- `route_hint`
- `api_surface_summary`
- `capability_hints`
- `capability_profiles`
- `evidence thresholds`
- `knowledge_hit_*`

而不是优先给：

- 产品名
- 某个历史漏洞名

## 5.3 第三优先级：产品画像只做偏置

产品画像应改为：

- 只影响优先级和顺序
- 不直接主导验证框架

## 5.4 第四优先级：继续扩充文库结构化字段

后续还可以增加：

- 常见认证方式
- 常见对象引用参数
- 常见上传/下载路径
- 常见误报噪声模式

## 6. 建议的演进顺序

推荐顺序：

1. 建立 `基础能力矩阵`
2. 建立 `场景 -> 能力` 映射
3. 再做 `产品画像偏置`
4. 最后用 `PoC 文库` 做增强

而不是：

1. 产品名特判
2. 文库命中
3. 再补基础能力

## 7. 一句话结论

`AI+MCP 渗透测试` 的主干，应当是“OWASP / PortSwigger 风格的基础验证能力矩阵”，而不是产品特判或文库命中。

产品画像和 PoC 文库都很重要，但它们应当是增强层，而不是主驱动层。
