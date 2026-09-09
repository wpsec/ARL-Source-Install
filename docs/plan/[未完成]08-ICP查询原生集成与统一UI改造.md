# 计划 8：ICP 查询原生集成与统一 UI 改造

> 当前状态：[开发完成]。ARL 原生后端、Celery 任务、Mongo 持久化、API、统一 UI、配置示例和自动化测试已落地；真实 ICP 接口验证码、上游限流和目标环境容器运行仍由测试环境验证后再归档。

## 1. 目标

将 [HG-ha/ICP_Query](https://github.com/HG-ha/ICP_Query) 的核心查询能力整合到 ARL 现有系统中，不新增独立容器、服务、端口或独立 Web 应用。

在“资产搜索”和“资产监控”之间新增“ICP 查询”侧边栏入口，在一个统一页面内整合上游除“配置管理”以外的功能：

- 查询
- 批量查询
- 查询历史
- 批量任务
- 系统日志
- 关于

本计划定义方案和实施边界；代码实施已完成，真实接口和发布环境验收保留为后续验证工作。

## 2. 已确定的设计决策

- 采用 ARL 原生适配，不启动 ICP_Query 的 aiohttp Web 服务。
- 单次查询和批量查询统一使用现有 Celery/Mongo 任务链。
- 任务复用现有 arlweb 队列，不新增 Celery 队列和 Worker 容器。
- ICP 数据独立保存，不自动写入 ARL 的域名、站点、IP 等资产集合。
- 查询历史和批量任务支持 JSON、Excel 两种导出格式。
- 页面采用顶部标签页，不增加二级侧边栏。
- 开发环境默认启用 ICP 查询，同时保留环境变量总开关。
- 以功能行为为参考进行 ARL 内部重实现，保留上游来源链接，不直接复制上游 Web/UI 和整包源码。

上游功能范围参考：[ICP_Query 仓库](https://github.com/HG-ha/ICP_Query)、[上游页面定义](https://raw.githubusercontent.com/HG-ha/ICP_Query/main/templates/index.html)、[查询路由](https://raw.githubusercontent.com/HG-ha/ICP_Query/main/src/python/routes/query_routes.py) 和 [批量任务路由](https://raw.githubusercontent.com/HG-ha/ICP_Query/main/src/python/routes/batch_routes.py)。

## 3. 总体架构

### 3.1 后端分层

新增 ICP 查询内部模块，职责拆分如下：

1. 查询引擎
   - 对接官方 ICP 查询接口。
   - 支持网站、App、小程序、快应用及对应违规类型。
   - 处理分页、验证码、请求超时、有限重试和结果标准化。
   - 不负责 Flask 路由、页面渲染和配置管理。

2. 任务服务
   - 创建单次查询任务和批量查询任务。
   - 持久化排队、运行、完成、部分失败、失败、取消等状态。
   - 记录每个批量输入项的独立状态和错误摘要。
   - 支持 Worker 重启后的任务状态恢复和用户取消。

3. Mongo Repository
   - 统一封装任务、历史、结果和日志的读写。
   - 避免将大批量结果全部写入单个 Mongo 文档。
   - 统一处理 TTL、分页、排序和结果脱敏。

4. Flask-RESTX API
   - 复用 ARL 现有 Token 认证、错误响应和日志体系。
   - 仅暴露 ARL 内部 API，不暴露 ICP_Query 原有 16181 端口和 aiohttp 路由。

### 3.2 Celery 执行模型

所有外部 ICP 请求均通过现有 arlweb 队列执行：

- Web 请求只负责参数校验、创建任务和返回 job_id。
- Worker 负责网络请求、验证码处理、分页和结果持久化。
- 前端通过轮询任务状态获取进度和结果。
- 批量任务使用服务端并发上限，忽略客户端提交的过大并发值。
- 取消操作先写入 cancel_requested，Worker 在输入项和分页之间检查取消状态，避免直接破坏现有 Worker 进程。

## 4. API 接口规划

统一前缀：/api/icp。所有接口必须使用 ARL 现有 Token 认证。

### 4.1 元信息和单次查询

~~~text
GET  /api/icp/meta
POST /api/icp/query
GET  /api/icp/query/<job_id>
GET  /api/icp/query/<job_id>/results
~~~

单次查询请求至少包含：

~~~json
{
  "type": "web",
  "keyword": "example.com",
  "page": 1,
  "page_size": 26
}
~~~

支持的查询类型固定为：

~~~text
web, app, mapp, kapp,
bweb, bapp, bmapp, bkapp
~~~

其中 bweb、bapp、bmapp、bkapp 表示对应违规查询类型。服务端必须执行类型白名单、关键词长度、空值、控制字符和分页参数校验。

### 4.2 批量查询

~~~text
POST   /api/icp/batch
GET    /api/icp/batch
GET    /api/icp/batch/<task_id>
POST   /api/icp/batch/<task_id>/cancel
DELETE /api/icp/batch/<task_id>
~~~

批量任务每次只使用一种 ICP 查询类型，输入为关键词数组。服务端默认：

- 单批最多 200 条。
- 自动去除空行和重复项。
- 每条输入保留原始顺序。
- 每条输入独立记录成功、空结果、失败和取消状态。
- 全部成功或空结果时为 succeeded。
- 同时存在成功和失败时为 partial。
- 全部失败时为 failed。
- 用户取消后为 cancelled。

### 4.3 查询历史

~~~text
GET    /api/icp/history
GET    /api/icp/history/<history_id>
DELETE /api/icp/history/<history_id>
POST   /api/icp/history/clear
~~~

历史记录支持按类型、关键词、状态、时间和分页查询。单次查询和批量任务中的每条逻辑查询都可以形成历史记录，批量任务通过关联 ID 追踪来源。

### 4.4 日志、导出和关于

~~~text
GET  /api/icp/logs
POST /api/icp/logs/clear

GET /api/icp/export
GET /api/icp/about
~~~

导出接口支持：

~~~text
format=json
format=xlsx
~~~

导出内容必须沿用 ARL 的鉴权和下载处理，不直接返回上游原始响应、验证码数据或代理信息。

## 5. 数据模型规划

使用现有 Mongo 数据库新增独立集合：

### 5.1 icp_query_task

保存单次查询和批量任务的生命周期信息：

~~~text
task_id
task_kind: single | batch
celery_id
dispatch_queue
dispatch_ts
recovery_at
query_type
status
total
queued_count
running_count
succeeded_count
empty_count
failed_count
cancelled_count
cancel_requested
created_at
started_at
finished_at
error_summary
expires_at
~~~

### 5.2 icp_query_history

保存每次逻辑查询的元信息：

~~~text
history_id
task_id
batch_item_id
query_type
keyword
status
result_count
page_count
created_at
finished_at
error_category
error_message
expires_at
~~~

### 5.3 icp_query_result

按查询记录保存标准化结果，字段至少包括：

~~~text
history_id
page
order
record_type
company_name
domain
service_name
license_number
record_status
website
province
city
update_time
extra
expires_at
~~~

不同业务类型无法统一的非敏感字段放入 extra，不得因为字段差异丢弃上游有效结果。

### 5.4 icp_query_log

保存 ICP 专用运行日志：

~~~text
level
event
task_id
history_id
message
created_at
expires_at
~~~

日志只保存脱敏后的错误和状态摘要，不保存 Token、代理认证信息、验证码图片、完整请求 URL 或敏感响应内容。

### 5.5 索引和保留策略

- icp_query_task.task_id 唯一索引。
- icp_query_task.status + created_at 联合索引。
- icp_query_history.query_type + created_at 联合索引。
- icp_query_result.history_id + page + order 联合索引。
- 所有集合使用 expires_at TTL 索引。
- 历史和结果默认保留 30 天，日志默认保留 7 天。

## 6. 配置和安全边界

不新增 ICP 配置管理页面。配置优先级为：

~~~text
环境变量 > ARL 运行配置 > 安全默认值
~~~

初始配置项：

~~~text
ARL_ICP_QUERY_ENABLE=true
ARL_ICP_QUERY_TLS_VERIFY=true
ARL_ICP_QUERY_TIMEOUT_SEC=30
ARL_ICP_QUERY_RETRY=2
ARL_ICP_QUERY_BATCH_CONCURRENCY=2
ARL_ICP_QUERY_PAGE_SIZE=26
ARL_ICP_QUERY_MAX_ITEMS=200
ARL_ICP_QUERY_MAX_PAGES=100
ARL_ICP_QUERY_KEYWORD_MAX_LENGTH=255
ARL_ICP_QUERY_HISTORY_RETENTION_DAYS=30
ARL_ICP_QUERY_LOG_RETENTION_DAYS=7
~~~

ICP 请求支持独立出口策略，配置位于现有 `PROXY.ICP` 节点，只有 ICP Worker 会读取：

~~~yaml
PROXY:
  ICP:
    TUNNEL:
      URL: ""
    EXTRA_API:
      URL: ""
      REFRESH_SEC: 180
      POOL_SIZE: 20
      CHECK: true
      CHECK_TIMEOUT_SEC: 5
      CHECK_CONCURRENCY: 4
    IPV6_ENABLE: false
    IPV6_REFRESH_SEC: 60
~~~

其中 `TUNNEL.URL` 是固定隧道地址；`EXTRA_API.URL` 由部署方提供代理列表接口，Worker 拉取换行分隔的 `host:port`、检测可用性后随机选择；未配置或池为空时回退到固定隧道，再回退到既有 `PROXY.HTTP_URL`。IPv6 开启后仅从本机 `ip -6 addr show` 输出中提取 `scope global` 地址，并按请求轮换；没有可用地址时保持普通连接回退。客户端不能提交或覆盖这些代理配置。

网络和代理配置不允许客户端自定义任意代理地址。请求目标必须限制在 ICP 官方接口白名单内，代理列表仅来自部署方配置的外部接口，不能将该模块变成任意 URL 代理。

上游实现存在全局关闭 SSL 校验的行为，[上游核心代码](https://raw.githubusercontent.com/HG-ha/ICP_Query/main/src/python/ymicp.py)中相关逻辑不得直接引入 ARL。ARL 默认必须保持证书校验，不能通过全局 monkey patch 修改进程级 SSL 行为。
当前实现将 TLS 校验开关限制在 ICP Session：`ARL_ICP_QUERY_TLS_VERIFY=false` 只影响 ICP 请求，适用于用户明确接受风险的受控测试网络，不影响 ARL 其它扫描请求。

验证码、网络连接、IPv6 和官方接口临时失败必须采用有限超时和有限重试，并将错误分类为：

- 参数错误
- 验证码失败
- 网络超时
- 上游拒绝或限流
- 上游响应格式异常
- 系统内部错误

## 7. 前端 UI 规划

### 7.1 侧边栏

新增 icp_query 入口，顺序固定为：

~~~text
资产搜索
ICP 查询
资产监控
~~~

使用 Lucide 图标，与现有侧边栏字号、间距、选中背景和主题语义色保持一致。不得引入新的 UI 框架或独立样式体系。

### 7.2 ICP 查询页面

新增自定义页面 IcpQueryView，通过现有路由级懒加载接入 App.tsx，不套用普通资产表格模块。

顶部标签页包括：

1. 查询
   - 查询类型选择。
   - 关键词输入。
   - 查询提交和任务状态。
   - 结果数量、分页和详情展开。

2. 批量查询
   - 多行关键词输入。
   - 去重后的数量预览。
   - 批量任务提交。
   - 进度统计、失败详情、取消和导出。

3. 查询历史
   - 类型、关键词、状态和时间筛选。
   - 历史详情查看。
   - 单条删除、清空和 JSON/Excel 导出。

4. 批量任务
   - 任务状态筛选。
   - 任务进度和输入项统计。
   - 任务详情、结果查看、取消、删除和导出。

5. 系统日志
   - 日志级别和时间筛选。
   - 自动刷新。
   - 脱敏错误展示。
   - 清空日志。

6. 关于
   - ICP 查询功能说明。
   - ARL 集成版本。
   - 上游来源链接。
   - 当前不自动写回 ARL 资产库的说明。

页面必须复用 ARL 当前主题变量、卡片、按钮、输入框、表格、弹窗和分页组件，覆盖浅色和深色主题，并处理窄屏下的标签页横向滚动和结果表横向滚动。

## 8. 容器和依赖评估

继续使用现有 arl:local 镜像：

- 不新增 icp 容器。
- 不新增 compose service。
- 不开放 16181 端口。
- Web、Worker、scheduler 继续使用同一套代码和运行时。
- 不复制上游 templates、static、独立启动脚本、MCP 服务和上游 Web 页面。
- 只加入查询引擎实际需要且兼容当前 Python 运行时及 x86/arm64 构建的依赖。
- 优先复用 ARL 已有 HTTP、缓存、日志和配置能力。
- 确需新增时，仅评估异步 HTTP、验证码图像处理等最小依赖，不引入与 ARL 页面无关的 aiohttp-jinja2、mcp 等组件。

当前双架构生产构建以 `build.sh` 调用的 `ARL/docker/Dockerfile` 为准，该路径统一编译 Python 3.10 并按 `TARGETARCH` 选择架构依赖；历史遗留的 `ARL/docker/ARMWorker/Dockerfile` 已在归档计划中明确不纳入当前发布验收，不作为本计划依赖兼容性的判断基准。

## 9. 测试和验收标准

### 9.1 后端

- 8 种查询类型能够正确校验和映射。
- 空输入、超长输入、非法类型和重复批量输入被正确处理。
- 正常结果、空结果、分页结果和异常响应均能标准化。
- 超时、验证码失败、临时网络错误不会无限重试。
- 单次和批量任务状态、进度、取消、部分失败和 Worker 重启恢复正确。
- Mongo 结果拆分、索引、TTL 和分页查询正确。
- 日志中不出现 Token、代理凭据、验证码和完整敏感请求信息。
- 所有接口均受 ARL Token 认证保护。

### 9.2 前端

- 侧边栏位置、选中状态和页面持久化正确。
- 六个标签页均可访问，配置管理不出现在 ICP 页面。
- 单次查询轮询、分页、错误和空状态正确。
- 批量任务提交、进度、取消、部分失败和详情正确。
- 历史、日志、清空和 JSON/Excel 导出操作正确。
- 浅色、深色、窄屏和长文本场景下无裁切、溢出或不可见文字。
- TypeScript、Vitest、生产构建和静态资源冒烟测试通过。

### 9.3 容器

- docker compose config 确认没有新增服务。
- Web、两个 Worker 和 scheduler 使用同一镜像成功启动。
- arlweb consumer 正常注册。
- 没有新增 ICP 独立监听端口。
- 设置 ARL_ICP_QUERY_ENABLE=false 后，入口和 API 均被受控关闭。

真实官方接口验证不作为本计划的代码完成前置条件，后续由用户在测试环境单独验证验证码、网络出口、接口限流和真实返回字段。

## 10. 实施阶段

1. [x] 完成上游功能、协议、依赖和许可证边界确认，建立脱敏响应样例。
2. [x] 完成查询类型、结果标准化、重试和安全边界设计。
3. [x] 完成 Mongo Repository、Celery 任务模型和 Flask API。
4. [x] 完成 IcpQueryView、侧边栏入口和六个顶部标签页。
5. [x] 完成依赖构建、compose 服务展开检查和自动化测试。
6. [x] 完成 Worker 启动恢复、消息投递元数据和批量子项断点恢复。
7. [ ] 由用户进行真实 ICP 查询验证，根据真实返回结构补充字段兼容和异常处理。

### 10.1 开发收口记录

- 既有后端定向回归记录：67 项（66 项通过，1 项因本机未安装 Pillow/numpy 跳过），包含批量分页取消检查、验证码定位、查询类型归一化、关键词类型校验、非映射响应归一化、上游限流重试、Mongo 内部字段过滤、Celery 恢复和配置模板一致性回归样例。
- API 路由隔离测试：4 项通过，覆盖资源方法认证、单次/批量任务边界、总开关状态和内部异常统一响应。
- 历史既有 Celery 恢复回归测试：16 项通过，包含 ICP 任务执行前配置热刷新检查；本轮新增恢复场景统一计入下方 18 项回归。
- 本轮收口回归：ICP 相关测试 41 项（40 项通过，1 项因本机未安装 Pillow/numpy 跳过）；Celery 恢复测试 18 项全部通过，覆盖八类查询映射、有限重试、批量去重/上限与入口调度、分页合并、TTL/索引、TLS 校验/禁止重定向、API 读取边界过滤、JSON 导出和 JSON 异常文本二次脱敏、孤儿 ICP 任务重投成功和投递失败场景。
- 持久化与生命周期清理已覆盖任务删除时的孤儿历史回收、清空历史时的全量结果删除和任务子项关联重置、partial/cancelled 状态统计、成功子项历史关联、取消前置检查；导出边界增加结果文档二次脱敏；新增独立脱敏响应 fixture，覆盖网站、应用详情和违规域名响应形态。
- 前端 `npm run lint`：通过。
- 前端 Vitest：22 个测试文件、136 项通过（含 ICP 页面、侧边栏顺序、总开关关闭态和接口错误态测试）。
- 前端 `npm run build`：通过，生成 ICP 懒加载资源。
- Python ICP 模块 AST 校验：通过。
- 结果表支持行级详情展开，日志页支持级别和日期范围筛选。
- ICP 配置同时支持启动加载、环境变量和运行时热刷新，重试次数允许配置为 0。
- ICP 出口层已接入固定隧道、部署方代理 API 拉取/存活检测/随机选择，以及本机 `scope global` IPv6 按请求轮换；上述连接适配器、代理池和 TLS 开关均只存在于 ICP 查询模块，不修改 ARL 全局 SSL 或其它扫描模块网络行为。
- ICP 代理列表只读取部署方提供的外部接口，候选地址经过格式校验和官方站点可用性检测；日志不输出代理 URL、认证信息或代理列表内容。
- Docker 生产配置模板已补齐 ICP 默认项，`sync_runtime_config` 会将其增量同步到挂载的 `config-runtime.yaml`；新增模板一致性回归测试。
- Compose 已向 web、两个 worker 和 scheduler 透传 ICP 环境变量；未设置的变量保持为空并沿用 runtime YAML，避免默认值覆盖运行时开关。
- 配置读取已将空字符串环境变量视为“未设置”，因此 Compose 的可选透传不会把 runtime YAML 的布尔开关误判为 `false`。
- `/api/icp/meta` 返回明确的 `enabled` 状态；总开关关闭时前端进入只读关闭态，查询相关接口仍返回受控拒绝。
- compose 服务展开：保留原有 mongodb、rabbitmq、redis、web、nginx、scheduler、worker_1、worker_2，无独立 ICP 服务或 16181 端口。
- 2026-09-09 测试服务器首次真实单次查询：任务创建、arlweb 投递、Worker 执行、失败状态回写和前端展示均正常；工信部上游返回风控拦截，当前未通过真实数据验收。该结果说明需要在测试环境更换可用出口或配置可访问官方接口的代理后重试，不能据此将 10.7 标记为完成。
- 生产 Dockerfile 静态校验：`docker buildx build --check --file ARL/docker/Dockerfile .` 通过且无 warning。
- arm64 本地生产镜像构建：`docker buildx build --platform linux/arm64 --tag arl-icp-dev:arm64 --load --file ARL/docker/Dockerfile .` 通过；镜像架构为 `linux/arm64`，Dockerfile 内置的 Python、Playwright、Nuclei、Ncrack、WIH、Rust 加速模块和前端产物检查均通过。
- arm64 容器级导入冒烟：`numpy==1.26.4`、`Pillow==10.4.0`、`openpyxl==3.1.5` 以及 `app.routes.icp_query`、`app.services.icp_query` 均成功导入。
- 兼容性修复：`openpyxl==3.0.0` 与 `numpy==1.26.4` 存在 `np.float` 不兼容，已升级到 `openpyxl==3.1.5`，并以内存 `BytesIO` 实现兼容的工作簿导出辅助函数；同时将完整 ICP 路由导入加入生产镜像校验。
- 双架构依赖边界复核：确认当前生产构建入口为统一多架构 Dockerfile；`numpy==1.26.4`、`Pillow==10.4.0` 和 `openpyxl==3.1.5` 按生产 Python 3.10 运行时评估，旧 Python 3.8 ARMWorker 路径不在本轮验收范围。
- 完成性审阅：已复核认证、输入校验、SSRF/日志脱敏、任务取消、Celery 重投、并发上限、分页索引、单次/批量路由边界、API 异常收敛和前端类型边界；已修复运行时配置刷新、批量取消列表刷新、恢复投递失败状态、HTTP 429 限流重试和 500 内部错误回显问题。
- 上游协议复核：再次核对 [上游核心实现](https://raw.githubusercontent.com/HG-ha/ICP_Query/main/src/python/ymicp.py)、[单次查询路由](https://raw.githubusercontent.com/HG-ha/ICP_Query/main/src/python/routes/query_routes.py) 和 [批量任务路由](https://raw.githubusercontent.com/HG-ha/ICP_Query/main/src/python/routes/batch_routes.py)，确认官方域名、接口路径、网站/App/小程序/快应用类型映射、验证码 uuid/sign 和详情查询流程与当前适配一致；未发起真实请求。
- 真实接口、验证码识别准确率、上游限流策略、双架构镜像运行和正式发布仍未在本机执行。
- amd64 部署和运行验证按用户安排由测试环境执行，本机不重复启动 amd64 构建或部署流程。

### 10.2 测试环境验收入口

以下步骤由测试环境执行，本机不代执行 AMD64 构建或部署：

1. 使用现有部署流程启动后，确认 `docker compose ps` 只有原有的 `mongodb`、`rabbitmq`、`redis`、`web`、`nginx`、`scheduler`、`worker_1`、`worker_2` 服务，不存在 ICP 独立容器或 16181 端口。
2. 登录 ARL 后确认侧边栏顺序为“资产搜索 → ICP 查询 → 资产监控”，ICP 页面包含“查询、批量查询、查询历史、批量任务、系统日志、关于”六个标签，不出现配置管理标签。
3. 分别验证 `web`、`app`、`mapp`、`kapp` 及 `bweb`、`bapp`、`bmapp`、`bkapp`；确认单次查询、批量去重、进度、取消、部分失败、历史查看和 JSON/Excel 导出可用。
4. 验证 `ARL_ICP_QUERY_ENABLE=false` 时入口进入关闭态，查询 API 返回受控拒绝；恢复为 `true` 后再验证正常流程。
5. 发生异常时仅采集 ICP Worker、Web 和 RabbitMQ 的时间窗口日志，使用以下方式过滤；粘贴前删除 Cookie、Token、sign、代理认证、验证码内容和完整敏感请求 URL：

   ```bash
   for c in arl_worker_1 arl_worker_2 arl_web arl_rabbitmq; do
     docker logs --since 30m --timestamps --no-color "$c" 2>&1
   done | grep -Ei 'error|exception|traceback|timeout|failed|retry|denied|captcha|rate|icp'
   ```

6. 真实接口、验证码、限流和 AMD64 容器运行均通过后，将第 10 节第 7 项改为 `[x]`，把本文件移动到 `docs/history/`，并在 `docs/plan/README.md` 中删除当前计划条目。

开发代码和本地测试完成后，文档状态更新为 [开发完成]；真实接口、容器运行和发布验收全部闭环后，再移动至 docs/history/。
