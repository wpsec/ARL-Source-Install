<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1771929911927-d85a6718-38c0-48e1-8841-aab9082b1c69.png)

基于 ARL 的互联网资产自动化收集二开版本（挑来挑去，还是灯塔好用些）  
这套平台利用成熟的平台ARL作为基础：支持批量导出、钉钉机器人通知、钉钉知识库结构化写入、计划任务聚合通知与对比统计、前后端稳定性修复，基础设施的升级维护。

> 站在外部的角度，如果不知道自己拥有什么，就无法保护什么
>
> 帮助团队收集暴露的资产，一是让团队有哪些资产暴露在互联网上，避免因不小心的配置错误或者其它原因造成暴露在互联网上的遗留、边缘资产问题，二是尽可能避免项目代码不小心被推送到github上，出现泄漏问题。利用主流三方API做网络空间搜索引擎和传统的域名爆破、前端暴露的url拼接、端口扫描、host碰撞等方法进行资产信息的收集，自动化定时执行推送到知识库、群机器人。

---

## 快速开始

### 前置条件

- Docker
- Docker Compose
- 可用内存建议 >= 2GB
- 可用磁盘建议 >= 8GB

```plain
# 新版UI及调整优化 newUI分支
git clone -b newUI https://github.com/wpsec/ARL-Source-Install.git
cd ARL-Source-Install
cp .env.example .env
# 请修改密码～
chmod +x build.sh start.sh scripts/quick-build.sh
./build.sh
./start.sh
```

可提前开代理下载Playwright 以提升部署速度

参考：

```plain
tools/playwright/README.md
```

只在 x86 环境做了测试，arm 没有做测试，不知道兼不兼容

密码修改配置

忘记系统账户密码

密码重置为 admin123

```plain
./resetpass.sh
```

### 访问方式

- 访问地址：`http://<服务器IP>`
- Basic Auth：
  - 用户名：`.env` 中 `BASIC_AUTH_USERNAME`（默认 `admin`）
  - 密码：`.env` 中 `BASIC_AUTH_PASSWORD`（默认 `admin123456`）
- ARL 应用默认账号：
  - 用户名：`.env` 中 `ARL_APP_USERNAME`（默认 `admin`）
  - 密码：`.env` 中 `ARL_APP_PASSWORD`（默认 `arlpass`）
  - 说明：仅在 Mongo 数据卷首次初始化时生效。若已存在 `arl_db`，需清理数据卷后重新初始化。

## 二开功能总览

UI 重构与优化调整

- 全新 UI 风格
- 系统监控页面
- ......

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1773050416633-e5db0816-848a-43ea-be14-c134f221fb1b.png)

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1773050540924-54f05c58-88c5-47e4-b57f-070b9c1057ed.png)

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1773050429917-468fcaea-327f-48e3-ba11-a7f44a526632.png)

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1773050448413-2fa1b510-5254-4a8f-8be6-456dace3c72c.png)

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1773050462124-fb2710fe-4955-41b2-853e-84d8eeb1a7ce.png)

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1773050469136-16e89e60-4099-4a6f-8b9b-9ebc8da7d9c1.png)

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1773112033563-a2b26876-d19e-4a6b-90c9-cdc574be7c7b.png)

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1773112217332-c2a54d0a-906d-410e-9ca0-98d6844f2876.png)

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1773112617478-94083134-f952-4008-aa87-7a35249a9c5f.png)

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1773112630389-e71fdb5e-39c8-4d31-aced-84ee763d5d01.png)

### 批量表格导出

- 功能：任务多选后一次性导出 `xlsx`
- 特性：与单任务导出结构保持一致，支持合并与去重

### 钉钉通知体系

- 保留原群机器人通知能力（Webhook）
- 新增钉钉开放平台知识库写入（WORKBOOK）
- 支持按任务类型开关：普通任务 / 计划任务 / GitHub 监控
- GitHub 监控机器人消息已优化为摘要，并可附知识库报告链接

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1771926597402-de72ed7e-631d-46ba-9a19-18a6d99520bf.png)

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1771929284237-725a1633-0890-48bc-9ebd-629080a1368e.png)

### 指纹与规则库增强

- 优化 `ARL/app/dicts/webapp.json`：补充现代组件指纹（如 MinIO、Nacos、Harbor、Portainer、Argo CD、RabbitMQ Management、Nexus 等）
- 收紧部分弱特征规则（如 `jquery`、`vue`、`WebLogic`、`KindEditor`）以降低误报
- 优化 `ARL/app/dicts/wih_rules.yml`：新增多类高价值敏感信息规则（OpenAI/Anthropic/SendGrid/Stripe/数据库连接串等）
- 增加 WIH 排除规则（示例值、占位符、Swagger/OpenAPI 示例 token）减少噪声
- 修正 `ARL/app/dicts/cdn_info.json` 冲突与覆盖项（如 `dwion.com` 归属、`dnsv1.com` 覆盖）

### 基础设施版本升级

| 组件         | 当前版本                          | 说明                                          |
| ------------ | --------------------------------- | --------------------------------------------- |
| 基础系统镜像 | `rockylinux:8`                    | ARL 主应用镜像基座（`ARL/docker/Dockerfile`） |
| MongoDB      | `mongo:7.0`                       | 资产数据存储                                  |
| RabbitMQ     | `rabbitmq:3.13-management-alpine` | Celery 消息队列                               |
| Redis        | `redis:7-alpine`                  | 业务缓存与性能优化                            |
| nginx        | `nginx:1.24-alpine`               | basic 和服务暴露                              |

### 其它

其它 bug 修复

## 日常升级与重建

### 常规更新

```bash
git pull
./scripts/quick-build.sh quick
```

### 常用构建命令

```bash
./scripts/quick-build.sh           # 默认 quick
./scripts/quick-build.sh full      # 完整构建
./scripts/quick-build.sh clean     # 清缓存重建
./scripts/quick-build.sh frontend  # 仅更新前端静态资源
```

### 查看日志

```bash
cd ARL/docker
docker compose logs -f web
docker compose logs -f worker
docker compose logs -f scheduler
```

---

## 配置说明

```plain
ARL/docker/config-docker.yaml
```

### 钉钉机器人（群通知）

```yaml
DINGDING:
  ACCESS_TOKEN: ""
  SECRET: ""
```

说明：

- 仅 Access Token 也可工作（不加签机器人、适配钉钉应用不加签格式）
- 若机器人开启签名校验，需同时配置 `SECRET`

### 钉钉知识库（开放平台）

请参考：

```plain
https://open.dingtalk.com/
https://open.dingtalk.com/document/development/get-knowledge-base-list
https://open.dingtalk.com/document/api/explore/explorer-page?api=wiki_2.0%23ListWorkspaces&devType=org
```

如果不需要钉钉报告推送，可不配置

```yaml
DINGTALK_API:
  ENABLE: false
  BASE_URL: "https://api.dingtalk.com"
  CORP_ID: ""
  APP_KEY: ""
  APP_SECRET: ""
  OPERATOR_ID: ""
  WORKSPACE_ID: ""
  PARENT_NODE_ID: ""
  CREATE_NODE_PATH: "/v1.0/doc/workspaces/{workspace_id}/docs"
  KB_TIMEOUT: 20
  TITLE_PREFIX: "互联网资产自动化收集"
  DRY_RUN: false
  REPORT_BASE_URL: ""
```

当 `ENABLE=true` 时，以下字段必填：

- `CORP_ID`
- `APP_KEY`
- `APP_SECRET`
- `OPERATOR_ID`
- `WORKSPACE_ID`
- `PARENT_NODE_ID`

### 三方域名插件采集

修复了三方api不调用问题

### 公网 DNS 解析器（内网环境部署扫描到内网域名服务器问题）

在环境中建议显式配置公网 DNS 解析器，避免优先使用内网 DNS 导致资产混入：

```yaml
ARL:
  DNS_RESOLVERS:
    - 223.5.5.5
    - 119.29.29.29
    - 114.114.114.114
    - 8.8.8.8
```

说明：

- 为空时使用系统默认 DNS
- 配置后由 `web/worker/scheduler` 进程统一生效
- 建议配合 `BLACK_IPS` 对私网网段做过滤

### 自定义字典持久化（避免容器重建丢失）

自定义字典支持两类目录：

- 代码内置目录：`ARL/app/dicts/domain/`、`ARL/app/dicts/file_leak/`
- 宿主机持久化目录（推荐）：`ARL/docker/dicts/domain/`、`ARL/docker/dicts/file_leak/`

说明：

- `配置管理 -> 扫描配置 -> 域名爆破字典` 会自动枚举 `domain/` 下的 `.txt`
- 页面上传字典将写入 `ARL/docker/dicts/domain/uploaded/`
- `ARL.FILE_LEAK_DICT` 可直接指向 `file_leak/` 下自定义文件
- `任务管理 -> 新建任务` 支持选择“域名爆破字典”；不选则默认使用配置管理字典
- 以上目录通过 `docker-compose` 挂载，容器重建后文件仍保留

## Bug？

添加公众号联系我，如果使用的人多，在考虑修复

<!-- 这是一张图片，ocr 内容为： -->

## 更新日志

建议以 [CHANGELOG.md](./CHANGELOG.md) 为主，`README` 保留最近版本摘要（同日版本合并记录）。

### 2026-03-11（v3.0.10 ~ v3.0.26）

- `[v3.0.26]` 钉钉集成页移除 `DryRun` 配置项；配置区改为更稳健网格布局，修复 `SSL提醒天数` 新增后控件挤压溢出
- `[v3.0.25]` 钉钉“SSL证书扫描通知”升级为“SSL证书过期通知”，支持配置提醒阈值 `DINGTALK_API.SSL_CERT_NOTIFY_DAYS`（默认 `<=30` 天）
- `[v3.0.25]` SSL 告警消息新增生效时间/失效时间/证书有效期字段，且默认过滤内网IP证书告警，域名展示优先任务内真实域名
- `[v3.0.25]` 钉钉知识库报告中 `SSL证书` 工作表移除任务ID列，并新增 `过期证书` 工作表展示已过期证书明细
- `[v3.0.24]` 任务管理、资产分组、策略配置列表“操作”列固定最小宽度，按钮改为不换行，避免被其他列内容挤压导致位置跳动
- `[v3.0.23]` 钉钉调试接口每次请求前同步配置文件到当前进程，降低多 worker 下旧配置导致的随机报错
- `[v3.0.23]` 钉钉 OpenAPI 请求增加瞬时失败重试与鉴权失败自动刷新 token，提升“空间/节点/连通性”稳定性
- `[v3.0.23]` 钉钉集成页错误提示增强：优先展示 `error_message/detail`，避免仅显示“系统异常”
- `[v3.0.21]` 仪表盘“资产分布概览”图表配色优化为青蓝绿橙组合；柱状图新增浅色轨道背景并统一圆角样式
- `[v3.0.20]` 策略配置（新建/编辑）固定 `domain_config.domain_brute=true`；策略表单文案收敛为“默认字典模式”
- `[v3.0.19]` 新建任务隐藏“域名爆破”勾选开关；提交时固定 `domain_brute=true`
- `[v3.0.18]` 任务管理“异常”状态支持点击查看详情弹窗；后端统一记录 `last_error/error_logs`
- `[v3.0.17]` 新建任务端口扫描范围支持 `custom`；前后端增加 `port_custom` 校验
- `[v3.0.16]` 新建任务文案统一为“域名爆破字典”；选择字典后默认模式自动标记不生效
- `[v3.0.15]` 新建任务支持按任务选择域名爆破字典；后端校验字典文件存在；执行时优先使用任务级字典
- `[v3.0.14]` 增加宿主机持久化字典目录与容器挂载；配置管理支持字典自动枚举与旧路径兼容
- `[v3.0.13]` 字典目录规整：域名字典与敏感目录字典分目录归档，并保留兼容映射
- `[v3.0.12]` 删除交互统一为前端确认弹窗；接口返回消息净化；同步前端构建产物
- `[v3.0.10]` SSL证书采集/展示增强；导出和钉钉知识库新增 SSL 工作表；新增证书临期告警推送

![](https://cdn.nlark.com/yuque/0/2026/jpeg/27875807/1771929928377-73947b1a-b47e-45da-b30d-a74da57a76fd.jpeg)
