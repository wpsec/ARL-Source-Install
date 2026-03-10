<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1771929911927-d85a6718-38c0-48e1-8841-aab9082b1c69.png)

基于 ARL 的互联网资产自动化收集二开版本（挑来挑去，还是灯塔好用些）  
这套平台利用成熟的平台ARL作为基础：支持批量导出、钉钉机器人通知、钉钉知识库结构化写入、计划任务聚合通知与对比统计、前后端稳定性修复，基础设施的升级维护。

> 站在外部的角度，如果不知道自己拥有什么，就无法保护什么
>
> 帮助团队收集暴露的资产，一是让团队有哪些资产暴露在互联网上，避免因不小心的配置错误或者其它原因造成暴露在互联网上的遗留、边缘资产问题，二是尽可能避免项目代码不小心被推送到github上，出现泄漏问题。利用主流三方API做网络空间搜索引擎和传统的域名爆破、前端暴露的url拼接、端口扫描、host碰撞等方法进行资产信息的收集，自动化定时执行推送到知识库、群机器人。

---

# 这是ARL原生版本，新版请移步分支newUI

https://github.com/wpsec/ARL-Source-Install/tree/newUI



## 1. 项目简介

ARL-Source-Install 用于互联网资产自动化收集与持续监控，支持：

- 资产扫描（域名/IP/站点/端口/URL/漏洞等）
- 计划任务（周期执行、聚合通知）
- GitHub 监控（关键词泄露监控）
- 批量导出（任务多选合并导出）
- 钉钉通知（群机器人）
- 钉钉知识库报告（WORKBOOK 工作表）
- 指纹管理+Nuclei 联动扫描（新增 500+指纹联动 Nuclei 针对性 poc 扫描）

该仓库默认采用 Docker 方式部署。

---

## 2. 二开功能总览

### 2.1 批量表格导出

- 功能：任务多选后一次性导出 `xlsx`
- 特性：与单任务导出结构保持一致，支持合并与去重
- 输出工作表：`站点`、`IP`、`系统服务`、`域名`、`资产统计`

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1771928255293-e8c0e961-193f-469c-ae47-2596bded18f2.png)

### 2.2 钉钉通知体系

- 保留原群机器人通知能力（Webhook）
- 新增钉钉开放平台知识库写入（WORKBOOK）
- 支持按任务类型开关：普通任务 / 计划任务 / GitHub 监控
- GitHub 监控机器人消息已优化为摘要，并可附知识库报告链接

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1771928799983-f2935527-2685-459f-91a0-c858ecb3eb8b.png)

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1771929322579-66f3d50a-fb9e-4974-870d-6ccbf0b67ba7.png)

### 2.3 计划任务通知增强

- 通知聚合后发送，避免多目标触发重复刷屏
- 支持知识库报告链接回传
- 增加与上次执行结果的对比统计

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1771926597402-de72ed7e-631d-46ba-9a19-18a6d99520bf.png)

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1771929284237-725a1633-0890-48bc-9ebd-629080a1368e.png)

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1771928088655-9cb7123e-2531-4366-bad1-4a0c08455692.png)

### 2.4 稳定性与一致性修复

- 批量停止计划任务改为幂等处理（已停止项跳过，不阻断整体）
- 钉钉工作表写入增强（字符串规范化、失败诊断信息）
- 列表缓存一致性优化（新增/删除后延迟显示问题已修复）
- 监控任务重建域名数据时保留真实来源（如 `fofa`、`hunter_qax`、`quake_360`、`virustotal`）

### 2.5 容器安全基线优化

- 仅 `arl_nginx` 对外暴露端口
- `web/worker/scheduler/mongodb/redis/rabbitmq` 走容器内通信

### 2.6 基础设施版本升级

当前核心基础设施镜像如下（已纳入二开维护范围）：

- `redis:7-alpine`
- `rabbitmq:3.13-management-alpine`
- `mongo:7.0`
- `rockylinux:8`（`arl:local` 基础镜像）
- `nginx:1.24-alpine`

版本清单：

| 组件         | 当前版本                          | 说明                                          |
| ------------ | --------------------------------- | --------------------------------------------- |
| 基础系统镜像 | `rockylinux:8`                    | ARL 主应用镜像基座（`ARL/docker/Dockerfile`） |
| MongoDB      | `mongo:7.0`                       | 资产数据存储                                  |
| RabbitMQ     | `rabbitmq:3.13-management-alpine` | Celery 消息队列                               |
| Redis        | `redis:7-alpine`                  | 业务缓存与性能优化                            |
| nginx        | `nginx:1.24-alpine`               | basic 和服务暴露                              |

### 2.7 钉钉集成功能

集成钉钉开发者平台 api，方便调试

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1771928900888-61aea190-6f28-4f59-9b9d-93f24b1b70e0.png)

### 2.8 指纹管理与 nuclei 调用联动

新增指纹 558 条，通过指纹调用 nuclei，而非无脑批量扫描，提高扫描效率，降低攻击行为

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1772260771323-e7df082b-8f37-4e7f-b723-6180d45d7906.png)

### 2.9 nuclei 定向扫描与模板库管控

- 恢复「任务管理 -> 添加任务」中的 `nuclei` 扫描选项
- nuclei 扫描支持读取站点指纹，并按指纹映射到 tags 后分批扫描
- 可配置兜底策略：指纹未命中时使用默认 tags 或自动扫描（`-as`）
- 模板目录默认指向项目内 `tools/nuclei-templates`，避免运行时自动拉取远程模板库

### 2.10 部署初始化自动导入指纹库

- Docker 部署启动时会检查 `/code/tools/finger.json`
- 文件存在时自动执行导入脚本，写入 `fingerprint` 集合并刷新缓存
- 导入逻辑为可重复执行，适合镜像重建和容器重启场景

### 2.11 截图回传模式（worker -> web）

- 新增截图内部回传链路：worker 截图成功后可主动上传到 web 内部接口
- 解决 K8s 场景下 `web/worker` 本地目录不共享导致的截图全部失败问题
- 安全控制包含：复用系统 `Token` 鉴权、`task_id` 格式校验、文件名白名单、文件大小限制、图片魔数校验
- 默认开启且可自动降级，不影响非 K8s 或共享目录部署场景

### 2.12 指纹与规则库增强

- 优化 `ARL/app/dicts/webapp.json`：补充现代组件指纹（如 MinIO、Nacos、Harbor、Portainer、Argo CD、RabbitMQ Management、Nexus 等）
- 收紧部分弱特征规则（如 `jquery`、`vue`、`WebLogic`、`KindEditor`）以降低误报
- 优化 `ARL/app/dicts/wih_rules.yml`：新增多类高价值敏感信息规则（OpenAI/Anthropic/SendGrid/Stripe/数据库连接串等）
- 增加 WIH 排除规则（示例值、占位符、Swagger/OpenAPI 示例 token）减少噪声
- 修正 `ARL/app/dicts/cdn_info.json` 冲突与覆盖项（如 `dwion.com` 归属、`dnsv1.com` 覆盖）

---

## 3. 系统架构

```latex
Browser
  -> arl_nginx (80, Basic Auth)
    -> arl_web (Flask + Gunicorn)
      -> MongoDB / Redis / RabbitMQ
      -> arl_worker (Celery)
      -> arl_scheduler (周期调度)
```

容器编排文件：`ARL/docker/docker-compose.yml`

默认服务名：

- `arl_nginx`
- `arl_web`
- `arl_worker`
- `arl_scheduler`
- `arl_mongodb`
- `arl_redis`
- `arl_rabbitmq`

---

## 4. 快速开始

### 4.1 前置条件

- Docker
- Docker Compose
- 可用内存建议 >= 2GB
- 可用磁盘建议 >= 8GB

钉钉自动化推送

通过钉钉开发者平台，需要提前获取以下信息，以配置钉钉自动化推送（因为我只用得到钉钉，所以用飞书的各位大佬可以自行完善）

参考：

[https://open.dingtalk.com/](https://open.dingtalk.com/)

[https://open.dingtalk.com/document/development/get-knowledge-base-list](https://open.dingtalk.com/document/development/get-knowledge-base-list)

[https://open.dingtalk.com/document/api/explore/explorer-page?api=wiki_2.0%23ListWorkspaces&devType=org](https://open.dingtalk.com/document/api/explore/explorer-page?api=wiki_2.0%23ListWorkspaces&devType=org)

新建应用

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1771926828978-1bb612e4-b903-4ef4-9e24-1e4c74f8c794.png)

应用凭证后面会用到

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1771926856658-23022d41-6b44-43a3-9c45-aae8add80fdf.png)

在应用中创建机器人

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1771927318881-d81da6e1-eeb3-430c-9560-be3e8c1de1bb.png)

至少需要以下权限以保证资产收集的报告可以正常写入

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1771927394442-b72f85d0-af75-42ea-abdf-7013e456aa82.png)

操作者的unionId 自行在钉钉开发者平台上去调试获取

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1771927566292-215eae01-b0ea-4bf0-ae91-3b9455fa1a96.png)

也可以在系统跑起来后配置调试

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1771928926002-7ddcc5d0-7e89-4419-bb96-49d6e51d3002.png)

知识库空间 id 需要创建后获取，也是在钉钉开发者平台

获取并调试好权限后配置到这里，重启应用～

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1771927115516-a0827ff4-76d0-4280-af46-585153752536.png)

自行补充网络空间搜索引擎 APIkey，并开启

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1771927044180-9ed803a5-d242-47c9-a66e-d87b50175945.png)

github 监控

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1771927712491-e03e3203-9ae0-44b7-b042-e90d6ecae53d.png)

配置域名服务器地址

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1771927735789-dcb7fefc-6f98-46bb-98d3-03a7be539d9e.png)

机器人配置

钉钉群-机器人-添加机器人（需要在钉钉开发者平台发布的应用才又机器人）

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1771929462558-4a394e35-1eff-4b43-8db0-a65257d4096d.png)

添加后记得完善 access-token

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1771929419879-8ef7ef17-800a-45a7-9037-f49a081d3b2e.png)

### 4.2 一键构建与启动

在项目根目录执行：

```bash
chmod +x build.sh start.sh scripts/quick-build.sh
./build.sh
./start.sh
```

`start.sh` 会自动检查并创建 `arl_db` volume（不存在时）。

### 4.3 访问方式

- 访问地址：`http://<服务器IP>`
- Basic Auth：
  - 用户名：`admin`
  - 密码：`admin123456`
- ARL 应用默认账号：
  - 用户名：`admin`
  - 密码：`arlpass`

---

## 5. 日常升级与重建

### 5.1 常规更新

```bash
git pull
./scripts/quick-build.sh quick
```

### 5.2 常用构建命令

```bash
./scripts/quick-build.sh           # 默认 quick
./scripts/quick-build.sh full      # 完整构建
./scripts/quick-build.sh clean     # 清缓存重建
./scripts/quick-build.sh frontend  # 仅更新前端静态资源
```

### 5.3 查看日志

```bash
cd ARL/docker
docker compose logs -f web
docker compose logs -f worker
docker compose logs -f scheduler
```

---

## 6. 核心配置说明

主配置文件：`ARL/docker/config-docker.yaml`

可参考模板：`ARL/app/config.yaml.example`

### 6.1 Redis（业务缓存）

```yaml
REDIS:
  ENABLE: true
  HOST: "redis"
  PORT: 6379
  DB: 0
  PASSWORD: ""
  CACHE_EXPIRE: 1800
```

### 6.2 钉钉机器人（群通知）

```yaml
DINGDING:
  ACCESS_TOKEN: ""
  SECRET: ""
```

说明：

- 仅 Access Token 也可工作（不加签机器人、适配钉钉应用不加签格式）
- 若机器人开启签名校验，需同时配置 `SECRET`

### 6.3 钉钉知识库（开放平台）

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

### 6.4 K8s / 环境部署

`config.py` 已支持钉钉配置通过环境变量覆盖，在k8s环境中用 Secret 注入敏感项，例如：

- `ARL_DINGTALK_APP_KEY`
- `ARL_DINGTALK_APP_SECRET`
- `ARL_DINGTALK_WORKSPACE_ID`
- `ARL_DINGTALK_PARENT_NODE_ID`

### 6.5 三方域名插件采集

修复了三方api不调用问题

### 6.6 新增公网 DNS 解析器（内网环境部署问题解决）

在集群环境中建议显式配置公网 DNS 解析器，避免优先使用内网 DNS 导致资产混入：

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

---

## 7. 钉钉推送链路

### 7.1 机器人通知

- 任务结束后按开关触发
- 推送摘要 Markdown
- 计划任务支持聚合后推送
- GitHub 监控支持附加知识库报告链接

### 7.2 知识库写入

- 创建 WORKBOOK 文档
- 写入执行概览和资产明细工作表
- 常见工作表：`执行概览`、`域名`、`IP`、`系统服务`、`站点`、`资产统计`
- 计划任务报告可包含与上次执行的对比统计

### 7.3 联调接口

后端提供钉钉 API 调试接口：

- `ARL/app/routes/dingtalk_api.py`
- `/api/dingtalk_api/config/`
- `/api/dingtalk_api/test/`
- `/api/dingtalk_api/workspaces/`
- `/api/dingtalk_api/nodes/`
- `/api/dingtalk_api/create_workbook/`
- `/api/dingtalk_api/sheets/`
- `/api/dingtalk_api/write_markdown/`

---

## 8. 前端功能入口

- 任务批量导出：`任务管理 -> 批量导出 -> 表格批量导出`
- 添加任务：支持钉钉通知开关
- 添加计划任务：支持钉钉通知/知识库推送相关开关
- GitHub 监控：支持钉钉通知与知识库推送开关
- 钉钉 API 配置：提供运行时配置与联调能力

---

## 9. 常见问题排查

### 9.1 知识库写入失败：`dingtalk kb config incomplete or disabled`

排查：

1. `DINGTALK_API.ENABLE` 是否为 `true`
2. 必填字段是否完整
3. `OPERATOR_ID` 是否有目标知识库权限

### 9.2 知识库写表失败：`MissingString`

当前版本已做字符串规范化。若仍出现，优先检查：

- 是否部署了最新镜像
- 是否有自定义改动绕过了写入规范化流程

### 9.3 计划任务批量停止报错

当前版本为幂等逻辑：已停止任务会跳过，不应影响其他任务停止。

### 9.4 日志查询建议

```bash
cd ARL/docker
docker compose logs --since 30m scheduler | grep -E "kb push|notify|task schedule"
docker compose logs --since 30m worker | grep -E "dingtalk|write workbook|sheet_write_result"
```

说明：部分系统没有 `rg`，请用 `grep`。

---

## 10. 项目目录

```latex
ARL-Source-Install/
├── ARL/
│   ├── app/
│   │   ├── routes/                  # API 路由
│   │   ├── services/                # 业务服务
│   │   ├── helpers/                 # 通知、调度辅助
│   │   ├── tasks/                   # 异步任务（含 github 监控）
│   │   ├── utils/                   # 通用工具（含钉钉 OpenAPI）
│   │   └── config.py
│   └── docker/
│       ├── docker-compose.yml
│       ├── config-docker.yaml
│       ├── Dockerfile
│       ├── frontend/                # 已编译前端
│       └── nginx-reverse-proxy/
├── ARL-NPoC/
├── docs/
│   ├── 开发规范.md
│   └── 钉钉推送功能开发与修改日志.md
├── scripts/
│   └── quick-build.sh
├── build.sh
├── start.sh
└── README.md
```

---

欢迎关注公众号，不定期更新～

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/jpeg/27875807/1771929928377-73947b1a-b47e-45da-b30d-a74da57a76fd.jpeg)
