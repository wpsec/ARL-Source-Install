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
- 可用内存建议 >= 4GB
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

### 注意！

可提前开代理下载Playwright 以提升部署速度，不建议开启nuclei与afrog，确实太慢了且扫不出来啥漏洞。

参考：

```plain
tools/playwright/README.md
```

只在 x86 环境做了测试，arm 没有做测试，不知道兼不兼容

### 密码修改

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
- 支持1-2个 Worker
  - 在 .env 中镜像配置

### 升级

### 常规更新

```bash
# 日常更新
git pull
./scripts/quick-build.sh
```

### 配置说明

```plain
ARL/docker/config-docker.yaml   # 版本模板（随代码更新）
ARL/docker/config-runtime.yaml  # 运行配置（用户实际生效，不进 git）
```

为避免升级后覆盖用户 key 与自定义参数，系统已采用“模板 + 运行配置”分离：

- `config-docker.yaml`：版本模板，可随版本更新新增配置项
- `config-runtime.yaml`：运行时配置，容器实际挂载此文件，UI 配置保存也写入此文件
- `start.sh / restart.sh / scripts/quick-build.sh` 均会在缺失时自动从模板创建 `config-runtime.yaml`

如果系统 UI 不支持某些配置项，可直接编辑 `config-runtime.yaml`

### Worker 横向扩展说明（v4.3.0）

扫描容器服务名统一为 `worker_1`、`worker_2`，支持部署时选择 1 个或 2 个 worker：

```plain
# .env
ARL_WORKER_REPLICAS=1   # 可选: 1 或 2，默认 1
```

- `./start.sh` 与 `./scripts/quick-build.sh` 会自动读取该参数
- `1`：启动 `worker_1`
- `2`：启动 `worker_1 + worker_2`
- 不影响任务重启、停止、重试逻辑（队列与任务状态流转保持不变）
- 不会“按域名固定绑定某个 worker”
- 实际模型是 Celery/RabbitMQ 的“同队列竞争消费”：谁先空闲，谁先拿下一条消息
- 同一条 Celery 消息只会被一个 worker 进程消费，不会被两个 worker 同时执行

任务分配可以这样理解：

1. 创建任务时，系统先决定投递到哪个队列（`arltask`、`arlheavy`、`arlweb`）。
2. 该队列中的消息由可用 worker 抢占消费（1个或2个，取决于部署参数）。
3. 某个任务一旦被某个进程拿到，整个主扫描流程在该进程内完成（不是“阶段1在 worker1、阶段2在 worker2”）。
4. AI 去噪是独立 Celery 任务，按队列再调度；可以由任一可用 worker 执行。

关于“是否会重复扫描同资产”：

- 横向扩容本身不会导致同一条消息重复执行。
- 可能出现“看起来重复”的主要来源：重复创建同目标任务、手动重启任务、异常恢复重投（极端情况下）。
- 为降低恢复抖动，默认仅主 `worker_1` 执行启动恢复（`ARL_WORKER_RECOVER_ON_BOOT=1`），`worker_2` 默认关闭启动恢复（`ARL_WORKER_RECOVER_ON_BOOT=0`）。

建议先用保守并发运行（当前默认 `2/2/2/1`），观察稳定后再升并发。可用以下命令观察 MQ 压力：

```bash
docker exec arl_rabbitmq rabbitmqctl list_queues name messages_ready messages_unacknowledged consumers
```

## 二开功能总览

### 资产发现

- 域名、IP、站点、URL、目录扫描、证书、服务识别、指纹识别
- 多测绘源接入与联动查询
- `WIH -> URL/JS增强 -> API文档解析 -> URLFinder二次敏感扫描 -> TruffleHog` 的 Web 信息收集链路
- 指纹库兼容增强，支持单文件指纹库合成与本地扩展

### Web 专项能力

- 页面情报提取：链接、表单、脚本入口
- API 文档解析：`Swagger / OpenAPI / Postman`
- 渗透测试模块：SQL 注入、XSS、LFI、RCE、XXE、SSTI、SSRF 等主动测试
- DOM XSS 轻量静态分析与 JS 参数提取
- WAF 观测、命中证据、有限试探绕过与失败后跳过
- 云安全只读检测：凭证泄露、存储桶遍历、可接管、ACL / Policy 泄露

### 平台化增强

- 同名任务查看、批量任务操作、任务同步
- 计划任务、钉钉机器人通知、钉钉知识库结构化写入
- `Excel / HTML / AI Markdown` 三格式任务报告导出（AI 未完整配置时自动降级为离线模板，不报错）
- 配置管理新增 `AI管理`：支持多模型配置、上方生效模型切换、OpenAI 兼容接口、提示词管理与总测试按钮
- 配置热刷新、扫描日志聚合、系统监控、任务可观测性增强
- Celery / RabbitMQ 稳态增强与重任务队列隔离

### AI 降噪与 AI + MCP 渗透

- 根据扫描得到的资产信息进行 AI 降噪与 AI 渗透测试
- 其它。。。

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1773228172922-d4b58648-0aa2-4371-8381-b3901fbf0bf8.png)

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1773228196339-42bcae2e-63d8-45b8-b304-4f718ed3284b.png)

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1773228219353-51f9bdeb-5bee-44f4-98ed-68d6801f8175.png)

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1773228253396-5cec67df-a2c9-4a7c-9356-a59bd79bd6ac.png)

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1773228385246-41c5f9e2-fd5f-44fe-bb50-48376fd0c29a.png)

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1773228343138-4e70644f-6fcf-4593-b624-92961998900f.png)

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1774513802827-5253f290-e8a3-4dff-8ede-e95f0a959ec6.png)

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1774513825277-58d6c929-3d98-4ff9-bd2c-c4915971969b.png)

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1774513896707-f7db26c1-ccd1-40a4-88ed-71d8d4ee3517.png)

![]()

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1773112617478-94083134-f952-4008-aa87-7a35249a9c5f.png)

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1773112630389-e71fdb5e-39c8-4d31-aced-84ee763d5d01.png)

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1771926597402-de72ed7e-631d-46ba-9a19-18a6d99520bf.png)

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1771929284237-725a1633-0890-48bc-9ebd-629080a1368e.png)

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1773224125241-86e27af2-5cd7-4151-bb6a-28f8b9f521d9.png)

### 基础设施版本升级

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1773228570340-62949951-33a3-44df-a8fb-c68e3b62d91d.png)

| 组件         | 当前版本                          | 说明                                          |
| ------------ | --------------------------------- | --------------------------------------------- |
| 基础系统镜像 | `rockylinux:8`                    | ARL 主应用镜像基座（`ARL/docker/Dockerfile`） |
| MongoDB      | `mongo:7.0`                       | 资产数据存储                                  |
| RabbitMQ     | `rabbitmq:3.13-management-alpine` | Celery 消息队列                               |
| Redis        | `redis:7-alpine`                  | 业务缓存与性能优化                            |
| nginx        | `nginx:1.24-alpine`               | basic 和服务暴露                              |
| node         | `node:20.20.1-bookworm`           | 编译前端                                      |
| golang       | `go1.22.4`                        | 构建阶段编译 `wih`（优先离线包，构建后清理）  |
| Python       | `Python-3.10.20`                  | 后端（离线安装包）                            |

其它 bug 修复

---

### 低性能环境

- 不建议使用nuclei与afrog进行poc扫描，性能太差的机器效果也不好

<!-- 这是一个文本绘图，源码为：flowchart TD

  U[用户/前端] --> N[arl_nginx 入口认证与反代]

N --> W[arl_web: Gunicorn API]

W --> M[(MongoDB: task/asset/result)]

W --> R[(RabbitMQ: Celery queues)]

S[arl_scheduler 定时调度] --> R

R --> Q1[arltask queue]

R --> Q2[arlheavy queue]

R --> Q3[arlweb queue]

R --> Q4[arlgithub queue]

Q1 --> WK1[arl_worker_1]

Q2 --> WK1

Q3 --> WK1

Q4 --> WK1

Q1 --> WK2[arl_worker_2]

Q2 --> WK2

Q3 --> WK2

Q4 --> WK2

WK1 --> SCAN[扫描阶段执行: 域名/IP/站点/目录/漏洞/WIH...]

WK2 --> SCAN

SCAN --> AID[AI 去噪增量任务入队 arlweb]

AID --> WK1

AID --> WK2

WK1 --> M

WK2 --> M

M --> W

W --> U -->
![](https://cdn.nlark.com/yuque/__mermaid_v3/c4761538d01543e85d19f9792359b89c.svg)

## Bug？

添加公众号联系我，如果使用的人多，在考虑修复

## 更新日志

更多补丁级（PATCH）更新明细、版本号与日期，请以 [CHANGELOG.md](./CHANGELOG.md) 为准。

## 免责声明

本项目仅用于合法授权的资产梳理、安全验证与研究场景。请勿用于未授权目标。

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/jpeg/27875807/1771929928377-73947b1a-b47e-45da-b30d-a74da57a76fd.jpeg)
