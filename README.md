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

### 注意！

可提前开代理下载Playwright 以提升部署速度

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

## 升级（当前版本v3.0.33）

### 常规更新

```bash
git pull
./scripts/quick-build.sh
```

## 二开功能总览

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

### 其它

其它 bug 修复

---

## 配置说明

```plain
ARL/docker/config-docker.yaml
```

该目录保留了 ARL 原生大量配置，如果系统 UI 不支持配置，可自行 vim 配置

### 自定义字典持久化（避免容器重建丢失）

自定义字典支持两类目录：

- 宿主机持久化目录：`ARL/docker/dicts/domain/`、`ARL/docker/dicts/file_leak/`

说明：

- `配置管理 -> 扫描配置 -> 域名爆破字典` 会自动枚举 `domain/` 下的 `.txt`
- 页面上传字典将写入 `ARL/docker/dicts/domain/uploaded/`
- `配置管理 -> 扫描配置 -> 敏感文件泄漏字典` 会自动枚举 `file_leak/` 下的 `.txt`
- 页面上传敏感文件字典将写入 `ARL/docker/dicts/file_leak/uploaded/`
- `ARL.FILE_LEAK_DICT` 可直接指向 `file_leak/` 下自定义文件
- `任务管理 -> 新建任务` 支持选择“域名爆破字典”；不选则默认使用配置管理字典
- 以上目录通过 `docker-compose` 挂载，容器重建后文件仍保留

### TruffleHog JS 二次扫描（可选）

系统在 `web_info_hunter` 阶段可对 WIH 已发现的 JS 源做 TruffleHog 二次扫描（默认跟随 WIH 开启）。

前置：

- 将 TruffleHog 可执行文件放到 `tools/TruffleHog/trufflehog` 并赋予执行权限

说明：

- 当前仅扫描 WIH 已发现的 JS URL（`source/content` 为 `http(s)` 且命中 `.js`），不直接扫描 `html/txt` 文件
- 扫描结果写入 `wih` 表，记录类型前缀为 `trufflehog_*`
- 结果内容默认原文入库，便于复核与定位
- `trufflehog_*` 与 `app_key/api_key/token` 等高价值敏感记录会同步写入 `vuln` 风险模块，并在 WIH 页面高亮显示

## Bug？

添加公众号联系我，如果使用的人多，在考虑修复

## 更新日志

建议以 [CHANGELOG.md](./CHANGELOG.md) 为主，`README` 保留最近版本摘要（同日版本合并记录）。

### 2026-03-13（v3.0.45 ~ v3.0.48）

- `[v3.0.45]` `nuclei` 分批策略优化：`NUCLEI_TARGETS_PER_BATCH<=1` 时自动按并发与超时预算计算批次，避免默认单目标拆分导致扫描明显变慢
- `[v3.0.45]` `nuclei` 自动扫描回退优化：仅在执行失败或模板未命中时才回退 `-tags`，不再因“无结果”重复跑一轮
- `[v3.0.46]` 策略配置（新建/编辑）移除“扫描配置”可视化编辑区，策略层不再承载主机超时/发包速率等细粒度调优项
- `[v3.0.46]` 策略配置新增“域名爆破字典 / 敏感文件泄漏字典”选择，支持按策略指定任务字典或留空跟随配置管理默认值
- `[v3.0.47]` WIH 增强：`trufflehog_*` 与 `app_key/api_key/token` 等敏感记录会同步进入风险模块，并在 WIH 列表高亮提示
- `[v3.0.48]` SSL证书告警降噪：同一任务内按“域名+证书身份+到期时间”合并多端点，跨任务仅在告警等级升级时再推送；证书 `HOST` 展示改为“域名 -> ip:port”

### 2026-03-12（v3.0.33）

- `[v3.0.33]` 配置管理（扫描配置）新增 `nuclei` 单目标最大扫描时间配置项 `NUCLEI_SINGLE_TARGET_TIMEOUT_SEC`
- `[v3.0.33]` 提供硬件推荐档位：`2核2G=1小时`、`4核4G=2小时`、`8核16G=3小时`
- `[v3.0.33]` `nuclei` 增加带宽限速参数（`-rl/-c/-bs`）和按目标分批执行，缓解扫描时出口被打满的问题
- `[v3.0.33]` `nuclei` 扫描超时支持按目标数折算，并在超时后安全结束当前批次
- `[v3.0.33]` 任务状态更新写库增加重试兜底，降低 Mongo 短时解析异常导致任务中断风险

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

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/jpeg/27875807/1771929928377-73947b1a-b47e-45da-b30d-a74da57a76fd.jpeg)
