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

## 升级

### 常规更新

```bash
# 日常更新
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
| node         | `node:20.20.1-bookworm`           | 编译前端                                      |
| golang       | `go1.22.4`                        | 构建阶段编译 `wih`（优先离线包，构建后清理）  |
| Python       | `Python-3.10.20`                  | 后端（离线安装包）                            |



### 其它

其它 bug 修复

---

## 配置说明

```plain
ARL/docker/config-docker.yaml
```

该目录保留了 ARL 原生大量配置，如果系统 UI 不支持配置，可自行 vim 配置

### 自定义字典持久化

（避免容器重建丢失

自定义字典支持两类目录：

- 宿主机持久化目录：`ARL/docker/dicts/domain/`、`ARL/docker/dicts/file_leak/`

### TruffleHog

系统在 `web_info_hunter` 阶段会按 `WIH -> URL/JS增强提取 -> URLFinder同目标二次敏感扫描 -> TruffleHog` 链路执行敏感信息发现（默认跟随 WIH 开启）。

前置：

- 将 TruffleHog 可执行文件放到 `tools/TruffleHog/trufflehog` 并赋予执行权限

说明：

- 自研 `urlfinder_extract` 会从目标站点页面和 JS 中提取 URL/JS 引用，支持相对路径归一化与受控递归
- URLFinder 二次敏感扫描仅处理“同目标 host”来源的 URL/HTML/JS，避免扫描到无关站点
- TruffleHog 仅扫描当前任务目标 host 范围内来源的 JS URL，不在目标范围内的第三方 JS 会被过滤
- TruffleHog 不直接扫描 `html/txt` 文件
- 扫描结果写入 `wih` 表，记录类型前缀为 `trufflehog_*`
- 结果内容默认原文入库，便于复核与定位
- `trufflehog_*` 与 `app_key/api_key/token` 等高价值敏感记录会同步写入 `vuln` 风险模块，并在 WIH 页面高亮显示

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/png/27875807/1773386503749-b9f62581-c8d8-4774-80e5-3db616465da3.png)

### 低性能环境

- 不建议使用nuclei与afrog进行poc扫描，性能太差的机器效果也不好

## Bug？

添加公众号联系我，如果使用的人多，在考虑修复

## 更新日志

`README` 仅保留大版本摘要；详细版本变更请查看 [CHANGELOG.md](./CHANGELOG.md)。

### v3.3（2026-03）

- 发布 `v3.3.1`：端口扫描链路升级为“分片执行 + 两阶段扫描（先快扫后精扫）”，在保持识别质量的同时降低全端口和大目标任务对系统的瞬时压力。
- 新增重任务隔离调度：引入 `arlheavy` 独立队列与 worker，自动将高负载任务（如全端口/深度识别）与普通任务分离执行，减少任务互相阻塞。
- 精扫阶段改为“逐主机 + 端口分段”执行，覆盖全部发现开放端口的主机与端口，不再按高价值目标裁剪范围，保证结果不缩水。
- RabbitMQ 增加长任务确认超时放宽配置（2小时）并精简 API 管理项（隐藏 PassiveTotal），降低长任务异常中断与无效配置干扰。

### v3.2（2026-03）

- 发布 `v3.2.0`：仪表盘实时扫描日志改为优先读取 `arl_worker.log`，并补齐 `web/worker` 日志目录共享挂载，日志展示与实际扫描输出保持一致。
- 仪表盘页面精简并增强可读性：移除“ARL 引擎”卡片，扩大实时日志区域与拉取条数上限，便于排障观察。
- 资产搜索“文件泄漏 / URL信息”模块补齐 `body 长度(content_length)` 排序能力，便于快速定位大响应体目标。
- 配置生效链路优化：`配置管理` 与 `API管理` 保存后触发运行时热刷新，`worker` 在任务执行前按配置文件变更自动加载关键参数，常见扫描/API参数无需重启容器即可在下一次任务生效。
- 任务扫描体验优化：`新建任务` 入口文案统一；扫描功能新增“跳过WAF”开关（默认关闭），开启后会在同任务目标范围内按主机识别疑似 WAF 拦截并自动跳过，任务统计与仪表盘日志会显示跳过摘要。

### v3.1（2026-03）

- 发布 `v3.1.0`：版本进入 `3.1` 迭代周期。
- 继承 `v3.0` 系列在任务管理、扫描稳定性、证书采集和导出链路上的增强成果，后续以 `v3.1.x` 持续演进。
- 任务管理搜索体验继续统一：`GitHub 任务` 与 `GitHub 监控任务` 页面将任务名与关键字入口合并为单一搜索框，减少重复筛选操作并降低误用成本。

### v3.0（2026-03）

- 任务管理与交互体验持续增强：新增同名任务聚合查看、异常可视化、默认分页与操作流优化。
- 扫描与调度稳定性增强：Mongo/RabbitMQ 短时抖动容错、PhantomJS 不可用兜底、字典持久化路径与挂载完善。
- 资产发现能力增强：WIH 增强提取链路 + TruffleHog 集成、SSL 证书采集与过期通知精细化治理。
- 构建与部署链路升级：前端改为 Docker 多阶段编译，构建流程在集群和本地环境更稳定。

更多补丁级（PATCH）更新明细、版本号与日期，请以 [CHANGELOG.md](./CHANGELOG.md) 为准。

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/jpeg/27875807/1771929928377-73947b1a-b47e-45da-b30d-a74da57a76fd.jpeg)
