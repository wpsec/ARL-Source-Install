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

## 升级

### 常规更新

```bash
git pull
./scripts/quick-build.sh
```

说明：

- 前端构建已迁移到 `ARL/docker/Dockerfile` 多阶段构建，镜像构建时会直接基于 `ARL/docker/frontend-src` 源码编译。
- `./scripts/quick-build.sh` 的 `quick/full/clean/tag` 不再依赖仓库内预编译前端目录，避免“代码已更新但页面仍旧版本”。
- `./scripts/quick-build.sh frontend` 仅用于本地热更新：编译 `frontend-src/dist` 后同步到运行中容器。
- 默认前端 npm 镜像为 `https://registry.npmmirror.com`，可在 `.env` 中通过 `ARL_FRONTEND_NPM_REGISTRY` 覆盖。
- 若环境已安装 `docker buildx`，`quick-build.sh` 会自动优先使用 BuildKit 构建以减少重复传输与构建耗时。

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

## Bug？

添加公众号联系我，如果使用的人多，在考虑修复

## 更新日志

`README` 仅保留大版本摘要；详细版本变更请查看 [CHANGELOG.md](./CHANGELOG.md)。

### v3.0（2026-03）

- 任务管理与交互体验持续增强：新增同名任务聚合查看、异常可视化、默认分页与操作流优化。
- 扫描与调度稳定性增强：Mongo/RabbitMQ 短时抖动容错、PhantomJS 不可用兜底、字典持久化路径与挂载完善。
- 资产发现能力增强：WIH 增强提取链路 + TruffleHog 集成、SSL 证书采集与过期通知精细化治理。
- 构建与部署链路升级：前端改为 Docker 多阶段编译，构建流程在集群和本地环境更稳定。

更多补丁级（PATCH）更新明细、版本号与日期，请以 [CHANGELOG.md](./CHANGELOG.md) 为准。

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/jpeg/27875807/1771929928377-73947b1a-b47e-45da-b30d-a74da57a76fd.jpeg)
