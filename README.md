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

可提前开代理下载Playwright 以提升部署速度

参考文档：

```plain
tools/playwright/README.md
```

主生产运行时按 Python 3.10+ 规划，Rust 加速模块的镜像构建目标包含 amd64 与 arm64。已在 macOS Apple Silicon 的 ARM64 Docker 环境完成镜像构建、Rust native smoke、AArch64 工具链和核心回归测试；部署到 x86 服务器时仍应使用 amd64 builder 或对应架构的 buildx/runner 构建并验收。

### 密码修改

忘记系统账户密码时，使用重置脚本按提示设置新密码；仓库文档不记录明文密码。

```plain
./resetpass.sh
```

### 访问方式

- 访问地址：`http://<服务器IP>`
- Basic Auth：
  - 用户名：`.env` 中 `BASIC_AUTH_USERNAME`（默认 `admin`）
  - 密码：必须在 `.env` 中设置 `BASIC_AUTH_PASSWORD`，系统不再提供默认密码
- ARL 应用默认账号：
  - 用户名：`.env` 中 `ARL_APP_USERNAME`（默认 `admin`）
  - 密码：建议在 `.env` 中显式设置 `ARL_APP_PASSWORD`，生产环境不要依赖 Compose 默认值
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

### Rust + Python 混合加速层

系统已使用 Rust 重构部分关键接口，以降低 CPU 密集型处理开销并提升批量处理效率。当前采用 Python 业务编排与 Rust CPU 加速相结合的方式，固定调用链为：

```plain
Celery -> Python Orchestrator -> Python Adapter -> Rust 批处理模块 -> WihRecord -> Mongo
```

- Python 保留 Flask、Celery、Mongo、配置、AI、Playwright、网络策略、预算控制和任务生命周期。
- Rust 只处理无副作用、可批处理的 CPU 密集型逻辑：URL/JS/HTML 提取、URL 归一化、过滤、去重、候选排序和指纹计算。
- 当前 Rust 加速已接入 URLFinder 批量提取、HTML 页面结构提取、JS 接口候选提取和敏感候选排序等关键接口；Python 公共函数签名保持不变，业务结果仍统一转换为现有 `WihRecord` 并写入 Mongo。
- Rust 不直接访问 Mongo、Redis、Celery、LLM、浏览器、DNS/WAF 或外部扫描器；现有 Go 版 `tools/wih` 继续保持 Go 实现。
- Rust 模块位于 `ARL/native/arl_accel`，通过 PyO3/maturin 构建 `abi3` wheel，主生产 Python 版本为 3.10+，使用 release 构建。
- `RUST_ACCEL_ENABLE` 控制是否优先使用 Rust；`RUST_ACCEL_FALLBACK_ENABLE` 控制 Rust 不可用或单批异常时是否回退当前批次的 Python 实现。回退会记录阶段、批次、原因和次数，不会静默发生。
- URL/HTML/JS 加速批次会记录独立的 Rust 执行、fallback、网络等待和请求数量指标，便于区分 CPU 处理瓶颈与外部网络探测耗时。

域名发现结果保留兼容字段 `source`，并通过 `sources` 聚合 FOFA、Hunter、证书、爆破等所有命中来源；前端列表筛选和 Excel 导出会展示完整来源集合。该能力只对新版本运行期间捕获的命中生效，历史任务需要重新扫描才能补齐之前丢失的来源关系。

对应环境变量为 `ARL_RUST_ACCEL_ENABLE` 和 `ARL_RUST_ACCEL_FALLBACK_ENABLE`。Rust 结果只有在 Python golden corpus 一致性和性能门禁通过后，才扩大生产覆盖范围。

#### 性能验收口径

Rust 加速层不以“已接入”直接等同于“已提速”。在 64 个代表性目标的冷启动、热缓存两轮基线中，候选热点必须满足以下任一条件，才扩大 Rust 覆盖范围：

- p95 CPU 时间较 Python 基线降低至少 30%
- 吞吐达到 Python 基线的 1.5 倍。

同时，接入 Rust 后端到端阶段耗时不得较 Python 基线恶化超过 5%。若 CPU 并非该阶段的主要耗时来源，不强制迁移，保留 Python 实现和可观测 fallback。当前 Rust/Python 结果一致性以及 ARM64/amd64 release wheel、同一套 native smoke test 已通过，64 目标真实性能基线仍在采集中。

### Worker 横向扩展说明（v4.3.0）

扫描容器服务名统一为 `worker_1`、`worker_2`，支持部署时选择 1 个或 2 个 worker：

```plain
# .env
ARL_WORKER_REPLICAS=1   # 可选: 1 或 2，默认 1
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
- WAF 观测、命中证据与失败后跳过

### 平台化增强

- 同名任务查看、批量任务操作、任务同步
- 计划任务、钉钉机器人通知、钉钉知识库结构化写入
- `Excel / HTML / AI Markdown` 三格式任务报告导出（AI 未完整配置时自动降级为离线模板，不报错）
- 配置管理新增 `AI管理`：支持多模型配置、上方生效模型切换、OpenAI 兼容接口、提示词管理与总测试按钮
- 配置热刷新、扫描日志聚合、系统监控、任务可观测性增强
- Celery / RabbitMQ 稳态增强与重任务队列隔离

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
| Rust         | `1.85.1`                          | 构建 `ARL/native/arl_accel` release wheel     |
| PyO3/maturin | `PyO3 0.29.2` / `maturin 1.8.6`   | Python `abi3` 扩展与 manylinux 构建           |

其它 bug 修复

---

![](https://cdn.nlark.com/yuque/__mermaid_v3/c4761538d01543e85d19f9792359b89c.svg)

## Bug？

添加公众号联系我，如果使用的人多，在考虑修复

## 更新日志

更多补丁级（PATCH）更新明细、版本号与日期，请以 [CHANGELOG.md](./CHANGELOG.md) 为准。

## 免责声明

本项目仅用于合法授权的资产梳理、安全验证与研究场景。请勿用于未授权目标。

<!-- 这是一张图片，ocr 内容为： -->

![](https://cdn.nlark.com/yuque/0/2026/jpeg/27875807/1771929928377-73947b1a-b47e-45da-b30d-a74da57a76fd.jpeg)
