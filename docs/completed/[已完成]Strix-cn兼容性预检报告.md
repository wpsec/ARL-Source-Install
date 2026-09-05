# Strix-cn 兼容性预检报告

## 1. 结论

本次预检未通过生产集成门禁，暂停将 `strix-cn` 接入 ARL 的生产执行链路。

原因不是 CLI 无法运行，而是上游默认执行能力与本项目首期约束不一致：上游是自治渗透测试代理，具备 Shell、Filesystem、浏览器、代理重放、子代理编排和大量主动扫描/利用工具；其 scope 约束主要由平台上下文、提示词和代理层主机规则共同表达，尚未证明能够强制覆盖所有执行路径。直接把 ARL 或 gateway 的宿主 Docker 控制面交给该运行时，会扩大到容器创建、网络和命令执行风险，不能作为“未登录、低副作用 Web 验证”实现。

本结论遵循重构计划中的安全门禁：预检不满足低副作用和严格 scope 时，不进入生产执行。

## 2. 固定版本、许可证和依赖

| 项目 | 预检结果 |
| --- | --- |
| 上游仓库 | `wpsec/strix-cn` |
| 固定 commit | `3a04cd51cac8c1d9a970d8b12e0f3fa1a8a61774` |
| 版本声明 | `1.4.1` |
| Python | `>=3.12` |
| 核心 Agent SDK | `openai-agents[litellm]==0.14.6` |
| 其他关键依赖 | `openai`、`litellm`、`pydantic`、`docker>=7.1.0` 等，以该 commit 的 `pyproject.toml` 为准 |
| 许可证 | Apache License 2.0；需要在派生镜像、源码修改和分发物中保留许可及 NOTICE 要求 |
| 运行时镜像 | README 默认使用 `ghcr.io/usestrix/strix-sandbox:1.1.0`；不得把浮动 tag 当作生产依赖，需后续固定 digest 并做镜像复核 |

预检只固定了源码 commit，尚未批准生产依赖安装、镜像拉取或发布。

## 3. CLI、API、模型和结果格式

- 上游提供 `strix` CLI，入口为 `strix.interface.main:main`，支持 `--non-interactive`、`--target`、`--instruction`、`--scan-mode`、预算和轮次限制。
- 上游没有可直接部署的 HTTP API 或常驻 daemon。程序化接入需要自行包装 `run_strix_scan` 或启动 CLI，并自行处理进程、状态、取消、日志和 artifact 生命周期。
- 模型通过 LiteLLM/OpenAI Agents 配置，依赖运行时环境和 CLI 配置；需要由 ARL gateway 注入当前生效 model profile，并确保密钥不进入任务、日志、trace、报告或 native payload。
- 默认结果落在 `strix_runs/<run-name>`，包含 `run.json`、`vulnerabilities.json` 以及 Markdown、CSV、SARIF、HTML 等报告文件。需要重新定义 artifact 白名单、大小限制、脱敏和 schema 校验后才能入库。

兼容性结论：可以作为独立进程封装，但不能直接作为 ARL Python 3.10 进程内依赖；原生结果也不能未经校验直接写入 ARL。

## 4. 运行时与能力边界

已确认的上游行为：

- 运行时仅发现 Docker backend，使用 `docker.from_env()` 创建 sandbox。
- sandbox 创建逻辑增加 `NET_ADMIN`、`NET_RAW`，并配置 host gateway；这不符合“gateway 不挂载 Docker socket、执行服务最小权限”的目标，且需要单独审计 Docker daemon 边界。
- sandbox 镜像为 Kali 类环境，包含 nmap、sqlmap、nuclei、subfinder、naabu、ffuf、Chromium、agent-browser、semgrep 等主动探测或利用工具。
- Agent factory 默认赋予 `Filesystem` 和 `Shell` capability，并支持命令执行、文件操作、浏览器、代理工具、报告工具、子代理编排等能力。
- prompt 中虽然注入 authorized target、proxy allowlist/denylist 和“不扩大 scope”等规则，但这些内容不能替代网络层、进程层和工具层的强制拦截。
- quick/standard/deep 是工作深度和预算模式，不是经过验证的“低副作用模式”；上游仍包含主动探测、漏洞验证和利用导向行为。

## 5. 安全门禁逐项结果

| 门禁 | 结果 | 依据与缺口 |
| --- | --- | --- |
| 固定源码版本 | 通过 | 已固定 commit，禁止运行时拉取浮动分支 |
| 固定依赖和镜像 | 未完成 | Python 依赖未生成项目锁定清单，sandbox 镜像尚未固定 digest 和完成镜像审计 |
| CLI/API 可编排 | 部分通过 | CLI 可非交互运行，但没有原生 HTTP API；取消、恢复、幂等需自行实现 |
| 复用 ARL 模型配置 | 可设计 | 需要 gateway 做 profile 映射和密钥隔离，当前未实施 |
| 浏览器和结果格式 | 部分通过 | 依赖 Docker sandbox；已有多种报告输出，但 artifact 需要白名单和 schema 校验 |
| 严格 target scope | 未通过 | prompt 和 host 级 proxy scope 不能证明覆盖 Shell、浏览器、重定向、DNS rebinding、端口和其他外联路径 |
| 未登录、低副作用 | 未通过 | 默认能力支持主动扫描、PoC/利用、Shell 和后渗透导向；没有已验证的强制低副作用开关 |
| 禁止爆破和破坏性操作 | 未通过 | 未发现能够覆盖所有工具、命令和代理重放路径的强制策略层 |
| 不越界访问 | 未通过 | 需要独立 egress proxy/firewall、解析固定、重定向复核和每次请求授权校验，当前上游不提供完整能力 |
| ARL 运行时兼容 | 未通过 | ARL 当前 Python 3.10，而上游要求 Python 3.12；不能直接进程内引入 |

## 6. 不允许的直接落地方式

在安全整改完成前，不执行以下方式：

- 在 ARL web/worker 容器中直接安装并 import `strix-cn`。
- 把宿主机 `/var/run/docker.sock` 或等价 Docker 控制面挂给 gateway、Celery worker 或 Strix agent。
- 仅依赖 system prompt、`--scan-mode quick`、最大轮次或最大预算宣称实现低副作用。
- 让 Strix 直接接收未经过 ARL origin、task scope 和授权校验的 URL。
- 将 Strix 的 native payload、请求头、Cookie、Authorization、模型配置或原始 trace 未脱敏写入 Mongo、日志和导出文件。

## 7. 恢复实施的前置条件

后续如需继续，必须先完成一个隔离的安全适配层，而不是直接开启旧计划第 3 步：

1. 对上游做最小能力 fork，移除或默认禁用 Shell、Filesystem、主动扫描、爆破、登录、破坏性利用、任意子代理和非必要外联能力。
2. 采用独立且不可访问宿主 Docker 控制面的运行时；执行服务只能访问专用 egress gateway 和受限 artifact 目录。
3. 在网络层实现 origin/port/path scope、重定向复核、私网及云元数据地址阻断、DNS rebinding 防护和请求速率/数量限制。
4. 对每一次实际请求进行授权和 scope 校验，并对取消、超时、worker 重启和异常退出做资源回收。
5. 固定完整依赖锁文件、sandbox 镜像 digest、补丁集和许可证清单。
6. 完成 Prompt-Optimizer 至少一轮，并将版本、模型、优化器、测试集和评分写入 `docs/prompts/`。
7. 用隔离测试目标验证越界、爆破、破坏性命令、重定向、DNS rebinding、私网探测和敏感信息泄漏均被阻断；任一失败不得进入生产。

## 8. 预检范围和后续风险

本报告基于固定 commit 的源码、`README.md`、`pyproject.toml`、Docker 构建文件及运行时/Agent factory/prompt 代码静态检查，并检查了本地 Docker Compose 客户端可用性；当前环境未具备可用 Docker daemon，因此未执行真实 sandbox smoke test。真实运行前仍需补充镜像 digest、依赖安装、Docker 隔离、网络策略和黑盒安全测试。

在前置条件满足前，ARL 不新增 Strix 生产任务、API、数据写入、前端执行入口或旧 AI 实现清理。现有其他扫描、AI 去噪和 AI 报告能力保持不变。
