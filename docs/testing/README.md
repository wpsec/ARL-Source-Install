# 测试体系运行说明

实施范围与验收记录见 [全系统自动化测试体系建设计划](<../completed/[已完成]全系统自动化测试体系建设计划.md>)。API 操作、可见页面、关键工作流和高风险业务域映射由 `python3 scripts/generate_test_inventory.py` 生成，结果在 [`test-inventory.md`](test-inventory.md)。

## 分层入口

- `scripts/run-offline-tests.sh`：运行无公网 Python 全量测试与测试卫生检查、Rust 离线单测/原生 smoke/corpus 一致性、前端类型检查/Vitest/build，以及两组 Playwright：固定 API fixture 和真实隔离 Compose 的确定性任务流程。Python 与专用服务通过 Compose `internal: true` 网络协作；浏览器系统测试只把 API 临时绑定到测试机 `127.0.0.1` 随机端口，Rust 通过 Docker `--network none` 执行。只有一次性源码快照可写，运行配置从 `config.yaml.example` 派生。脚本本身不会联网下载依赖；需要快照标记、Node.js 满足 lockfile engines（建议 Node 24.21.0）、npm、已安装前端依赖、预装容器镜像，以及 Rust `cargo`/`rustc` 与 Cargo 离线依赖缓存。Rust 结果导出到唯一临时目录，不覆盖固定镜像标签。
- `scripts/run-container-regression.sh`：兼容入口，转交给离线测试入口；旧版固定容器名和联网构建逻辑已移除。
- `scripts/run-system-tests.sh`：只允许在带 `.arl-system-test-snapshot` 标记的一次性源码快照中运行。它创建唯一 Compose 项目和 `internal: true` 网络，启动 MongoDB、Redis、RabbitMQ、API 与固定 HTTP fixture；先运行真实服务协作测试，再逐模块执行 Python unittest 并检查导入污染。启用 `ARL_RUN_SYSTEM_UI_E2E=1` 时，它为浏览器测试临时启动确定性 worker 和真实 API 登录账号；API 端口随机绑定至测试机 loopback，只供本机 Playwright 经过 Vite 同源代理调用。结束后移除本次项目容器和内部网络。
- `scripts/check-test-hygiene.py`：逐模块独立进程执行 Python 测试，收集失败、零用例和污染都会使命令失败；逐项输出跳过测试及原因，空原因会使命令失败。基础卫生运行有 48 项显式跳过：41 项网络测试、5 项未包含实现的云安全测试、2 项测试容器中不可运行的 Docker CLI 检查。全量入口还会在卫生阶段跳过 9 项系统集成测试，因为这些用例在同轮隔离 Compose 阶段单独执行；完整运行报告因此记录 57 项 skip。

## 系统测试隔离边界

- MongoDB 使用 `arl_system_test` 数据库；Redis 使用 DB 13；RabbitMQ 使用独立 `arl-system-test` vhost。每轮随机生成 RabbitMQ 临时凭据，只通过进程环境传给临时容器，结果日志不输出凭据。
- Compose 只创建内部 Docker 网络，不提供公网路由。靶场服务只读提供固定 HTML 页面，唯一允许的靶场地址由 Compose 服务别名 `arl-test-target` 提供。
- 系统测试创建确定性 Celery 测试任务，验证投递、一次重试、worker 停止后的队列保留、worker 重启、撤销延迟任务、重试耗尽后错误终态写回、Mongo 写入及 Redis 隔离读写。浏览器全栈流程通过真实登录和任务创建 API 创建两条测试任务，由专用 worker 完成/失败，再在任务列表、Task ID 详情和异常对话框中查看；隔离 Web 入口只替换生产扫描入队函数。该流程不会调用扫描器或创建真实扫描任务。
- `run-system-tests.sh` 在快照结束后把生成的 `config.yaml` 覆盖回无凭据模板，并停止本次 Compose 项目。失败日志保留于 `ARL_TEST_REPORT_DIR` 指定目录，默认 `/var/tmp/arl-system-test-reports`。

## 当前覆盖边界

`ARL/test/test_api_route_contract_inventory.py` 对所有 189 个 Flask HTTP 操作核对运行时路由注册；显式公开 allowlist 仅允许登录和登出，其余 187 个操作逐项验证缺少 Token 的统一响应包络。高风险业务域的主要测试文件和覆盖边界见 [`test-inventory.md`](test-inventory.md)：32 项专用 API 合同测试覆盖任务/报告所有者隔离、用户口令、资产和漏洞删除目标、策略创建/删除、计划任务写入、系统监控响应、GitHub 入参和配置密钥脱敏；现有模块测试进一步覆盖策略、导出、ICP、配置、GitHub 和系统监控逻辑。外部扫描队列和 provider 通过 mock/fixture，不运行真实扫描或请求真实 provider。最新完整离线报告：`/var/tmp/arl-offline-test-reports/20261018185223-3566351.log`；隔离系统报告：`/var/tmp/arl-system-test-reports/arl-system-test-3ed1de5d-20261018185223-4906ca.md`。测试以 `3ed1de5d` 为一次性快照基线，并叠加本轮工作区测试改动；不代表这些改动已提交。跳过项均有原因与显式控制：41 项历史网络用例由 `ARL_RUN_LEGACY_NETWORK_TESTS=0` 关闭，5 项云安全服务用例需实现存在并设置 `ARL_RUN_CLOUD_SECURITY_SCAN_TESTS=1`，2 项 Docker Compose 渲染用例在测试容器中设置 `ARL_SKIP_DOCKER_COMPOSE_TESTS=1`；另有 9 项系统测试在卫生阶段关闭，并在同轮隔离 Compose 阶段单独通过。

前端 lockfile 中 jsdom 要求 Node `^22.22.2 || ^24.15.0 || >=26.0.0`；旧 Dockerfile 固定 Node 20.20.1 时，`npm run lint` 通过但 Vitest worker 会因 `undici`/`webidl` API 不匹配而无法启动。前端构建基底已切换至 Node 24.21.0-bookworm；该版本下干净 `npm ci`、lint、186 项 Vitest、build 和 8 项 Playwright 均通过。`frontend_builder` Docker 阶段也已在本机以 `linux/amd64` 重建通过，覆盖 apt、`npm ci` 和 production build。测试机宿主原本没有 Node/npm，完整离线入口已通过一次性快照中的 Node 24.21.0、前端依赖和临时 Rust runner 执行。

Playwright 的 fixture 页面 smoke 遍历前端可见模块，并阻断对本地 Vite 测试服务之外的浏览器请求；系统用例通过 localhost API 代理连接隔离 Compose，复用同一个后端生成的 Task ID 验证列表、详情与错误状态呈现。Celery 集成覆盖重复投递幂等、RabbitMQ 发布连接失败后的恢复、MongoDB 暂不可用时错误结果与恢复重试、任务撤销、重试耗尽后的 Mongo 错误终态和 worker 重启。最新全量运行结果：Python 清洁检查 `1310` 项、`0` fail、`0` error、`57` skip，`194/194` 个模块干净加载；隔离系统测试 `9/9` 通过；Rust 单测 `21/21`、原生 smoke 与两个 corpus 对照通过；Vitest `29` 个文件/`186` 项、fixture Playwright `8/8` 和真实后端系统 E2E `1/1` 通过，lint 和 production build 通过。构建有一个大于 500 kB 的 chunk 提示，不影响通过。自动化测试不触发真实扫描；真实扫描由用户后续手工验收。

## 最近一次全量验收

执行节点 `192.168.10.205`，Node `24.21.0`，Rust `1.85.1`，Docker Server `29.8.0`。完整 `scripts/run-offline-tests.sh` 退出码为 `0`，报告为 `/var/tmp/arl-offline-test-reports/20261018185223-3566351.log`；同轮隔离系统报告为 `/var/tmp/arl-system-test-reports/arl-system-test-3ed1de5d-20261018185223-4906ca.md`。9 项系统集成测试、1 项真实隔离后端 Playwright E2E、1310 项 Python 卫生测试（0 失败、0 错误、57 项有原因的跳过）、Rust 21 项单测、Vitest 186 项和 fixture Playwright 8 项均通过。当前没有待用户确认的自动化测试事项。真实扫描和外部 provider 的线上行为仍由用户按实际授权手动验收；它们不属于自动化测试范围。
