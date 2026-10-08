# ARL 全系统综合 Review（2026-10-08）

## 1. 结论

本轮复核覆盖 ARL 后端、任务与 Celery 链路、NPoC 联动、Web 前端、规则清单校验及 Docker 部署配置。确认任务范围守卫把目标主机扩展到了整个可注册域；按维护者确认的范围规则，该项属于 P1 缺陷。任务所有权缺少登录用户过滤仅在启用多登录用户时触发，本系统目前按单用户部署处理，列为未来多用户扩展项。

另发现截图上传读取上限的防御性加固项、PoC 全局同步并发竞争、GET 修改资产范围，以及指纹导入接口兼容性问题。维护者确认 PoC 同步采用全局单实例语义；F-03 暂缓，F-04、F-05、F-06 已修改但尚未测试。前端现有回归、lint、build 和主题对比度检查通过；NPoC 清单与 legacy PoC 校验通过。后端计划 5/6/7 离线回归有 2 个模块失败，均是测试桩未跟上当前接口，不能据此判定相应运行路径已通过；这些结果发生在本轮代码修改前。

这是基于当前代码和本机隔离检查的静态与离线 Review，不构成生产部署放行结论。未连接真实 MongoDB、RabbitMQ、Redis 或 Celery worker，未启动完整 Docker 服务、未扫描真实目标，也未做浏览器视觉、性能、依赖在线审计或多架构验证。

## 2. 范围与方法

- 基线：分支 `newUI`，HEAD `1a89ac45`；开始检查时工作树干净。随后按讨论结论修改 F-02、F-04、F-05、F-06，并调整相应回归测试替身和本报告。
- CodeGraph 已有当前索引，覆盖 19,358 个文件、19,422 个节点、48,787 条边；使用索引和源码检查定位后端路由、授权、任务编排及前端边界。
- 对 2026-09-14 综合 Review 中的整改项逐项复核，并抽查高风险路由、所有权守卫、scope guard、上传入口、重定向处理、POC 同步、配置解析和部署限制。
- 后端测试使用 `env -i` 和仓库外的临时合成配置钩子，仅用于避免应用导入真实本机运行配置；没有读取真实配置文件或环境变量中的敏感值。
- 范围覆盖一方应用代码和 NPoC 清单结构。4,420 条规则只执行清单完整性与 legacy 校验，没有逐条人工审阅规则语义或对目标发起请求。

## 3. 检查结果

| 检查 | 结果 | 说明 |
|---|---|---|
| Web 前端 Vitest | 通过 | 23 个文件、158 项测试通过；有 Recharts 容器尺寸及导航相关测试警告，未导致失败。 |
| Web 前端 lint | 通过 | `npm run lint` 退出码 0。 |
| Web 前端 build | 通过 | `npm run build` 退出码 0；存在 Vite deprecation 提示。 |
| 主题对比度 | 通过 | 6 个主题通过现有脚本门禁；未做真实浏览器视觉和键盘操作验证。 |
| 后端聚焦回归 | 通过 | 7 个既有测试模块、27 项通过，覆盖历史修复、endpoint probe 和资产范围模块。 |
| 计划 5/6/7 离线回归 | 部分失败 | 共 31 个模块，29 个通过；`test_fingerprint_wiring_fetchsite` 和 `test_wih_orchestrator` 失败，见第 6 节。 |
| NPoC manifest 校验 | 通过 | 4,420 项；4,419 个可执行项、1 个 alias 重复项、0 quarantine、0 未引用项。 |
| legacy PoC 校验 | 通过 | 40/40。校验使用仓库内既有模拟输入，不连接外部目标。 |
| Docker Compose 静态配置 | 通过 | 通过 `docker compose config --quiet`；只注入临时合成值，未启动服务。 |
| Python 安全模式检索 | 有条件通过 | 未发现 `shell=True`、`os.system()` 或应用代码中的 `eval()`；配置读取采用 `SafeLoader`。仍有 Redis 缓存 `pickle.loads`，安全性依赖 Redis 写入边界可信，部署 ACL/网络边界未验证。 |

未运行全量后端 pytest 收集和测试：完整套件可能导入运行配置或触发真实服务依赖。本轮使用的聚焦回归和计划 5/6/7 脚本均为仓库标注的离线检查。

## 4. 新发现

### F-01（多用户触发时 P1；当前单用户暂缓）：任务及任务数据缺少登录用户所有权校验

任务创建时写入 `owner_username`，且已有 `can_access_owned_resource()` 按登录用户限制资源访问；但任务列表经通用查询直接返回，停止、删除、重启操作也只按 task ID 查找。批量导出仅按 task ID 查询结果集合。相关位置：[task.py](../../ARL/app/routes/task.py#L201)、[task.py](../../ARL/app/routes/task.py#L292)、[task.py](../../ARL/app/routes/task.py#L424)、[task.py](../../ARL/app/routes/task.py#L492)、[task.py](../../ARL/app/routes/task.py#L843)、[collection_query_service.py](../../ARL/app/services/collection_query_service.py#L246)、[__init__.py](../../ARL/app/routes/__init__.py#L410)、[user.py](../../ARL/app/utils/user.py#L77)。

**触发条件与影响：**启用认证且存在多个登录用户时，登录用户可通过列表或已知 ID 读取其他用户任务及结果，也可能停止、删除或重启他人任务。API 管理主体当前按全局管理处理。单账户部署降低了触发概率，但不消除代码层越权。

**建议：**在共享任务访问层按当前 principal 注入 owner 条件；对 task ID 列表逐项校验归属后再执行读、写、删除、重启或导出。为历史无 owner 任务沿用现有唯一用户回退规则，避免将不明归属资源开放给多用户。

### F-02（P1）：任务范围守卫按可注册域放宽主机范围

`_append_host()` 原先将输入主机的 FLD 加入允许集合，`host_in_scope()` 随后允许同一 FLD 下的任意主机。[task_scope_guard.py](../../ARL/app/services/task_scope_guard.py#L53)、[task_scope_guard.py](../../ARL/app/services/task_scope_guard.py#L60)。

**已确认的范围规则：**输入根域时，允许该域及其所有子域；输入子域时，只允许该子域及其子域，不允许父域或兄弟子域。当前 FLD 判断会违反第二条；任务已有结果也不能反过来成为新的授权根。

**整改：**代码已改为按授权主机边界进行精确匹配和子域后缀匹配，过滤任务结果时要求其先落入原授权根；IP 地址仅允许精确匹配。测试尚未运行。

### F-03（P3，暂缓）：截图上传在大小检查前读取完整请求体

上传接口先执行 `upload_file.read()`，然后才与应用层上限比较；反向代理统一允许最大 300 MB 请求体。[image.py](../../ARL/app/routes/image.py#L215)、[image.py](../../ARL/app/routes/image.py#L223)、[nginx.conf](../../ARL/docker/nginx-reverse-proxy/nginx.conf#L45)。

**影响：**认证用户可让 Web worker 在拒绝超限图片前先分配大块内存；并发请求会放大内存压力。截图 worker 在发送前已有本地大小检查，且项目其他上传路径也采用读取后校验。按单用户部署和现有惯例，本轮暂缓处理。

**建议：**后续统一上传入口限制时，为该路由配置与截图上限一致的请求体限制，并分块读取至上限加 1 字节后立即拒绝。

### F-04（P2）：PoC 全局单实例检查与创建存在并发窗口

同步入口按全局 queued/running 状态复用活动任务，这是已确认的系统单实例语义；但查找与插入之间原本没有原子占位。[poc.py](../../ARL/app/routes/poc.py#L226)、[poc.py](../../ARL/app/routes/poc.py#L239)、[poc.py](../../ARL/app/routes/poc.py#L245)。跨登录用户标识可见性在当前单用户部署下暂缓处理。

**整改：**代码已增加基于 Mongo 唯一索引的全局活动槽位；Celery 任务进入终态和提交失败时释放槽位。测试尚未运行。

### F-05（P2）：删除单个资产范围使用 GET 并修改数据库

原 `GET /assetScope/delete/` 会从资产组中移除范围并写回记录。[assetScope.py](../../ARL/app/routes/assetScope.py#L217)、[assetScope.py](../../ARL/app/routes/assetScope.py#L252)。

**影响：**GET 被约定为安全读取操作，但客户端预取、链接检查或误调用可能产生意外状态变更；也增加 CSRF 评估复杂度。

**整改：**单项范围删除已改为 DELETE；同一路径下批量删除整个资产组仍使用 POST。新版前端没有调用旧 GET 单项删除接口。测试尚未运行。

### F-06（P2）：指纹规则上传解析与当前 PyYAML 版本不兼容，且上传先全量读入内存

上传处理原先无大小限制地读取完整文件，随后调用不带 `Loader` 的 `yaml.load()`；PyYAML 6 下会抛出 `TypeError`，合法导入无法完成。[fingerprint.py](../../ARL/app/routes/fingerprint.py#L178)、[fingerprint.py](../../ARL/app/routes/fingerprint.py#L184)、[fingerprint.py](../../ARL/app/routes/fingerprint.py#L190)。

**整改：**代码已改用 `yaml.safe_load()`，限制上传文件为 5 MiB，并在读取前检查请求体长度、以最大值加 1 字节有界读取，同时校验记录结构。测试尚未运行。依赖声明见 [ARL/requirements.txt](../../ARL/requirements.txt#L12)。

## 5. 2026-09-14 历史问题复核矩阵

| 历史项 | 本轮状态 | 当前证据与剩余边界 |
|---|---|---|
| ARCH-01 跨 Celery 消息共享 DiscoveryContext | 部分整改 | 有持久化 ledger 和状态恢复；不同 Celery 消息是否满足完整共享语义及生产故障恢复未验证。 |
| ARCH-02 fileLeak 子进程响应与指标 | 部分整改 | 子进程响应回灌有通过的离线用例；生产端到端请求计数、重复抑制和指标仍需运行证据。 |
| ARCH-03 CommonTask/DomainTask 复杂度中心 | 未整改 | 仍是跨领域编排中心，属于架构债务；本轮未做重构。 |
| ARCH-04 深度阶段与消息内长链路 | 未验证 | 静态可见长链路；没有 worker profiling 或真实任务时序证据。 |
| ARCH-05 多个直接 DB 写入 owner | 未整改 | 仍可见 routes/services 直接操作集合；一致性治理未完成。 |
| FUNC-01 风险巡航异常终态 | 代码已修复 | 当前路径会记录错误并更新 ERROR/结束状态；未在真实 worker 上验证。 |
| FUNC-02 PoC/Brute 子线程异常与竞态 | 代码已修复 | 子线程异常回传与错误终态路径存在；真实 Celery 重投和压力下行为未验证。 |
| FUNC-03 manifest duplicate 口径 | 部分整改 | 本轮清单为 4,420 项、4,419 个 ready、1 个 alias 重复；“源规则数/执行实体数”的对外定义仍应保持明确。 |
| UI-01 跨页多选 | 已修复 | 选择状态按上下文维护；当前前端测试通过。 |
| UI-02 搜索 debounce 与取消 | 已修复 | 现有实现包含 debounce/AbortController；当前前端测试通过。 |
| UI-03 表格选择可访问名称 | 已修复 | 现有选择控件含 aria label；当前前端测试通过。 |
| UI-04 主题对比度与真实渲染 | 部分验证 | 6 个主题的脚本门禁通过；真实浏览器尺寸、焦点态和键盘流程未验证。 |
| SEC-01 截图读取认证与归属 | 已修复 | GET 校验任务归属、路径和扩展名；上传亦做归属与文件内容校验。上传内存限制见 F-03。 |
| SEC-02 PoC 全量删除 GET | 已修复 | 当前为 POST，仅 API 管理主体可调用，要求显式确认并记录审计事件。 |
| SEC-03 同名 task 扩大 scope | 原问题已修复 | scope 只按当前 task ID 关联；但 FLD 放宽是新发现，见 F-02。 |
| SEC-04 endpoint probe 跟随越界重定向 | 已部分修复 | 每跳先校验 host scope、DNS 策略，并禁用 requests 自动重定向；端口未纳入 scope，DNS 检查与实际连接也未绑定同一解析地址。 |
| SEC-05 配置模板中的默认凭据 | 未验证 | 按本轮安全边界未读取运行配置或含敏感信息的配置模板；不得据此判定已整改。 |
| SEC-06 query token 与改密认证 | 已修复 | 当前 principal 从 `Token` 请求头取得；改密路由使用统一 auth decorator。 |
| SEC-07 TLS 证书校验默认关闭 | 已修复 | 当前 probe 配置默认校验证书，静态检查未发现 `verify=False`。 |
| SEC-08 异步导出归属过滤 | 已修复但不完整 | 报表导出 job 的创建、状态和下载校验 owner；批量结果导出未做 task owner 检查，归入 F-01。 |
| SEC-09 错误响应泄露异常文本 | 部分整改 | 多条关键路径使用 `safe_error_text`；未审完全部 API 的异常回显。 |
| SEC-10 PoC 更新分支未固定 | 已修复 | 更新代码要求完整 commit hash 并按 pin 拉取；本轮未访问远端仓库。 |
| PERF-01 PoC 同步逐条写数据库 | 已修复 | 大批同步使用分批 `bulk_write`；真实数据量耗时未测。 |
| PERF-02 深分页 skip/count 成本 | 部分整改 | 对过深 offset 有上限；查询仍使用 skip/count，索引和线上 p95 未测。 |
| STAB-01 NPoC 临时文件清理 | 未完整验证 | 本轮未覆盖所有异常与终止路径。 |
| STAB-02 只读流程使用 r+ | 静态复核未发现 | 当前限定的应用 Python 检索未命中该模式；没有对所有外部工具脚本做运行检查。 |
| SEC-11 敏感资产文档边界冲突 | 未整改 | 仓库既有敏感资产准则与本轮“不得输出凭据/Token”等边界仍存在冲突；不在报告中复述其敏感内容。 |

## 6. 未通过测试与待验证项

计划 5/6/7 的 2 个失败模块都在测试桩或测试调用处出现 `AttributeError`：

- `test_fingerprint_wiring_fetchsite` 将方法挂在模块中不存在的 `WebSiteFetch` 名称下；当前实现类为 `FetchSite`，实际方法在该类上。
- `test_wih_orchestrator` 的 `_Task` 测试桩没有实现当前编排器传入 URLFinder 的 `_url_in_task_scope` 回调。

本轮没有修正这两个失败模块的测试桩；新增的索引 mock 只对应 PoC 同步测试。计划 5/6/7 结果不能作为 fingerprint 接线或 WIH 编排链路通过的证明。

以下内容仍需要隔离部署环境或授权的运行环境验证：

- MongoDB、RabbitMQ、Redis、Celery worker 的实际运行、重试、并发、任务终态和 owner 隔离。
- Docker 全栈启动、截图目录挂载权限、TLS、容器健康检查及 amd64/arm64 构建。
- 浏览器视觉、键盘导航、真实响应式尺寸，以及大列表和并发上传的性能。
- 配置模板/运行配置中的默认凭据审计和轮换状态；本轮按要求没有读取这些文件。
- endpoint probe DNS 重绑定窗口和目标端口授权策略。

## 7. 后续事项

1. 若未来开放多登录用户，在上线前补齐 F-01 的 task/结果 owner 校验。
2. 后续统一上传入口限制时，处理 F-03 的截图流式读取。
3. 修正 fingerprint 接线和 WIH 编排的两个离线测试桩，再重跑计划 5/6/7。
4. 在隔离部署环境补足 MongoDB、RabbitMQ、Redis、Celery、浏览器视觉与多架构验证。

## 8. 讨论决议与本轮实施状态

| 项目 | 决议 | 本轮状态 |
|---|---|---|
| F-01 任务 owner 过滤 | 当前单用户部署，暂缓；未来启用多登录用户前需补齐 | 未修改 |
| F-02 域名任务范围 | 根域包含其后代；子域只包含自身及其后代 | 已修改，未测试 |
| F-03 截图上传读取上限 | 按现有上传惯例暂缓，作为后续加固项 | 未修改 |
| F-04 PoC 同步 | 全局单实例是预期行为，消除并发重复创建 | 已修改，未测试 |
| F-05 单项资产范围删除 | 使用 DELETE；整组批量删除继续 POST | 已修改，未测试 |
| F-06 指纹规则导入 | 修复 PyYAML 6 兼容、请求体限制及格式校验 | 已修改，未测试 |

本轮没有运行测试或构建。此前第 3 节的通过/失败结果都是这些修改前的基线结果；代码差异仅做静态检查。
