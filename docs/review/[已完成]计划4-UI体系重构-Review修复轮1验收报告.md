# 计划4 UI 体系重构：Review 修复轮 1 验收报告

## 1. 验收范围

- 计划文档：[docs/plan/[进行中]04-计划4-UI体系重构-daisyUI与骨架拆分.md](<../plan/[进行中]04-计划4-UI体系重构-daisyUI与骨架拆分.md>)
- 修复提交：`bd6a299e`（Review 修复轮 1）、`c8b9a537`（Review 修复轮 2）
- 记录补充：`77cbc126`（同步更新 docs/03 执行记录）
- 验收日期：2026-09-04
- 验收方式：静态审查、TypeScript 检查、生产构建、主题对比度检查
- 本轮未修改业务代码、未重启容器；工作区中既有的 README、CHANGELOG 和文档目录调整不纳入本轮代码结论。

## 2. 总体结论

**Review 修复轮 1/2 静态验收通过，进入联调与部署验收阶段。**

密钥注入、列表本地缓存、任务列表轮询、全局新建任务失效、视图错误边界、Modal 无障碍名、稳定行 key、前端依赖锁定和 AI 用量日志 DataTable 接入均已落地。未发现新的代码阻断项；剩余内容属于容器、浏览器、性能和自动化测试验收。

## 3. 逐项验收

| 评审项 | 结论 | 证据与说明 |
|---|---|---|
| `GEMINI_API_KEY` 前端注入 | 通过 | [vite.config.ts](../../ARL/docker/frontend-src/vite.config.ts:19) 仅保留版本号常量；`.env.example` 和前端 README 已改为后端 `/api` 边界说明；构建产物中未检出 `GEMINI_API_KEY`。 |
| 列表本地缓存长期复用旧数据 | 通过 | [TableModuleView.tsx](../../ARL/docker/frontend-src/src/views/TableModuleView.tsx:455) 已移除一次性 `moduleListLoadedRef` 语义，快照只用于即时绘制，数据新鲜度交由 `fetchQuery` 判断。 |
| React Query 失效与任务轮询 | 通过 | [TableModuleView.tsx](../../ARL/docker/frontend-src/src/views/TableModuleView.tsx:992) 已接入按模块、分页、排序和筛选签名的查询缓存；任务存在 `running/waiting` 行时按 15 秒轮询；列表动作和全局动作均会失效缓存。全局动作另通过 `refreshSignal` 触发当前任务列表显式刷新。 |
| `Suspense` 外错误边界 | 通过 | [App.tsx](../../ARL/docker/frontend-src/src/App.tsx:345) 已使用 `ViewErrorBoundary` 包裹视图区，异常会展示恢复页面并保留控制台证据。 |
| Modal 无障碍名称 | 基本通过 | [Modal.tsx](../../ARL/docker/frontend-src/src/components/ui/Modal.tsx:38) 打开时自动绑定首个标题到 `aria-labelledby`，现有调用点无需逐一改动。尚未完成 Safari 和真实键盘交互验证。 |
| 行 key 稳定性 | 通过 | [TableModuleView.tsx](../../ARL/docker/frontend-src/src/views/TableModuleView.tsx:3461) 和 [DashboardView.tsx](../../ARL/docker/frontend-src/src/views/DashboardView.tsx:532) 均使用稳定兜底；全仓 `Math.random()` 仅剩 Modal 标题 ID 的一次性生成。 |
| Docker 前端依赖锁定 | 通过静态审查 | [Dockerfile](../../ARL/docker/Dockerfile:58) 已在前端 builder 缺少 `package-lock.json` 时直接失败并强制 `npm ci`；`tools/wih` 的无锁回退属于外部上游目录，保留合理。 |
| DataTable 实际消费 | 部分通过 | [AiConsoleView.tsx](../../ARL/docker/frontend-src/src/views/AiConsoleView.tsx:2327) 已接入 AI 用量日志表，虚拟滚动路径存在真实消费者；`TableModuleView` 主列表仍为自定义表格，按当前决策留给 Phase2b/联调窗口。 |
| React 类型门禁 | 通过但需加强 | 已补 `@types/react`、`@types/react-dom`，当前 `tsc --noEmit` 为真实类型检查并通过；`tsconfig.json` 尚未启用 `strict`，建议后续分阶段开启。 |

## 4. Review 修复轮 2 复核

### Dashboard 行 key

已修复为 `taskId || recent-task-{index}`，不再根据渲染次数生成随机 key。

### 全局新建任务缓存失效

已修复：[App.tsx](../../ARL/docker/frontend-src/src/App.tsx:278) 在非下载全局动作成功后执行任务列表缓存失效并递增刷新信号；[TableModuleView.tsx](../../ARL/docker/frontend-src/src/views/TableModuleView.tsx:490) 将该信号纳入激活取数依赖。

该链路覆盖两种场景：

- 当前已在任务页：刷新信号使列表重新取数；
- 当前不在任务页：打开任务模块时按同一套失效状态取数。

静态复核未发现轮 2 新增问题。

## 5. 已执行验证

| 检查项 | 结果 |
|---|---|
| `npm run lint`（`tsc --noEmit`） | 通过 |
| `npm run build` | 通过 |
| 首屏最大 JS chunk | gzip `142.10KB`，低于 `180KB` 预算 |
| 6 套主题、12 类对比度检查 | 全部通过，最低 `4.58:1` |
| `git diff --check bd6a299e^ bd6a299e` | 通过 |
| 构建产物检索 `GEMINI_API_KEY` | 未发现 |
| Git 跟踪构建产物检查 | 未发现 `dist`、`node_modules`、Rust `target` 或 wheel |

## 6. 尚未执行

- amd64/x86 Docker 构建和 smoke test；
- ARM64 Docker 构建和同套 smoke test；
- Safari `<dialog>` 的 Tab、Enter、Esc 和焦点行为；
- 视觉走查（每模块 3 屏）；
- Lighthouse TTI/INP；
- Modal、DataTable、任务轮询和缓存失效的自动化 UI 测试；当前前端未发现 Vitest、RTL 或同类测试基建。

## 7. 最终建议

1. 决定是否将 UI 测试基建纳入计划 4 收尾；若暂不引入，应在计划文档中明确记录豁免范围。
2. 完成 Docker 双架构、Safari、视觉和后端在线联调验收。
