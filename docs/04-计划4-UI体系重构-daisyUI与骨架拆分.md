# 04 计划4：UI 体系重构（daisyUI 组件层 + 骨架拆分 + 性能）

状态：**修订执行版，待最终确认**（遗留决策点见文末）。启动前提：**x86 构建与基础 smoke 验证完成后即允许启动 UI 开发**；64 目标性能门禁与生产部署验收不前置，仍按总计划排在全部重构最后执行。

## 决策结论（TL;DR）

1. **后端保留 Flask**。前后端已完全分离，Flask 只做 JSON API/鉴权/导出，扫描重活在 Celery；换框架收益为零。导出专项见"后端附带项"。
2. **UI 采用 daisyUI 5 做组件层**（Tailwind v4 CSS-first 接入，不引入第二套样式体系、不引 antd 等并存库）；现有 `brand-*` CSS 语义 token 与 `[data-theme]` 多主题机制保留并注册为 daisy 主题。
3. **根治"页面套页面/割裂感"靠骨架收敛而不是调色**：滚动源收敛 + 统一 Page/Card/Modal/Table 四件套 + App.tsx 按已存在但未接线的 `components/` 目录完成拆分。

## 现状诊断（基线由脚本采集，禁止手填）

数据唯一来源：`./scripts/collect-ui-baseline.sh`（重构各阶段前后各跑一次，输出贴进 docs/03 批次记录）。最近一次实测（rev `c2c0a9cd`，2026-09-04）：

| 指标 | 值 |
|---|---|
| App.tsx 行数 | **18936** |
| src 总行数 / components 文件数 | 19859 / **16**（多为未接线的占位壳） |
| `brand-*` 类内联引用行数 | 894 |
| overflow-* 使用次数 | 64 |
| 内联 modal 遮罩块（`fixed inset-0 bg-black`） | **19** |
| useEffect 站点 | 42 |
| API fetch 调用点 | 3（**已有统一封装**，问题在 42 处手写 useEffect 拉取状态机，不在 fetch 本身） |
| 最大 JS chunk | 1197046 B（gzip ≈328KB），无代码分割 |

症状→根因对照：

| 症状 | 根因 | 证据 |
|---|---|---|
| 资产页双滚动条、页中页 | 根 `h-screen overflow-hidden`（App.tsx:18816）→ `main overflow-y-auto`（:18823）→ 部分表格卡再套 `max-h + overflow-y-auto` | overflow 64 处、逐页不一致 |
| 居中/对齐不统一 | 无共享 PageHeader/Card/Modal，19 个内联 modal 各写各的遮罩、padding、对齐 | 基线脚本 |
| 内容割裂 | App.tsx 单文件承载全部模块页；`components/` 拆分半途而废 | 行数/文件对照 |
| 点击/响应慢 | 单 bundle 无分割；交互重渲染整棵巨型组件树；模块往返重拉数据 | chunk + 42 useEffect |

主题底子：`index.css` 已有完整语义 token（bg/card/border/accent/accent-strong/secondary/warning/danger/text/text-muted + rgb 分量 + alpha 分层）与 `[data-theme='midnight']` 多主题钩子——daisy 映射可无损平移。

## 目标架构

```
src/
  index.css         tailwind + @plugin "daisyui"（CSS-first，含主题注册与覆盖）
  layout/           AppShell / PageHeader / ScrollContainer
  components/
    ui/             Card / DataTable / Badge / Modal(原生<dialog>) / FormRow / CheckboxCard
    modules/        每个数据模块一页：TaskList / AssetList / WihEndpoint / NucleiResult / Vuln ...
    domain/         BrandLogo / Sidebar / AiAnalysisCell 等既有业务件
  api/              既有统一 fetch 封装 + react-query 查询层
  state/            主题、通知、全局 action
```

### 依赖与构建接入（当前 package.json 均未引入，属新增项）

| 依赖 | 接入方式 | 构建验证 |
|---|---|---|
| `daisyui@^5` | Tailwind v4 CSS-first：`npm install --save-dev daisyui`；`index.css` 加 `@plugin "daisyui" { themes: arl-dark {...自定义token...}, midnight {...} }`；**不使用** tailwind.config/PostCSS 旧接线 | 本地 `npm run build` + **x86 quick-build 镜像构建** + **arm64 容器构建** 双通过 |
| `@tanstack/react-query` | `main.tsx` 挂 QueryClientProvider | 同上 |
| `@tanstack/react-virtual` | 仅 DataTable 内部使用 | 同上 |
| 清理脚手架死重 | 移除 `express`、`@google/genai`、`@types/express`、`dotenv`（确认零引用后） | `npm run lint` + 构建 |

**lock 文件强制要求**：当前 `frontend-src` 无 `package-lock.json`，构建每次全量解析安装（此前 x86 构建 npm 层 400s+ 的直接原因之一）。规则：
- 新增依赖必须同步生成并提交 `package-lock.json`；
- Dockerfile 构建统一 `npm ci`（有 lock 即走 ci，禁止生产构建使用无锁 `npm install`）；
- 首次接入时以当前可构建状态生成基线 lock，之后依赖变更必须随代码同 commit。

### 滚动模型（收敛规则，非绝对禁令）

- **业务页面默认只有一个纵向滚动源**（全局 `main`）；表格卡不再自套 `max-h-[xvh]+overflow-y-auto` 纵向滚。
- **允许受控内部滚动**的明确白名单：弹窗内容（统一 `max-h-[72vh]` 单一来源）、日志/报文 `<pre>`、代码块、下拉列表弹层、侧边栏导航。判据：内部滚动必须有确定高度来源与可见滚动条样式（`custom-scrollbar`），且不吞页面滚轮（滚到边界交还）。
- 表格超宽仍用局部 `overflow-x-auto`；超长列表交给服务端分页（现有 API 已有 page/limit），行数 >200 时虚拟滚动。

### token 映射表（brand → daisy）

| 现有 | daisy 语义 | 备注 |
|---|---|---|
| --brand-bg | base-100 | 页面底 |
| --brand-card | base-200 | 卡片面（含 alpha 分层沿用现值） |
| --brand-border | base-300 系 | 边框仍可用独立变量 |
| --brand-accent-strong (#5f7892) | primary | 现 accent 饱和低，做按钮底色对比不足 |
| --brand-danger / warning | error / warning | severity 色阶在 badge 一处映射 |
| --brand-text / -muted | base-content / 60% | |
| [data-theme='midnight'] | daisy 同名主题注册 | 氛围层 CSS 不动 |

**主题完整定义要求（不只映射前景底色）**：daisy 主题注册必须同时定义 `primary-content`、`base-content`、`error-content`、`warning-content` 与 hover / focus / disabled 全状态色；`brand` 与 `midnight` 两套主题分别通过 WCAG AA 对比度检查（正文 ≥4.5:1，大字号/图标 ≥3:1，按钮主色与其 content 色成对检查），检查结果数值记入 Phase 1 验收。

### 组件映射（ad-hoc → daisy）

| 现状 | 目标 |
|---|---|
| 19 个内联 modal 遮罩块（wihEndpointDetail / riskRecordDetail / aiDenoiseDetail / taskErrorDialog 等） | 统一 `<Modal>`：原生 `<dialog>` + `modal-box`，Esc/遮罩/焦点行为一致 |
| `CONSOLE_CHECKBOX_CARD_CLASS` 等手写 checkbox 卡 | `label + input-checkbox/toggle` |
| 手写 `<table>` + 行内样式 | `table table-zebra` + `DataTable`（列定义驱动，替代 columns 字符串魔法） |
| 状态/等级彩色小字 | `badge badge-*`，severity→色一处定义 |
| 任务详情 service 列表 | `collapse` / `timeline` |
| Dashboard 指标数字 | `stats` |
| 各页页头/工具栏 | `PageHeader`（标题+操作+筛选，全站一处对齐规则） |

### 数据层（react-query 能力边界，防误解）

react-query **只解决 UI 页面切换/返回时的 API 重复拉取与加载态闪烁，不替代后端 DiscoveryContext 的响应复用**（那是扫描引擎内部网络层，两者无交集）。接入规则与验收：

- query key 必含：`[module, taskId, filters, page, pageSize]`——任务上下文与筛选变化必须产生新 key；
- 运行中任务页 `staleTime` 短（默认 0 + `refetchInterval` 沿用现有轮询节奏），已完结任务页 `staleTime` 长（≥30s），避免状态展示滞后；
- 变更失效：任务创建/删除/重启、批量操作、配置保存成功后对相应 key `invalidateQueries`，禁止靠加大 staleTime 掩盖失效缺失；
- **不得改变**任务状态语义、阶段指标字段与任何结果文档字段——react-query 只是读侧缓存，写路径与轮询协议保持现状。

## 分阶段执行与验收

执行顺序（评审定稿）：**① 冻结 → ② 基线 → ③ Phase0 → ④ Phase1 → ⑤ Phase2 → ⑥ 数据层 → ⑦ 性能 → ⑧ 构建与回归**。

**Step 1 · 冻结**：API 请求/响应契约、结果字段、任务状态语义、导出行为全量记录（curl 样本入 docs 附录或测试夹具），重构期间只读不改。

**Step 2 · 自动基线**：`scripts/collect-ui-baseline.sh` 输出存档；Lighthouse/手动计时记录 TTI、点击→可交互、模块切换耗时。

**Phase 0 · 骨架止血**（不引 daisy；~半天）：滚动白名单模型落地、页头/卡片统一、`main` 单滚动。
验收：资产/接口/风险三页各只剩一个纵向滚动源；before/after 截图对。

**Phase 1 · daisyUI 组件层**（~2-3 天）：依赖接入（上表方式）、`ui/` 六件套、19 个 modal 收口 `<Modal>`、badge/table/checkbox 替换、清死重依赖。
验收：`brand_class_lines` 显著下降（目标 <300，脚本度量）；`inline_modal_blocks` ≤1（Modal 组件自身）；视觉走查每模块抽 3 屏；`npm run build` + x86/arm64 镜像构建通过。

**Phase 2 · 模块拆分**（~3-5 天，与 Phase1 交替推进）：逐页搬入 `modules/`（目标 App.tsx <3000 行，只留路由壳与全局状态）。
验收：任一模块页可独立 review；`App_tsx_lines` 达标；模块页行为与冻结契约逐项一致。

**Phase 3 · 数据层**（~1-2 天）：react-query 按上节规则接入。
验收：模块往返 Network 面板无重复请求（对比 42 个 useEffect 迁移前后）；失效路径用例（建任务→列表出现、删任务→列表消失、重启→状态翻转 ≤ 一个轮询周期）；API 请求数量对比基线不升。

**Phase 4 · 性能**（~1 天）：路由级 `React.lazy + Suspense`、大表虚拟滚动。
验收：`largest_js_bytes` 预算——首屏 chunk gzip <180KB，产出 chunk 报告贴批次记录；Lighthouse TTI/INP 对比。

**全阶段回归清单（每阶段末执行）**：
- 既有 HTTP API 请求/响应兼容（对照 Step 1 冻结样本）；
- 任务状态 `pending/degraded/failed/done` 与阶段 service 展示正确；
- `sources` 来源聚合展示不回退；
- 分页、筛选、批量操作、导出（含异步 job 轮询下载）逐项冒烟；
- 主题切换（brand/midnight）与键盘操作（Tab/Enter/Esc，重点 `<dialog>`）；
- Safari 与两个容器架构（ARM64 Docker、amd64 Docker）构建+冒烟；
- chunk 预算与 API 请求数量脚本比对基线。

## 后端附带项（独立提交，不占 UI 阶段）

异步导出链路（job 仓储 + Celery + 轮询下载）**已存在**，本专项是复核与实现替换，不是从零异步化：

1. `save_virtual_workbook` 兼容替换——openpyxl 3.x 无此 API，改 `BytesIO + workbook.save(buf)`（顺带消除 requirements 版本锁死风险）；
2. 导出进程资源占用——大表导出的内存/CPU 上限复核（openpyxl 非 read-only 模式全量驻留内存），必要时 `write_only=True`；
3. 过期与失败态——job 文件 TTL 清理、失败状态回写与重试语义复核；
4. 多 worker 文件共享——导出文件落在哪、`arl_web` 与 worker 是否同一卷（compose 现状：`./image` 挂载需覆盖导出目录），轮询下载跨节点时的路径一致性。

## 风险与约束

- **冻结窗口**：x86 验证轮结束前 `frontend-src` 不动；各 Step 独立可回滚。
- **不破坏项**：多主题 `data-theme`、氛围层、导出下载链接、AI 分析单元格交互语义。
- **不做项**：不引 Next/SSR；不并存第二 UI 库；本轮不做 i18n。
- `<dialog>` 旧 Safari 行为差异列入回归清单键盘项。

## 遗留决策点（开工前确认）

1. `primary` 取 `accent-strong`（保守）还是提饱和重定主色（更跳，动品牌观感）。
2. Phase 2 拆分粒度：按 `modules` 配置驱动拆（现状延续）vs 真实路由组件（推荐；配置驱动是"页中页"的组织根源之一）。
