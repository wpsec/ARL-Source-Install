# 更新日志

本文件记录 `newUI` 分支的重要变更。  
日志按日期合并维护：同一天内的修复统一写在同一条日期记录下，并在条目前标注版本号（PATCH 级别详细变更以本文件为准），版本号从下往上。

## 2026-04-09（v4.6.51）

- `[v4.6.51]` `WIH` 隐藏接口发现能力增强：静态扫描阶段开始递归跟踪懒加载 `JS chunk`，不会再只停留在入口脚本；新增前端页面候选提取，能从 `Vue Router` 等路由定义、`router.push/replace`、`location.href/assign/replace`、`window.open` 等导航语义中恢复页面入口，并对 `/login/:sysCode?` 这类模板路由自动降级为 `/login`，`hash route` 也会同步沉淀为页面与目录候选。运行时 `Playwright` 链路现在会接收这些页面候选并优先访问登录页、认证页、管理页，同时允许低风险点击“密码登录 / 管理员登录 / 其他登录方式 / 登录方式切换”等认证模式切换动作，但明确避开真实提交按钮与高风险动作；交互后会直接从当前 DOM 抽取同域表单的 `action/method/enctype/字段骨架`，将新出现的隐藏登录接口作为结构化接口面产出，而不主动提交凭证。对应补齐懒加载 chunk、路由候选、`hash route` 与递归扫描回归测试，帮助 `WIH` 更适合承担“替代人工啃前端 JS 找隐藏接口”的工作
- `[v4.6.52]` `WIH/ARL` 隐藏登录口挖掘与结果口径继续收口：`WIH` 继续增强“更像人工”的页面状态探索能力，运行时开始递归消费同源 `iframe`、`shadow DOM`、响应体里的 `HTML/JSON/JS/XML` 文本线索，并捕获 `history.pushState/replaceState/hashchange/popstate` 导致的当前页面 URL 变化，让“默认 SSO / 点击密码登录后切到隐藏登录页”的场景更容易被沉淀为页面候选与接口面；静态链同时补强前端框架状态恢复与轻度反混淆，可从 `page/fullPath/route/loginUrl/adminPath` 等内联状态、`atob/decodeURIComponent`、字符串拼接与模板字符串中恢复登录页、管理页和隐藏导航入口。与此同时，`ARL` 侧 `WIH接口提取` 不再对 `WIH` 结构化接口做二次轻量验证，任务落库、页面展示和导出统一改为直接使用 `WIH` 原始 `status_code/response_size`，无响应时保持 `-`，避免平台侧补探测导致与单独运行 `WIH` 的结果口径不一致；同任务重扫时也会用最新 `WIH` 原始记录覆盖旧的接口结果，减少历史补探测数据残留
- `[v4.6.53]` `WIH` 参数值恢复与更深状态切换探索继续推进：静态链新增面向 `bootstrap API / inline state / config.js / localStorage / sessionStorage` 的值候选恢复，开始把 `dt/sysCode/tenant/appId` 这类键从页面状态、存储写入与字符串表达式里提出来，并参与 `router path`、模板字符串、查询参数与隐藏页面 URL 的展开，让 `/login/:sysCode`、`/portal/:tenant/app/:appId`、`/Login?dt=...` 这类入口不再只停留在模板层。运行时链同步补充状态值池与更深的交互探索，开始从 `__NEXT_DATA__ / __NUXT__ / __INITIAL_STATE__ / __CONFIG__ / __BOOTSTRAP__ / __MICRO_APP_STATE__` 等全局状态、`script[type="application/json"]`、浏览器存储、响应体文本中持续恢复页面候选和值候选，并把这些值继续用于页面队列展开；低风险交互也继续覆盖 `menu / tree / dropdown / data-route / router-link / micro-app` 等复杂 `tab`、菜单与微前端切换入口，帮助 `WIH` 更稳定地接近“人工点开隐藏登录方式、再跟着状态跳转继续挖接口”的过程。对应补齐值恢复与模板路由替换回归测试，避免后续增强把这条主链弄丢
- `[v4.6.54]` `WIH/ARL` 通用隐藏页面候选保留补齐：继续把能力从“识别登录隐藏口”收口到更通用的“发现前端未直露页面与接口面”。`WIH` 现在会把同 host 的页面候选直接沉淀为 `page_url` 记录，不再只把它们塞进 runtime 队列里等待后续访问；这意味着 `/portal?tenant=...`、`/entry?scene=...`、`/Login?dt=...` 这类带查询参数的隐藏页面，即使最终没来得及转成接口，也不会在结果里凭空消失。运行时 `Playwright` 链路也开始把真实访问过和运行时新发现的页面 URL 回写成 `page_url` 记录，并把低风险点击策略进一步向 `data-route/data-url/router-link/href/micro-app` 等导航语义倾斜，降低对特定业务文案的依赖。与此同时，`ARL` 侧 `urlfinder_url_probe`、后续 URL 候选消费与渗透候选收集开始接纳 `page_url` 记录，让这类隐藏页面 URL 能继续进入可达性探测和后续分析链，而不是只在 `WIH` 内部短暂停留

## 2026-04-08（v4.6.39 ~ v4.6.50）

- `[v4.6.50]` 导出报告风险凭证列补齐：`风险` 工作表新增“凭证”列，优先导出 `credential` 字段，缺失时回退到 `verify_data`，让 `WIH` 敏感信息、弱口令、凭证泄漏等风险在报告里可以直接看到泄漏内容或验证信息，不再只能从“详情”列里间接推断。风险摘要里疑似误报读取“详情”列的索引也同步跟随新列调整，避免报告结构变化后引用错列
- `[v4.6.49]` `WIH接口提取` 验证状态提示优化：新增接口轻量验证后处理，`WIH` 接口结果在任务范围校验通过后，会对 `GET/HEAD/POST/OPTIONS` 尝试低超时轻量验证并回填状态码与响应大小；`DELETE/PUT/PATCH/TRACE/CONNECT` 等可能产生副作用的危险方法不主动请求，改为落库 `verification_status/verification_note` 并在页面、详情弹窗和导出报告中提示“未验证/危险方法未主动验证”。旧数据缺少验证字段时也会从方法推断显示为“未验证”，不再只显示容易误解的 `-`
- `[v4.6.48]` 任务删除关联结果清理修复：任务管理页删除单个任务、批量删除任务、停止并删除任务时，前端会明确传入 `del_task_data=true`，让后端同步清理该任务产生的资产搜索结果数据，避免任务记录已删除但站点、域名、URL、目录扫描、`WIH` 等任务结果仍在资产搜索页残留。后端级联清理名单同步补齐 `wih_endpoint`，确保新增的 `WIH接口提取` 数据也会随任务结果清理，同时不触碰已经同步到资产组的 `asset_*` 表，降低误删正式资产组数据的风险
- `[v4.6.46]` `WIH接口提取` 格式与导出继续收口：`WIH` 结构化接口提取补强 `application/json / application/x-www-form-urlencoded / multipart/form-data / text/xml / application/xml / text/plain / application/octet-stream` 等 `POST` 请求体识别，运行时与静态 `JS` 提取都会尽量保留更准确的 `content_type/body_kind/body_text/request_packet`，避免 `text/plain` 中的 `a=b` 被误判为表单。`ARL` 入库侧同时修复接口 URL 已带查询参数时又追加同名同值参数导致的重复 query；`WIH接口提取` 页面与导出对未知状态码/响应大小不再展示误导性的 `0`，而是显示为 `-`。此外，资产导出 Excel 与钉钉知识库报告新增 `WIH接口提取` 工作表，包含序号、目标、页面 URL、方法、状态码、响应大小、请求 URL 与请求报文，方便直接复核和复现接口
- `[v4.6.45]` 部署文档与离线浏览器包流程优化：`tools/playwright/README.md` 改为推荐按 `tools/wih` 锁定的 Node 版 `Playwright` 生成离线浏览器包，并补充宿主机无 `npm` 时使用 Docker Node 镜像生成 `ms-playwright` 离线包的方式；主镜像中 `WIH` Node 依赖安装阶段保持 `PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1`，不再二次执行 `npx playwright install chromium`，避免已准备离线包后仍触发在线下载
- `[v4.6.44]` Docker `npm/npx` 运行时入口修复：主镜像从前端构建阶段复用 Node 20 时，不再直接复制 `/usr/local/bin/npm` 与 `/usr/local/bin/npx`，避免 Docker `COPY --from` 将 symlink 解引用成脚本文件后触发 `Cannot find module '../lib/cli.js'`。现在改为复制 Node 与全局 npm 模块目录后，在 runtime 阶段显式重建 `npm/npx` symlink，并提前执行 `node/npm/npx --version` 自检，让 WIH Playwright 依赖安装能继续进入后续步骤
- `[v4.6.43]` Docker `WIH Playwright` 构建链路修复：`tools/wih` 的 `package-lock` 调整为兼容性更好的 `lockfileVersion=2` 并同步包名，避免部分 `npm ci` 场景报 `Cannot read property 'playwright' of undefined`；镜像构建阶段在安装 Node 版 `playwright` 时跳过 postinstall 浏览器下载，并改为非阻断方式尝试补装 `chromium`，保证离线/弱网环境下主镜像构建不被浏览器下载失败卡死。同时补充 `node/npm` 版本输出与 `.dockerignore` 中 `tools/wih/node_modules` 排除规则，减少本地依赖污染构建上下文并提升后续排障可读性
- `[v4.6.42]` Docker `WIH runtime` Node 版本收口：主镜像运行阶段不再依赖 Rocky/EPEL 的 `nodejs npm` 包，改为复用前端构建阶段的 Node 20、`npm/npx` 与全局 npm 模块路径，避免系统仓库 Node 版本偏旧导致 `WIH` 内置 `Playwright` runtime 依赖安装或运行异常
- `[v4.6.41]` Docker `NPM_REGISTRY` 参数作用域修复：在主镜像运行阶段补充 `ARG NPM_REGISTRY`，确保后续 `tools/wih` 的 Node 依赖安装能正确继承构建时传入的 npm 镜像源，避免多阶段 Dockerfile 中前端阶段的 `ARG` 无法传递到 runtime 阶段而导致构建脚本变量未定义
- `[v4.6.40]` `WIH接口提取` 结果页落地：资产搜索/任务详情的 `WIH` 旁新增 `WIH接口提取` 页面，列表展示目标、页面 URL、请求方法、状态码、响应大小与详情入口，并保持与现有 ARL 表格交互一致。后端新增 `wih_endpoint` 集合与查询/删除/导出接口，`InfoHunter` 会从 `WIH` 结构化 `endpoints` 中归一化接口 URL、请求模板、请求报文、响应状态与大小，并在任务链路中按 scope 校验后独立落库；详情弹窗支持 `GET` 展示带参数 URL、`POST` 展示请求 URL，同时统一展示可复制请求报文，方便后续人工复核与复现
- `[v4.6.39]` `WIH/目录扫描` 展示链路打通：`urlfinder_url_probe` 现在会把 `WIH` 提取并探测命中的 `path_url/urlfinder_url` 同步写入 `fileleak` 目录扫描集合，来源统一标记为 `wih_url_probe`，同时保留原 `URL信息` 入库逻辑。原目录扫描字典爆破结果新增 `dict_brute` 来源标识，历史无来源记录在列表与导出时兜底展示为“字典爆破”；前台目录扫描页新增“来源”列和来源筛选，批量导出也同步补充来源列，便于区分 `WIH` 接口发现与传统字典爆破结果

## 2026-04-06（v4.6.36）

- `[v4.6.36]` `WIH` 独立能力与 `ARL` 兼容链路同步收口：`tools/wih` 这一轮围绕“独立可用 + 结果更可消费”做了较大一轮完善。扫描链新增同域范围约束与静态浅层页面探索，开始继续抓取同 host 下的 `a[href] / iframe[src] / GET form action` 页面，并把下一层页面里的表单接口、GET/POST 参数和额外 `JS` 继续纳入结果；运行时链默认启用内置 `Playwright`，`records/endpoints/parameters` 输出补齐中文表头、请求报文展示、接口状态码与响应大小，`CSV` 文件输出统一收口为单个 `xlsx` 工作簿多工作表，结构化与主输出目录也调整为按“域名 + 时间戳”落盘，减少覆盖和产物散落。与此同时，为避免 `ARL` 运行依赖 `WIH` 的默认行为，`ARL` 侧同步新增 `WIH_RUNTIME_*` 配置项，并在 `InfoHunter` 调用 `wih` 时显式透传 `runtime-enable/driver/timeout/max-pages/max-actions/max-requests` 与 `disable-structured-output`，保证平台侧行为稳定可控；主 Docker 镜像也补装 Node 版 `playwright` 运行环境，确保容器内默认 runtime 链路可直接工作
- `[v4.6.36]` `WIH/ARL` 输出与代理联动细节继续收口：`WIH` 新增 `--output-dir`，`--csv` 在未显式指定 `-o` 时默认落盘为 `result.xlsx`，多目标任务在保留“每目标单独目录”的同时补充任务级汇总 `CSV/XLSX`；同时静态抓取请求与内置 `Playwright runtime` 现在都会自动携带 `X-WIH-Target` 并共同继承 `-x/--proxy`，便于在 `Burp` 等代理中按目标批量筛选运行时流量。对应 `ARL` 侧 `InfoHunter` 帮助探测、超时切分与回归测试也已重新校验，保证现有 `-J -o -t` 调用协议不受影响

## 2026-04-05（v4.6.14）

- `[v4.6.34]` `WIH参数提取` 静态变量引用解析增强：继续补强 `JS` 静态参数提取对现代前端写法的适配。当前静态链已经可以识别更多“先定义变量、后传入请求”的模式，例如 `const payload = {...}; axios.post(url, payload)`、`params: queryData`、`headers: authHeaders`、`variables: variables` 等，不再只依赖请求调用点内联对象字面量。与此同时，`GraphQL` 请求模板也进一步增强，若查询文本先绑定到变量，再在请求里通过 `query: gqlQuery` 传入，静态链会尽量把真实 `query` 文本保留下来，而不是回退成默认占位查询。对应回归测试已补齐，并通过 `go test ./scan ./dataType ./util`
- `[v4.6.33]` `WIH参数提取` 静态链继续补强：`tools/wih` 继续沿“静态分析 + 运行时 Hook + 交互驱动”三条主线往前推进。静态链这轮新增 `SourceMap` 利用能力：扫描 `JS` 时会优先解析 `sourceMappingURL`，消费 `sourcesContent`，并在缺少内嵌源码时回拉少量同 host 源文件，再把这些源码继续送入现有接口与参数提取链。与此同时，`JS` 静态参数提取新增 `schema hints` 过渡增强，开始从 `zod / yup / joi / json schema` 中回填 `type / required / default / enum / schema_lib` 到已提取参数，并把 `GraphQL query` 文本尽量保留到请求模板里，不再总是落成默认占位查询。运行时链同步补入 `WebSocket` Hook，进一步扩大现代前端下的动态接口面覆盖。对应 `WIH` 规划文档也已更新为“现状版”，明确当前已完成能力、过渡实现与剩余未完成项
- `[v4.6.31]` `WIH参数提取` runtime 页面探索与结构化观测增强：内置 `Playwright` 运行时驱动继续沿“运行时 Hook + 低风险探索”主链推进，`--runtime-max-pages` 现在会真实参与同 host 页面浅层探索，驱动会在目标页之外继续从 `a[href] / iframe[src] / GET form action` 中收集候选页并按预算顺序访问；同时在原有页面内 `fetch/xhr/sendBeacon` Hook 之外，新增基于 `Playwright page.on('request')` 的网络请求观测补充，用于覆盖原生表单跳转和部分未被页面 Hook 捕获的请求。运行时 endpoint 去重也从“完整 URL 值”收口为更偏接口面的 `method + origin/path + query键集合 + body键集合 + body_kind`，减少分页、筛选值变化导致的大量近似重复记录。配套地，runtime 归一化结果开始稳定补齐 `endpoint.page_url`、`parameter.source=runtime`、`parameter.source_detail.page_url` 与 `parameter.occurrence_count`，让 `WIH` 脱离 `ARL` 独立输出时，运行时参数结果也具备更完整的页面来源与观测频次信息；对应 Go 回归与 Node 语法校验已同步通过
- `[v4.6.30]` `WIH参数提取` 最小 `Playwright` 运行时驱动落地：`tools/wih` 继续沿“运行时 Hook + 低风险自动交互 MVP”推进，扫描主链路新增 `runtime-driver=playwright`，在不再手工拼 external 命令的前提下即可直接调用仓库内置的 `tools/wih/runtime/playwright_driver.js`。这版驱动已能在真实浏览器里采集页面加载期的 `fetch / xhr / sendBeacon` 请求，并补充 `xhr.setRequestHeader`、`json/graphql/form` 请求体解析，同时开始执行少量可审计的低风险交互，例如搜索类输入框填充、`select` 切换、`tab` 切换，以及“搜索/筛选/下一页/更多”等弱副作用按钮点击，尽量在不引入明显高风险动作的前提下把动态参数提取能力从“首屏请求”推进到“轻交互后的运行时请求”。配套地，`WIH` 运行时文档与主 `Readme` 也同步更新，明确了内置 Playwright 驱动的启用方式、依赖前提、当前能力边界与 external driver 契约的并存关系；与此同时，`js_surface` 里历史遗留的 Go 标准库正则不兼容写法也一起清理，并补上对象简写参数与 `runtime graphql` 参数位置推断的修复，保证这轮 `runtime + 静态 JS + 表单` 三条基础链可以在同一组测试里稳定通过
- `[v4.6.14]` 前台主题 `质感重做`：针对 `钛金黑/专业灰蓝/午夜科技/北欧极光` 统一收口了主题底色、卡片透明度与氛围层，不再继续用大面积高斯模糊彩团堆氛围，改为更干净的径向背景层，减少深色主题下容易出现的“虫影/脏影”观感；其中 `钛金黑` 也从偏蓝黑重做为更接近石墨钛金的中性黑灰。与此同时，`ARL Logo` 改为按主题分别走更协调的材质色，不再除了 `砂岩白` 外都统一顶一个过亮的蓝色块，侧栏主题色预览同步调整为更贴近实际主题观感
- `[v4.6.15]` `AI渗透测试` 筛选与接口展示收口：列表筛选新增 `类型` 与 `获取接口` 下拉，`获取接口` 支持直接筛 `POST>0 / GET>0`；来源下拉补齐 `目录扫描` 并统一改为精确匹配。详情页里重复的“示例接口”区块已移除，只保留真正来自 `JS` 提取链路的接口样例，减少同一批接口被重复展示。与此同时，`POST` 复制逻辑从原先经常只剩“请求行 + Host”提升为更接近可复现请求包的形式：会按已有上下文或请求画像补 `User-Agent / Accept / Content-Type / Content-Length` 及 `body` 模板，`json/form/multipart/xml` 等常见形态也会尽量给出对应的参数化请求体，减少复制出来却无法直接使用的信息噪声
- `[v4.6.16]` `站点爬虫` 发现率增强：在不放宽 `host` 边界的前提下，先修正了 URL 相似去重逻辑，避免不同路径但查询参数名相同的 URL 被误压成一条；与此同时，站点爬虫启动时新增 `robots.txt / sitemap.xml` 入口发现，能够直接把同 host 下的 sitemap 页面纳入首轮 URL 采集。对于未开启 `web_info_hunter` 的普通站点爬虫任务，后处理阶段也会额外补跑一次 `page_intel + urlfinder + urlfinder_url_probe`，把页面里的 `script/js` 与静态文本里能提出来的同 host URL 继续探测并写入 `URL信息` 表，从而在保持任务范围收敛的同时，提高现代前端站点下的 URL 覆盖率
- `[v4.6.18]` `WIH参数提取` 第一阶段启动：开始把 `WIH` 从“文本命中器”往“结构化接口/参数发现器”推进。`tools/wih` 新增 `endpoint / parameter` 结构化数据模型，并将其直接挂入 `ScanResult`，保证 `JSON` 输出在独立运行时也能携带接口与参数结果。与此同时，扫描主链路先接入一版 `HTML form` 提取：能够从页面表单中识别 `action/method/enctype`、输入字段、`required/default/example/enum` 等信息，输出结构化 `endpoint/parameter` 结果，为后续的 `runtime hook / AST / schema / GraphQL` 提取继续叠加打底；文本输出也同步补齐最小的接口与参数摘要，避免 `WIH` 脱离 `ARL` 后新能力只能在平台侧可见
- `[v4.6.19]` `WIH参数提取` 独立输出与 `JS静态参数` 增强：`tools/wih` 继续向“脱离 `ARL` 也能完整使用”的方向推进，新增 `--endpoint-output / --parameter-output / --disable-structured-output` CLI 参数，主输出文件不是 `-` 时会自动推导并独立落盘 `xxx_endpoint.json / xxx_parameter.json`，方便单独消费结构化接口与参数结果。与此同时，扫描主链路补入一版 `JS` 静态接口/参数提取，开始覆盖 `fetch / axios / request({...}) / URLSearchParams / FormData.append / GraphQL variables` 等常见模式，把 `query/body/header/graphql_variable/path` 等位置的参数纳入统一 `endpoint/parameter` 模型，让 `WIH` 在独立运行时不只会提 `URL` 和表单参数，也能开始结构化消费前端脚本里的主要接口面
- `[v4.6.21]` `WIH参数提取` 参数画像与请求模板增强：继续围绕“让 `WIH` 脱离 `ARL` 也能直接输出可消费的接口/参数结果”推进。参数模型新增 `is_pii / entropy` 字段，开始在 `HTML form` 与 `JS` 静态提取链路中对 `password/token/authorization` 等疑似敏感字段做基础识别，并对示例值计算熵值，为后续参数排序、过滤和 AI 语义增强提供更稳定的底层画像。与此同时，`EndpointRequestTemplate` 扩展出 `path/query/body/query_string/body_text/request_packet` 等字段，`HTML form` 与 `JS` 静态提取结果会开始生成更接近真实请求的模板和请求包预览，而不再只是简单的参数名占位，方便后续独立消费 `endpoint.json` 时直接做接口面复用与验证
- `[v4.6.23]` `WIH参数提取` runtime 骨架接入：为后续浏览器运行时采集铺路，`tools/wih` 新增 `--runtime-enable / --runtime-max-pages / --runtime-max-actions / --runtime-max-requests` 参数，并把运行时采集调用点接入扫描主链路；当前阶段先提供默认 `noop` 的 `runtime_surface` 实现，保证独立工具在未接入浏览器依赖前仍可稳定运行，同时让后续 `fetch/xhr/FormData/URLSearchParams` 等真实 Hook 能在不改 CLI、预算配置与输出模型的前提下直接落到现有 `endpoint/parameter` 结构中。`Readme` 也同步补充了这组参数说明，明确该能力目前仍处于骨架阶段
- `[v4.6.25]` `WIH参数提取` external runtime driver 契约落地：继续把运行时采集从“空骨架”推进到“可接真实浏览器实现”的阶段。`tools/wih` 新增 `--runtime-driver / --runtime-command / --runtime-timeout` 参数，运行时链路现在支持通过 `stdin/stdout JSON` 调用外部 driver，并将返回的 `endpoints/parameters` 结果继续纳入同 host 过滤、参数画像与主链路归并中。这样后续无论接 `Playwright/CDP` 还是独立 Node 浏览器脚本，都不需要再重改 `WIH` 的 CLI、预算配置和结构化输出模型；`Readme` 也同步补充了 external driver 的接入说明与当前边界
- `[v4.6.26]` `WIH参数提取` runtime 结果归一化增强：继续把 external driver 返回结果从“能接入”推进到“可直接消费”的阶段。运行时返回的 `endpoint` 现在会自动补齐 `method/protocol/request_template/request_packet/body_kind/content_type` 等核心字段，`parameter` 也会在进入主链路前完成 `endpoint_id` 映射、`location/type` 推断、示例值回填以及 `is_pii/entropy` 元数据增强。这样外部 driver 端不需要完全理解 `WIH` 内部模型，只要按最小 JSON 契约返回基本的接口与参数信息，`WIH` 就能在主链路里完成标准化、同 host 过滤和结构化输出，减少后续浏览器实现的耦合成本
- `[v4.6.28]` `WIH参数提取` external driver 样例补齐：继续把运行时采集从“有契约”推进到“可直接照着接”。`tools/wih/runtime/` 目录新增最小可运行的 `external_driver_example.py`、输入样例 `request.example.json`、输出样例 `response.example.json` 与独立 `README.md`，把 external runtime driver 的 `stdin/stdout JSON` 契约落成可直接对照的样例文件；主 `Readme` 也同步补上这些文件入口，降低后续接入真实浏览器驱动时的试错成本

## 2026-04-05（v4.6.13）

- `[v4.6.13]` 临时下线 `渗透测试/AI渗透测试`：由于当前误报率过高，任务创建、策略新增/编辑与前台任务详情页已移除 `Web专项渗透测试 / AI渗透测试 / WAF绕过` 相关入口，资产视图里的 `AI渗透测试` 页签也先隐藏。后端同时新增统一兜底：无论通过新建任务、策略下发、资产组补扫、FOFA 下发还是历史任务重跑进入的任务参数，`penetration_test/ai_penetration_test/waf_bypass` 都会被强制收敛为 `false`；`/ai_pen_test/retry/` 与 `/ai_pen_test/batch_run/` 也会直接返回“功能已临时下线”，避免旧入口或遗留任务继续触发主动验证链路

## 2026-04-05（v4.6.12）

- `[v4.6.12]` AI渗透 `引用脚本接口面补齐`：当候选目标本身是普通页面而不是 `.js` 资源时，后端现在会继续从页面 HTML 与浏览器情报里的 `script src` 收集站内引用脚本，在任务范围内按需拉取这些脚本并补做一次 `JS API` 提取，把原本只藏在 `app.js/admin.js` 里的 `GET/POST` 接口、参数名与请求模板也并入 `js_api_targets/api_surface_summary`。同时新增轻量页面级 HTML fallback，不再只依赖浏览器情报那一小撮目标才能拿到脚本列表；JS 提取规则也补强了 `axios/request({...})` 这类配置式调用、模板字符串 URL 与对象简写参数（如 `{ id, mode }`）识别，减少现代前端打包产物里“明明有接口却一个参数都提不出来”的情况。对应回归同步补齐“合并 HTML + 浏览器脚本列表”“页面引用脚本继续提取接口”以及“配置式请求/页面 fallback 提取参数”等样例

## 2026-04-04（v4.6.11）

- `[v4.6.11]` `WIH/AI渗透` 误报与重复结果一并收口：继续压低前端静态资源里的 `secret_key/basic_token` 噪声，`secret=").concat(...)`、`Token="+变量`、`accessKey:"accessKey"`、`Basic c2FiZXI6c2FiZXJfc2VjcmV0`、`base64:` 作者/联系方式资料串，以及 `SECRET_DO_NOT_PASS_THIS_OR_YOU_WILL_BE_FIRED` 这类占位/调试/示例常量现在会统一识别为噪声，不再推进到 `WIH` 风险提升与 `AI渗透` 人工复核。同时，`WIH` 入库前新增统一记录规范化与重算哈希能力：对 `URL` 去掉默认端口、统一根路径与尾斜杠，对 `site` 收口到站点 origin，并在主任务链与资产监控链复用同一规范化入口，减少同一站点同一条记录因页面路径、首页写法或 URL 形式不同而被重复落库；对应回归同步补齐 `JS secret/bearer/basic` 噪声、站点页差异去重与根路径 URL 去重样例

## 2026-04-03（v4.6.1 ~ v4.6.10）

- `[v4.6.1]` 资产搜索 `AI渗透测试` 页签 UI 统一修复：点击该页签时不再误切到独立工作台视图，而是回到与 `站点/子域名/IP/SSL证书/服务/目录扫描/URL信息/风险/PoC风险/WIH/WAF识别` 一致的统一资产表格容器，修复“只有 AI渗透测试 点击后界面样式突变、不统一”的问题，同时保留原有 AI 渗透详情与操作能力
- `[v4.6.3]` 仪表盘 `资产增长趋势` 与 `今日新增` 统计修复：当 `/console/dashboard` 回退使用旧 `site` 集合时，7 日趋势与今日新增不再因为历史记录缺少 `save_date/update_date` 而长期显示 `0`；后端统计新增 `_id` 时间戳兜底，兼容老数据立即恢复趋势展示，同时为 `site` 新写入链路统一补齐 `save_date/update_date`，避免后续新增资产继续被统计漏掉，并补充对应回归测试覆盖 `update_date/_id` 双回退场景
- `[v4.6.4]` AI渗透 `误报进一步收敛`：继续压低“明显一看就是无风险却仍进入人工复核”的噪声结果。未授权直访现在会先识别统一认证/登录壳页面，带 `form + password/captcha/login` 语义的页面即使混入 `dashboard/console` 词也不再误判为未授权入口；管理后台/管理接口也从“弱关键词命中”收紧为必须出现更强的后台、身份或配置暴露信号才保留。与此同时，`SQL注入` 新增独立分级，只有 `error/time/boolean` 这类可复现利用证据才继续抬高，单纯响应差异默认降为 `likely_false_positive`；`文件上传/下载` 也区分“真实表单/附件/探针成功证据”和“仅路径命名线索”，像单独的 `upload.html` 这类入口名不再默认进入人工复核。最后，`JS/WIH` 敏感信息噪声继续收紧：`password:"password"`、`Token="+变量`、`token=")&&(SYNO.Debug("` 这类前端占位符、调试拼接和模板片段会直接按噪声压下，不再推进到风险/AI渗透候选；对应回归同步补齐，覆盖未授权登录壳、文件路径噪声、SQL 响应差异误报、JS 占位符与调试片段等典型高频样例
- `[v4.6.5]` AI渗透 `详情展示降噪`：AI 渗透详情、工作台列表与执行链路详情现在会根据最终结论、`HTTP` 状态、证据类型与说明文本识别“弱线索结果”；像 `404 + 当前证据不足`、仅命中文件路径命名线索这类记录，不再继续沿用“高价值文件处理入口”之类易误导标题，而会改成更贴近事实的“未证实弱线索”展示，并新增低优先处理提示。与此同时，`登录面黑盒摘要`、任务级图谱上下文、认知图谱摘要等背景区块也改成按内容是否真实有信息再显示，避免详情页继续堆满 `0 / 暂无` 的无效信息，减少人工复核时的视觉噪声与判断负担
- `[v4.6.6]` AI渗透 `请求画像与 POST 模板` 第一版落地：浏览器运行时情报现在不再只保留 `method/url/status`，而会额外采集并结构化保存 `request_headers/content_type/mode/body_kind/param_names/request_body_template` 等请求形态线索，让 `POST/PUT/PATCH` 接口第一次具备“接近真实请求模板”的基础。后端 `api_surface_summary.sample_interfaces` 与 `request_template_summary` 也同步扩展，开始统一归纳 `query/json_data/form_data/body`、`json/graphql/form_urlencoded/multipart/xml/text` 等请求画像，并额外落库 `request_profile_summary/display_decision/display_reason` 作为后续 AI 展示决策的统一结构。前台详情页则新增 `GET/POST` 分流复制：运行时接口请求样例支持“复制 GET URL / 复制 POST 模板”，接口结构摘要中的 `示例接口 / JS提取接口样例` 也支持按路径或 `POST` 模板一键复制，显著降低人工从页面抄接口和手拼请求包的成本；对应回归补齐运行时 GraphQL/JSON POST、请求画像归一化与 AI 合并请求画像等关键场景
- `[v4.6.7]` AI渗透 `运行时接口样例交互优化`：根据实际使用反馈，运行时接口请求样例不再只展示前 `8` 条，而是改为“全部展示 + 容器内滚动”；顶部保留批量复制 `GET URL`，但 `POST/PUT/PATCH` 不再提供容易混淆的总按钮，改成每条记录单独提供 `复制URL / 复制请求包`，复制内容也从简化模板提升为更接近 Burp Raw Request 的结构，包含请求行、可公开头部和请求体模板，进一步降低人工逐条抄接口和手工拼包的成本
- `[v4.6.8]` AI渗透 `接口语义与高价值参数接口` 增强：继续围绕“从 JS/运行时提接口、提参数、提上下文并指导测试”这条主线收口。后端 `api_surface_summary` 新增接口角色分类（如 `url_input_interface/config_i18n_interface/static_resource/auth_interface/file_interface/object_interface` 等）、高价值参数接口筛选与评分、以及参数化模板（`path_template/url_template/request_packet_template`）输出，前台详情页也同步新增“接口角色分类”和“高价值参数接口”卡片，让真正值得人工跟进的 `url/file/id/auth` 等参数接口能被单独顶出来，而不是和静态资源、国际化配置接口混在一起。与此同时，`auth/login` 路径识别从宽松子串匹配收紧为更偏路径分段与明确语义的判断，减少把普通参数接口误挂到“登录面黑盒摘要/鉴权相关接口”里的情况；对应回归补齐高价值 URL 输入接口识别、角色分布统计与 `environment -> me` 误命中抑制等关键样例
- `[v4.6.9]` AI渗透 `获取接口` 列补齐：`AI渗透测试` 列表新增 `获取接口` 列，会优先基于 `api_surface_summary.sample_interfaces` 统计当前结果已提取到的 `POST/GET` 接口数量，并在缺少接口摘要时回退到运行时请求样例统计，统一显示为 `POST：x条 / GET：x条`，让工程师在列表层就能快速判断这条结果是否真的挖到了可消费的接口面，而不必逐条点进详情页再确认
- `[v4.6.10]` AI渗透 `AI裁决权重提升与导出精简`：进一步把“明显更像噪声或弱线索”的结果交给 AI 自动收口，`merge` 阶段现在会结合 `display_decision/display_reason`、接口角色分布、结构化请求画像和 `HTTP` 状态，允许高置信 `AI` 结果更积极地将 `needs_manual_review` 压到 `likely_false_positive`，同时避免低置信 `AI` 把已判定的误报又抬回人工复核，从而减少无效人工复核量。与此同时，导出的 `Excel` 报告里 `AI渗透测试` 工作表按实际复核需求大幅瘦身，只保留 `来源/风险类型/风险名称/目标/状态/有效接口/获取接口/Payload/Request请求包/说明/时间`，并将 `Payload` 改成更利于快速复现的 `curl` 形式；新增 `有效接口` 与 `获取接口` 两列，分别展示提取到的接口模板与 `POST/GET` 数量，避免导出里继续堆积验证阶段、证据家族、证据强度等低价值字段。对应回归同步补齐 AI override 合并逻辑与导出工作表表头约束

## 2026-04-02（v4.5.66 ~ v4.5.70）

- `[v4.5.66]` AI渗透 `JS secret_key` 误报收紧：`js_context` 分析将 `risk_type=secret_key` 并入与 `sensitive_info` 相同的前端静态资源降噪链，对 `Token="+变量`、`secret="+变量`、`key="+变量` 以及本地存储/运行时拼接痕迹这类 bundle 片段统一收敛为 `secret_template_noise`，不再误判为硬编码密钥；同时补齐 `secret_key` 的 JS 拼接噪声与真实硬编码字面量双向回归，确保正常的 `secret_key` 硬编码命中不被误伤
- `[v4.5.67]` AI渗透工作台文案继续收口：将原本偏内部实现口径的“阶段 F 能力就绪度”改成更直白的“基础能力覆盖情况”，并将与其语义过近的“基础渗透测试能力”进一步改成“建议优先复核能力”，让“覆盖情况”和“优先排序”两张卡片各自表达更清楚；同时删除已基本完成使命的 `AI渗透测试MCP总体方案` 文档，避免继续维护过期方案说明
- `[v4.5.68]` AI渗透 `站点候选补齐与筛选日志细化`：候选构建新增“站点基础探测”基线能力，让普通 `site` 资产也能进入 AI渗透测试并在“进入 AI 渗透测试的资产 / 执行链路详情”中显示；同时补齐 `site` 候选筛选统计与样本日志，可直接观察 `high_value / keyword / baseline / skip_status / skip_out_of_scope` 的分布，排查“为什么这批站点没有进入 AI 渗透测试”时更直观
- `[v4.5.69]` 任务管理导出反馈与 AI渗透 `授权上下文` 增强：任务管理“报告导出”新增进度弹窗，覆盖创建任务、排队、生成文件、下载、成功/失败与错误信息；仪表盘修复 7 日资产增长趋势在回退模式下误用总资产数的问题；AI渗透页面继续收口，保留“进入 AI 渗透测试的资产 + 执行链路详情”主视图并把“返回任务管理”恢复到顶部。与此同时，AI渗透默认 SOP、控制台默认模板和后端规划请求统一补充“已授权、合规、范围受控”的安全验证上下文，并在模型因安全/授权语境拒绝规划时自动补充授权说明重试一次，尽量减少对自有/客户授权资产验证场景的误拒绝，同时仍把高破坏性、越界或需人工确认的动作收口到 `needs_manual_review/manual_required`
- `[v4.5.70]` AI渗透 `验证深度与站点能力面` 扩展：默认 `MCP` 工具调用预算从 `3` 提升到 `6`、控制台保存上限提升到 `12`，`AI` 规划候选默认上限提升到 `36`，外部工具默认最大执行次数提升到 `2`，并将内置 `sqlmap` 默认探测强度从 `level/risk 1` 提升到 `2`，让“主计划 + fallback + 外部工具”真正有机会跑完整；与此同时，站点基线候选不再只派生未授权、配置暴露和少量注入面，而是会按参数面继续扩展 `IDOR`、路径穿越、`SSTI`、`XXE`、文件上传、下载/导出等能力，减少“给了前序资产但 AI 还是只会浅测一轮”的情况；前后台配置默认值与运行配置也同步放开，避免保存配置后又被旧的浅层上限压回去

## 2026-04-01（v4.5.10 ~ v4.5.65）

- `[v4.5.65]` AI渗透 `性能与误报治理` 第一轮收敛：`/ai_pen_test/stats/` 改为单次 `find()` 取数后本地汇总，去掉多轮 Mongo `_agg_group()` 聚合与额外计数，降低任务级统计压力；验证链同步收紧“仅命中证据片段即 verified”的 broad 裁决，AI/Agent 不再仅凭高置信直接把 `needs_manual_review` 抬成 `verified`，必须满足结构化硬证据门槛。与此同时，未授权分析新增 `Actuator` 敏感端点白名单与“与基线页相同响应”降噪，runtime 侧新增同轮工具调用语义去重，减少重复探针请求并继续压低 `unauth` 与泛化入口误报

- `[v4.5.64]` AI渗透 `最小基线` 工作台与后端摘要落地：`/ai_pen_test/stats/` 新增 `minimal_baseline_summary`，会按第一版 10 个最小正负样例输出 `passed/partial/failed/missing`、`pass_rate`、`top_gaps` 与 `recommended_action`，让系统开始直接回答“离最小基线还差哪些”；前台 `AI渗透测试` 工作台同步新增“最小基线概览/最小基线缺口”区块，可直接查看通过数、缺样本数、当前最关键缺口与建议动作，把阶段 F 从“只有统计口径”推进到“已有可消费的基线视图”

- `[v4.5.63]` AI渗透版本口径同步：对齐 `version.txt` 自动递增后的版本号，统一修正 `CHANGELOG` 与 `AI渗透测试MCP总体方案` 的同步版本，避免版本文件、日志与方案说明出现错位

- `[v4.5.60]` AI渗透 `守门工作台` 前台继续收口：`AI渗透测试` 工作台新增“裁决守门概览”卡片，直接展示守门触发数、降级/提升次数、强证据占比、主导守门动作与建议动作；搜索区新增 `证据强度/守门动作` 筛选，结果列表与详情面板补齐 `proof_strength / decision_guard_action / decision_guard_reason` 标签，工程师现在可以直接在页面上区分“强证据真入口”和“被系统主动压下去的噪声”

- `[v4.5.59]` AI渗透 `裁决守门` 量化摘要落地：`/ai_pen_test/stats/` 新增 `decision_guard_summary`，并将 `proof_strength / decision_guard_action` 接入顶层分组与 `capability_benchmarks`；现在不仅能看到某条结果为何被守门降级，还能直接量化“多少结果被守门触发、多少属于 downgrade/boost、主导守门动作是什么、强/弱证据分布如何”，让“少给水洞”的收口逻辑从结果解释进一步推进到统计可量化

- `[v4.5.58]` AI渗透 `证据强度/裁决守门` 主链落地：新增统一 `proof_strength` 与 `decision_guard_action/reason`，让 `proof_family / proof_type / unauth_negative_type / unauth_probe_summary` 不再只是展示字段，而会真正参与最终裁决和误报抑制；例如 `access_control` 结果默认收敛为人工复核，`unauth_health_endpoint`、`health_only`、`auth_blocked/login_wall/guarded_mixed` 会主动压低过于激进的未授权结论。与此同时，这批字段已经打通到结果落库、工程师优先队列、导出列和回归测试，进一步把“少给水洞”的收口逻辑从统计层推进到最终判定层

- `[v4.5.56]` AI渗透 `工作台证据视图` 前台继续收口：`AI渗透测试` 页新增更完整的未授权概览、基础能力覆盖情况和基础渗透测试能力细视图，前台会直接消费 `unauth_access_overview` 的正负分布与负信号占比、`phase_f_readiness` 的覆盖率/命中率/能力明细，以及 `engineer_focus_queue` 的误报率/平均轮次/平均工具调用数；结果列表也新增 `证据家族/探针类型/未授权负信号` 的行内速览，右侧详情补齐 `proof_summary/request_template_summary/unauth_probe_summary` 的证据总览，进一步把“当前哪些基础渗透能力更值得优先看、为什么值得接手”从后端统计真正产品化到前台工作台

- `[v4.5.52]` AI渗透 `未授权基线摘要` 继续收敛：`/ai_pen_test/stats/` 新增 `unauth_access_overview`，会把未授权相关结果中的正向命中、`needs_manual_review` 线索、负信号分布、主导类型和建议动作收成一段顶层摘要，便于工程师快速区分当前更像“真未授权入口”还是“被鉴权/登录墙保护住的面”；对应回归同步补齐，进一步强化阶段 F 统计对“少给水洞”的支撑

- `[v4.5.50]` 任务管理交互修复与 AI渗透 `未授权负信号` 结构化收敛：任务详情类页签中的“返回任务管理”现在会显式回到任务管理顶部，不再沿用前一个详情页的滚动位置；任务管理的目标列新增就地“复制”按钮，便于快速复制目标而不影响点击进入任务详情。与此同时，AI渗透未授权复核新增 `unauth_negative_type`（`auth_blocked/login_wall/guarded_mixed/health_only`）并接入结果落库、工程师优先入口、`/ai_pen_test/stats/` 分组与 benchmark、导出和 `phase_f_readiness`；当某类未授权能力当前主要表现为“被鉴权挡住/登录墙/仅健康检查端点”且没有正向命中时，readiness 会从过于乐观的 `covered` 收紧为 `partial`

- `[v4.5.49]` AI渗透 `未授权直访` 负信号摘要打通：新增 `unauth_probe_summary`，会把一轮未授权复核中的 `targets/success/blocked/login_wall/health_like` 收成结构化摘要，并接入结果落库、工程师优先入口与导出；当高价值复核大多被鉴权拦截或登录墙阻断时，系统会更明确地下调优先级并解释“为什么当前不判未授权”

- `[v4.5.48]` AI渗透 `未授权直访` 误报抑制继续收紧：`replay` 现会自动扩展高价值未授权复核目标（如 `api/me/userinfo/account/current/manage/actuator/admin/dashboard`），并在多响应里自动挑选更强的未授权证据；同时新增 `unauth_actuator_surface` 与 `unauth_health_endpoint` 分层，`actuator/health/info` 这类公开健康检查端点默认降为 `needs_manual_review`，避免与真正敏感的管理面同档误报

- `[v4.5.47]` AI渗透 `未授权直访` 结果层打通：`unauth_access_hit/type/reason` 已随验证结果落库，并接入 `/ai_pen_test/stats/` 的 `unauth_access_type` 分组与 benchmark、`Phase F readiness` 能力匹配、`engineer_focus_entries` 优先级排序和导出列，工程师现在可以直接按“未授权类型 + 证据摘要”筛选更值得接手的入口

- `[v4.5.46]` AI渗透 `未授权直访` 基础链落地：新增高价值 `admin/dashboard/account/current/profile` 路径的无登录直访分析器，命中后会收敛为 `unauth_access` 证据家族（如 `unauth_admin_portal/unauth_profile_data`），并直接参与最终裁决与 proof summary；同时 `IDOR/access_control` 口径继续收紧为“访问控制线索，需人工复核”，不再自动给出越权 `verified`

- `[v4.5.45]` AI渗透 版本与方案口径同步：对齐 `version.txt` 自动递增后的版本号，统一修正 `CHANGELOG` 与 `AI渗透测试MCP总体方案` 的同步版本，避免版本号、方案状态和代码能力说明出现错位

- `[v4.5.43]` AI渗透 `证据家族与工程师优先级视图` 继续收敛：在统一 `proof_type/proof_summary` 之上新增 `proof_family`（如 `auth_bypass/surface_exposure/realtime_exposure/response_differential/sensitive_disclosure`），并将其接入 `/ai_pen_test/stats/` 的分组与 benchmark、`engineer_focus_entries` 优先级排序和导出表，工程师现在可以直接按“证据家族 + 证据摘要”筛选更值得接手的真入口
- `[v4.5.41]` AI渗透 `proof_summary` 与细日志主干落地：验证链新增统一 `payload_variant/payload_expected_signal/payload_proof_candidates/proof_type/proof_signals/proof_summary` 摘要，在 `planner -> main_plan -> fallback -> verify done` 各阶段输出更细日志；同时这些字段已随结果落库、重试更新和统计链传递，不再只是运行时临时信息

- `[v4.5.40]` AI渗透 `受控 payload 模板库` 主干落地：新增 `xss/sqli/ssrf/cmdi/ssti/xxe` 等探针家族的受控模板目录与模板选择器，会按 `request_mode/content_type` 优先选择更贴近接口形态的 payload 变体（如 `json_data` 优先 `boolean_json_string`、`application/xml` 优先 `entity_file_read_hosts`）；同时 AI planner 请求新增 `controlled_payload_variants`，模型可回 `payload_variant` 由执行链安全映射到受控模板，不再依赖自由 payload 生成
- `[v4.5.40]` AI渗透 `请求模板摘要` 与工程师视图打通：`request_template_mode/content_type/params/summary` 已随验证结果落库，并接入 `/ai_pen_test/stats/` 的 `request_template_mode` 分组/benchmark、`engineer_focus_entries` 结构化入口视图与导出“请求模板摘要”列，便于直接区分 `query/form/json/body` 入口及优先复核结构化接口

## 2026-03-31（v4.5.10 ~ v4.5.38）

- `[v4.5.38]` AI渗透 `参数单引擎` 接口级 payload 编排继续推进：新增 `sample_interface` 目标构造，参数驱动编排在当前 URL 无 query 或仅命中通用 fallback 时，会优先利用 `sample_interfaces` 里的 `GET/POST` 线索生成更贴近真实接口的低副作用探针；同时 fallback payload 重放也同步支持接口级参数命中，减少“一律改 arl_probe”带来的噪声

- `[v4.5.35]` AI渗透 `参数单引擎` 第一阶段推进：新增 `parameter_probe_families`，将参数标签统一映射为 `IDOR/路径穿越/SSRF/JWT/上传下载/SQLi/XSS` 探针家族，并让参数编排器优先按家族优先级构建低副作用验证链；同时修正 `redirect` 被 `dir` 子串误判为 `file_path` 的噪声问题，减少把 URL 跳转参数错误排到路径穿越链上的误报

- `[v4.5.34]` AI渗透 `受控字典资源` 第一阶段封装：`ARL/docker/dicts/dict/user.txt + pass.txt` 新增 preview/计数加载与缓存能力，登录上下文摘要补充 `controlled_dict_ready/user_count/pass_count` 可观测信息；`weak_password_probe` 的最小默认凭证集开始可按高价值登录面安全引入极小受控 preview 组合（如 `admin/admin`、`root/root`、`admin/123456`），为后续预算/节流/熔断治理版第二层字典能力做准备

- `[v4.5.10]` 仪表盘 `资产增长趋势(7日)` 统计口径修复：`/console/dashboard` 的 `asset_trend_7d` 从“累计总量曲线”调整为“按日新增曲线”，并额外保留 `assets_total/vulns_total` 累计字段用于兼容；修复高基数资产下曲线长期近似直线的问题（例如 tooltip 持续显示同一总量值）
- `[v4.5.10]` 仪表盘当日新增资产统计兼容修复：`new_assets_today` 改为统一复用日统计逻辑，兼容 `save_date` 为 `date/string` 的混合存储，并在 `save_date` 缺失时回退 `update_date`，避免历史数据口径差异导致“新增始终为 0”
- `[v4.5.11]` AI渗透 `config_probe` 家族化探测增强：新增配置/诊断端点目标生成器，`infer/fallback` 计划从“单 URL 探针”升级为“同域多端点低副作用探测”（如 `actuator/env/configprops/mappings/beans/conditions/loggers`），并在 `/api/*` 目标下优先探测 `/api/actuator/*` 路径，提升高价值配置暴露发现率
- `[v4.5.11]` AI渗透 `weak_password` 主计划链路增强：`_infer_ai_pen_tool_plan` 新增 `session_start -> extract_csrf_token -> credential_probe -> detect_login_success` 受预算会话链（非仅 fallback），让登录与会话验证更符合 MCP 工具闭环；AI planner 的 `output_schema` 与 `available_tools` 同步改为动态映射当前真实工具/载荷列表，减少模型输出旧工具名导致的执行偏差
- `[v4.5.12]` AI渗透 `JWT/认证链` 继续收敛到 MCP 工具闭环：`_infer_ai_pen_tool_plan` 与 `_build_ai_pen_fallback_tool_plan` 新增 `token_replay`（`Authorization: Bearer <none-token>`）步骤，`_verify_ai_pen_candidate` 的 JWT none-token 验证改为从 runtime `token_replay` 观测结果统一判定，不再走 runtime 外手写请求分支；同时补齐 JWT tool plan 回归测试，确保 `jwt_probe + token_replay` 在预算内稳定输出
- `[v4.5.13]` AI渗透 `IDOR/访问控制` 证据标准分级：新增 `_classify_ai_pen_idor_outcome`，将“变异后被 401/403 拒绝”收敛为 `likely_false_positive`（访问控制生效），将“同为成功状态且出现敏感字段差异”的高置信场景提升为 `verified`，其余维持 `needs_manual_review`；并补齐 IDOR 分级判定回归测试，降低“有差异但非越权”噪声
- `[v4.5.14]` AI渗透 `Token/认证协议` 探针链扩展：新增 OAuth/OIDC 协议端点家族化目标生成器（如 `/.well-known/openid-configuration`、`/.well-known/jwks.json`、`/oauth/token`、`/connect/token`），`jwt_probe` 的 infer/fallback 计划由“单 URL 复测”升级为“当前入口 + 协议端点”组合探测；运行时新增认证协议响应识别与摘要提取，在 JWT 分支可对公开可访问的协议端点给出结构化验证结论
- `[v4.5.15]` AI渗透 `IDOR` 一致性信号增强：`idor_probe` 多响应分析新增一致性统计（`consistency_hits/consistent_sensitive_fields`），评分与差异摘要同步纳入“重复出现的敏感字段差异”信号；当多次对象引用变异都指向同类敏感字段变化时，判定置信度更稳定，减少单次偶发响应差异对结论的干扰
- `[v4.5.16]` AI渗透 高价值认证目标收敛：高价值 URL 提取新增 OAuth/OIDC 协议端点家族（`/.well-known/openid-configuration`、`jwks`、`oauth2 token/introspect/userinfo`）的专门识别，相关候选统一归类为 `risk_type=jwt` 并优先进入 `jwt_probe` 认证链；同时补齐 OAuth/OIDC 风险分类回归测试，避免协议端点误走普通登录入口链路
- `[v4.5.17]` AI渗透 认证协议证据分级：新增 `_classify_ai_pen_auth_protocol_outcome`，将“仅 OpenID/JWKS 元数据端点可访问”收敛为 `likely_false_positive`（入口暴露不直接判洞），将“token/introspect/userinfo 成功返回令牌字段或敏感凭据”升级为 `verified`，其余保持 `needs_manual_review`；同步补齐认证协议分级回归测试，降低 JWT 认证链误报
- `[v4.5.18]` AI渗透 注入类证据标准补齐：新增 `SSTI/CMDI/XXE/SSRF` 专项 proof 检测（如模板表达式执行、`id` 命令输出、外部实体文件读取、元数据返回），并将其接入 `jwt` 之外的主判定链与 `verified` proof guard；同时把这四类从“通用 evidence 命中即可 verified”收敛为“有专项证据才可 verified”，降低阶段 C 快速迭代下的泛化误报
- `[v4.5.19]` AI渗透 认证协议探针细化：OAuth/OIDC 端点探测从“统一 GET”升级为“按端点类型自动 method/参数”（如 `token/introspect` 使用 `POST form`、`userinfo` 携带 `Bearer`），并将 `invalid_client/invalid_token/unsupported_grant_type` 等标准鉴权错误收敛为 `likely_false_positive`（鉴权生效），减少认证链探针误报
- `[v4.5.20]` AI渗透 认证协议语义判定增强：新增 `_extract_auth_protocol_error_semantics`，对 `client 鉴权失败 / token 无效 / scope 不足 / grant 参数错误` 做语义分类并在 `auth_protocol` 分级中统一降噪；同时新增 `userinfo/introspect` 成功响应语义判定（如 `userinfo` 返回身份字段、`active=true/false`）以区分“鉴权生效”与“疑似未鉴权泄露”，提升阶段 C 认证链判定精度
- `[v4.5.21]` AI渗透 SQLi 证据标准增强：`_detect_sqli_proof_type` 在原 `error_based` 基础上新增 `boolean_based/time_based` 判定（结合布尔条件差异、状态变化与延时特征），并在主决策链中将这两类纳入可利用证据分支；同时运行时观测新增响应耗时字段用于时间盲注判定，补齐对应回归测试
- `[v4.5.22]` AI渗透 DOM XSS 证据结构化：`js_context` 分析新增 `dom_xss_proof_type`（`source_sink_only/source_sink_popup_hint`）并回写验证结果字段，形成 DOM XSS 的标准化证据描述，避免仅靠泛化 reason 文本；同时补齐 DOM XSS proof type 回归测试，便于后续在阶段 C 完成度核查中直接量化
- `[v4.5.23]` AI渗透 `C-AutoPassive` 链路补齐第一批：新增 `path_traversal_probe / web_policy_probe / socketio_probe` 三类探针并打通 `risk_type -> payload_hint -> infer/fallback tool_plan -> runtime observation -> decision/proof_guard` 全链路；同时扩展参数资产图（`parameter_assets/parameter_tag_stats`）用于参数类型标签化，强化“参数驱动编排 + 证据分级”执行能力
- `[v4.5.23]` AI渗透文档与回归同步：`docs/AI渗透测试MCP总体方案.md` 的阶段 C 更新为 `C-Core/C-AutoPassive` 双口径，并新增 `C-AutoPassive=100%` 验收与开发优先级；补齐 `test_ai_pen_js_context.py` 对 `path_traversal/web_policy/socketio` 的计划编排、运行时观测、分类与工具注册回归用例
- `[v4.5.24]` AI渗透 `弱口令/登录会话` 闭环增强：新增登录后 follow-up 目标构造与 `session_request/logout_probe` 标准化判定，`weak_password_probe` 主计划与 fallback 均可在预算内自动执行 `session_start -> extract_csrf_token -> credential_probe -> detect_login_success -> session_request -> logout_probe`；运行时将“认证后资源可访问 / 退出后回登录页”纳入证据与结果落库
- `[v4.5.25]` AI渗透 `轨迹与导出` 产品化继续推进：验证链日志补充登录面、会话摘要与 `tool_plan_source`，重试优先沿用历史 `tool_plan/tool_calls`；导出字段新增 `session_summary/tool_plan_source/ai_plan_tool_plan/evidence_snippet/http_status/response_hash_diff` 等轨迹面数据，便于复盘 Agent 决策与验证链路
- `[v4.5.26]` AI渗透 `统计维度` 扩展：`/ai_pen_test/stats/` 新增 `tool_plan_source/stop_reason` 聚合，可直接观察 AI 计划命中、历史重试占比，以及 `manual_required/budget_exhausted/error` 等停止原因分布，为阶段 E 结果轨迹分析补齐数据面
- `[v4.5.27]` AI渗透 `高价值目标通用化` 主干落地：新增统一 `AI_PEN_HIGH_VALUE_FAMILY_SPECS` 与高价值摘要构造器，融合 `site/url/fileleak/wih/browser/runtime/login` 多层线索生成 `high_value_summary/high_value_family/high_value_family_rank/high_value_keywords`，并接入候选排序、AI planner 输入、重试、导出与统计；同时补齐 `WebSocket` 与多家族聚合回归测试
- `[v4.5.28]` AI渗透 `阶段 F 量化指标` 数据面落地：`/ai_pen_test/stats/` 在原有分组统计之外新增 `quant_metrics` 摘要，直接输出覆盖率、成功率、误报率、执行状态占比、平均轮数、平均工具调用数，并支持从 `budget_used` 缺失场景回退 `agent_trace/tool_calls` 计算；同步新增独立路由统计回归测试，为后续靶场基线与前台图表复用提供稳定口径
- `[v4.5.29]` AI渗透方案文档同步：刷新 `docs/AI渗透测试MCP总体方案.md` 当前状态判断，补齐阶段 `A/B/D/E/F` 的真实完成度、已实现能力、未完成缺口与建议优先级，并同步更新高价值目标家族与弱口令受控接入口径，便于后续按阶段继续排期开发
- `[v4.5.30]` AI渗透 `阶段 F benchmark` 统计增强：`/ai_pen_test/stats/` 新增 `capability_benchmarks`，可按 `risk_type/high_value_family/verification_step` 输出分能力覆盖率、成功率、误报率、平均轮数、平均工具调用数，并统一复用 `quant_metrics` 口径；同步补齐 stats 分组 benchmark 回归测试，并更新方案文档阶段 F 当前状态
- `[v4.5.31]` 启动脚本运行配置自动补齐：`start.sh` 与 `restart.sh` 在创建或复用 `ARL/docker/config-runtime.yaml` 后，统一调用 `ARL/app/tools/sync_runtime_config.py` 以模板为基准补齐缺失配置项并保留用户现有值；当同步脚本或 `python3` 缺失时会友好跳过，若配置补齐失败则显式中止，避免升级后因新配置项缺失导致运行时异常
- `[v4.5.32]` AI渗透定位与阶段 F 视图收敛：方案文档将系统定位明确为“互联网资产侧的高价值漏洞入口发现器 + 低副作用验证器”，强调“真漏洞优先、少给水洞”；`/ai_pen_test/stats/` 新增 `phase_f_readiness` 与 `engineer_focus_queue` 所需的优先级/原因字段，可直接按登录、JWT、API 文档、配置暴露、IDOR、SQLi、XSS、文件处理、SSRF 等核心能力判断 `covered/partial/missing` 并给出工程师优先关注顺序；同步补齐对应回归测试
- `[v4.5.33]` AI渗透 工程师入口列表增强：`/ai_pen_test/stats/` 新增 `engineer_focus_entries`，基于 `verified/needs_manual_review`、高价值家族、置信度、登录后命中、外部工具命中、HTTP 状态等信号，对具体结果样本进行优先级打分并输出可直接接手的入口 Top 列表（含 `target/vuln_url/risk_type/payload_type/reason/focus_reason`）；同步更新方案文档阶段 F 当前状态并补齐回归测试

## 2026-03-30（v4.3.60 ~ v4.5.4）

- `[v4.5.4]` `WIH` 执行链修复“大批量目标卡死后整任务异常退出”问题：`InfoHunter.exec_wih` 改为“按站点分批执行 + 超时后二分缩批继续”策略，主命令与最小参数回退都支持在单批超时后继续拆分处理，并将成功批次结果聚合回统一结果文件；当部分目标长时间卡住时，`web_info_hunter` 现在会尽量保留已成功站点的情报结果，而不是在 `7200s` 超时后直接抛出 `TimeoutExpired` 使整任务进入 `error`

- `[v4.5.3]` AI渗透新增独立 `GraphQL` 入口发现链：`commonTask` 现将 `/graphql`、`/api/graphql`、`/graphiql`、`/graphql-playground` 等路径纳入高价值目标家族，新增 `graphql_probe` payload/tool/route_hint/capability_profile，并通过一次低副作用 `__typename` 探针确认入口是否真实可访问；运行时可提取 `GraphQL` 响应摘要（如 `typename / introspection / playground`），结果以“发现可接手口子”为目标保守止步，不继续自动深挖 schema 或业务授权链

- `[v4.5.2]` AI渗透弱口令验证从“关键词/证据片段判定”推进到“最小登录会话 + 受控默认口令探针”链路：`commonTask` 新增登录表单抽取、隐藏字段/CSRF 字段复用、最小默认凭证集与登录成功/阻断判定能力，MCP runtime 同步注册 `session_start/login_probe/credential_probe/detect_login_success` 工具；当目标存在可复用登录表单且无明显验证码/锁定时，会执行一次低副作用默认口令验证，否则保守降级为 `needs_manual_review`，避免把“未真正尝试登录”的弱口令线索直接误判为验证失败或有效漏洞
- `[v4.5.2]` AI渗透执行方案文档继续收敛为“真 Agent MCP”实施口径：`AI渗透测试MCP总体方案` 重写为目标定位、能力下限、架构问题、阶段路线图和受控弱口令接入策略的统一说明，明确 `PortSwigger` 能力下限、登录/会话工具链缺口以及 `ARL/docker/dicts/dict` 只能在会话层与风控止损能力补齐后再受控接入，减少后续实现偏离“低副作用、强审计、可回放”的设计边界

- `[v4.5.1]` AI渗透阶段 A 的“真 Agent Loop”骨架落地：`AiPenMcpRuntime` 新增 `run_agent_loop` 与 `final_output/turn_count` 审计字段，运行时不再只能顺序执行静态 `tool_plan`，而是开始支持按轮次输出 `tool_call / final_decision / manual_required`，为后续把控制权从 `commonTask` 继续迁移到 runtime 提供最小闭环基础
- `[v4.5.1]` AI渗透验证链接入“规划结果回喂后的多轮决策”通道：`commonTask._call_ai_pen_planner` 新增 `agent_loop_context` 输入模式，`_verify_ai_pen_candidate` 与重试链开始支持 `seed tool_plan + 观察回填 + 下一轮决策` 的 Agent 执行流，并新增 `mcp_agent_loop` 步骤标识与回归测试；当前仍保留本地证据规则兜底，确保在引入多轮决策时不放松 `verified` 证据门槛

- `[v4.5.0]` AI渗透高价值目标提取从“少量固定示例”扩展为“通用高价值家族”能力：`AI渗透` 候选源新增纳入 `目录扫描(fileleak)`，并对 `site/url/fileleak` 统一引入状态码优先与高价值目标识别，重点覆盖 `接口说明/Schema`、`管理/诊断端点`、`认证入口`、`文件处理入口`、`敏感文件/配置端点` 等多类目标；执行窗口按 `知识命中 + 高价值优先级 + 状态码` 共同排序，不再只围绕个别 `api-docs/actuator/env` 示例路径构建候选
- `[v4.5.0]` AI渗透执行链升级为“AI 单次规划 + runtime 多步 tool plan 执行”：planner 现可输出 `tool_plan`，运行时会按统一工具协议顺序执行多步探针并汇总结果，再回写到 `agent_trace/tool_calls/tool_results` 与结果详情；当前已支持围绕高价值 URL 做多步验证链，但仍保留任务范围约束和低副作用原则，为后续真正的“逐轮结果回喂模型再决策”式 Agent loop 继续铺路

- `[v4.3.67]` AI渗透 JS 上下文归因增强：`commonTask` 新增统一 `js_context_summary` 采集与缓存能力，针对 `secret_key/client_secret/access_key/private_key` 等敏感信息命中补充 `Key类型 / 组件线索 / 应用线索 / 上下文摘要`，并将这些信息同时注入 AI planner 请求、验证结果落库与详情页展示，支持把“这是哪类 key、像哪个组件/哪个应用”的上下文直接给到 AI 和用户
- `[v4.3.67]` AI渗透 JS 构建产物误报收敛继续加强：针对 `arl_probe` 命中 `.js` 静态资源、`Location/Set-Cookie/Content-Type` 等 HTTP 头关键字实际落在前端 bundle 键名/变量中的场景，新增 `header_keyword_in_bundle / bundle_noise / secret_template_noise` 规则降噪，统一下调为 `likely_false_positive` 并在原因中明确标注“与 HTTP 响应头注入无关”，修复 `umi.*.js` 等前端框架代码被误判为可利用风险的问题

- `[v4.3.66]` AI渗透测试工作台修复“复制请求包/复制URL”在部分环境报错 `Cannot read properties of undefined (reading 'writeText')`：复制逻辑改为“优先 `navigator.clipboard.writeText`，不可用时自动降级 `document.execCommand('copy')`”，恢复在非安全上下文或受限浏览器下的可复制能力
- `[v4.3.66]` AI渗透测试资产视图补回任务详情模块统计数：顶部 `站点/子域名/IP/SSL证书/服务/目录扫描/URL信息/风险/PoC风险/WIH/WAF识别/AI渗透测试` 页签恢复显示 `label - count`，并按当前筛选条件拉取总数，修复“进入 AI渗透测试后统计数消失”的问题

- `[v4.3.65]` AI渗透 MCP 探针执行链继续按方案推进：`commonTask._verify_ai_pen_candidate` 新增内置工具注册（`http_fetch/payload_probe/idor_probe/api_doc_probe/jwt_probe/websocket_probe`）并统一走 `AiPenMcpRuntime` 调用，探针审计结果优先复用 runtime 真实产出的 `agent_trace/tool_calls/tool_results`，不再仅由 `tool_trace` 字符串反推，补齐 P0 阶段“统一工具协议 + 预算治理 + 可追溯调用记录”的落地深度
- `[v4.3.65]` AI渗透测试工作台细节增强：详情面板新增 `复制URL/复制请求包` 快捷操作；`ARL 与 AI 对话记录` 支持解析“字符串包裹 JSON”并按角色进行结构化格式化展示，减少对话区原始 JSON 嵌套文本带来的阅读负担

- `[v4.3.64]` 前端请求链路新增“后端就绪探测”启动保护：`requestApi` 在遇到 `502/503/504`（常见于系统升级或刚启动阶段 `nginx bad gateway`）时，会先对 `/api/` 执行短周期就绪探测并在就绪后自动重试原请求；若探测期内仍未就绪，则统一返回“系统正在启动中，后端服务尚未就绪，请稍后重试”的友好提示，避免用户看到原始 `HTTP 502: 502 Bad Gateway nginx/1.14.1` 页面级报错

- `[v4.3.63]` AI渗透测试工作台二次优化：`AI调用与思考` 区域新增“结构化摘要 + 完整对话流程”展示，提升 `ai_plan_request/ai_plan_reply` 的可读性并减少原始 JSON 直出；`MCP` 区域新增调用时间线（按 turn 串联 `agent_trace/tool_calls/tool_results`）与原始记录并排查看，补齐“从计划到工具执行结果”的可追溯链路
- `[v4.3.63]` AI渗透结果新增 `Request 请求包` 数据面：后端 `commonTask/_verify_ai_pen_candidate` 增加 `request_method/request_url/request_path/request_headers/request_body/request_packet` 结构化字段并随 `retry`/落库同步；请求包按 `payload_type + verification_step + tool_trace` 自动推断方法与内容，兼容 `GET/POST/PUT/PATCH` 及 `upload/websocket/jwt/api_doc` 等探针场景，前端详情同步改为“Request请求包 + Payload原始值”双视图
- `[v4.3.63]` 报告导出补齐 `Request请求包`：`AI渗透测试` 工作表新增请求包列并扩展投影字段，保证页面与导出对齐，便于复现验证链路

- `[v4.3.62]` 资产搜索新增独立 `AI渗透测试` 工作台页面：将 `AI渗透` 模块升级为资产视角入口并归入“资产数据”，保留系统统一视觉风格，页面改为“左侧资产列表 + 右侧完整链路详情”布局；支持查看进入 AI 渗透测试的资产、AI 调用与思考摘要、MCP 工具调用记录（`tool_trace/tool_calls/tool_results/agent_trace/external_tool_runs`）以及最终 `payload/结论/证据`，并补齐筛选、统计、单条重试与按任务重跑交互，提升 AI 渗透结果的可读性与可追溯性

- `[v4.3.60]` AI 管理连通性测试收紧：`/api_console/ai_config/test/` 的 `reasoning_test` 改为严格按配置模型测试，禁用“模型不可用时自动切换到默认 chat 模型”的降级；当思考模型不可用时会直接失败并提示“已禁用自动切换模型”，避免出现 `configured_model=DeepSeek-R1` 但 `model=deepseek-chat` 的误导结果
- `[v4.3.60]` AI渗透裁决规则升级为“可利用证据优先”：`xss / sqli / weak_password` 默认不再因关键词、静态链路或普通回显直接升为有效风险；`XSS` 需具备可执行弹窗证据，`弱口令` 需具备登录成功证据，`SQL注入` 需具备可复现利用证据（如报错注入或外部工具命中），并同步收紧 AI planner 合并阶段对 `verified` 的提升条件，降低“可疑但不可利用”结果进入渗透结论的噪声
- `[v4.3.61]` AI渗透 P0 运行时骨架落地：新增 `ARL/app/services/ai_pen_mcp_runtime.py`，补齐统一 Tool Schema、预算约束与 `agent_trace/tool_calls/tool_results/stop_reason/budget_used/runtime_version` 审计产物；`commonTask._verify_ai_pen_candidate` 与 `ai_pen_test` 重试链路接入 runtime 结构化字段并保持原有判定兼容，导出投影同步补充新字段，为后续“多轮 tool_call 闭环 + 前端轨迹时间线”提供数据面基础

## 2026-03-29（v4.3.42 ~ v4.3.55）

- `[v4.3.55]` AI 管理连通性测试修复：`/api_console/ai_config/test/` 从“仅测试分析模型”升级为“分析模型 + 思考模型”双通道测试，返回结果新增 `analysis_test/reasoning_test` 明细与汇总判定；当思考模型与分析模型相同时复用结果并显式提示，避免误判“思考模型未测试”
- `[v4.3.55]` 文档目录清理收敛：`docs/` 删除重复与历史分散规划文档（含 SSL 基线文档清理），保留 `开发规范.md` 并统一收敛为 `AI渗透测试MCP总体方案.md`，降低文档检索与维护成本
- `[v4.3.54]` 任务管理交互与上传体验优化：任务详情返回任务管理后默认恢复离开前滚动位置，修复长列表阅读中断；任务列表“目标”列新增悬浮资产统计（站点/子域名/IP/URL/风险）与 WAF 概览，减少来回切换查看成本；资产搜索 `site/asset_site` 的 `headers` 列默认折叠并支持展开/收起，提升表格可读性；Nginx `client_max_body_size` 提升到 `300M`（内置 Web Nginx 与反向代理 Nginx 同步），修复上传较大字典触发 `413 Request Entity Too Large` 的问题

- `[v4.3.42]` 任务资产范围守卫统一落地：新增 `ARL/app/services/task_scope_guard.py`，收敛 `host/url` 归一化与范围判断逻辑（`normalize_scope_host/host_in_scope/url_in_scope`），并提供 `load_task_scope_context` 从“当前任务目标 + 同名历史任务目标 + 已沉淀 site/url/domain”聚合 `allowed_hosts/allowed_flds`，作为 WIH/PoC/AI 渗透等链路的统一范围基线
- `[v4.3.42]` 扫描结果与情报入库链路范围收口：`commonTask` 与 `WebSiteFetch` 接入任务级 scope cache，`nuclei/afrog/risk_cruising` 结果、`WIH` 记录升级风险、`AI渗透` 候选聚合、`page_url_set` 更新等流程新增“仅保留任务范围内目标”的过滤，修复跨站点/跨域噪声结果进入当前任务的问题
- `[v4.3.42]` 任务侧扫描执行补齐范围校验：`DomainTask` 的 `run_risk_cruising` 与 `find_vhost` 结果新增 URL 范围判定；`cloud_security_scan` 与 `penetration_scan` 改为复用统一 `task_scope_guard` 判定主机范围，并在云存储目标加入前增加 scope 拦截，减少越界探测与无关结果写入
- `[v4.3.42]` 报告一致性修复：钉钉知识库写入任务导出时，单任务场景改为复用单任务导出链路（`export_arl`），多任务继续走批量导出（`export_merge_tasks`），避免“知识库报告与导出报告口径不一致”的问题
- `[v4.3.42]` AI渗透列表列精简：`AI渗透` 列表默认隐藏 `知识命中 / 说明 / 工具轨迹` 三列，保留在 `AI渗透详情` 中查看，提升列表横向可读性与操作效率

## 2026-03-28（v4.3.26 ~ v4.3.41）

- `[v4.3.26]` AI 管理补齐“思考模型”配置：提供方预设新增 `default_reasoning_model`，前后端模型配置新增 `reasoning_model` 字段并接入读写；DeepSeek 默认展示 `DeepSeek-R1`，配置弹窗与卡片摘要同步显示“分析模型 / 思考模型 / API Base URL”，为后续区分分析模型与思考模型保留数据面
- `[v4.3.26]` AI 渗透结果页可读性增强：`AI渗透` 列表新增 `详情` 按钮与详情弹窗，集中展示 `目标 / 漏洞URL / 说明 / 知识命中 / 证据片段 / 工具轨迹 / 响应摘要`，修复长文本挤压表格导致下方内容难以查看的问题；同时将 `目标 / 漏洞URL` 改为居中展示并复用超链接渲染
- `[v4.3.26]` 配置管理新增 `PoC 更新代理`：扫描配置新增 `POC_UPDATE_PROXY` 并接入运行时热刷新、`config-docker.yaml` 模板与前端表单；`更新 Nuclei PoC / 更新 afrog PoC` 接口执行 `git clone/pull` 时自动透传 `http_proxy/https_proxy/all_proxy`，成功提示与失败文案同步展示代理信息，方便受限网络环境下更新 PoC 仓库
- `[v4.3.27]` AI 管理思考模型改为“全提供方通用”默认策略：`通义千问 / Kimi / OpenAI-GPT / 智谱GLM / DeepSeek` 的 `reasoning_model` 在未单独配置时默认跟随当前分析模型，DeepSeek 继续保留 `DeepSeek-R1` 预置；前后端模型归一化、默认 profile 创建、旧配置回填与弹窗占位文案同步调整，修复“只有 DeepSeek 真正补了思考模型，其它提供方仍为空”的体验问题
- `[v4.3.28]` AI 渗透 JS 误报收敛增强：`commonTask._verify_ai_pen_candidate` 新增 `.js` 静态上下文分析分支，对 `sensitive_info / DOM XSS` 命中补充“硬编码字面量、变量拼接、本地存储、框架构建产物、source->sink` 等上下文判断；可将 `Nuxt/Webpack` 构建产物与变量拼接类线索降为 `likely_false_positive`，对真实硬编码敏感值提升为 `verified/needs_manual_review`，并将 `JS上下文` 证据回写到 `reason/evidence_snippet/tool_trace`
- `[v4.3.29]` AI+MCP 渗透编排增强：`commonTask` 新增 `route_hint/product_hints` 与 `API文档结构摘要` 能力，AI planner 请求体现在会携带 `js_sensitive_context/js_dom_context/api_doc_structure/jwt_token_first/websocket_handshake/structured_id_mutation` 等路由提示、产品线索与结论门槛；运行时对真实 API 文档命中补充 `paths/auth_paths/parameter_names/securitySchemes` 摘要并回写到 `reason/evidence_snippet/response_hash_diff`，让 AI+MCP 更像“基于上下文做验证”而不是只做通用重放
- `[v4.3.29]` AI渗透 SOP 升级：`ARL/docker/ai/sop/default_ai_pen_test.yaml` 新增“上下文先行、PoC知识仅作提示、JS误报抑制、API文档结构化优先”的运行时约束，并明确 `verified/needs_manual_review/likely_false_positive` 三档证据标准，减少 planner 因提示词过于泛化而做出激进判断
- `[v4.3.30]` AI渗透编排 Skill 初版：新增 `ARL/docker/ai/skills/ai-pen-orchestrator/`，以中文为主沉淀 `SKILL.md + routing/evidence-criteria/product-playbooks/false-positive-rules` 四类参考文件，用于统一 AI渗透测试后续开发中的候选路由、证据标准、产品画像与误报抑制方法论，降低“规则、SOP、代码三处各说各话”的维护成本
- `[v4.3.31]` 结构化接口消费增强：AI渗透验证链将 `API文档摘要` 扩展为统一的 `api_surface_summary`，开始同时消费 `Swagger/OpenAPI` 与 `JS` 中提取出的接口面（`method/url/params/source`），补充 `auth/object_id/upload/download` 风格统计；`AI渗透详情` 新增“接口结构摘要 + JS提取接口样例”展示，帮助用户确认即使目标没有标准 API 文档，前端暴露出的接口与参数也已被结构化纳入验证输入
- `[v4.3.32]` PoC 文库结构化二期：`build_ai_pen_knowledge_index.py` 从 `tools/poc/POC` 语料中进一步提炼 `product_labels / vuln_types / entry_paths / verify_actions / record_refs` 等结构化知识，运行时 `AI渗透` 候选命中新增对应字段并参与 planner 输入与详情展示；`AI渗透详情` 新增“知识画像”区域，直接展示知识命中的产品组件、漏洞类型、入口路径与建议验证动作，让 `PoC 文库` 从“只命中 token 的参考语料”升级为“可解释的验证知识源”
- `[v4.3.33]` AI渗透能力模型去产品特判化：`commonTask` 中原本偏向具体产品名的 `product_hints/playbook` 逻辑收敛为通用系统家族/能力画像（如 `api_doc_surface/js_bundler_app/token_auth_flow/admin_office_portal`），不再将用户举例的某些产品直接写死为运行时优先对象；同时清理重复 helper 定义并同步更新测试与 Skill 参考文档，使后续能力建设更贴近 `OWASP / PortSwigger` 风格的基础能力矩阵
- `[v4.3.34]` 浏览器情报采集层与认知图谱最小版本接入：新增 `browser_intel_scan` 服务并补齐 `BROWSER_INTEL_*` 配置，基于 Playwright 对高价值页面目标做低侵入采集，输出 `browser_surface_summary / runtime_api_calls / dom_form_summary`；`AI渗透` 验证链按条件补充浏览器视角，并新增 `task_ai_pen_graph_summary` 摘要字段（节点数、边数、核心路径/参数、auth/object_ref/file cluster），前端 `AI渗透详情` 同步新增“浏览器情报摘要 / 认知图谱摘要”区块，为后续图谱化推理与认证上下文接入打基础
- `[v4.3.35]` 浏览器情报默认跟随 `AI渗透测试` 启用：`config.py` 与 `config-docker.yaml` 中 `BROWSER_INTEL_ENABLE` 默认调整为开启，但运行时仅在 `AI_PEN_TEST_ENABLE && BROWSER_INTEL_ENABLE` 同时满足时才会实际参与 `AI渗透` 链路，确保浏览器情报作为 AI 渗透的受控补充能力，而不是独立后台采集任务
- `[v4.3.35]` `WIH/静态情报` 与浏览器运行时情报边界收口：`commonTask` 新增 `intel_layers` 摘要与“静态上下文已足够则不再触发浏览器采集”的判断，浏览器情报结果新增 `runtime_enrichment/passive` 角色标识；`AI渗透详情` 和 `认知图谱摘要` 现在会显式展示“静态情报 / 文库知识 / 浏览器运行时”三层来源，减少重复采集、重复展示和用户理解成本
- `[v4.3.36]` AI渗透任务级图谱上下文复用：`commonTask` 新增 `task_ai_pen_graph_context`，将单候选 `graph_summary` 聚合为任务级共享上下文（候选数、来源分布、路线分布、情报层分布、任务级核心路径/参数、认证/对象引用/文件处理存在性），并在 AI planner、结果落库、重试链与前端详情中统一复用；同时新增 `docs/AI渗透测试能力清单.md`，以“已具备 / 部分具备 / 未具备”方式盘点当前能力边界
- `[v4.3.37]` 黑盒能力补强：文件处理与登录页分析进入 AI渗透主链。`commonTask` 新增 `file_handling_surface/login_entry_surface` 能力画像与对应上下文分析，对 `upload/download/export/attachment/template` 入口、`multipart` 表单、下载响应头、登录表单、密码输入、验证码/风控线索、认证相关运行时接口做保守识别与低副作用裁决；`browser_intel_scan` 表单摘要新增 `enctype/has_file_input/has_password_input/password_fields/has_captcha_hint/submit_text`，前端 `AI渗透详情` 新增“登录面黑盒摘要”并增强 DOM 表单展示，SOP 默认模板同步补充“文件处理/登录入口不等于已证明漏洞”的约束
- `[v4.3.38]` AI渗透结果对齐与报告补齐：`AI渗透详情` 新增“ARL 与 AI 对话记录 / 渗透测试记录”，可直接查看 `ai_plan_request / ai_plan_reply / ai_plan_actions / verification_step / payload / external_tool_runs`；资产搜索页隐藏 `指纹统计` 模块，减轻页面拥挤；`Excel` 导出与钉钉知识库报告同步新增 `AI渗透测试` 工作表/章节，保证页面、导出报告、知识库三条链路展示一致
- `[v4.3.39]` 导出报告改为异步任务，彻底规避大报告同步导出导致的 `504 Gateway Time-out`：`export` 新增 `job` 创建/查询/下载接口，前端报告导出改为“创建任务 -> 轮询状态 -> 完成后下载”；后台通过 Celery `arlweb` 队列异步生成 `excel/html/ai_markdown` 报告并写入共享导出目录，`Workbook` 结果直接落盘而非先整份转字节串，降低大报告场景下的请求时长与内存峰值；同时补齐 `export_job` 索引、共享导出目录配置与 `web/worker` 挂载，避免继续依赖提高 nginx/gunicorn 超时来硬扛导出
- `[v4.3.40]` AI渗透对话记录可读性增强：`AI渗透详情` 中的 `ARL请求摘要 / AI回复摘要` 不再直接展示原始 JSON，而是优先解析为“目标、风险类型、路由提示、能力画像、结论、置信度、原因、关键证据、下一步动作”等结构化可读文本；`Excel` 导出的 `AI渗透测试` 工作表同步采用同样的友好摘要逻辑，仅在解析失败时回退原文，降低用户在页面和报告中阅读原始 JSON 的负担
- `[v4.3.41]` `web_info_hunter/urlfinder_extract` 容错修复：针对 JS/页面文本中误提取出的畸形 URL 候选（如 NFKC 非法 netloc、残缺 IPv6 URL），为 `urlfinder_extract` 与 `web_info_intel_utils` 的 URL 解析/归一化逻辑补充异常保护，策略改为“跳过单条脏候选，继续处理其它正常 URL/JS”，避免 `domain_task / web_info_hunter` 因单条异常字符串导致整个任务失败

## 2026-03-27（v4.3.19 ~ v4.3.25）

- `[v4.3.25]` AI 渗透外部工具执行器升级为“可扩展框架”：`commonTask` 新增外部工具说明文件加载机制（`yaml/json`），支持用户在 `tools/ai_pen_tools` 目录按清单定义工具 `id/match/exec/result`，并通过 `AI_PEN_EXTERNAL_TOOLS` 白名单启用；运行时支持内置 `sqlmap/httpx` 与同名覆盖，匹配逻辑新增 `risk_name` 参与命中，`api_doc` 关键词命中修正，提升外部工具策略可维护性与命中稳定性
- `[v4.3.25]` AI 管理默认开关统一：`启用AI渗透测试 / 启用AI渗透-MCP / 启用AI渗透-外部工具白名单执行器 / 启用AI渗透-AI规划` 全部默认开启；后端配置默认值、API 读写默认值、前端表单默认值、`config-docker.yaml` 模板保持一致，降低新部署环境首次配置成本
- `[v4.3.25]` 文档补齐：新增 `tools/ai_pen_tools/README.md` 与示例模板（`sqlmap.yaml.example/httpx.yaml.example`），并新增 `docs/AI渗透外部工具接入说明.md`；总 `README` 补充“AI 渗透外部工具扩展说明”，明确容器目录 `/code/tools/ai_pen_tools` 与宿主机目录 `tools/ai_pen_tools` 映射关系、接入步骤与验证方式

- `[v4.3.24]` AI渗透测试接入“外部 MCP 工具白名单执行器”：在 `AI管理` 新增 `AI_PEN_EXTERNAL_ENABLE / AI_PEN_EXTERNAL_TOOLS / AI_PEN_EXTERNAL_TIMEOUT_SEC / AI_PEN_EXTERNAL_MAX_RUNS` 配置与前端开关，后端 `run_ai_penetration_test` 验证链路新增外部工具执行阶段（当前支持 `sqlmap/httpx`），并将执行轨迹、命中结果回写到 `ai_pen_test_result`（`external_tool_runs/external_tool_hit`）与任务日志元数据；同时补齐 `SQLMAP_BIN/HTTPX_BIN` 配置项与运行时热刷新，明确 `nuclei` 仍归属 AI-POC 扫描链路，不进入 AI渗透外部执行器

- `[v4.3.23]` AI渗透测试接入 `tools/poc` 知识索引命中增强：运行时自动加载 `ai_pen_knowledge_index`（支持 `ARL_AI_PEN_KNOWLEDGE_INDEX_FILE` 覆盖），候选验证阶段按命中 token 提升优先级，并将命中 token/样例路径写入 `ai_pen_test_result` 与 `ai_pen_test_plan/exec` 日志元数据，提升“为何优先验证该目标”的可解释性

- `[v4.3.22]` AI 渗透测试接入最小 MCP 执行链：新增 `AI_PEN_TEST_ENABLE / AI_PEN_MCP_ENABLE / AI_PEN_MCP_MAX_TOOL_CALLS / AI_PEN_MCP_TIMEOUT_SEC` 配置并贯通前后端，`AI管理` 可直接开关与调参；`run_ai_penetration_test` 增强为“基线重放 + Payload 探针”双阶段验证，支持证据命中、回显检测、响应差异判断与 WAF 智能跳过标注，结果与 AI 日志同步记录 MCP 运行参数
- `[v4.3.22]` AI 渗透知识索引脚本新增：新增 `ARL/app/tools/build_ai_pen_knowledge_index.py`，支持从 `tools/poc/POC / vulhub / PoC-in-GitHub` 构建轻量 token 索引并默认输出到 `ARL/docker/ai/sop/ai_pen_knowledge_index.json`，为后续 AI+MCP 渗透验证提供可检索语料底座

- `[v4.3.21]` AI 渗透测试 M1 首版落地：新增任务开关 `ai_penetration_test` 与执行阶段 `ai_pen_test`，在 `WebSiteFetch` 后验证链路中汇聚 `风险(vuln) / PoC风险(nuclei_result) / WIH` 结果，执行轻量 HTTP 二次验证并输出结构化结论（`verified / likely_false_positive / needs_manual_review`）
- `[v4.3.21]` AI 渗透结果数据面与接口补齐：新增集合 `ai_pen_test_result`（含任务/来源/目标/payload/证据/结论/置信度/状态等字段），补齐索引与任务删除联动清理；新增查询接口 `/ai_pen_test/` 并接入主路由注册
- `[v4.3.21]` 前端任务详情新增 `AI渗透` 页签：位置在 `WAF识别` 右侧，支持按来源、风险类型、结论、状态检索；任务创建表单与策略链路同步新增 `AI渗透测试` 开关，任务阶段展示新增 `AI渗透测试`

- `[v4.3.20]` AI 管理日志详情弹窗可用性修复：修复“最近对话日志 -> AI对话日志详情”在超长内容场景下标题栏溢出、关闭按钮不可点击的问题；弹窗新增 `max-height + 内部滚动` 结构，标题支持换行且关闭按钮固定不挤压，长字段按 `break-all` 包装，避免只能通过 `Esc` 关闭

- `[v4.3.19]` AI-POC 扫描决策阶段落地：`commonTask` 新增 `ai_poc_scan` 预决策流程，在 `nuclei/afrog` 前汇聚站点指纹、标题、Body、URL/WIH 线索与别名命中，按开关自动生成候选 `nuclei tags` 与 `afrog keywords/severity`，并将实际应用参数注入对应扫描调用链路
- `[v4.3.19]` AI-POC 可观测性增强：任务服务阶段新增 `ai_poc_scan` 计时与决策明细，AI 管理日志新增 `AI-POC扫描-计划/决策` 场景，前端任务阶段与配置文案统一为 `AI-POC扫描`，便于确认“调用了哪些 PoC 候选策略”
- `[v4.3.19]` PoC 索引能力补齐：新增 `ARL/app/tools/build_poc_index.py`，支持从 `nuclei-templates/afrog-pocs` 构建 `token -> tags/keywords` 索引；运行时优先读取 `/code/docker/ai/sop/poc_index.json`（兼容历史路径并支持 `ARL_AI_POC_INDEX_FILE` 覆盖），避免每次运行全库检索
- `[v4.3.19]` AI 去噪 PoC 风险触发修复：`run_task_ai_denoise_pipeline` 启动时会先合并已累计的 `pending_modules`，修复并发阶段下 `nuclei_result/vuln` 等模块因状态切换被清空后漏执行的问题

## 2026-03-26（v4.3.0 ~ v4.3.18）

- `[v4.3.18]` AI 提供方命名区分优化：`AI管理` 中官方 `OpenAI` 提供方名称调整为 `OpenAI-GPT`，与 `OpenAI 兼容接口` 做明确区分，降低用户在模型来源配置时的混淆风险

- `[v4.3.17]` 域名任务保底种子修复：开启 `domain_brute` 时，任务仍会保留并扫描用户输入的目标域名本身（保底种子），修复“爆破无结果导致后续阶段空跑、任务完成但资产统计全 0”的问题
- `[v4.3.17]` WIH 域名更新新增泛解析过滤：`domain_site_update(source=wih)` 在入库前增加随机子域探测与泛解析 IP 过滤，拦截命中泛解析的 `wih` 域名，降低“WIH 发现域名被泛解析污染后落库”的误报噪声

- `[v4.3.15]` AI 用量看板增强：`Token用量统计与AI对话日志` 默认日志条数调整为 `10`，摘要卡片改为“累计总量 / 总体成功率 / 平均响应耗时”；新增“最近窗口高频模型 Top5、高消耗场景 Top5、失败原因 Top3”摘要，减少“近24小时/近7天”重复信息
- `[v4.3.15]` AI 用量后端统计增强：`/api_console/ai_usage/stats/` 新增窗口平均响应耗时与样本数、失败原因 Top3 聚合；AI 调用日志新增 `elapsed_ms/error_reason` 落库字段，支持更精准的性能与失败分析
- `[v4.3.15]` AI 管理安全与可控性增强：新增 `AI.REQUEST_DELAY_MS`（请求延迟毫秒）并接入 AI 测试/去噪调用链路；`/api_console/ai_config/reveal/` 改为仅进入 Key 编辑模式不再回传历史明文 Key，前端保存时仅提交“已编辑”的 Key 字段，关闭配置弹窗后清空内存中的 Key 草稿，降低抓包与前端明文暴露风险
- `[v4.3.12]` AI 管理配置重构为“提供方独立配置”模式：通义千问 / Kimi / OpenAI / 智谱GLM / DeepSeek / OpenAI 兼容接口统一改为独立卡片展示，新增顶部“默认 AI”选择；卡片支持已配置状态标记与“设为默认/配置”操作，点击后弹窗按提供方单独维护 `API Key / 分析模型 / API Base URL / 网络代理`，降低原“模型与对话配置”集中表单的复杂度
- `[v4.3.12]` AI 模型配置新增代理能力并接入调用链路：前后端模型配置新增 `proxy/proxy_url` 字段，`AI配置保存/读取/连通性测试/AI去噪调用` 均支持按模型透传代理（`http/https/socks5`），兼容历史无代理配置场景
- `[v4.3.12]` 前端稳定性修复：修正 API 管理保存链路中的未定义状态引用，消除 `tsc` 校验报错，避免构建阶段中断

- `[v4.3.11]` AI 管理交互优化：修复 `SOP管理` 文件选择交互异常（支持重复选择同名文件、扩展名校验与一键清空，并在切换模块时自动清理已选文件），避免上传前状态残留导致误操作；同步优化“模型与对话配置”区布局（关键字段宽度与分组层次更清晰），并将 `OpenAI 兼容接口管理` 上移至更靠前位置，提升配置路径一致性与操作效率

- `[v4.3.9]` 运行配置增量补齐能力落地：新增 `ARL/app/tools/sync_runtime_config.py`，用于在升级后将 `config-docker.yaml` 的新增键自动补齐到运行配置（容器内 `/code/app/config.yaml`，宿主机 `config-runtime.yaml`）；补齐策略为“只补缺失不覆盖用户值”，并支持递归字典、`list[dict{id}]` 按 `id` 增量补齐、文件锁与可选备份
- `[v4.3.9]` 启动链路接入自动补齐：`web/worker/scheduler` 启动前统一尝试执行运行配置补齐，减少跨主机升级后因 `config-runtime.yaml` 缺少新键导致的新功能不可用问题
- `[v4.3.9]` 快速升级流程增强：`scripts/quick-build.sh` 在确保运行配置文件存在后新增模板差量同步步骤并更新帮助文案，实现 `quick-build` 一次操作自动补齐配置
- `[v4.3.9]` 运维与文案优化：新增仓库根目录 `stop.sh` 一键停机脚本（执行 `docker compose down --remove-orphans`，保留数据卷）；前端“配置管理/钉钉集成”文案同步修正为“写入运行配置”，避免误导为写入模板文件

- `[v4.3.5]` AI 配置改为 SOP 文件化：`config-docker.yaml` 中默认 `PROMPT_TEMPLATES` 由内联 `content` 切换为 `file` 引用（`ai/sop/*.yaml`），并新增 `ARL/docker/ai/sop/` 内置模板目录（`AI报告/误报复核/站点/目录扫描/SSL证书/URL信息/风险/PoC风险`）
- `[v4.3.5]` 后端新增 SOP 文件读写与安全校验：`api_console` 增加提示词文件路径解析、项目目录越界拦截、YAML 解析与落盘能力；保存 AI 配置时优先把模板内容回写到对应 SOP 文件，配置中保留模板元信息与文件引用，兼容历史仅 `content` 模式
- `[v4.3.5]` AI 管理新增 SOP 上传接口：新增 `/api_console/ai_config/sop/upload/`，支持按模块上传 `.yaml/.yml`（UTF-8、最大 `512KB`），自动校验模块映射并更新 `AI_DENOISE_PROMPT_IDS`，落库前保留配置备份并尝试热刷新运行时配置
- `[v4.3.5]` 前端 AI 管理切换为 SOP 运维流：界面文案统一由“提示词”改为“SOP”，移除页面内新增/编辑/删除提示词，改为“按模块上传 SOP 文件”；AI 去噪模块面板改为展示当前绑定 SOP 名称、场景、文件路径与更新时间

- `[v4.3.0]` worker 横向扩展落地：`docker-compose` 新增第二个任务容器 `worker_2 (arl_worker_2)`，与 `worker_1` 共同消费 `arltask/arlheavy/arlweb/arlgithub` 队列，实现“同队列多消费者”分担模式，在不新增基础中间件的前提下提升扫描与 AI 去噪阶段吞吐
- `[v4.3.0]` Worker 服务命名与部署开关优化：服务名统一为 `worker_1/worker_2`；新增 `ARL_WORKER_REPLICAS=1|2` 部署选择能力，`start.sh` 与 `quick-build.sh` 按参数自动启动对应 worker 数量（默认 `2`），`restart.sh` 改为优先重启当前运行中的服务并兼容旧参数 `worker -> worker_1` 映射
- `[v4.3.0]` 横向扩展首版并发策略：`worker_1` 与 `worker_2` 均采用保守并发默认值（`task/heavy/web=2`、`github=1`），并分别写入独立日志文件（`arl_worker.log`、`arl_worker_2.log`），避免扩容初期总并发翻倍对 `Mongo/RabbitMQ/Redis` 造成瞬时冲击
- `[v4.3.0]` Celery 节点名冲突修复：`start_worker.sh` 中四类队列 worker 名称调整为 `arlgithub@%h/arlheavy@%h/arlweb@%h/arltask@%h`，确保多 worker 容器同时运行时节点名唯一，避免 mailbox 冲突导致的异常退出
- `[v4.3.0]` Worker 启动恢复职责拆分：`start_worker.sh` 新增 `ARL_WORKER_RECOVER_ON_BOOT` 开关；默认仅主 `worker_1` 执行“中断任务恢复/孤儿 waiting 重投”，`worker_2` 默认跳过启动恢复，减少双实例并发恢复时的抖动与重复争抢风险
- `[v4.3.0]` 运维脚本同步：`scripts/quick-build.sh` 的强制重建服务列表新增 `worker_2`；`start.sh/restart.sh` 日志查看提示新增 `worker_2`，便于扩容后的统一运维与排障
- `[v4.3.0]` 文档补充：`README` 新增“Worker 横向扩展说明”，明确队列竞争消费模型、任务分配机制、重复扫描边界与 MQ 观测命令

## 2026-03-26（v4.2.21）

- `[v4.2.21]` AI 去噪调度改造为“子阶段增量触发”：在保留“任务完成后兜底触发”链路的同时，新增按扫描阶段触发的模块级去噪任务（`ssl_cert/site_saved/site_spider/search_engines/web_info_hunter/file_leak/nuclei_scan/poc_run/weak_brute/findvhost/penetration_test` 对应 `cert/site/url/fileleak/nuclei_result/vuln`），支持“阶段完成即分析、未完成阶段继续等待”；新增 `AI_DENOISE_MODULE_TASK`、`pending_modules` 合并与补偿调度机制，避免并发重复执行与触发丢失
- `[v4.2.21]` AI 去噪流水线支持按模块增量执行：`run_task_ai_denoise_pipeline` 新增 `modules` 入参并改为模块粒度执行与状态回写，保持结果统一落库 `ai_denoise_result`，详情页继续仅读取落库结果、不触发实时模型调用
- `[v4.2.21]` 新增运行架构文档：补充 `docs/容器职责与任务流程分析.md`，系统说明 `arl_web/arl_worker/scheduler` 各自职责、队列分发关系（`arltask/arlheavy/arlweb/arlgithub`）、AI 去噪执行位置与全链路/单任务 Mermaid 流程图，便于容量规划与排障定位

## 2026-03-25（v4.1.24 ~ v4.2.21）

- `[v4.2.21]` 报告导出 AI 去噪字段补齐：`Excel/HTML` 报告中的 `站点 / 目录扫描 / SSL证书 / URL信息 / 风险 / PoC风险` 工作表统一新增 `AI分析` 列，导出内容仅读取扫描阶段已落库的 `ai_denoise_result` 结果（不触发实时 AI 调用）；其中 `风险` 表对 `npoc` 与 `nuclei` 来源分别回填对应模块 AI 结论，批量导出的 `站点` 合并视图按“危险优先、AI来源优先”选择更高价值 AI 分析结果展示
- `[v4.2.16]` 任务管理与资产搜索排序优化：在“未做筛选”场景下，任务列表默认优先级调整为 `运行中 -> 已完成(按结束时间倒序) -> 等待中 -> 异常/已停止`；资产搜索（`站点/目录扫描/SSL证书/URL信息/风险/PoC风险`）在默认排序时新增 AI 价值优先展示，按 `危险 -> 可疑 -> 安全 -> 未分析` 前置高价值目标（同级优先 AI 模型来源）
- `[v4.2.16]` 任务管理进入资产搜索默认分页优化：通过“全局查看/同名任务查看”等带 `task_id` 过滤进入资产搜索时，列表默认每页数量由 `50` 提升为 `200`，减少任务内资产翻页次数并提升复核效率
- `[v4.2.16]` AI 管理新增用量观测：新增 `Token用量统计` 与 `AI对话日志` 面板，后端增加 `ai_usage_log` 落库与统计查询接口（`/api_console/ai_usage/stats/`、`/api_console/ai_usage/logs/`），覆盖 `AI测试` 与 `AI去噪` 调用的 `prompt/completion/total tokens`、请求状态、请求与回复摘要
- `[v4.2.16]` AI 去噪详情与提示词优化：AI分析详情新增“当前记录说明 + 使用提示词”展示，规则/回退场景补齐可读的对话摘要；默认 AI 去噪提示词（站点/目录扫描/SSL证书/URL信息/风险/PoC风险）统一升级为“渗透测试前置研判”导向，强调可执行验证建议与误报收敛

- `[v4.2.14]` AI 去噪分析交互与模型容错增强：资产搜索中 `目录扫描` 补齐 `AI分析` 搜索下拉（与 `SSL证书/URL信息/风险/PoC风险` 统一）；`目录扫描/URL信息/风险/PoC风险` 的 `AI分析` 列统一支持点击查看详情（含未分析/回退场景）。后端新增模型名规范化与不可用模型自动重试机制（如 `Qwen3.5-Plus` 自动映射并按提供方默认模型兜底重试），并优化详情对话记录文案，减少回退场景下“AI回复”重复误解

- `[v4.2.13]` AI 管理安全与交互优化：`/api_console/ai_config/` 默认不再回传明文 key，新增 `/api_console/ai_config/reveal/` 二次验证后按需解密显示；保存与测试链路补齐“未编辑敏感字段自动回填”避免误清空。前端 `模型提供方` 切换改为优先匹配已存在模型配置；`模型配置ID` 改为自动生成并从表单与列表隐藏；顶部 `总测试` 改为 `AI测试`，测试结果改为弹窗对话展示（显示“发送：你好呀～”与 AI 回复）

- `[v4.2.12]` 首行冻结默认值调整：保留 `首行冻结` 按钮能力不变，统一改为各模块默认关闭，避免进入列表即自动冻结造成阅读干扰

- `[v4.2.11]` 搜索引擎与任务耗时展示优化：修复 `search_engines` 阶段耗时统计口径（计时覆盖真实外部调用，避免阶段实际执行却显示 `0秒`）；`Bing/Baidu` 调用改为并行执行并补充单引擎耗时与结果日志，提升搜索引擎阶段整体吞吐与可观测性；任务执行时间概览新增 `<1秒` 展示，避免子任务短耗时被误读为 `0秒`

- `[v4.2.7]` 任务管理与资产列表交互优化：`状态` 悬浮卡片改为仅展示“当前悬停任务”的执行时间概览与子任务阶段耗时（如目录扫描、域名爆破等），不再混入整页任务汇总；悬浮信息支持鼠标移入后保持显示，移出后再关闭。资产搜索相关模块新增 `首行冻结` 按钮并默认开启，支持 `站点/子域名/IP/URL/风险/PoC风险` 等列表在滚动时固定表头，提升长表浏览与对照效率

- `[v4.2.1]` AI 去噪能力落地：新建任务新增 `AI去噪分析` 开关（默认开启）；资产搜索 `目录扫描 / SSL证书 / URL信息 / 风险 / PoC风险` 新增 `AI分析` 列并接入批量分析接口；`目录扫描/URL信息` 支持“可疑/危险”点击查看详情，`SSL证书/风险/PoC风险` 支持点击查看详情，详情统一展示分析摘要、依据与处置建议
- `[v4.2.1]` AI 管理新增去噪配置项：新增 `AI去噪总开关 + 模块级开关 + 模块提示词绑定`（默认全开启），支持按模块独立启停与提示词映射；提示词场景新增 `ai_denoise_fileleak/cert/url/vuln/nuclei_result`
- `[v4.2.1]` AI 配置保存反馈增强：`/api_console/ai_config/` 保存返回运行时热加载状态，前端在不支持热加载时弹出“需重启容器”提示（与配置管理重启提示一致），降低“配置已保存但未生效”的误判

- `[v4.1.33]` AI 管理与 PoC 风险展示优化：`OpenAI 兼容接口` 新增/列表不再展示接口ID，接口ID改为按名称自动生成并做重名/冲突兜底；`PoC风险` 的 `风险URL` 单元格改为上下左右居中显示；后端增强 `afrog` 风险名称解析策略（按 `vul_name -> rule_id -> verify_data -> detail -> description` 多级提取，并扩展名称检索字段），减少大量显示“afrog 漏洞”的泛化名称

- `[v4.1.32]` AI 管理交互与布局优化：提示词新增弹窗移除“提示词ID”手填项（改为按名称自动生成）；`OpenAI兼容接口/新增提示词` 弹窗支持 `Esc` 快捷关闭与遮罩点击关闭；模型与对话配置区统一输入/下拉宽度与字段对齐，修复部分选项框过长、视觉不齐的问题
- `[v4.1.31]` 更新日志版本排序全量修正：按“版本号从下往上”规范统一重排各日期段条目顺序，确保每个日期段内均为“从上到下版本递减、从下到上版本递增”
- `[v4.1.30]` 更新日志规范修正：按“版本号从下往上”规则校正当日版本区间与条目顺序，确保顶部版本与当前仓库版本一致
- `[v4.1.29]` 更新日志一致性修正：补齐 AI 管理交互改动对应版本标注，避免版本号与变更描述错位
- `[v4.1.28]` AI 管理交互体验优化：补充 `Temperature` 参数说明并将 `输出语言` 选项规范为 `中文/英文` 下拉；`OpenAI 兼容接口管理` 与 `提示词管理` 改为“顶部按钮 + 弹窗表单”新增流程；`系统提示词` 调整为“高级可选”并支持默认折叠展开，减少主流程配置干扰
- `[v4.1.26]` 资产搜索新增“超链接”开关：在 `站点 / URL信息 / 目录扫描 / 风险 / PoC风险 / WIH` 模块新增工具栏按钮 `超链接`（默认关闭）；开启后按钮高亮，并将对应 URL 字段渲染为可点击链接（新标签页打开），关闭后恢复纯文本展示
- `[v4.1.26]` TruffleHog 离线包清理：移除仓库内 `tools/TruffleHog/trufflehog_3.93.8_linux_arm64.tar.gz`，减少无用大体积二进制占用并避免后续仓库体积继续膨胀
- `[v4.1.24]` API 管理敏感 Key 安全修复：`/api_console/service_api/` 读写回显默认不再回传敏感字段明文，新增 `sensitive_configured` 状态位；前端仅展示“已配置”占位提示并按需提交改动字段，未编辑的敏感字段在保存与测试时自动回填当前配置，避免“前端 type=password 假隐藏、抓包可见明文”与误清空风险
- `[v4.1.24]` API 管理新增敏感字段按需解密接口：新增 `/api_console/service_api/reveal/`，点击“显示 Key”需通过当前登录账号密码二次验证后才返回敏感明文，前端改为验证通过后临时拉取并显示，关闭后自动回收为隐藏态
- `[v4.1.24]` 任务管理状态列可观测性增强：状态单元格新增悬浮概览，支持查看“当前任务开始/结束时间与执行时长”，并同时展示当前页全部任务时长清单、总时长与平均时长，便于调优扫描配置
- `[v4.1.24]` 任务管理指纹列可读性修复：`finger` 字段改为默认折叠（超过 3 行显示省略），新增“展开/收起”按钮；同时增强指纹名称解析，兼容字符串/数组/对象与 JSON/Python 列表文本，减少显示截断与空白问题
- `[v4.1.24]` AI 管理黑屏修复：修正 `aiApiKeyEdited` 状态变量作用域，消除 `AI 管理` 页面渲染时报错导致的黑屏

## 2026-03-24（v4.1.18 ~ v4.1.24）

- `[v4.1.24]` 配置管理交互修正：`API管理/AI管理` 的 Key 字段改为“编辑输入时明文可见，保存成功后自动回到隐藏态”，避免录入阶段看不到已输入内容；同时 `AI管理` 从 `配置管理` 内嵌区域拆分为侧栏平级独立模块（位于 `配置管理` 下方），导航与模块映射同步调整
- `[v4.1.24]` 快速更新路径补齐配置兜底：`scripts/quick-build.sh` 新增 `config-runtime.yaml` 自动补齐逻辑，确保执行 `quick-build` 时与 `start.sh/restart.sh` 一致复用用户运行配置，避免升级后因运行配置缺失导致重建流程异常
- `[v4.1.23]` 配置持久化防覆盖：`docker-compose` 改为挂载 `ARL/docker/config-runtime.yaml -> /code/app/config.yaml`，并在 `start.sh` 首次启动时自动由 `config-docker.yaml` 模板生成 `config-runtime.yaml`。后续升级代码仅更新模板文件，不再覆盖用户已保存的 API/AI key 与运行配置；`README` 同步补充分离机制说明
- `[v4.1.23]` 配置管理新增 `AI管理`：在“配置管理”页面下方新增统一 AI 配置面板，支持 `通义千问 / Kimi / OpenAI / 智谱 GLM / DeepSeek / OpenAI 兼容接口`，并升级为“多模型配置 + 生效模型选择”模式；运行期每次任务仅使用一个生效模型。面板新增上方 `总测试` 按钮（`/api_console/ai_config/test/`）与配置保存（`/api_console/ai_config/`），同时支持模型级 `API Key/Base URL/模型/超时/temperature/max_tokens` 参数维护
- `[v4.1.23]` 敏感密钥显示安全增强：`API管理` 与 `AI管理` 的 `Key` 字段默认中间脱敏展示，新增 `显示Key` 按钮；点击后需通过当前登录账号/密码二次验证（`/api_console/sensitive_verify/`）才可临时明文显示，刷新配置后自动回收为隐藏态，降低误操作泄露风险
- `[v4.1.23]` 提示词管理能力落地：AI 管理面板新增默认提示词展示、新增提示词、编辑提示词、切换生效提示词能力，覆盖 `AI报告导出` 与 `误报复核` 场景；后端配置新增 `AI.PROMPT_TEMPLATES/AI.ACTIVE_PROMPT_ID` 持久化字段
- `[v4.1.23]` 任务管理报告导出新增 `AI报告（MD）`：任务单条导出与批量导出均支持 `format=ai_markdown`，新增 Markdown 模板结构（任务概览、关键资产、风险聚类、误报疑似项、修复与复测建议）；导出链路改为“未完整配置 AI 时自动降级模板导出、不抛错”，并在报告头部显示生效模型与配置状态
- `[v4.1.23]` 配置示例补齐 AI 节点：`config.yaml.example` 与 `config-docker.yaml` 新增 `AI` 配置段与默认模板，保证新部署实例可直接在 UI 中查看并调整 AI 管理配置
- `[v4.1.23]` AI 规划文档补齐执行计划：`docs/AI智能调度与误报抑制规划.md` 新增“工作计划（执行版）”，明确 `M1~M4` 里程碑、4周节奏与验收清单，便于后续按阶段灰度推进
- `[v4.1.18]` 目录扫描链路稳定性修复：修复 `file_leak` watchdog 子进程启动时触发的循环导入异常 `ImportError: cannot import name 'domain_site_update' from partially initialized module 'app.services'`，导致目录扫描阶段无法正常执行、结果长期为 `0` 的问题。调整 `domainSiteUpdate/domain` 相关导入为按模块直连并将 `find_domain_by_task_id` 下沉到函数内延迟导入，避免 `services -> helpers -> celerytask -> tasks -> services` 启动环路

## 2026-03-23（v4.1.12 ~ v4.1.17）

- `[v4.1.17]` 导出口径一致性补齐：报告新增 `PoC风险` 与 `指纹统计` 工作表，分别对齐任务详情页 `nuclei_result` 与 `stat_finger` 结果；`站点` 工作表同步补充 `headers/截图` 列，减少“页面可见但导出缺失”的信息落差。对应批量导出与单任务导出链路均已接入，并更新导出测试断言
- `[v4.1.14]` 版本同步：按 `ARL/version.txt` 当前版本 `v4.1.14` 更新本节版本标识，保持日志版本与发布版本一致
- `[v4.1.14]` 任务报告导出增强：单任务与批量导出的 `XLSX/HTML` 报告新增 `WAF识别` 工作表（来源 `task.waf_skip_summary.blocked_hosts`，字段覆盖 `IP/域名/端口/WAF厂家/命中原因/证据` 等），并为 `域名` 工作表补充 `来源` 列（支持多来源合并展示），便于报告侧复核 WAF 跳过资产与域名情报来源
- `[v4.1.14]` 仪表盘实时日志可读性修复：前后端同步取消 `recent_logs` 文本截断，`实时扫描日志` 改为完整展示单条日志并保留换行，修复日志尾部长期显示 `...` 无法查看完整内容的问题
- `[v4.1.14]` 任务管理批量处置增强：新增 `停止并删除` 一键按钮，按“先停止、后删除”顺序批量处理已勾选任务，并统一复用确认弹窗与执行中状态，减少手动分两步操作成本
- `[v4.1.14]` 任务重启可用性增强：重启操作新增二次确认；后端 `/task/restart/` 返回新建任务ID列表 `restart_task_id`，前端在重启成功后直接提示新任务ID与筛选可见性说明，降低“点击重启但看起来无响应”的误判
- `[v4.1.14]` 任务列表排序优化：任务管理列表改为按状态优先级固定排序 `运行中 -> 异常 -> 等待中 -> 已完成 -> 已停止`，无论是否按任务名筛选都统一生效，便于优先关注进行中与异常任务
- `[v4.1.12]` 域名任务稳定性修复：修复 `domain_task` 在 `cert_query_plugin` 阶段触发增量端口扫描时，因复用同一份 `scan_port_option` 并在 `ScanPort.__init__` 中执行 `del option["skip_scan_cdn_ip"]` 导致的 `KeyError: 'skip_scan_cdn_ip'` 异常。调整为“拷贝入参 + `pop` 安全读取”后，首次端口扫描与证书反查后的二次增量端口扫描可连续执行，避免任务在中途被标记为 `error`
- `[v4.1.12]` 扫描资源预设并发策略调整：配置中心三档预设改为“按目标并发体感”统一口径，`低性能配置=1/1/1`、`中性能配置=2/2/2`、`高性能配置=3/3/3`（`CELERY_TASK_WORKER_CONCURRENCY / CELERY_HEAVY_WORKER_CONCURRENCY / CELERY_WEB_WORKER_CONCURRENCY`），减少“同档位下体感近似串行”的认知偏差，便于按硬件规格稳定提升多目标并行扫描吞吐
- `[v4.1.12]` 预设与默认值统一升级到高性能档位：`Config` 默认值、`config.yaml.example`、`config-docker.yaml` 与前端预设回退值统一切换为高性能配置（含 `Nuclei/afrog/Celery/URL 探测/端口速率` 等关键参数），并补齐配置中心对 `CELERY_HEAVY_WORKER_CONCURRENCY / CELERY_WEB_WORKER_CONCURRENCY` 的完整“应用预设 -> 保存 -> 回显 -> 档位命中”链路，确保新装即用高性能预配置且并行目标策略稳定为 `低=1 / 中=2 / 高=3`
- `[v4.1.12]` 扫描档位命名规范化：配置中心前后端统一采用 `低性能配置 / 中性能配置 / 高性能配置` 命名，移除用户可见的硬件型号文案；后端 `scan_profile_id` 同步升级为 `low_performance / medium_performance / high_performance`，并保留旧 ID（`2c2g3m/4c4g5m/8c16g10m`）兼容映射，避免历史配置保存后失效
- `[v4.1.12]` 任务详情新增 `WAF识别` 视图：在 `WIH` 右侧增加独立页签与后端查询接口 `waf_host`，集中展示 `WAF 智能跳过` 主机列表，字段包含 `序号 / IP / 域名 / 端口 / WAF厂家`，并支持按 `task_id/ip/domain/port/waf_name` 检索，便于快速核查被跳过资产与厂商命中情况
- `[v4.1.12]` WAF识别接口稳定性修复：修复任务详情页点击 `WAF识别` 时可能出现 `500` 的问题；后端 `waf_host` 查询路由新增“非法端口 URL / 无 scheme URL / 历史脏结构 blocked_hosts”兼容处理，避免 `urlparse(...).port` 异常直接中断请求
- `[v4.1.12]` WAF识别接口二次修复：修复 `waf_host` 路由误调用不存在的 `utils.is_ip` 导致点击即 `500` 的问题，改为路由内 `ipaddress` 标准库判定 IP，兼容域名与 IP 主机解析并补充对应回归测试，避免同类回归
- `[v4.1.12]` 目录扫描提速与超时策略优化：`file_leak` 新增“目标级并行”能力（`FILE_LEAK_TARGET_CONCURRENCY`）与“站点级自适应超时预算”机制，按 URL 规模自动扩展 `site_timeout/no_progress_timeout`（`基础值 + 每1000 URL追加 + 上限`），避免大字典/大目标场景被固定超时过早回收导致“以前可扫出、现在为 0”的问题；同步新增配置项 `FILE_LEAK_SITE_TIMEOUT_PER_1000_URLS_SEC / FILE_LEAK_SITE_TIMEOUT_MAX_SEC / FILE_LEAK_NO_PROGRESS_TIMEOUT_PER_1000_URLS_SEC / FILE_LEAK_NO_PROGRESS_TIMEOUT_MAX_SEC`
- `[v4.1.12]` PoC 风险可用性增强：`PoC风险` 模块的 `验证信息` 列新增一键复制；后端 `nuclei_result` 聚合对 `afrog verify_data` 新增 curl 归一化（优先读取已有 curl 字段，其次从 request 文本推导 curl，最后回退到 URL 级 curl），便于复现与二次验证

## 2026-03-22（v3.3.46 ~ v4.1.0）

- `[v4.1.0]` 版本升级：发布 `v4.1.0`，延续 `v4` 主线能力演进，作为本轮稳定性治理、提速优化与渗透测试增强的阶段版本基线
- `[v4.0.11]` 长任务稳态治理（第一批）：为 `domain` 链路中的 `dns_query_plugin` 新增“按来源分批执行 + 自适应阶段预算（基础值 + 来源数追加 + 上限）”机制，避免三方来源串行查询长时间占用单任务；为 `ssl_cert` 新增“按 endpoint+SNI 展开目标分批抓取 + 自适应阶段预算（基础值 + 目标数追加 + 上限）”机制，域名任务与 IP 任务共用同一证书抓取分批能力；`port_scan` 同步采用“自适应阶段预算（基础值 + 目标数追加 + 端口规模追加 + 上限）”，快扫/精扫/单阶段扫描在预算耗尽后返回已发现的部分结果并继续后续流程，降低单阶段超长运行导致 `delivery acknowledgement timed out` 的风险。同步新增可配置项 `SSL_CERT_FETCH_TARGET_BATCH_SIZE / SSL_CERT_FETCH_CONCURRENCY / SSL_CERT_STAGE_TIMEOUT_SEC / SSL_CERT_STAGE_TIMEOUT_PER_TARGET_SEC / SSL_CERT_STAGE_TIMEOUT_MAX_SEC / DOMAIN_DNS_QUERY_PLUGIN_SOURCE_BATCH_SIZE / DNS_QUERY_PLUGIN_STAGE_TIMEOUT_SEC / DNS_QUERY_PLUGIN_STAGE_TIMEOUT_PER_SOURCE_SEC / DNS_QUERY_PLUGIN_STAGE_TIMEOUT_MAX_SEC / PORT_SCAN_STAGE_TIMEOUT_SEC / PORT_SCAN_STAGE_TIMEOUT_PER_TARGET_SEC / PORT_SCAN_STAGE_TIMEOUT_PER_1000_PORTS_SEC / PORT_SCAN_STAGE_TIMEOUT_MAX_SEC`，并补充 Celery 软/硬超时配置入口 `CELERY_TASK_TIME_LIMIT_SEC / CELERY_TASK_SOFT_TIME_LIMIT_SEC` 作为兜底保护
- `[v4.0.11]` 扫描配置中心预定义档位优化：上调 `8核16G10M` 预定义资源参数，按“稳态优先、兼顾准确率与吞吐”重平衡 `域名爆破 / Celery 并发 / Nuclei / afrog / URL 探测 / 端口扫描速率`，减少高配机器空闲浪费，同时避免激进并发导致的长任务波动
- `[v4.0.11]` PoC 扫描提速调优：针对高配环境进一步上调 `nuclei / afrog` 并发与速率（`NUCLEI_RATE_LIMIT / NUCLEI_CONCURRENCY / NUCLEI_BULK_SIZE / AFROG_CONCURRENCY / AFROG_RATE_LIMIT`），并将 `NUCLEI_SINGLE_TARGET_TIMEOUT_SEC` 下调到 `900s`，减少单目标长时间占用导致的总耗时偏大问题
- `[v4.0.11]` 任务管理体验优化：`风险` 模块的 `类别(plg_type)` 查询改为下拉选择（动态汇总当前范围类别），`指纹统计` 新增 `数量(cnt)` 排序并默认按数量降序；任务详情页隐藏 `C段` 页签与对应批量导出入口；`目录扫描` 在无结果时补充“未开启目录扫描或被 DNS 策略过滤”提示，降低排障成本
- `[v4.0.11]` 渗透测试误报抑制：`cloud_key_leak` 增加同域来源约束、赋值上下文校验与“代码标识符形态”过滤，避免第三方 CDN/压缩 JS 函数名误判为云凭证；`DOM XSS` 静态分析默认跳过常见第三方库路径并收敛短变量污点命中；`SQLi` 差分判定收紧为强信号优先（不再仅凭长度/结构变化直接报 SQL 注入），降低动态页面场景下的噪声
- `[v4.0.10]` waiting 任务启动恢复增强：worker 启动时新增“高置信丢消息 waiting 任务安全重投”能力。对于数据库仍为 `waiting`、已存在历史 `celery_id`、派发超过保护时间、当前无 live task 且 broker 对应队列消息数为 `0` 的任务，系统会优先按原 `dispatch_queue` 自动重新投递并刷新 `celery_id/dispatch_time/dispatch_ts`；仅对无法安全重投的残余孤儿 `waiting` 任务，才继续沿用原有 `error` 收敛逻辑，修复系统更新/重启后部分未开始任务长期停留在“等待中”且不会自动继续的问题
- `[v4.0.9]` 任务报告导出增强：任务管理页的报告导出改为支持下拉选择 `表格格式 / HTML格式`，单任务行内导出同步支持两种格式；后端新增 HTML 报告生成能力，并与 Excel 共用同一份工作簿构建逻辑，保证 `站点 / IP / 系统服务 / SSL证书 / 域名 / URL信息 / 目录扫描 / WIH / 风险 / 资产统计` 等内容口径一致。HTML 报告进一步补充页内目录、任务名/目标、扫描开始时间、截止时间与生成时间，长报告可直接按工作表跳转查看
- `[v4.0.9]` 新建任务体验收敛：移除新建任务弹窗中渗透测试的长段说明文字，避免在勾选开关时占用过多可视空间；同时将 `WAF试探绕过` 统一更名为 `WAF绕过`，前后端配置项展示与接口描述保持一致
- `[v4.0.9]` 访问控制风险检测增强：在现有渗透测试链路上新增保守版“通用后台未授权访问”“水平越权风险”“垂直越权风险”检测能力；后台未授权访问基于后台路径候选与响应特征做只读验证，越权风险则复用 `JS` 提取出的端点与参数，对 `id/user/role/admin/permission` 等关键参数执行低噪声差分探测，仅在响应显著变化且伴随敏感字段或后台权限特征增强时才落风险，尽可能降低误报
- `[v4.0.8]` 文档刷新：重写 `README`，按当前 `v4` 主线重新梳理项目定位、核心能力、快速开始、报告导出、渗透测试、WAF、云安全与部署建议，减少历史截图与过时 `v3` 摘要带来的信息偏差
- `[v4.0.7]` 渗透测试请求策略与 JS 静态分析增强：新增独立请求策略层，为 `penetration_test` 主动链路补齐自适应限速、四类浏览器画像轮换与浏览器风格 Header；同时增强 JS 解码、source -> 变量 -> sink 型 DOM XSS 轻量污点分析，以及 `fetch / axios / $.ajax / XMLHttpRequest` 的 API 端点与参数名提取，并将这些 JS 派生参数回流为主动测试种子。新增目标风险评分与低污染策略后，危险动作路径、敏感参数和高风险表单会被主动收敛或跳过，避免在渗透测试阶段插入过多脏数据
- `[v4.0.6]` WAF 观测与主动链路试探绕过增强：在保留现有 `智能跳过WAF` 保守策略的前提下，补充按主机维度的厂商画像、命中证据、置信度与跳过摘要；新增独立 `waf_bypass` 开关，仅对 `渗透测试` 主动链路启用轻量 Header/节流型试探绕过，形成“先识别、再有限绕过、失败后再跳过”的闭环，同时继续避免把高攻击性绕过逻辑扩散到被动采集阶段
- `[v4.0.5]` 渗透测试能力增强：在原有主动测试器基础上补充 `DOM XSS` 静态分析与更稳的 SQL 布尔/时间差分判断，进一步降低纯内容回显型规则的漏报；同时新增只读版 `cloud_security_scan`，复用 `WIH / URL / 页面` 线索检测云凭证泄露、云存储桶遍历、可接管、ACL / Policy 泄露等问题，明确不引入 `DNSLog`、不执行上传/删除/ACL 写入等高副作用动作
- `[v4.0.4]` Web 专项渗透测试链路重构：新建任务与策略模板新增统一的 `渗透测试` 开关，并将其与 `nuclei / afrog` 的 PoC 扫描链路解耦；新增独立 `penetration_scan` 主动测试器，基于页面表单、带参 URL、API 文档端点与现有 `WIH` 线索构建测试面，采用“基线请求 + 少量 payload + 响应差分/特征”方式，优先覆盖 SQL 注入、XSS、LFI、RCE、XXE、SSTI、SSRF 等高价值场景；同时在未显式开启 `WIH` 时自动补做一次前置 Web 信息收集，承接页面表单 / API 文档 / URL 资产等前置信息
- `[v4.0.2]` 单文件指纹库合成能力：新增本地脚本 `build_fingerprint_bundle.py`，可将多个 JSON 指纹源归一、去重并生成单一 `human_rule` 指纹文件，便于继续沿用现有 `KSCAN_FINGERPRINT_FILE` 配置；同时默认忽略本地生成的 `kscan_fingerprint.local.json`，避免把外部来源规则产物直接带入仓库
- `[v4.0.1]` 指纹识别链路增强：在保留现有 `human_rule + Mongo/Redis 缓存 + kscan` 架构的前提下，补齐标准化 JSON 指纹规则兼容能力，`import_fingerprint` 与 `kscan` 运行时加载链路均可直接承接 `name/method/keyword` 结构并自动去重；表达式引擎新增 `url` 变量，支持 `url/path` 型指纹落入现有识别体系；站点识别结果改为按命中特征给出差异化置信度，不再统一写死为 `80`
- `[v4.0.1]` 版本主线升级：版本号正式切入 `v4` 主线，后续新能力与结构性增强统一按 `v4.x` 演进
- `[v3.3.48]` Web 信息收集链路增强：在保留 `WIH -> URLFinder -> URLFinder 二次敏感扫描 -> TruffleHog` 主链路的前提下，新增受控 `页面情报提取` 与 `API 文档解析`，补充页面链接、表单、脚本入口以及 `Swagger/OpenAPI/Postman` 文档端点发现；同时将 `js_intel_scan` 收敛为“JS 端点/API 文档入口增强器”，不再重复承担 `WIH` 已覆盖的 secrets 与子域名识别职责，避免双规则源带来的重复命中与维护成本
- `[v3.3.46]` Celery / RabbitMQ heartbeat 稳态增强：Celery 侧显式固定 `broker_heartbeat=120` 与 `broker_heartbeat_checkrate=2.0`，RabbitMQ 改为通过独立 `rabbitmq.conf` 固定 `heartbeat=120`，降低宿主机或容器短时卡顿导致的 `Too many heartbeats missed` 误判断链概率；同时回归测试补充心跳默认值断言。`consumer_timeout` 不再额外上调，沿用 RabbitMQ 默认值，避免与“故障检测时长”语义混淆
- `[v3.3.46]` 配置入口收敛与日志维护：将 heartbeat 调优保留为项目内部固定值，不再暴露到 `config-docker.yaml`、示例配置和配置管理页面，减少误配空间；并修正更新日志顶部时间轴与版本区间顺序

## 2026-03-20（v3.3.38 ~ v3.3.39）

- `[v3.3.39]` Web 重任务队列隔离增强：新增独立 Celery 队列 `arlweb` 与并发配置 `CELERY_WEB_WORKER_CONCURRENCY`，将 `目录扫描 / Nuclei / afrog / 站点截图 / 站点爬虫 / WebInfoHunter` 等 Web 重阶段任务从主队列中隔离；手工任务、监控任务与资产站点/WIH 更新任务会按配置自动分流到 `arlweb`，同时 worker 启动守护、孤儿 `waiting` 回收与等待任务重投脚本同步兼容新队列，降低 Web 重任务长期占用 `arltask` 导致后续任务等待、CPU 被拖慢或队列假卡住的问题
- `[v3.3.39]` nmap 分片批次上调：提高端口扫描单批目标数默认值，常规扫描从 `24 -> 48`、重负载端口集从 `8 -> 16`、全端口扫描从 `2 -> 4`，减少大批量目标任务的批次数与阶段切换开销，在保持 `常规 / heavy / 全端口` 分层保护的前提下提升整体吞吐
- `[v3.3.39]` 钉钉通知与知识库摘要对齐修复：SSL 证书临期提醒不再附带“报告链接：未生成/点击查看”占位；计划任务完成通知与钉钉知识库“执行概览”改为复用导出口径统计，统一按实际导出报告中的 `站点/域名/IP/URL/风险` 数据生成摘要，修复通知摘要与知识库报告内容不一致的问题
- `[v3.3.39]` WIH 噪声过滤增强：收紧 `email/path` 规则与排除规则，减少 `avatar@2x.png` 这类静态资源名被误识别为邮箱，以及 `/.test(r)`、`/img.alicdn.com/...`、`/git.io/...`、`/localhost:8899/` 等 JS 代码碎片或外部主机样式路径进入 WIH 结果；ARL 侧对 WIH 解析结果新增二次清洗兜底，进一步抑制旧规则或异常二进制输出带来的邮箱/路径噪声
- `[v3.3.38]` 钉钉知识库任务报告完整性修复：恢复单任务/批量导出与钉钉知识库写入中的 `风险` 工作表，避免报告“写进去了但风险内容缺失”；同时将知识库工作表写入改为按行分块提交，降低 `URL信息/风险` 等大表一次性 PUT 导致的部分写入失败概率；当文档已创建但仅部分工作表写入成功时，任务通知改为展示知识库链接并明确标记“部分写入”，不再误报成完全失败
- `[v3.3.38]` 计划任务下 SSL 证书过期提醒修复：保留“计划任务子任务不单独发送完成通知”的收敛策略，但不再因此跳过 SSL 证书临期/过期机器人提醒，修复计划任务扫描已发现临期证书却没有任何机器人告警的问题
- `[v3.3.38]` Worker 队列守护增强：`worker` 容器内的 `arlgithub/arlheavy/arltask` 三个 Celery 进程改为受同一启动脚本监护，只要任一子 worker 异常退出，容器会主动退出并触发 Docker 自动拉起，修复“主 worker 仍在线但重任务队列子进程已挂，导致部分任务长期停留 waiting” 的假健康问题
- `[v3.3.38]` 目录扫描防卡死增强：保留原有 `file_leak` 功能入口与结果落库方式，但将单站点目录扫描改为受 watchdog 监护的独立子进程执行，新增 `FILE_LEAK_CONCURRENCY / FILE_LEAK_SITE_TIMEOUT_SEC / FILE_LEAK_NO_PROGRESS_TIMEOUT_SEC` 配置项；当站点因安全设备、异常响应或长时间无进展导致目录扫描卡住时，会按站点级总超时或无进展超时主动回收子进程，避免整条任务长期停留在 `目录扫描` 阶段

## 2026-03-19（v3.3.21 ~ v3.3.37）

- `[v3.3.37]` Celery 长任务 ACK 策略修复：将扫描任务队列切回“消费后尽早 ACK”，避免 `task_acks_late=true` 叠加 RabbitMQ `consumer_timeout` 时，长任务在 `Virustotal/搜索引擎/端口扫描` 等任意阶段运行超过阈值便触发 `PRECONDITION_FAILED - delivery acknowledgement timed out` 并连带 worker 通道退出；worker 启动恢复逻辑同步从“回 waiting”改为“收敛为 error”，避免消息已丢失但任务状态仍显示等待中的假象。进一步新增“高置信孤儿 waiting 任务”回收：仅在任务已有 `celery_id`、broker 对应队列消息数为 `0`、且不在任何 worker 的 `active/reserved/scheduled` 列表中时，才在启动阶段将其收敛为 `error`；同时补充 `dispatch_time/dispatch_ts` 字段辅助判断，并将默认扫描配置中的 `CELERY_PREFETCH_MULTIPLIER` 统一回落到 `1`，减少长任务抢占队列导致的等待感，并补充对应回归测试
- `[v3.3.35]` WIH 规则与风险提取降噪：系统性收紧 `tools/wih/config/rules.yml` 中高误报规则，`domain/path` 继续补充噪声过滤，AI Key 检测改为更依赖 provider 上下文，降低 `Cohere/Midjourney/Zhipu/Minimax` 及多家 `sk-` 规则的误命中与互相串标；通用线索规则 `debug_logic_parameters/url_as_value/dos_parameters` 新增边界约束与前端噪声排除。ARL 侧同步收紧 WIH 升级为“敏感信息泄露”风险的条件，不再仅因 `domain/path/urlfinder_js` 等载体型记录内容包含 `token/password` 字样就提升为风险，避免 `iToken.js`、`/password';`、前端国际化占位串等无意义结果进入风险列表；同时将 WIH 内置 fallback 规则模板与主规则文件保持一致，并补充对应回归测试
- `[v3.3.33]` WIH URL 候选清洗增强：收紧 `tools/wih` 的 `path` 拼接探测逻辑，新增对路由方法后缀、占位符模板、静态资源路径与 `head/body/html` 等明显噪声路径的过滤，减少 `path_url` 误命中；ARL 侧新增统一 URL 候选归一化模块，对 `wih/urlfinder` 记录中的 `path_probe status=200` 注释污染、模板路由与静态资源 URL 进行二次清洗，避免无意义链接继续进入 `URL信息` 并拖慢后续探测；同时补充对应 Python / Go 回归测试
- `[v3.3.32]` 测绘源调度与弱口令构建链路修复：测绘引擎自动模式调整为“`FOFA / Shodan` 优先执行但不跳过其它已启用来源”，新增 provider 状态分类与汇总日志，收敛 `quake_360` 配额不足及 `hunter.how` 空响应场景下的误导性报错；同时新增对应回归测试。Docker 构建链路改为优先使用本地 `tools/ncrack/ncrack-0.7.tar.gz` 离线源码编译 `ncrack`，仅在离线包缺失时再联网回退，并在镜像构建末尾执行 `ncrack -V` 自检；任务兼容逻辑同步取消对 `service_brute` 的“仅 x86_64 预编译二进制”限制，避免源码编译场景仍被前置自动关闭
- `[v3.3.25]` 502/假死卡顿熔断问题彻底修复：通过解耦服务长响应超时限制与增加 Nginx 内网动态 DNS，解决当运行巨型前置任务时导致的后续容器启动假死死锁。修改点包含：1）Web/Worker 取消启动项中对数据库/队列强制 `60s` 内连接成功的超时硬性断言（改更为无限等待），防止因历史遗留脏数据启动排障过长反复引流致死；2）Gunicorn 超时时间由 `30s` 暴增至 `300s` 且匹配对应的 `nginx proxy_read_timeout`，杜绝巨型历史记录加载触发容器进程内部互砍；3）Docker external Nginx 配置项中追加通过 `127.0.0.11` 动态解析重构 `upstream`，防止单体通过 `docker-compose restart web` 重建节点导致的反向代理 IP 遗留缓存造成持久化 `502`
- `[v3.3.21]` 体验优化与检测覆盖面增强：配置管理新增直观的资源占用参数文案描述（如 Celery 预取、限制进程寿命），并适量提升 `2c2g3m` 保守预设的利用率边界；保存时追加“手工重启容器生效”弹窗通知与 PoC 超时更新备选方案提示；底层全局拦截补充 `401` 认证失效后的主动路由恢复逻辑；同时向 WIH 特征库补充注入包含 OpenAI、Anthropic、DeepSeek、百川、月之暗面等多家国内外头部大模型的 API Key 泄露监控正则

## 2026-03-18（v3.3.1 ~ v3.3.19）

- `[v3.3.19]` afrog PoC 链路与展示增强：修复 `afrog` 离线包自动解压时误调用 `app.utils.stable_hash` 缺失导致任务在 `afrog_scan` 阶段异常退出的问题；配置管理“扫描超时与端口参数”新增 `AFROG_CONCURRENCY / AFROG_RATE_LIMIT` 两项并透传到 `afrog -c/-rl`；同时将 `Nuclei + afrog` 结果统一收敛到新的 `PoC风险` 模块展示与删除，风险模块默认不再重复展示 afrog 结果，避免同一批 PoC 结果分散在两个入口
- `[v3.3.18]` 三方测绘查询能力增强：`hunter.how` 新增 `domain="..."` 与 `ip=="..."` 两类查询入口，支持按域名和公网 IP 提取关联域名；`Shodan` 新增 `domain/hostname/ip/ssl.cert.subject.cn/ssl.cert.fingerprint/ssl.cert.serial` 多入口查询，并将域名扫描中的“证书反查增强”复用到 `Shodan` 证书搜索链路，使任务在收集到证书信息后可继续自动补充同域资产；同时补充对应查询插件测试用例，便于后续回归验证
- `[v3.3.17]` 重任务队列分流稳态修复：保留 `arlheavy` 重任务隔离能力，但在任务下发（手工任务 + 监控任务）前新增活跃消费者探测，只有检测到 `arlheavy` 在线时才分流，否则自动回退到 `arltask` 并记录回退原因，避免 `Docker Compose`/K8s 部署未完整拉起 `arlheavy` 时新任务长期停留在“等待中”；同时 Celery worker 在消费历史积压消息前会先校验数据库任务状态，对已停止/已完成/异常/已删除任务直接跳过，防止旧 broker 消息被误执行
- `[v3.3.16]` SSL/TLS 合规审计增强：新增 `ARL TLS 基线` 判定模块，对证书扫描结果中的协议与加密套件统一识别“旧协议/弱算法/CBC/静态 RSA/弱 DHE 参数/非基线套件”等不合规项；任务导出 `SSL证书` 工作表新增“`不合规项（协议/套件）`”与“`修复建议`”两列，并补充覆盖常规部署与 `ingress-nginx`/K8s 加固方法的专门规范文档，便于整改与报告交付
- `[v3.3.15]` 任务管理搜索增强：`任务名` 搜索框在保留“直接输入关键字搜索/回车搜索”现有模式的同时，新增已有任务名下拉建议能力；进入任务管理页后会自动拉取任务名候选，并在当前列表结果变化时同步补充建议项，支持“输入搜索 + 下拉选择”两种用法并复用现有同名任务查看与按任务名批量操作链路
- `[v3.3.13]` API 管理验证体验增强：新增顶部“一键验证”按钮，仅对已填写必需凭据的 API 执行批量验证，并以弹窗形式展示逐项成功/失败结果；同时将 `VirusTotal` 单项验证改为轻量鉴权探测，避免沿用完整子域名分页查询导致前端长时间等待或 `502`
- `[v3.3.1]` API 管理增强：新增 `Shodan` 与 `hunter.how` 三方测绘引擎接入（后端查询插件 + 配置模板 + API 管理页配置项）；同时 API 管理支持“按 provider 单项测试”能力，用户可在不落盘的情况下直接验证当前表单凭据可用性并查看测试结果
- `[v3.3.1]` WIH 路径探测增强：`wih` 新增 `path` 记录智能拼接探测能力，默认同时尝试“根路径拼接（host + path）”与“当前目录拼接（source 目录 + path）”，对命中状态（2xx/3xx/401/403/405）输出 `path_url` 记录；记录会保留在 WIH，并继续参与 ARL URL 可达性探测，命中后写入 `URL信息`（来源 `wih_url_probe`）
- `[v3.3.1]` 任务状态一致性修复：Celery worker 在实际消费任务后会立即执行 `waiting -> running` 状态切换（含 `start_time` 兜底写入），避免 `task_acks_late=false` 场景下手动重启/异常中断导致“消息已确认但任务仍长期显示等待中”的假等待问题；与 worker 启动恢复逻辑配合后，中断任务可被正确收敛为 `error`
- `[v3.3.1]` 端口扫描链路性能重构：`port_scan` 新增“分片执行 + 两阶段扫描（先快扫后精扫）”模式，先快速发现开放端口，再对全部发现开放端口的主机执行 `-sV/-O` 逐主机分段精扫（仅分段不裁剪），保证扫描结果完整不缩水；同时补齐阶段化日志，降低全端口/大目标任务对 worker 的长时间占用
- `[v3.3.1]` `file_leak` 探测 URL 生成修复：修复路径为 `/` 时拼接 `a1337` 导致 `host:porta1337` 的 malformed URL 问题；`gen_check_url` 改为基于 `urljoin` 的安全拼接，并新增 URL 合法性校验（含非法端口拦截），避免 `Failed to parse` 噪声日志与无效请求
- `[v3.3.1]` 截图超时治理：`phantomjs` 回退截图链路新增 `PHANTOMJS_TIMEOUT_SEC`（默认 `30s`）并在超时时输出精简告警后快速降级返回，避免未显式超时时命中 `exec_system` 默认 `14400s` 导致单站点长时间卡死与 traceback 噪声
- `[v3.3.1]` 任务统计与 WIH 可观测性修复：任务收尾写入统计时改为强制刷新缓存源数据，修复运行中缓存导致 `服务/指纹统计/WIH` 偶发显示为 `0` 的问题；同时新增 `web_info_hunter` 未开启时的显式日志，便于快速区分“功能未开启”与“执行无命中”
- `[v3.3.1]` 重任务隔离调度：新增 Celery 队列 `arlheavy` 及独立 worker，并在任务下发（手工任务 + 监控任务）时按扫描负载自动分流（如 `all/top1000`、`os_detection`、高端口数+高目标数），避免重任务阻塞普通任务；配置中心补齐相关阈值与并发参数（含 `CELERY_HEAVY_WORKER_CONCURRENCY` 与端口扫描分片/精扫阈值）
- `[v3.3.1]` 长任务稳定性与配置项优化：`docker-compose` 为 RabbitMQ 增加 `consumer_timeout=7200000`，缓解全端口等长任务触发 ACK 超时导致通道被强制关闭；API 管理前端移除 `PassiveTotal` 配置块，减少无维护来源造成的配置干扰
- `[v3.3.1]` 导出与钉钉报告对齐：任务导出新增 `URL信息/目录扫描/WIH` 三个工作表，并统一工作表顺序为 `站点 -> IP -> 系统服务 -> SSL证书 -> 域名 -> URL信息 -> 目录扫描 -> WIH -> 资产统计`；钉钉知识库写入顺序同步与导出保持一致

## 2026-03-17（v3.2.0 ~ v3.2.16）

- `[v3.2.16]` 任务管理状态展示优化：在保持 `status=running` 筛选兼容的前提下，任务列表状态列改为显示当前执行节点（如 `运行中（域名爆破）`、`运行中（站点爬虫）`），提升运行中任务排障与进度感知效率
- `[v3.2.15]` `file_leak` 网络异常降级处理：对 DNS 解析失败/连接失败/超时等请求层异常改为“可恢复跳过”并输出精简诊断日志（含目标 URL 与错误摘要），不再抛出整段 traceback 触发阶段 ERROR；在大字典场景下可显著降低“不可解析子域”导致的日志噪声与任务中断感知
- `[v3.2.14]` 扫描稳定性与离线包诊断日志补齐：`afrog` 扫描新增“离线 Linux zip 自动解压执行”兜底（当 `AFROG_BIN` 不可用时自动在临时目录提取二进制），并补充二进制路径解析、Windows 包误投放提示、PoC 目录解析、目标文件生成等关键诊断日志；同时截图链路在检测到 Playwright 浏览器缺失后按任务维度一次性降级至 `phantomjs`，避免同类报错重复刷屏；Celery 增加 broker 断连自动重连配置，降低 RabbitMQ 短时重启导致的 worker 退出风险
- `[v3.2.13]` 指纹同步启动链路优化：`web` 容器启动默认跳过阻塞式 `import_fingerprint`，改为依赖 `start.sh/quick-build` 触发的后台同步；`sync-fingerprint.sh` 新增默认 `90s` 延迟与 `nice` 低优先级导入，避免 `docker compose` 重启后与服务就绪阶段争抢 CPU 导致“已启动但长时间不可用”。如需恢复旧行为可设置 `ARL_WEB_IMPORT_FINGERPRINT_ON_BOOT=1`
- `[v3.2.12]` 配置管理新增 PoC 一键更新：新增“更新 Nuclei PoC / 更新 afrog PoC”按钮，后端提供 `git clone/pull` 更新接口并返回分支与提交信息；兼容历史“非 git 解压目录”自动备份后重建仓库。部署链路同步增强：`web` 容器 `tools` 挂载改为可写以支持在线更新，镜像安装 `git` 并打包 `tools/afrog` 离线安装包（含 `afrog-pocs`）
- `[v3.2.11]` 新增 afrog 漏洞扫描能力：任务/策略配置与前端“新建任务-扫描功能”新增 `afrog_scan` 开关，后端接入 `afrog -T/-P/-s/-S/-json` 扫描链路并写入 `vuln` 风险模块；同时补充执行与结果日志（可执行文件检查、PoC 目录解析、WAF 过滤前后目标数、落库统计、异常退出告警）以提升可观测性
- `[v3.2.10]` 服务资产 Product 识别修复：恢复 `service_detection` 开启时 `nmap -sV` 产品/版本识别能力，并保留 `npoc_sniffer` 协议增强；`service` 入库阶段对空 `product` 增加协议名兜底，修复资产搜索“服务/Product 长期无结果或空白”的问题
- `[v3.2.9]` 重启稳定性与搜索性能修复：`worker` 启动阶段新增“中断任务恢复”机制，将“已开始但非终态”的历史任务自动收敛为 `error` 并记录中断原因，修复 `docker compose` 手动重启后任务卡在中间阶段的问题；列表接口新增 `_refresh` 强制刷新参数与 `API_LIST_CACHE_EXPIRE` 可配置缓存时长，前端改为“首次加载一次 + 模块内缓存 + 手动搜索/刷新触发更新”，减少任务管理/资产搜索页面切换时的高频 API 请求
- `[v3.2.8]` API 管理补齐 Zoomeye 高级参数：配置中心与前端表单新增 `max_page/request_interval/rate_limit_retry/rate_limit_backoff/rate_limit_max_sleep` 的读取、展示与保存能力，修复“Zoomeye 在配置文件支持分页/超时与限频参数但 API 管理页缺失”的问题
- `[v3.2.7]` 站点指纹识别改为“先快扫后精扫”：`WebSiteFetch` 新增高价值站点评分与分层筛选策略（按状态码/标题关键词/主机关键词/端口/响应特征综合打分，`401/403` 强制入选），第一阶段优先执行 URL 发现，第二阶段仅对高价值子集执行 `site_identify`，显著降低大规模任务下全量指纹识别带来的性能压力且对用户无新增配置要求
- `[v3.2.6]` 中文域名扫描支持：新增域名 IDN 规范化能力（`Unicode -> Punycode/xn--`），并在任务目标解析、资产范围校验、监控任务下发、域名构建/解析、DNS 插件归一化、证书域名提取匹配、导出与证书告警链路中统一使用规范化域名；修复中文域名“校验失败/范围不匹配/链路中途丢失”问题
- `[v3.2.0]` 仪表盘扫描日志链路回归 `arl_worker.log`：`/console/recent_logs` 改为优先读取 `ARL_DASHBOARD_SCAN_LOG_PATH`（默认 `/code/logs/arl_worker.log`）并兼容回退 `/code/arl_worker.log`；`docker-compose` 为 `web/worker` 增加共享日志卷挂载，`worker` 启动脚本统一将 Celery 日志写入共享目录（支持 `ARL_SCAN_LOG_FILE` 覆盖），修复“仪表盘日志与实际扫描日志不一致”问题
- `[v3.2.0]` 仪表盘可读性优化：移除“ARL 引擎”卡片，实时扫描日志窗口增大（默认拉取条数从 `24` 提升至 `120`，后端支持 `默认80/最大300`），提升低配主机场景下日志排障效率
- `[v3.2.0]` 资产搜索能力补齐：`文件泄漏` 与 `URL信息` 模块均新增 `body 长度(content_length)` 排序支持，便于按响应体体量快速定位高价值目标
- `[v3.2.0]` 文案修正：扫描资源档位 `2核2G3M` 描述修复错别字（`当能 -> 但能`）
- `[v3.2.0]` 配置热刷新增强：`配置管理` 与 `API管理` 保存后触发运行时配置热刷新；`worker` 在每次任务执行前按配置文件 `mtime` 自动刷新关键运行参数（扫描并发/超时、字典路径、`QUERY_PLUGIN`、API凭据等），使新配置在“下一次任务”即可生效，降低对容器重启的依赖
- `[v3.2.0]` 新建任务交互与文案统一：任务入口与弹窗标题统一为“新建任务”；扫描功能新增 `smart_skip_waf`（前端展示“跳过WAF”，默认关闭），开启后对同任务目标按主机识别疑似 WAF 拦截并跳过后续请求，任务统计与仪表盘日志新增跳过摘要提示

## 2026-03-17（v3.1.50）

- `[v3.1.50]` 扫描资源预定义档位增强：配置管理新增 `2C2G3M / 4C4G5M / 8C16G10M` 三档一键预设，统一覆盖 `Nuclei`（`timeout/rate-limit/concurrency/bulk-size`）、域名爆破并发、`Web/Celery` 并发、端口扫描参数与 `URLFinder` 探测并发；后端 `scan_config` 接口同步返回档位定义与命中状态，降低低配主机扫描时 CPU/带宽被打满导致系统不可用的风险

## 2026-03-16（v3.1.24 ~ v3.1.49）

- `[v3.1.49]` 指纹同步性能优化：`sync-fingerprint` 新增 hash 检测（指纹文件未变化且库内已有数据时跳过导入）与锁机制（避免重复并发导入）；`start.sh` 与 `quick-build.sh quick` 改为后台执行同步，不再阻塞容器重建完成流程
- `[v3.1.48]` Docker 构建兼容修复：移除 `wih` 编译阶段对 `RUN --mount`（BuildKit 专属语法）的强依赖，回退为普通 `COPY + RUN` 链路；在未开启 BuildKit 的 `docker build/docker compose build` 环境下也可正常构建，并保留 Go 离线包优先、在线下载回退逻辑
- `[v3.1.47]` 指纹升级链路增强：新增 `scripts/sync-fingerprint.sh`，`start.sh` 与 `quick-build.sh quick` 在容器启动/重建后自动触发 `tools/finger.json` 导入，保证重建与升级后指纹规则始终同步最新；同时清理无用文件 `tools/wih/LICENSE`
- `[v3.1.46]` 日志维护同步：补齐 `v3.1.45` 之后版本区间标注，确保 `ARL/version.txt` 与更新日志版本范围一致
- `[v3.1.45]` Docker 构建加速与文档同步：`wih` 编译阶段支持 Go 工具链离线优先（预置 `tools/go1.22.4.linux-amd64.tar.gz`）；`README` 同步补充离线构建与基础组件说明
- `[v3.1.44]` WIH 构建稳定性修复：修复 `wih` 规则模板 embed 路径（`lib/rules_embed.yaml`）导致的编译失败
- `[v3.1.43]` 文档说明补齐：`README` 同步补充基础设施组件说明与构建链路说明，降低升级与排障时的信息偏差
- `[v3.1.42]` 指纹库整合升级：合并外部收集指纹并统一为 `tools/finger.json` 标准结构（`cms/method/location/keyword`），完成去重与格式规范化，显著扩充可导入指纹规模
- `[v3.1.40]` 域名爆破字典扩充：新增 `ARL/app/dicts/domain/domain_10w.txt`，补齐更大规模域名字典数据源
- `[v3.1.39]` Docker 构建链路调整：移除独立 `golang` 构建阶段，改为在 `rockylinux:8` 阶段内按架构下载 Go toolchain 编译 `wih`，并在编译后清理工具链与缓存，统一运行时环境
- `[v3.1.38]` WIH 源码版能力补齐与性能优化：补齐原版核心参数（含中文说明）并统一 `wihscan -> wih` 命名；扫描链路新增“单站 JS 并发抓取 + 响应体读取限额 + 正则编译缓存 + 结果去重与上限控制”；完善 `--generate-rule/--ak-sk-output/--auto-save-name/--dc` 兼容行为，且保持 ARL 现有 `JSONL(target/records)` 调用协议不变
- `[v3.1.37]` WIH 引擎改为源码可维护版本：移除旧 `tools/wih` 预编译二进制分发，改为仓库内保留 `tools/wih` Go 源码并在 Docker 构建阶段编译 `wih`；CLI 与输出协议对齐 ARL 现有调用（`-r/-J/-o/-t/--concurrency/--log-level/--concurrency-per-site/--disable-ak-sk-output/--proxy`），默认规则路径切换到 `tools/wih/config/rules.yml`，并去除项目标识中的 `ifacker` 硬编码
- `[v3.1.36]` URLFinder URL 入库增强：`web_info_hunter` 阶段新增 `urlfinder_url` 可达性探测并写入 `url` 信息表（来源 `wih_url_probe`），探测前统一执行同目标过滤、任务内去重与 DNS 策略校验，降低“JS 拼接 URL 未进入 URL 资产”与解析漂移误扫风险；配置管理同步新增 `URLFINDER_URL_PROBE_ENABLE/MAX_TARGETS/CONCURRENCY`
- `[v3.1.35]` API 管理配置精简与限频参数补齐：`certspotter` 由于默认启用且无需 API Key，前端配置页不再展示；`hunter_qax` 新增 `request_interval/rate_limit_retry/rate_limit_backoff/rate_limit_max_sleep`，`quake_360` 新增 `rate_limit_retry/rate_limit_backoff/rate_limit_max_sleep`，并补齐配置中心读写映射以持久化到 `QUERY_PLUGIN`
- `[v3.1.29]` 配置管理分类与上传区优化：扫描配置页按“字典管理/并发与资源配置/扫描超时与端口参数/安全过滤与解析器”分组展示；“上传新字典”文案调整为“上传域名爆破字典”，并修复上传按钮文本居中显示问题
- `[v3.1.28]` GitHub 操作文案与系统集成布局一致性优化：`GitHub管理/监控` 批量按钮文案统一为“批量停止/批量删除”，并补齐 `GitHub管理` 的批量停止入口；`API管理/钉钉集成/配置管理` 进一步统一输入框高度、选择框高度与多列表单宽度，降低配置页面视觉混乱
- `[v3.1.27]` 系统集成配置表单样式统一：`API管理`、`钉钉集成`、`配置管理` 三个页面的输入框/文本域/文件选择框统一尺寸、内边距与聚焦态，修复配置项控件视觉不一致问题
- `[v3.1.26]` GitHub 批量操作入口补齐：`GitHub管理` 页面新增“删除所选”批量按钮；`GitHub监控` 页面新增“停止所选/删除所选”批量按钮，复用现有后端批量接口提升任务处置效率
- `[v3.1.25]` 同名任务操作精确匹配修复：同名任务查看与“按任务名执行批量操作/导出”统一改为任务名严格等值匹配，避免模糊匹配带入近似任务名导致报告口径偏差
- `[v3.1.24]` DNS 漂移校验增强：新增 `socket/getaddrinfo` 解析链路校验（覆盖 `/etc/hosts` 与运行时 NSS 解析偏移场景），并将 `get_ip/get_ip_system` 结果统一为“公网优先”排序；`http_req` 在未配置 `PROXY_URL` 时显式禁用环境代理；`fetchCert` 对域名目标接入 DNS 策略校验，降低站点/证书阶段误命中内网地址的风险

## 2026-03-14（v3.1.0 ~ v3.1.23）

- `[v3.1.23]` 分页滚动锚点修复：切换“每页条数”前记录是否在底部，列表刷新后自动恢复到底部，修复 `50/页 -> 100/页` 时位置停在中段的问题
- `[v3.1.22]` 登录页与品牌文案统一：登录卡片、输入框与按钮继续放大；系统名称统一为“互联网资产自动化收集系统”；`metadata` 名称与描述同步调整
- `[v3.1.20]` 日志维护补齐：更新 `2026-03-14` 区间为 `v3.1.0~v3.1.19` 并补充 `v3.1.17~v3.1.19` 条目，完善补丁级变更追踪
- `[v3.1.19]` 登录页体验优化：登录卡片与输入控件放大，系统标题在常见分辨率下避免换行；移除默认账号密码回填并关闭表单自动填充
- `[v3.1.18]` 全局分页交互修复：页码区域改为可下拉选择“第 N 页”；翻页按钮补充 `type=button`，修复点击翻页后页面上移问题
- `[v3.1.17]` SSL 告警收敛：正式移除“SSL 临期告警写钉钉知识库”的执行链路，仅保留机器人通知；任务报告 `SSL证书` 工作表保持不变
- `[v3.1.16]` SSL 告警链路调整：任务导出报告继续保留 `SSL证书` 工作表；SSL 临期提醒改为仅发送钉钉机器人消息，不再创建钉钉知识库 SSL 提醒报告
- `[v3.1.15]` 全局分页体验优化：统一分页区域新增“当前页”展示按钮（`第X/Y页`），每页条数上限从 `100` 提升到 `500`（新增 `200/500` 选项）；`README` 同步补充 `config-docker.yaml` 跳过跟踪指引，减少升级时本地配置冲突
- `[v3.1.14]` 配置管理补齐端口扫描全局默认参数：新增并持久化 `HOST_TIMEOUT_TYPE/HOST_TIMEOUT/PORT_PARALLELISM/PORT_MIN_RATE`；任务执行链路在策略未显式配置时统一回退全局默认，并同步补齐前后端读写/校验逻辑
- `[v3.1.13]` 报告导出与钉钉写入口径统一：修复导出结果与页面资产统计不一致问题；系统服务子表优先按 `service` 集合统计并在缺失时回退 `ip.port_info`；钉钉任务报告写入上限提升至 `10000` 行，降低大任务截断概率
- `[v3.1.11]` 报告导出一致性修复：任务 Excel 报告“风险”工作表移除 `任务ID` 列；钉钉知识库写入链路同步兼容去除“风险/漏洞”工作表 `任务ID` 列，确保导出与在线文档展示一致
- `[v3.1.10]` 品牌视觉细节修复：登录页标题改为可换行展示，修复长文案被截断；统一优化灯塔 Logo 的圆角/高光层与深色主题对比度，并为砂岩白主题提供单独可读性配色
- `[v3.1.9]` `nuclei` 阶段 Mongo 超时容错增强：Mongo `socketTimeout` 默认提升到 `60s`；`build_nuclei_targets` 读取 `site` 集合超时时最多重试 `3` 次；首次连续失败不再中断整任务，而是延后 `nuclei` 到后续阶段完成后补跑一次，补跑仍失败则记录告警并跳过 `nuclei`
- `[v3.1.8]` 任务管理与品牌视觉一致性修复：`任务管理` 页面将“任务名搜索 + 同名任务查看专用输入”整合为单一任务名输入（复用到同名查看与按任务名批量操作）；同时登录页与侧边栏统一复用灯塔 Logo 组件，修复深色主题下 `ARL/Lighthouse` 文案过暗与两处样式不一致问题
- `[v3.1.7]` 任务管理搜索入口整合：`GitHub 任务` 与 `GitHub 监控任务` 页面将“任务名称/关键字”双输入合并为单一“任务名/关键字”；后端新增 `search_text` 联合检索（`name OR keyword`）并保持与状态等筛选条件可叠加，避免重复搜索框带来的使用歧义
- `[v3.1.6]` 证书采集兜底增强：当 Python TLS 解析异常时自动回退 `nmap ssl-cert` 结果，降低异常目标导致证书缺失的概率
- `[v3.1.5]` 证书识别能力增强：集成 `nmap --script ssl-cert` 证书链路，并按 `SNI` 优先策略选取证书结果，提升复杂入口场景下证书识别准确性
- `[v3.1.4]` 证书采集策略优化：优先保留 `SNI` 命中证书，抑制默认兜底证书覆盖业务证书，减少“域名证书被默认证书污染”问题
- `[v3.1.2]` 钉钉知识库/计划任务对比摘要文案统一：对比指标标签中包含“漏洞”的文案统一替换为“风险”，修复“漏洞总数”仍被写入在线文档的问题
- `[v3.1.1]` `quick-build.sh frontend` 前端热更新构建链路升级：默认跟随 `Dockerfile` 的 Node 基础镜像版本；当本机 Node 低于 `20` 时自动切换 Docker Node 构建，避免旧版本 Node 导致构建失败或产物不一致
- `[v3.1.0]` 发布 `3.1.0` 版本：在 `v3.0` 系列稳定性与可用性改进基础上进入新小版本，后续功能迭代以 `v3.1.x` 持续演进

## 2026-03-14（v3.0.70 ~ v3.0.78）

- `[v3.0.78]` 前端可读性全局优化：统一主题主文字变量并提亮暗色主题的弱文本对比度；输入框/下拉框/占位符文本改为跟随主题高对比色；侧边栏导航、分组标题和版本信息同步提亮，修复“多模块文案发灰不清晰”问题
- `[v3.0.73]` 任务管理批量操作增强：批量停止/删除与各类批量导出（含报告导出）支持“输入任务名”后直接执行，无需先勾选列表；“同名任务查看”复用同一任务名聚合逻辑
- `[v3.0.73]` 导出与通知文案统一：任务导出中“漏洞”工作表更名为“风险”，并将导出列名、钉钉在线文档汇总列及任务通知文案统一为“风险”；导出样式由仅 SSL 表扩展为全表统一美化（冻结首行、筛选、表头高亮、边框与斑马纹）
- `[v3.0.72]` 调度与站点识别稳定性修复：`scheduler` 主循环及任务加载增加异常保护，避免 Mongo 短时抖动导致调度进程退出；`phantomjs --version` 超时改为安全降级（跳过 `site_identify` 而非任务异常）；`docker-compose` 为 `web/worker/scheduler` 增加 Mongo 超时环境变量并补齐 scheduler 字典挂载路径，修复自定义上传字典存在但容器内判定“not file”的问题
- `[v3.0.72]` 文档策略调整：`README` 更新日志改为仅记录大版本摘要，补丁级版本细节统一维护在 `CHANGELOG.md`；开发规范新增对应约束
- `[v3.0.71]` 任务管理视图升级：将“局部查看”改为按“任务名”聚合同名任务的扫描结果查看；筛选文案统一为“查看筛选条件”；默认分页从 `10` 调整为 `50`
- `[v3.0.70]` 前端主题明暗平衡优化：提升主色、边框和弱文本对比度，修复深色主题信息区“发灰难读”问题；左侧导航分组标题透明度同步提升，增强分组辨识度

## 2026-03-13（v3.0.45 ~ v3.0.69）

- `[v3.0.69]` WIH 信息提取链路增强：新增自研 `urlfinder_extract`，在 `web_info_hunter` 阶段按“`WIH -> URL/JS增强提取 -> TruffleHog`”执行；增强提取支持页面与 JS 中 URL/JS 引用提取、相对路径归一化与受控递归，且 TruffleHog 增加目标站点 host 过滤，仅扫描当前资产范围内来源的 JS
- `[v3.0.57]` 集群构建进一步兼容：前端构建阶段改为自动探测 `apk/apt` 安装编译工具；依赖安装统一使用 `npm install`，避免集群环境受未纳管 `package-lock.json` 或 `npm ci` 严格校验影响导致构建失败
- `[v3.0.56]` 前端依赖安装稳定性修复：移除 `frontend-src` 中触发 `node-gyp` 编译的 `better-sqlite3` 依赖，并在 `frontend_builder` 增加 `python3/make/g++` 兜底，修复 CI/集群构建阶段 `gyp ERR! find Python` 失败
- `[v3.0.55]` 集群构建兼容修复：`Dockerfile` 中前端产物复制改为 `COPY --from=0`（阶段索引），避免部分构建器将 `--from=frontend_builder` 误解析为外部镜像并触发 `frontend_builder:latest` 拉取失败
- `[v3.0.54]` 构建加速优化：前端 `npm` 默认切换 `npmmirror`（支持环境变量覆盖）；`quick-build` 自动优先使用 `buildx/BuildKit` 并把 `NPM_REGISTRY` 透传到 Docker 构建与前端热更新容器，缓解依赖下载慢与 legacy builder 性能瓶颈
- `[v3.0.53]` 前端构建改为 `Dockerfile` 多阶段编译：镜像构建时直接基于 `frontend-src` 产出静态资源，不再依赖仓库预编译目录；`quick-build` 同步移除构建前前端目录拷贝依赖，并新增 `.dockerignore` 排除 `frontend-src/node_modules|dist`，降低构建上下文污染导致的旧版本误打包风险
- `[v3.0.50]` 构建链路修复：`./scripts/quick-build.sh` 在 `quick/full/clean/tag` 模式下强制基于 `frontend-src` 重新编译前端，并校验产物包含当前 `ARL/version.txt`；无本机 `npm` 时自动改用 Docker Node 构建，避免回退旧静态文件导致版本显示滞后
- `[v3.0.49]` SSL 证书采集修复：同一 `ip:port` 支持“默认证书 + 多SNI证书”并行观测（配置项 `CERT_MULTI_SNI_MAX_PER_ENDPOINT`），修复多域名复用IP时证书被单条结果覆盖问题；证书告警/导出优先使用 `sni_domain`
- `[v3.0.48]` SSL 证书过期通知优化：任务内按“域名+证书身份+到期时间”聚合端点去重，跨任务按告警等级升级（如 `30 -> 15 -> 7 -> 3 -> 1 -> 0 -> 过期`）抑制重复推送；证书列表 `HOST` 展示调整为“域名 -> ip:port”
- `[v3.0.47]` WIH 结果增强：`trufflehog_*` 与 `app_key/api_key/token` 等高价值敏感记录会同步入 `vuln` 风险模块（按 `task_id+wih_fnv_hash` 去重），并在 WIH 列表中做敏感高亮，便于优先处置
- `[v3.0.46]` 策略配置（新建/编辑）移除“扫描配置”可视化编辑区，避免与配置管理职责重复；策略下发任务时不再带入 `host_timeout/port_parallelism/port_min_rate` 等策略级调优参数
- `[v3.0.46]` 策略配置新增 `domain_dict` 与 `file_leak_dict` 两个任务级字典字段，支持在策略中指定“域名爆破字典 / 敏感文件泄漏字典”（可留空跟随配置管理默认）
- `[v3.0.45]` `nuclei` 分批策略优化：当 `NUCLEI_TARGETS_PER_BATCH<=1` 时改为按 `-c * -bs` 与超时预算自动计算批次大小，避免默认单目标拆分导致进程创建开销过高
- `[v3.0.45]` `nuclei` 自动扫描回退策略优化：移除“结果文件为空即回退 tags”逻辑，仅在执行失败或模板匹配失败时回退，减少重复扫描

## 2026-03-12（v3.0.33 ~ v3.0.44）

- `[v3.0.44]` 域名解析器策略扩展为全局生效：域名构建/解析、站点爬虫（含302跳转）、站点抓取favicon、资产站点监控统一接入 DNS 策略校验，避免自定义解析器与系统解析漂移导致误扫内网
- `[v3.0.43]` 任务报告 `SSL证书` 工作表新增独立“域名”列，`HOST` 列仅展示 `ip:port`；同步优化导出样式（首行冻结/筛选/表头高亮/斑马纹），提升可读性并保持与钉钉知识库数据一致
- `[v3.0.42]` 任务报告导出 `SSL证书` 工作表移除任务ID列；`HOST` 列统一展示为 `域名 -> ip:port`，与钉钉知识库报告展示保持一致
- `[v3.0.41]` SSL证书采集支持 `IP直连 + SNI域名` 方式获取业务域名证书；`cert` 表新增 `host/domain/domains` 字段用于导出与关联展示
- `[v3.0.35]` `web_info_hunter` 阶段接入 TruffleHog JS 二次扫描（默认跟随 WIH 开启），支持将 WIH 发现的 JS 源做凭证泄漏检测并以 `trufflehog_*` 记录类型原文入库
- `[v3.0.33]` 配置管理（扫描配置）新增 `NUCLEI_SINGLE_TARGET_TIMEOUT_SEC` 字段，支持直接设置 `nuclei` 单目标最大扫描时长
- `[v3.0.33]` 配置管理（扫描配置）新增 `FILE_LEAK_DICT` 配置项与上传入口，支持“敏感文件泄漏字典”内置/自定义/上传三类选项
- `[v3.0.33]` 配置管理新增硬件推荐档位：`2核2G=1小时`、`4核4G=2小时`、`8核16G=3小时`
- `[v3.0.33]` `nuclei` 扫描新增带宽限速参数（`-rl/-c/-bs`）与按目标分批执行（`NUCLEI_TARGETS_PER_BATCH`），降低扫描对出口带宽冲击
- `[v3.0.33]` `nuclei` 扫描超时改为按目标数计算：`min(NUCLEI_EXEC_TIMEOUT_SEC, NUCLEI_SINGLE_TARGET_TIMEOUT_SEC * 目标数)`，并在超时后安全退出当前批次
- `[v3.0.33]` 任务状态写库增加重试兜底，缓解 Mongo 短时不可达（如 `mongodb:27017 Name or service not known`）导致任务中断

## 2026-03-11（v3.0.10 ~ v3.0.26）

- `[v3.0.26]` 钉钉集成页面移除 `DryRun（只演练不落地）` 配置项，避免无效开关干扰
- `[v3.0.26]` 钉钉集成配置区栅格布局优化（`SSL提醒天数` + `API超时`），修复字段新增后被挤压溢出问题
- `[v3.0.25]` 钉钉“SSL证书扫描通知”调整为“SSL证书过期通知”，新增提醒阈值配置 `SSL_CERT_NOTIFY_DAYS`（默认 `<=30` 天）
- `[v3.0.25]` 证书告警消息增强：新增生效时间/失效时间/证书有效期字段，告警域名优先使用任务内 IP 关联域名并过滤内网 IP 证书告警
- `[v3.0.25]` 钉钉知识库任务报告增强：`SSL证书` 工作表去除任务ID列，并新增 `过期证书` 工作表单独列出已过期证书
- `[v3.0.24]` 任务管理、资产分组、策略配置列表的“操作”列改为固定最小宽度，行内按钮改为不换行，避免被前置长字段挤压后错位
- `[v3.0.23]` 钉钉调试接口增强稳定性：每次请求前同步配置文件到当前进程，减少多 worker 下命中旧配置导致的随机失败
- `[v3.0.23]` 钉钉 OpenAPI 请求增强重试：工作区/节点/连通性接口增加瞬时失败重试与鉴权失败自动刷新 token
- `[v3.0.23]` 前端错误提示增强：优先显示 `error_message/detail`，不再只展示“系统异常”
- `[v3.0.21]` 仪表盘“资产分布概览”图表配色优化为青蓝绿橙组合；柱状图增加浅色轨道背景并统一圆角样式
- `[v3.0.20]` 策略配置（新建/编辑）提交时固定 `domain_config.domain_brute=true`；“域名爆破类型”文案调整为“默认字典模式”
- `[v3.0.19]` 新建任务页面隐藏“域名爆破”勾选开关；提交时前端固定 `domain_brute=true`
- `[v3.0.18]` 任务管理新增异常详情交互：`status=error` 可点击查看详情弹窗；后端新增 `append_task_error` 统一异常落库（`last_error/error_logs`）
- `[v3.0.17]` 新建任务新增端口扫描 `custom` 选项；前后端增加 `port_custom` 校验和标准化保存
- `[v3.0.16]` 新建任务文案统一为“域名爆破字典”；选择字典后默认字典模式自动禁用并提示不生效
- `[v3.0.15]` 新建任务支持 `domain_dict` 字段；后端增加文件存在性校验；域名任务执行优先使用任务级字典
- `[v3.0.14]` 新增字典持久化目录和容器挂载；配置管理支持内置/自定义/上传字典聚合与旧路径兼容
- `[v3.0.13]` 字典目录重构：域名字典与敏感目录字典分目录归档，并保留历史路径兼容
- `[v3.0.12]` 删除交互统一为前端确认弹窗；提示消息过滤 `<script>` 与 HTML 标签；同步前端构建产物
- `[v3.0.10]` SSL证书采集增强（协议/套件/强度）；任务详情与资产搜索展示增强；导出与钉钉知识库新增 SSL 工作表；钉钉新增证书临期告警

## 2026-03-10（v3.0.1 ~ v3.0.9）

- `[v3.0.9]` 仪表盘任务状态与进度展示优化：任务列表新增“当前执行节点”列（如 `运行中（域名爆破）`、`运行中（站点爬虫）`），并对运行中任务提供“取消/重试”操作入口；任务详情页新增“重试”按钮，支持对失败任务的一键重试
- `[v3.0.8]` 仪表盘可用性与稳定性增强：重构任务状态与进度计算逻辑，修复因网络抖动导致的任务状态反复切换与仪表盘卡顿问题；优化任务列表与详情页的加载性能，提升大规模任务场景下的响应速度
- `[v3.0.7]` API 管理增强：支持对接 `Zoomeye` 高级查询参数（如 `max_page/request_interval` 等），并可针对不同任务配置不同的查询并发与速率限制；同时支持对接 `PassiveTotal` 被动探测结果
- `[v3.0.6]` API 管理与任务配置统一优化：配置管理与 API 管理页新增“按 provider 单项测试”能力，用户可在不落盘的情况下直接验证当前表单凭据可用性并查看测试结果；同时任务配置中的 API 管理项支持一键填充为当前选中任务的有效凭据
- `[v3.0.5]` SSL/TLS 合规审计增强：新增 `ARL TLS 基线` 判定模块，对证书扫描结果中的协议与加密套件统一识别“旧协议/弱算法/CBC/静态 RSA/弱 DHE 参数/非基线套件”等不合规项；任务导出 `SSL证书` 工作表新增“`不合规项（协议/套件）`”与“`修复建议`”两列，并补充覆盖常规部署与 `ingress-nginx`/K8s 加固方法的专门规范文档，便于整改与报告交付
- `[v3.0.4]` 任务管理与搜索体验优化：任务管理页新增任务名下拉建议能力，进入任务管理页后会自动拉取任务名候选，并在当前列表结果变化时同步补充建议项；同时任务搜索框在保留“直接输入关键字搜索/回车搜索”现有模式的同时，支持“输入搜索 + 下拉选择”两种用法并复用现有同名任务查看与按任务名批量操作链路
- `[v3.0.3]` 任务恢复与持久化稳态机制：底层修复 `worker` 重启时会将正在运行的 `running` 任务直接标记为 `error` 直接抛弃导致的断崖死结，修改为优雅回拨至 `waiting` 状态以便重启后消息队列重新投递跑取；同时针对根因修复了 `docker-compose.yml` 中 `rabbitmq` 消息队列默认未挂载存储卷的缺陷（增加 `rabbitmq_data`），使宕机、停启期间的所有积压任务队列实现完全持久化；额外新增了异常任务排障重发脚本（一键清除本地积压队列并使用数据库状态重新强制填充队列）。
- `[v3.0.2]` 重启与恢复逻辑优化：任务在重启后会优先尝试恢复为 `waiting` 状态，避免因重启导致的任务状态异常；同时优化任务状态与进度计算逻辑，修复因网络抖动导致的任务状态反复切换与仪表盘卡顿问题
- `[v3.0.1]` 发布 `3.0.1` 版本：修复 `3.0.0` 版本中因任务状态与进度计算逻辑调整导致的任务异常与仪表盘卡顿问题

## 2026-03-09（v3.0.0）

- `[v3.0.0]` 全新 UI 界面发布：基于 React + Ant Design 的全新界面，任务管理、资产搜索、配置管理等核心模块全面优化升级；全新仪表盘任务状态与进度展示，支持任务取消与重试；增强的 API 管理与 SSL/TLS 合规审计能力；支持对接 Zoomeye 被动探测结果；任务恢复与持久化机制优化；全局搜索与过滤体验提升；支持自定义字典与多种扫描策略灵活组合；全新文档与更新日志说明
