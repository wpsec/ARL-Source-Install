# ARL 前端（frontend-src）

React 19 + TypeScript + Vite 6 + Tailwind CSS 4 + daisyUI 5（CSS-first）。
纯静态产物，所有数据经 `/api`（Flask-RESTX）获取；前端不持有任何第三方密钥。

## 命令

```bash
npm ci          # 安装依赖（package-lock.json 随代码提交，构建以 ci 为准）
npm run dev     # 本地开发（:3000）
npm run build   # 产出 dist/（容器构建后由 nginx/gunicorn 静态托管）
npm run lint    # tsc --noEmit 类型检查
```

## 目录结构（docs/plan/04 计划4 重构后）

```
src/
  App.tsx            路由壳 + 全局状态（MainShell；视图全部 React.lazy）
  views/             页面级组件（Login/Dashboard/SystemMonitor/ActionDialog/TableModule/ApiConsole/ConfigConsole/AiConsole/Dingtalk）
  components/ui/     daisy 六件套：Modal(原生 dialog)/Badge/Card/FormRow/CheckboxCard/DataTable(>200 行虚拟滚动)
  components/domain/ 业务组件（SensitiveRevealVerifyModal 等）；Sidebar/BrandLogo
  layout/            PageHeader（全站页头单一来源）
  domain/            纯函数：types/format/task/finger/wih/system/cells/payload
  config/modules.ts  模块配置数组（列表路径/列/搜索项/动作模板）
  api/client.ts      requestApi 统一封装（Token 头、后端就绪探测、404 尾斜杠回退）
  ui/classes.ts      控件共享类
  index.css          品牌 token 单一来源 + daisyui/theme 主题注册（brand/midnight/slate/nord/titanium/sandstone）
```

## 约束

- 主题与颜色：唯一来源是 `index.css` 的 `--brand-*` 变量，daisy 主题全部 var() 引用；新增色先进变量块再进主题注册，`scripts/check-theme-contrast.py` 需保持全绿。
- 滚动模型：业务页面唯一纵向滚动源是 `main`；内部滚动仅限白名单（modal 内容 max-h-[72vh]、pre/日志、下拉弹层、侧边栏、DataTable 虚拟模式）。
- API 契约：以 `docs/plan/04-附录A-API契约冻结清单.md` 为准（`scripts/freeze-api-contract.py` 生成），端点/字段/状态语义变更必须先改后端再重跑脚本。
- 版本号：`__ARL_VERSION__` 由 vite define 注入，来源 `ARL/version.txt`（pre-commit hook 自动递增）。
