import {
  lazy,
  Suspense,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { Lock, X } from 'lucide-react';
import {
  ACTIVE_MODULE_KEY,
  ACTIVE_MODULE_FILTERS_KEY,
  TOKEN_KEY,
  USERNAME_KEY,
  buildFilterSignature,
  requestApi,
} from './api/client';
import Sidebar from './components/Sidebar';
import { Modal } from './components/ui/Modal';
import { ViewErrorBoundary } from './components/ui/ErrorBoundary';
import SystemMonitorMiniWidget from './components/SystemMonitorMiniWidget';
import { TASK_DETAIL_TABS, getModuleById, resolveStoredModuleId } from './config/modules';
import { ThemeProvider } from './context/ThemeContext';
import { applyPathTemplate, deepClone } from './domain/format';
import type {JsonValue, ModuleAction, OpenModuleHandler} from './domain/types';
import { LoginView } from './views/LoginView';
import { CONSOLE_ALERT_ERROR_CLASS, CONSOLE_INPUT_CLASS, CONSOLE_PRIMARY_BUTTON_CLASS } from './ui/classes';

// 路由级代码分割（docs/04 Phase 4）：视图按需加载，首屏 bundle 不再包含全部页面。
const DashboardView = lazy(() => import('./views/DashboardView').then((m) => ({ default: m.DashboardView })));
const SystemMonitorView = lazy(() => import('./views/SystemMonitorView').then((m) => ({ default: m.SystemMonitorView })));
const ApiConsoleView = lazy(() => import('./views/ApiConsoleView').then((m) => ({ default: m.ApiConsoleView })));
const ConfigConsoleView = lazy(() => import('./views/ConfigConsoleView').then((m) => ({ default: m.ConfigConsoleView })));
const ConfigAiManagementPanel = lazy(() => import('./views/AiConsoleView').then((m) => ({ default: m.ConfigAiManagementPanel })));
const DingtalkIntegrationView = lazy(() => import('./views/DingtalkIntegrationView').then((m) => ({ default: m.DingtalkIntegrationView })));
const TableModuleView = lazy(() => import('./views/TableModuleView').then((m) => ({ default: m.TableModuleView })));
const ActionDialog = lazy(() => import('./views/ActionDialog').then((m) => ({ default: m.ActionDialog })));

function ViewFallback() {
  return (
    <div className="flex min-h-64 items-center justify-center gap-3 text-sm text-base-content/60">
      <span className="loading loading-spinner loading-sm" aria-label="加载中" />
      页面加载中…
    </div>
  );
}

function readStoredModuleFilters(): Record<string, JsonValue> {
  try {
    const raw = localStorage.getItem(ACTIVE_MODULE_FILTERS_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return {};

    return Object.entries(parsed).reduce<Record<string, JsonValue>>((result, [moduleId, filters]) => {
      if (!moduleId || !filters || typeof filters !== 'object' || Array.isArray(filters)) return result;
      result[moduleId] = filters as JsonValue;
      return result;
    }, {});
  } catch {
    return {};
  }
}

export function MainShell() {
  const queryClient = useQueryClient();
  // 全局动作（侧边栏"新建扫描"等）成功后的列表失效信号：TableModuleView 激活 effect 依赖它重跑，
  // 否则"已在任务页时新建任务"没有可见刷新路径（openModule 同模块不重挂载）。
  const [listRefreshSignal, setListRefreshSignal] = useState(0);
  const [token, setToken] = useState(() => localStorage.getItem(TOKEN_KEY) || '');
  const [username, setUsername] = useState(() => localStorage.getItem(USERNAME_KEY) || 'admin');
  const [activeModuleId, setActiveModuleId] = useState(() => resolveStoredModuleId(localStorage.getItem(ACTIVE_MODULE_KEY)));
  const [moduleExternalFilters, setModuleExternalFilters] = useState<Record<string, JsonValue>>(
    readStoredModuleFilters,
  );
  const [moduleScrollResetTokens, setModuleScrollResetTokens] = useState<Record<string, number>>({});
  const [globalAction, setGlobalAction] = useState<ModuleAction | null>(null);
  const [globalActionPayload, setGlobalActionPayload] = useState<JsonValue>({});
  const [globalNotice, setGlobalNotice] = useState('');
  const [loginError, setLoginError] = useState('');
  const [loginLoading, setLoginLoading] = useState(false);
  const [passwdDialogOpen, setPasswdDialogOpen] = useState(false);
  const [passwdForm, setPasswdForm] = useState({ old_password: '', new_password: '', check_password: '' });
  const [passwdError, setPasswdError] = useState('');
  const [passwdLoading, setPasswdLoading] = useState(false);
  const mainScrollRef = useRef<HTMLElement | null>(null);
  const moduleScrollResetCounterRef = useRef(0);

  const activeModule = getModuleById(activeModuleId);
  const viewToModuleMap: Record<string, string> = {
    dashboard: 'dashboard',
    tasks: 'task',
    assets: 'site',
    asset_monitor: 'scheduler',
    groups: 'asset_scope',
    monitoring: 'system_monitor',
    policies: 'policy',
    fingerprints: 'fingerprint',
    pocs: 'poc',
    schedules: 'task_schedule',
    github_mgmt: 'github_task',
    github_monitor: 'github_scheduler',
    api_mgmt: 'api_console',
    config_mgmt: 'config_console',
    ai_mgmt: 'ai_console',
    dingtalk: 'dingtalk_api',
  };
  const moduleToViewMap = useMemo(() => {
    const reversed: Record<string, string> = {};
    Object.entries(viewToModuleMap).forEach(([view, moduleId]) => {
      reversed[moduleId] = view;
    });
    reversed.asset_site = 'groups';
    reversed.asset_domain = 'groups';
    reversed.asset_ip = 'groups';
    reversed.asset_wih = 'groups';
    reversed.site = 'assets';
    reversed.domain = 'assets';
    reversed.ip = 'assets';
    reversed.cert = 'assets';
    reversed.service = 'assets';
    reversed.fileleak = 'assets';
    reversed.url = 'assets';
    reversed.vuln = 'assets';
    reversed.cip = 'assets';
    reversed.npoc_service = 'assets';
    reversed.nuclei_result = 'assets';
    reversed.stat_finger = 'assets';
    reversed.wih = 'assets';
    reversed.wih_endpoint = 'assets';
    reversed.waf_host = 'assets';
    reversed.github_result = 'github_mgmt';
    reversed.github_monitor_result = 'github_monitor';
    return reversed;
  }, []);
  const openModule = useCallback<OpenModuleHandler>((moduleId, nextFilters, options) => {
    if (options?.resetScroll) {
      const targetModuleCacheKey = `${moduleId}::${buildFilterSignature(nextFilters)}`;
      moduleScrollResetCounterRef.current += 1;
      setModuleScrollResetTokens((prev) => ({
        ...prev,
        [targetModuleCacheKey]: moduleScrollResetCounterRef.current,
      }));
      if (mainScrollRef.current) {
        mainScrollRef.current.scrollTop = 0;
      }
    }
    setActiveModuleId(moduleId);
    setModuleExternalFilters((prev) => {
      const next = { ...prev };
      if (nextFilters && Object.keys(nextFilters).length > 0) {
        next[moduleId] = deepClone(nextFilters);
      } else {
        delete next[moduleId];
      }
      return next;
    });
  }, []);
  const activeExternalFilters = useMemo(
    () => moduleExternalFilters[activeModuleId] || {},
    [moduleExternalFilters, activeModuleId]
  );
  const activeModuleCacheKey = useMemo(
    () => `${activeModuleId}::${buildFilterSignature(activeExternalFilters)}`,
    [activeExternalFilters, activeModuleId]
  );
  const clearActiveExternalFilters = useCallback(() => {
    setModuleExternalFilters((prev) => {
      if (!prev[activeModuleId]) return prev;
      const next = { ...prev };
      delete next[activeModuleId];
      return next;
    });
  }, [activeModuleId]);
  const activeViewId = useMemo(() => {
    const fallbackView = moduleToViewMap[activeModuleId] || activeModuleId;
    const isTaskDetailModule = TASK_DETAIL_TABS.some((tab) => tab.id === activeModuleId);
    if (!isTaskDetailModule) return fallbackView;

    const filters = moduleExternalFilters[activeModuleId] || {};
    const taskId = String(filters.task_id || '').trim();
    if (taskId) return 'tasks';
    return fallbackView;
  }, [activeModuleId, moduleExternalFilters, moduleToViewMap]);
  const onSidebarViewChange = (viewId: string) => {
    const mappedModuleId = viewToModuleMap[viewId] || viewId;
    openModule(mappedModuleId);
  };

  const doLogin = async (name: string, pass: string) => {
    setLoginLoading(true);
    setLoginError('');
    try {
      const result = await requestApi('', '/user/login', {
        method: 'POST',
        body: {
          username: name,
          password: pass,
        },
      });

      const newToken = result?.data?.token;
      const userName = result?.data?.username || name;
      if (!newToken) {
        throw new Error('登录返回缺少 token');
      }

      localStorage.setItem(TOKEN_KEY, newToken);
      localStorage.setItem(USERNAME_KEY, userName);
      localStorage.removeItem(ACTIVE_MODULE_FILTERS_KEY);
      setToken(newToken);
      setUsername(userName);
      setModuleExternalFilters({});
      openModule('dashboard');
    } catch (err: any) {
      setLoginError(err?.message || '登录失败');
    } finally {
      setLoginLoading(false);
    }
  };

  const doLogout = async () => {
    try {
      await requestApi(token, '/user/logout', { method: 'GET' });
    } catch {
      // ignore logout error
    }
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USERNAME_KEY);
    localStorage.removeItem(ACTIVE_MODULE_KEY);
    localStorage.removeItem(ACTIVE_MODULE_FILTERS_KEY);
    setToken('');
    setModuleExternalFilters({});
    setActiveModuleId('dashboard');
  };

  const changePassword = async () => {
    setPasswdLoading(true);
    setPasswdError('');
    try {
      const result = await requestApi(token, '/user/change_pass', {
        method: 'POST',
        body: passwdForm,
      });

      if (typeof result?.code === 'number' && result.code !== 200) {
        throw new Error(result?.message || '修改密码失败');
      }

      setPasswdDialogOpen(false);
      setPasswdForm({ old_password: '', new_password: '', check_password: '' });
      await doLogout();
    } catch (err: any) {
      setPasswdError(err?.message || '修改密码失败');
    } finally {
      setPasswdLoading(false);
    }
  };

  const openQuickCreateTask = () => {
    // 全局入口复用任务模块的“新建任务”动作模板
    const taskModule = getModuleById('task');
    const createTaskAction = taskModule.actions?.find((action) => action.id === 'create_task');
    if (!createTaskAction) {
      setGlobalNotice('任务模块未配置创建动作，已跳转任务管理');
      openModule('task');
      return;
    }

    setGlobalAction(createTaskAction);
    setGlobalActionPayload(deepClone(createTaskAction.payloadTemplate || {}));
  };

  const executeGlobalAction = async (action: ModuleAction, payload: JsonValue, file?: File | null) => {
    // 与列表动作保持一致的请求封装，避免重复实现各类动作参数处理
    const resolvedPath = applyPathTemplate(action.path, payload);
    if (/\{\w+\}/.test(resolvedPath)) {
      throw new Error('存在未填写的路径参数，请补全后再执行');
    }

    let body: JsonValue | FormData | undefined;
    let query: JsonValue | undefined;
    if (action.method === 'GET') {
      if (action.sendPayloadAsQuery) query = payload;
    } else if (action.fileFieldName) {
      if (!file) throw new Error('请先选择文件');
      const formData = new FormData();
      formData.append(action.fileFieldName, file);
      Object.entries(payload || {}).forEach(([key, value]) => {
        if (value === undefined || value === null || value === '') return;
        formData.append(key, typeof value === 'string' ? value : JSON.stringify(value));
      });
      body = formData;
    } else {
      body = payload;
    }

    const result = await requestApi(token, resolvedPath, {
      method: action.method,
      body,
      query,
      download: !!action.download,
    });

    setGlobalNotice(result?.message ? `执行成功: ${result.message}` : '操作执行成功');
    if (!action.download) {
      // 与模块内 runAction 同一套失效语义：标 stale 不后台重拉，激活视图由 signal 触发显式刷新
      queryClient.invalidateQueries({ queryKey: ['module-list', token], refetchType: 'none' });
      setListRefreshSignal((prev) => prev + 1);
    }
    if (action.id === 'create_task') {
      openModule('task');
    }
  };

  useEffect(() => {
    if (!globalNotice) return;
    const timer = window.setTimeout(() => setGlobalNotice(''), 3200);
    return () => window.clearTimeout(timer);
  }, [globalNotice]);

  useEffect(() => {
    if (!token) return;
    localStorage.setItem(ACTIVE_MODULE_KEY, activeModuleId);
    if (Object.keys(moduleExternalFilters).length > 0) {
      localStorage.setItem(ACTIVE_MODULE_FILTERS_KEY, JSON.stringify(moduleExternalFilters));
    } else {
      localStorage.removeItem(ACTIVE_MODULE_FILTERS_KEY);
    }
  }, [token, activeModuleId, moduleExternalFilters]);

  useEffect(() => {
    if (!token) return;

    const handleEsc = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return;

      if (globalAction) {
        event.preventDefault();
        setGlobalAction(null);
        return;
      }

      if (passwdDialogOpen) {
        event.preventDefault();
        setPasswdDialogOpen(false);
        setPasswdError('');
        return;
      }
    };

    window.addEventListener('keydown', handleEsc);
    return () => window.removeEventListener('keydown', handleEsc);
  }, [token, globalAction, passwdDialogOpen]);

  if (!token) {
    return <LoginView onLogin={doLogin} loading={loginLoading} error={loginError} />;
  }

  return (
    <div className="h-screen flex bg-base-100 text-base-content overflow-hidden">
      <Sidebar activeView={activeViewId} onViewChange={onSidebarViewChange} onNewScan={openQuickCreateTask} />

      <main ref={mainScrollRef} className="relative z-10 flex-1 overflow-y-auto custom-scrollbar">
        <header className="navbar sticky top-0 z-20 min-h-16 px-4 xl:px-6 border-b border-base-300 bg-base-100">
          <div className="flex-1 min-w-0 text-xs xl:text-sm text-base-content/60 truncate" role="status">
            {globalNotice || ' '}
          </div>
          <div className="navbar-end min-w-0 gap-1.5 xl:gap-2">
            <SystemMonitorMiniWidget token={token} onOpen={() => openModule('system_monitor')} />
            <span className="badge badge-ghost h-9 max-w-28 truncate px-2 xl:px-3 text-xs xl:text-sm font-medium">{username}</span>
            <button
              onClick={() => setPasswdDialogOpen(true)}
              className="btn btn-ghost btn-sm btn-square"
              title="修改密码"
            >
              <Lock className="w-4 h-4" />
            </button>
            <button
              onClick={() => void doLogout()}
              className="btn btn-ghost btn-sm btn-square"
              title="退出"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </header>
        <ViewErrorBoundary key={activeModuleId}>
        <Suspense fallback={<ViewFallback />}>
        {activeModule.id === 'dashboard' ? (
          <DashboardView token={token} onOpenModule={openModule} onQuickCreateTask={openQuickCreateTask} />
        ) : null}
        {activeModule.id === 'system_monitor' ? <SystemMonitorView token={token} /> : null}
        {activeModule.id === 'api_console' ? <ApiConsoleView token={token} /> : null}
        {activeModule.id === 'config_console' ? <ConfigConsoleView token={token} /> : null}
        {activeModule.id === 'ai_console' ? <ConfigAiManagementPanel token={token} /> : null}
        {activeModule.id === 'dingtalk_api' ? <DingtalkIntegrationView token={token} /> : null}
        {activeModule.id !== 'dashboard' &&
        activeModule.id !== 'system_monitor' &&
        activeModule.id !== 'api_console' &&
        activeModule.id !== 'config_console' &&
        activeModule.id !== 'ai_console' &&
        activeModule.id !== 'dingtalk_api' ? (
          <TableModuleView
            module={activeModule}
            token={token}
            onOpenModule={openModule}
            externalFilters={activeExternalFilters}
            onClearExternalFilters={clearActiveExternalFilters}
            scrollResetToken={moduleScrollResetTokens[activeModuleCacheKey] || 0}
            refreshSignal={listRefreshSignal}
          />
        ) : null}
        </Suspense>
        </ViewErrorBoundary>
      </main>

      {globalAction ? (
        <Suspense fallback={null}>
        <ActionDialog
          token={token}
          action={globalAction}
          initialPayload={globalActionPayload}
          onClose={() => setGlobalAction(null)}
          onSubmit={async (payload, file) => {
            await executeGlobalAction(globalAction, payload, file);
          }}
        />
        </Suspense>
      ) : null}

      {passwdDialogOpen ? (
        <Modal open onClose={() => setPasswdDialogOpen(false)} boxClass="w-full max-w-md!">
            <div className="flex items-center justify-between border-b border-base-300 px-6 py-4">
              <h4 className="text-lg font-semibold">修改密码</h4>
              <button onClick={() => setPasswdDialogOpen(false)} className="btn btn-ghost btn-sm btn-square">
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="space-y-4 p-6">
              <input
                type="password"
                placeholder="旧密码"
                value={passwdForm.old_password}
                onChange={(event) => setPasswdForm((prev) => ({ ...prev, old_password: event.target.value }))}
                className={CONSOLE_INPUT_CLASS}
              />
              <input
                type="password"
                placeholder="新密码"
                value={passwdForm.new_password}
                onChange={(event) => setPasswdForm((prev) => ({ ...prev, new_password: event.target.value }))}
                className={CONSOLE_INPUT_CLASS}
              />
              <input
                type="password"
                placeholder="确认新密码"
                value={passwdForm.check_password}
                onChange={(event) => setPasswdForm((prev) => ({ ...prev, check_password: event.target.value }))}
                className={CONSOLE_INPUT_CLASS}
              />

              {passwdError ? <div role="alert" className={CONSOLE_ALERT_ERROR_CLASS}>{passwdError}</div> : null}

              <button
                onClick={() => void changePassword()}
                disabled={passwdLoading}
                className={`${CONSOLE_PRIMARY_BUTTON_CLASS} w-full`}
              >
                {passwdLoading ? '提交中...' : '提交并重新登录'}
              </button>
            </div>
        </Modal>
      ) : null}
    </div>
  );
}

export default function App() {
  return (
    <ThemeProvider>
      <MainShell />
    </ThemeProvider>
  );
}
