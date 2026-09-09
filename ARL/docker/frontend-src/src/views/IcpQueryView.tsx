import { Fragment, useMemo, useState } from 'react';
import {
  BookOpen,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  Download,
  FileSearch,
  History,
  Info,
  ListTodo,
  LoaderCircle,
  RefreshCw,
  Search,
  ScrollText,
  Trash2,
  XCircle,
} from 'lucide-react';
import { useQuery } from '@tanstack/react-query';
import { requestApi } from '../api/client';
import { PageHeader } from '../layout/PageHeader';
import {
  CONSOLE_ALERT_ERROR_CLASS,
  CONSOLE_ALERT_INFO_CLASS,
  CONSOLE_ALERT_SUCCESS_CLASS,
  CONSOLE_COMPACT_SECONDARY_BUTTON_CLASS,
  CONSOLE_DANGER_BUTTON_CLASS,
  CONSOLE_INPUT_CLASS,
  CONSOLE_PAGE_CLASS,
  CONSOLE_PANEL_CLASS,
  CONSOLE_PRIMARY_BUTTON_CLASS,
  CONSOLE_SECONDARY_BUTTON_CLASS,
  CONSOLE_SELECT_CLASS,
  CONSOLE_TEXTAREA_MONO_CLASS,
} from '../ui/classes';

type IcpTab = 'query' | 'batch' | 'history' | 'tasks' | 'logs' | 'about';
type IcpType = 'web' | 'app' | 'mapp' | 'kapp' | 'bweb' | 'bapp' | 'bmapp' | 'bkapp';

type IcpTypeOption = {
  value: IcpType;
  label: string;
  service_type: number;
  black: boolean;
};

type IcpTask = {
  task_id: string;
  task_kind: 'single' | 'batch';
  query_type: IcpType;
  status: string;
  total: number;
  queued_count: number;
  running_count: number;
  succeeded_count: number;
  empty_count: number;
  failed_count: number;
  cancelled_count: number;
  cancel_requested?: boolean;
  items?: Array<{
    item_id: string;
    keyword: string;
    status: string;
    history_id?: string;
    result_count?: number;
    error_category?: string;
    error_message?: string;
  }>;
  created_at?: string;
  started_at?: string;
  finished_at?: string;
  error_summary?: string;
};

type IcpRecord = Record<string, unknown>;
type IcpHistoryRow = {
  history_id: string;
  query_type: string;
  keyword?: string;
  status: string;
  result_count?: number;
  created_at?: string;
};
type IcpLogRow = {
  created_at?: string;
  level?: string;
  event?: string;
  message?: string;
};

const FALLBACK_TYPES: IcpTypeOption[] = [
  { value: 'web', label: '网站备案', service_type: 1, black: false },
  { value: 'app', label: 'App 备案', service_type: 6, black: false },
  { value: 'mapp', label: '小程序备案', service_type: 7, black: false },
  { value: 'kapp', label: '快应用备案', service_type: 8, black: false },
  { value: 'bweb', label: '违规域名', service_type: 1, black: true },
  { value: 'bapp', label: '违规 App', service_type: 6, black: true },
  { value: 'bmapp', label: '违规小程序', service_type: 7, black: true },
  { value: 'bkapp', label: '违规快应用', service_type: 8, black: true },
];

const TYPE_LABELS: Record<string, string> = Object.fromEntries(
  FALLBACK_TYPES.map((item) => [item.value, item.label]),
);

const STATUS_LABELS: Record<string, string> = {
  queued: '排队中',
  running: '运行中',
  succeeded: '已完成',
  empty: '无结果',
  partial: '部分完成',
  failed: '失败',
  cancelled: '已取消',
};

const STATUS_CLASS: Record<string, string> = {
  queued: 'badge-info',
  running: 'badge-warning',
  succeeded: 'badge-success',
  empty: 'badge-ghost',
  partial: 'badge-warning',
  failed: 'badge-error',
  cancelled: 'badge-ghost',
};

const TAB_ITEMS: Array<{ id: IcpTab; label: string; icon: typeof FileSearch }> = [
  { id: 'query', label: '查询', icon: Search },
  { id: 'batch', label: '批量查询', icon: ListTodo },
  { id: 'history', label: '查询历史', icon: History },
  { id: 'tasks', label: '批量任务', icon: ListTodo },
  { id: 'logs', label: '系统日志', icon: ScrollText },
  { id: 'about', label: '关于', icon: Info },
];

function errorMessage(error: unknown, fallback: string) {
  return error instanceof Error && error.message ? error.message : fallback;
}

function formatValue(value: unknown) {
  if (value === undefined || value === null || value === '') return '-';
  if (Array.isArray(value)) return value.join('、');
  if (typeof value === 'object') return JSON.stringify(value, null, 2);
  return String(value);
}

function hasExtraFields(record: IcpRecord) {
  const extra = record.extra;
  return typeof extra === 'object' && extra !== null && Object.keys(extra).length > 0;
}

function StatusBadge({ status }: { status: string }) {
  return <span className={`badge badge-sm ${STATUS_CLASS[status] || 'badge-outline'}`}>{STATUS_LABELS[status] || status || '-'}</span>;
}

function EmptyState({ text = '暂无数据' }: { text?: string }) {
  return <div className="py-14 text-center text-sm text-content-muted">{text}</div>;
}

function QueryError({ error, text }: { error: unknown; text: string }) {
  if (!error) return null;
  return <div role="alert" className={CONSOLE_ALERT_ERROR_CLASS}>{text}：{errorMessage(error, '请稍后重试')}</div>;
}

function Pagination({
  page,
  size,
  total,
  onChange,
}: {
  page: number;
  size: number;
  total: number;
  onChange: (next: number) => void;
}) {
  const pages = Math.max(1, Math.ceil(total / size));
  if (pages <= 1) return null;
  return (
    <div className="flex items-center justify-between gap-3 border-t border-base-300 px-4 py-3 text-sm text-content-muted">
      <span>共 {total} 条，第 {page}/{pages} 页</span>
      <div className="join">
        <button className="btn join-item btn-sm" disabled={page <= 1} onClick={() => onChange(page - 1)} aria-label="上一页">
          <ChevronLeft className="h-4 w-4" />
        </button>
        <button className="btn join-item btn-sm" disabled={page >= pages} onClick={() => onChange(page + 1)} aria-label="下一页">
          <ChevronRight className="h-4 w-4" />
        </button>
      </div>
    </div>
  );
}

function ResultTable({ records }: { records: IcpRecord[] }) {
  const [expandedIndex, setExpandedIndex] = useState<number | null>(null);
  const columns = useMemo(() => {
    const preferred = [
      ['company_name', '主体名称'],
      ['domain', '域名'],
      ['service_name', '服务名称'],
      ['license_number', '备案号'],
      ['record_status', '备案状态'],
      ['website', '网站'],
      ['province', '省份'],
      ['city', '城市'],
      ['update_time', '更新时间'],
    ];
    return preferred.filter(([key]) => records.some((record) => record[key] !== undefined && record[key] !== '')).concat(
      records.some(hasExtraFields) ? [['extra', '其他字段']] : [],
    );
  }, [records]);

  if (!records.length) return <EmptyState text="查询完成，暂无结果" />;
  return (
    <div className="overflow-x-auto">
      <table className="table table-zebra table-sm">
        <thead>
          <tr>{columns.map(([key, label]) => <th key={key} className="whitespace-nowrap">{label}</th>)}<th className="whitespace-nowrap">详情</th></tr>
        </thead>
        <tbody>
          {records.map((record, index) => (
            <Fragment key={`${record.domain || record.service_name || 'record'}-${index}`}>
              <tr key={`${record.domain || record.service_name || 'record'}-${index}`}>
                {columns.map(([key]) => (
                  <td key={key} className="max-w-80 whitespace-pre-wrap break-words align-top">
                    {formatValue(record[key])}
                  </td>
                ))}
                <td className="align-top">
                  <button className="btn btn-ghost btn-xs gap-1" onClick={() => setExpandedIndex(expandedIndex === index ? null : index)} aria-expanded={expandedIndex === index}>
                    <ChevronDown className={`h-3.5 w-3.5 transition-transform ${expandedIndex === index ? 'rotate-180' : ''}`} />
                    {expandedIndex === index ? '收起' : '展开'}
                  </button>
                </td>
              </tr>
              {expandedIndex === index ? <tr key={`${record.domain || record.service_name || 'record'}-${index}-detail`}><td colSpan={columns.length + 1}><pre className="max-h-72 overflow-auto whitespace-pre-wrap break-words rounded-box bg-base-200 p-3 text-xs leading-5">{JSON.stringify(record, null, 2)}</pre></td></tr> : null}
            </Fragment>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function TaskSummary({ task }: { task: IcpTask }) {
  const finished = (task.succeeded_count || 0) + (task.empty_count || 0) + (task.failed_count || 0) + (task.cancelled_count || 0);
  const progress = task.total ? Math.round((finished / task.total) * 100) : 0;
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <StatusBadge status={task.status} />
          <span className="text-sm text-content-muted">{TYPE_LABELS[task.query_type] || task.query_type}</span>
        </div>
        <span className="font-mono text-xs text-content-muted">{finished}/{task.total}</span>
      </div>
      <progress className="progress progress-primary w-full" value={progress} max="100" />
      <div className="grid grid-cols-2 gap-2 text-xs text-content-muted sm:grid-cols-4">
        <span>成功 {task.succeeded_count || 0}</span>
        <span>空结果 {task.empty_count || 0}</span>
        <span>失败 {task.failed_count || 0}</span>
        <span>取消 {task.cancelled_count || 0}</span>
      </div>
    </div>
  );
}

export function IcpQueryView({ token }: { token: string }) {
  const [tab, setTab] = useState<IcpTab>('query');
  const [singleType, setSingleType] = useState<IcpType>('web');
  const [singleKeyword, setSingleKeyword] = useState('');
  const [singleTaskId, setSingleTaskId] = useState('');
  const [singleResultPage, setSingleResultPage] = useState(1);
  const [batchType, setBatchType] = useState<IcpType>('web');
  const [batchText, setBatchText] = useState('');
  const [batchTaskId, setBatchTaskId] = useState('');
  const [historyPage, setHistoryPage] = useState(1);
  const [historyType, setHistoryType] = useState('');
  const [historyKeyword, setHistoryKeyword] = useState('');
  const [historyStatus, setHistoryStatus] = useState('');
  const [historyFrom, setHistoryFrom] = useState('');
  const [historyTo, setHistoryTo] = useState('');
  const [selectedHistoryId, setSelectedHistoryId] = useState('');
  const [historyResultPage, setHistoryResultPage] = useState(1);
  const [taskPage, setTaskPage] = useState(1);
  const [taskStatus, setTaskStatus] = useState('');
  const [logPage, setLogPage] = useState(1);
  const [logLevel, setLogLevel] = useState('');
  const [logFrom, setLogFrom] = useState('');
  const [logTo, setLogTo] = useState('');
  const [notice, setNotice] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState('');

  const metaQuery = useQuery({
    queryKey: ['icp-meta', token],
    queryFn: () => requestApi(token, '/icp/meta', { method: 'GET' }),
    retry: 0,
  });
  const types: IcpTypeOption[] = Array.isArray(metaQuery.data?.data?.types) && metaQuery.data.data.types.length
    ? metaQuery.data.data.types
    : FALLBACK_TYPES;
  const featureDisabled = metaQuery.data?.data?.enabled === false
    || (metaQuery.isError && errorMessage(metaQuery.error, '').includes('ICP 查询功能当前已关闭'));

  const singleTaskQuery = useQuery({
    queryKey: ['icp-single-task', token, singleTaskId],
    queryFn: () => requestApi(token, `/icp/query/${singleTaskId}`, { method: 'GET' }),
    enabled: Boolean(singleTaskId) && tab === 'query',
    refetchInterval: (query) => {
      const status = query.state.data?.data?.status;
      return status === 'queued' || status === 'running' ? 1500 : false;
    },
    retry: 0,
  });
  const singleTask = singleTaskQuery.data?.data as IcpTask | undefined;
  const singleResultQuery = useQuery({
    queryKey: ['icp-single-result', token, singleTaskId, singleResultPage],
    queryFn: () => requestApi(token, `/icp/query/${singleTaskId}/results`, { method: 'GET', query: { page: singleResultPage, size: 26 } }),
    enabled: Boolean(singleTaskId) && tab === 'query' && ['succeeded', 'partial', 'failed', 'cancelled'].includes(singleTask?.status || ''),
    retry: 0,
  });

  const batchTaskQuery = useQuery({
    queryKey: ['icp-batch-task', token, batchTaskId],
    queryFn: () => requestApi(token, `/icp/batch/${batchTaskId}`, { method: 'GET' }),
    enabled: Boolean(batchTaskId) && tab === 'batch',
    refetchInterval: (query) => {
      const status = query.state.data?.data?.status;
      return status === 'queued' || status === 'running' ? 1500 : false;
    },
    retry: 0,
  });
  const batchTask = batchTaskQuery.data?.data as IcpTask | undefined;
  const batchListQuery = useQuery({
    queryKey: ['icp-batch-list', token, taskPage, taskStatus],
    queryFn: () => requestApi(token, '/icp/batch', { method: 'GET', query: { page: taskPage, size: 20, status: taskStatus } }),
    enabled: tab === 'tasks',
    refetchInterval: tab === 'tasks' ? 3000 : false,
    retry: 0,
  });

  const historyQuery = useQuery({
    queryKey: ['icp-history', token, historyPage, historyType, historyKeyword, historyStatus, historyFrom, historyTo],
    queryFn: () => requestApi(token, '/icp/history', {
      method: 'GET',
      query: { page: historyPage, size: 20, type: historyType, keyword: historyKeyword, status: historyStatus, created_from: historyFrom, created_to: historyTo },
    }),
    enabled: tab === 'history',
    retry: 0,
  });
  const historyDetailQuery = useQuery({
    queryKey: ['icp-history-detail', token, selectedHistoryId, historyResultPage],
    queryFn: () => requestApi(token, `/icp/history/${selectedHistoryId}`, { method: 'GET', query: { page: historyResultPage, size: 26 } }),
    enabled: Boolean(selectedHistoryId) && tab === 'history',
    retry: 0,
  });
  const logsQuery = useQuery({
    queryKey: ['icp-logs', token, logPage, logLevel, logFrom, logTo],
    queryFn: () => requestApi(token, '/icp/logs', { method: 'GET', query: { page: logPage, size: 50, level: logLevel, created_from: logFrom, created_to: logTo } }),
    enabled: tab === 'logs',
    refetchInterval: tab === 'logs' ? 3000 : false,
    retry: 0,
  });
  const aboutQuery = useQuery({
    queryKey: ['icp-about', token],
    queryFn: () => requestApi(token, '/icp/about', { method: 'GET' }),
    enabled: tab === 'about',
    retry: 0,
  });

  const run = async (label: string, callback: () => Promise<void>) => {
    setBusy(label);
    setError('');
    setNotice('');
    try {
      await callback();
    } catch (err) {
      setError(errorMessage(err, '操作失败'));
    } finally {
      setBusy('');
    }
  };

  const submitSingle = () => run('single', async () => {
    const keyword = singleKeyword.trim();
    if (!keyword) throw new Error('请输入查询关键词');
    const result = await requestApi(token, '/icp/query', {
      method: 'POST',
      body: { type: singleType, keyword, page: 1, page_size: 26 },
    });
    const taskId = String(result?.data?.task_id || '');
    if (!taskId) throw new Error('创建查询任务失败');
    setSingleResultPage(1);
    setSingleTaskId(taskId);
    setNotice('查询任务已提交，正在等待 Worker 处理');
  });

  const submitBatch = () => run('batch', async () => {
    const keywords = batchText.split(/\r?\n/).map((item) => item.trim()).filter(Boolean);
    if (!keywords.length) throw new Error('请输入至少一条批量查询内容');
    const result = await requestApi(token, '/icp/batch', {
      method: 'POST',
      body: { type: batchType, keywords },
    });
    const taskId = String(result?.data?.task_id || '');
    if (!taskId) throw new Error('创建批量任务失败');
    setBatchTaskId(taskId);
    setTab('batch');
    setNotice(`批量任务已提交，共 ${keywords.length} 条输入`);
  });

  const cancelTask = (taskId: string, kind: 'single' | 'batch') => run(`cancel-${taskId}`, async () => {
    await requestApi(token, kind === 'single' ? `/icp/query/${taskId}/cancel` : `/icp/batch/${taskId}/cancel`, { method: 'POST' });
    setNotice('已提交取消请求');
    if (kind === 'single') await singleTaskQuery.refetch();
    else {
      if (batchTaskId === taskId) await batchTaskQuery.refetch();
      if (tab === 'tasks') await batchListQuery.refetch();
    }
  });

  const deleteTask = (taskId: string) => run(`delete-${taskId}`, async () => {
    await requestApi(token, `/icp/batch/${taskId}`, { method: 'DELETE' });
    setNotice('任务已删除');
    await batchListQuery.refetch();
    if (batchTaskId === taskId) setBatchTaskId('');
  });

  const clearHistory = () => run('clear-history', async () => {
    await requestApi(token, '/icp/history/clear', { method: 'POST' });
    setSelectedHistoryId('');
    setNotice('查询历史已清空');
    await historyQuery.refetch();
  });

  const deleteHistory = (historyId: string) => run(`delete-history-${historyId}`, async () => {
    await requestApi(token, `/icp/history/${historyId}`, { method: 'DELETE' });
    if (selectedHistoryId === historyId) setSelectedHistoryId('');
    setNotice('历史记录已删除');
    await historyQuery.refetch();
  });

  const clearLogs = () => run('clear-logs', async () => {
    await requestApi(token, '/icp/logs/clear', { method: 'POST' });
    setNotice('ICP 日志已清空');
    await logsQuery.refetch();
  });

  const download = (params: Record<string, string>) => run(`download-${params.format}`, async () => {
    await requestApi(token, '/icp/export', { method: 'GET', query: params, download: true });
    setNotice('导出文件已开始下载');
  });

  const activeTask = singleTaskId ? singleTask : batchTask;
  const activeResult = singleResultQuery.data?.data;
  const historyData = historyQuery.data?.data || { items: [], total: 0, page: historyPage, size: 20 };
  const taskData = batchListQuery.data?.data || { items: [], total: 0, page: taskPage, size: 20 };
  const logData = logsQuery.data?.data || { items: [], total: 0, page: logPage, size: 50 };
  const historyItems = (historyData.items || []) as IcpHistoryRow[];
  const taskItems = (taskData.items || []) as IcpTask[];
  const logItems = (logData.items || []) as IcpLogRow[];
  const batchKeywords = batchText.split(/\r?\n/).map((item) => item.trim()).filter(Boolean);
  const batchUniqueCount = new Set(batchKeywords).size;

  return (
    <div className={CONSOLE_PAGE_CLASS}>
      <PageHeader
        title="ICP 查询"
        description="备案、App、小程序、快应用及违规信息查询；结果独立保存，不自动写入 ARL 资产库。"
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <span className="badge badge-soft badge-primary gap-1.5">
              <FileSearch className="h-3.5 w-3.5" />
              ARL 原生适配
            </span>
            {metaQuery.isFetching ? <span className="text-xs text-content-muted">读取查询类型…</span> : null}
          </div>
        }
      />

      <div role="tablist" className="tabs tabs-box w-full max-w-full overflow-x-auto bg-base-200/80">
        {TAB_ITEMS.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            role="tab"
            aria-selected={tab === id}
            disabled={featureDisabled}
            className={`tab gap-2 whitespace-nowrap ${tab === id ? 'tab-active' : ''}`}
            onClick={() => setTab(id)}
          >
            <Icon className="h-4 w-4" />
            {label}
          </button>
        ))}
      </div>

      {featureDisabled ? (
        <section className={CONSOLE_PANEL_CLASS}>
          <div className="card-body gap-2">
            <h2 className="card-title text-lg">ICP 查询当前已关闭</h2>
            <p className="text-sm text-content-muted">管理员已关闭 ICP 查询功能，重新启用后才可以提交查询任务。</p>
          </div>
        </section>
      ) : null}

      {!featureDisabled ? (
        <>
          {notice ? <div role="status" className={CONSOLE_ALERT_SUCCESS_CLASS}>{notice}</div> : null}
          {error ? <div role="alert" className={CONSOLE_ALERT_ERROR_CLASS}>{error}</div> : null}
          {metaQuery.isError ? <div role="alert" className={CONSOLE_ALERT_INFO_CLASS}>查询类型元信息加载失败，已使用内置类型列表。</div> : null}

      {tab === 'query' ? (
        <div className="space-y-5">
          <section className={CONSOLE_PANEL_CLASS}>
            <div className="card-body gap-5">
              <div>
                <h2 className="card-title text-lg">单次查询</h2>
                <p className="mt-1 text-sm text-content-muted">查询请求通过现有 Worker 异步执行，验证码或网络波动不会阻塞 Web 页面。</p>
              </div>
              <div className="grid gap-4 lg:grid-cols-[minmax(0,240px)_minmax(0,1fr)_auto] lg:items-end">
                <label className="form-control gap-1.5">
                  <span className="label-text text-sm font-semibold">查询类型</span>
                  <select className={CONSOLE_SELECT_CLASS} value={singleType} onChange={(event) => setSingleType(event.target.value as IcpType)}>
                    {types.map((item) => <option key={item.value} value={item.value}>{item.label}</option>)}
                  </select>
                </label>
                <label className="form-control gap-1.5">
                  <span className="label-text text-sm font-semibold">查询关键词</span>
                  <input className={CONSOLE_INPUT_CLASS} value={singleKeyword} onChange={(event) => setSingleKeyword(event.target.value)} onKeyDown={(event) => { if (event.key === 'Enter') void submitSingle(); }} placeholder="请输入域名、主体名称或应用名称" maxLength={255} />
                </label>
                <button className={CONSOLE_PRIMARY_BUTTON_CLASS} onClick={() => void submitSingle()} disabled={Boolean(busy)}>
                  {busy === 'single' ? <LoaderCircle className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
                  查询
                </button>
              </div>
            </div>
          </section>

          {singleTask ? (
            <section className={CONSOLE_PANEL_CLASS}>
              <div className="card-body gap-4">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <h2 className="card-title text-lg">查询任务</h2>
                    <p className="mt-1 break-all font-mono text-xs text-content-muted">{singleTask.task_id}</p>
                  </div>
                  {(singleTask.status === 'queued' || singleTask.status === 'running') ? (
                    <button className={CONSOLE_SECONDARY_BUTTON_CLASS} onClick={() => void cancelTask(singleTask.task_id, 'single')} disabled={Boolean(busy)}>
                      <XCircle className="h-4 w-4" />取消查询
                    </button>
                  ) : null}
                </div>
                <TaskSummary task={singleTask} />
                <QueryError error={singleTaskQuery.error} text="查询任务状态加载失败" />
                {singleTask.status === 'failed' ? <div role="alert" className={CONSOLE_ALERT_ERROR_CLASS}>{singleTask.error_summary || '查询失败，请查看系统日志。'}</div> : null}
                <QueryError error={singleResultQuery.error} text="查询结果加载失败" />
                {activeResult ? <ResultTable records={(activeResult.items || []) as IcpRecord[]} /> : null}
                {activeResult ? <Pagination page={Number(activeResult.page || singleResultPage)} size={Number(activeResult.size || 26)} total={Number(activeResult.total || 0)} onChange={setSingleResultPage} /> : null}
              </div>
            </section>
          ) : (
            <section className={CONSOLE_PANEL_CLASS}><div className="card-body"><EmptyState text="提交查询后，结果会在这里展示" /></div></section>
          )}
        </div>
      ) : null}

      {tab === 'batch' ? (
        <div className="space-y-5">
          <section className={CONSOLE_PANEL_CLASS}>
            <div className="card-body gap-5">
              <div>
                <h2 className="card-title text-lg">批量查询</h2>
                <p className="mt-1 text-sm text-content-muted">每行一个关键词，服务端会自动去空行和重试；单批上限由服务端配置控制。</p>
              </div>
              <div className="grid gap-4 lg:grid-cols-[minmax(0,240px)_minmax(0,1fr)]">
                <label className="form-control gap-1.5">
                  <span className="label-text text-sm font-semibold">查询类型</span>
                  <select className={CONSOLE_SELECT_CLASS} value={batchType} onChange={(event) => setBatchType(event.target.value as IcpType)}>
                    {types.map((item) => <option key={item.value} value={item.value}>{item.label}</option>)}
                  </select>
                </label>
                <label className="form-control gap-1.5">
                  <span className="label-text text-sm font-semibold">关键词列表</span>
                  <textarea className={`${CONSOLE_TEXTAREA_MONO_CLASS} min-h-48`} value={batchText} onChange={(event) => setBatchText(event.target.value)} placeholder={'example.com\nexample.cn\n主体名称'} />
                </label>
              </div>
              <div className="flex flex-wrap items-center justify-between gap-3 border-t border-base-300 pt-4">
                <span className="text-sm text-content-muted">输入 {batchKeywords.length} 条，去重后 {batchUniqueCount} 条</span>
                <button className={CONSOLE_PRIMARY_BUTTON_CLASS} onClick={() => void submitBatch()} disabled={Boolean(busy)}>
                  {busy === 'batch' ? <LoaderCircle className="h-4 w-4 animate-spin" /> : <ListTodo className="h-4 w-4" />}
                  创建批量任务
                </button>
              </div>
            </div>
          </section>

          <QueryError error={batchTaskQuery.error} text="批量任务状态加载失败" />
          {batchTask ? (
            <section className={CONSOLE_PANEL_CLASS}>
              <div className="card-body gap-4">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div><h2 className="card-title text-lg">最近批量任务</h2><p className="mt-1 break-all font-mono text-xs text-content-muted">{batchTask.task_id}</p></div>
                  <div className="flex flex-wrap gap-2">
                    <button className={CONSOLE_COMPACT_SECONDARY_BUTTON_CLASS} onClick={() => void download({ format: 'json', task_id: batchTask.task_id })} aria-label="导出 JSON" title="导出 JSON"><Download className="h-3.5 w-3.5" />JSON</button>
                    <button className={CONSOLE_COMPACT_SECONDARY_BUTTON_CLASS} onClick={() => void download({ format: 'xlsx', task_id: batchTask.task_id })} aria-label="导出 Excel" title="导出 Excel"><Download className="h-3.5 w-3.5" />Excel</button>
                    {(batchTask.status === 'queued' || batchTask.status === 'running') ? <button className={CONSOLE_SECONDARY_BUTTON_CLASS} onClick={() => void cancelTask(batchTask.task_id, 'batch')} disabled={Boolean(busy)}><XCircle className="h-4 w-4" />取消</button> : null}
                  </div>
                </div>
                <TaskSummary task={batchTask} />
                <div className="overflow-x-auto">
                  <table className="table table-zebra table-sm">
                    <thead><tr><th>序号</th><th>关键词</th><th>状态</th><th>结果数</th><th>错误</th><th>操作</th></tr></thead>
                    <tbody>{(batchTask.items || []).map((item, index) => <tr key={item.item_id}><th>{index + 1}</th><td className="max-w-80 break-all">{item.keyword}</td><td><StatusBadge status={item.status} /></td><td>{item.result_count || 0}</td><td className="max-w-80 break-words text-error">{item.error_message || '-'}</td><td>{item.history_id ? <button className={CONSOLE_COMPACT_SECONDARY_BUTTON_CLASS} onClick={() => { setHistoryResultPage(1); setSelectedHistoryId(item.history_id || ''); setTab('history'); }}>查看结果</button> : '-'}</td></tr>)}</tbody>
                  </table>
                </div>
              </div>
            </section>
          ) : null}
        </div>
      ) : null}

      {tab === 'history' ? (
        <div className="space-y-5">
          <section className={CONSOLE_PANEL_CLASS}>
            <div className="card-body gap-4">
              <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-6">
                <input className={CONSOLE_INPUT_CLASS} value={historyKeyword} onChange={(event) => { setHistoryKeyword(event.target.value); setHistoryPage(1); }} placeholder="搜索关键词" />
                <select className={CONSOLE_SELECT_CLASS} value={historyType} onChange={(event) => { setHistoryType(event.target.value); setHistoryPage(1); }}><option value="">全部类型</option>{types.map((item) => <option key={item.value} value={item.value}>{item.label}</option>)}</select>
                <select className={CONSOLE_SELECT_CLASS} value={historyStatus} onChange={(event) => { setHistoryStatus(event.target.value); setHistoryPage(1); }}><option value="">全部状态</option><option value="succeeded">已完成</option><option value="empty">无结果</option><option value="failed">失败</option></select>
                <input className={CONSOLE_INPUT_CLASS} type="date" value={historyFrom} onChange={(event) => { setHistoryFrom(event.target.value); setHistoryPage(1); }} aria-label="开始日期" />
                <input className={CONSOLE_INPUT_CLASS} type="date" value={historyTo} onChange={(event) => { setHistoryTo(event.target.value); setHistoryPage(1); }} aria-label="结束日期" />
                <div className="flex gap-2"><button className={`${CONSOLE_SECONDARY_BUTTON_CLASS} flex-1`} onClick={() => void historyQuery.refetch()}><RefreshCw className="h-4 w-4" />刷新</button><button className={CONSOLE_DANGER_BUTTON_CLASS} onClick={() => void clearHistory()} disabled={Boolean(busy)}><Trash2 className="h-4 w-4" />清空</button></div>
              </div>
              <div className="flex flex-wrap justify-end gap-2"><button className={CONSOLE_COMPACT_SECONDARY_BUTTON_CLASS} onClick={() => void download({ format: 'json', type: historyType, keyword: historyKeyword, status: historyStatus, created_from: historyFrom, created_to: historyTo })}><Download className="h-3.5 w-3.5" />JSON</button><button className={CONSOLE_COMPACT_SECONDARY_BUTTON_CLASS} onClick={() => void download({ format: 'xlsx', type: historyType, keyword: historyKeyword, status: historyStatus, created_from: historyFrom, created_to: historyTo })}><Download className="h-3.5 w-3.5" />Excel</button></div>
            </div>
          </section>
          <section className={CONSOLE_PANEL_CLASS}>
            <div className="card-body p-0">
              <QueryError error={historyQuery.error} text="查询历史加载失败" />
              {!historyQuery.isError && (historyQuery.isFetching && !historyItems.length ? <div className="flex justify-center py-14"><span className="loading loading-spinner" /></div> : historyItems.length ? <div className="overflow-x-auto"><table className="table table-zebra table-sm"><thead><tr><th>查询时间</th><th>类型</th><th>关键词</th><th>状态</th><th>结果数</th><th>操作</th></tr></thead><tbody>{historyItems.map((item) => <tr key={item.history_id}><td className="whitespace-nowrap">{item.created_at || '-'}</td><td>{TYPE_LABELS[item.query_type] || item.query_type}</td><td className="max-w-72 break-all">{item.keyword}</td><td><StatusBadge status={item.status} /></td><td>{item.result_count || 0}</td><td><div className="flex gap-2"><button className={CONSOLE_COMPACT_SECONDARY_BUTTON_CLASS} onClick={() => { setHistoryResultPage(1); setSelectedHistoryId(item.history_id); }}>查看</button><button className="btn btn-ghost btn-sm text-error" onClick={() => void deleteHistory(item.history_id)} disabled={Boolean(busy)} aria-label="删除历史记录" title="删除历史记录"><Trash2 className="h-4 w-4" /></button></div></td></tr>)}</tbody></table></div> : <EmptyState text="暂无查询历史" />)}
              <Pagination page={Number(historyData.page || historyPage)} size={Number(historyData.size || 20)} total={Number(historyData.total || 0)} onChange={setHistoryPage} />
            </div>
          </section>
          <QueryError error={historyDetailQuery.error} text="历史详情加载失败" />
          {selectedHistoryId && historyDetailQuery.data?.data ? <section className={CONSOLE_PANEL_CLASS}><div className="card-body gap-4"><div className="flex items-center justify-between gap-3"><h2 className="card-title text-lg">历史详情</h2><button className="btn btn-ghost btn-sm" onClick={() => setSelectedHistoryId('')}>关闭</button></div><div className="grid gap-2 text-sm sm:grid-cols-3"><span>类型：{TYPE_LABELS[historyDetailQuery.data.data.history?.query_type] || historyDetailQuery.data.data.history?.query_type}</span><span>关键词：{historyDetailQuery.data.data.history?.keyword}</span><span>状态：<StatusBadge status={historyDetailQuery.data.data.history?.status} /></span></div><ResultTable records={(historyDetailQuery.data.data.results?.items || []) as IcpRecord[]} /><Pagination page={Number(historyDetailQuery.data.data.results?.page || historyResultPage)} size={Number(historyDetailQuery.data.data.results?.size || 26)} total={Number(historyDetailQuery.data.data.results?.total || 0)} onChange={setHistoryResultPage} /></div></section> : null}
        </div>
      ) : null}

      {tab === 'tasks' ? (
        <div className="space-y-5">
          <section className={CONSOLE_PANEL_CLASS}><div className="card-body"><div className="flex flex-wrap items-center justify-between gap-3"><div><h2 className="card-title text-lg">批量任务</h2><p className="mt-1 text-sm text-content-muted">查看历史批量任务及其逐项执行状态。</p></div><div className="flex gap-2"><select className="select select-bordered select-sm" value={taskStatus} onChange={(event) => { setTaskStatus(event.target.value); setTaskPage(1); }}><option value="">全部状态</option><option value="queued">排队中</option><option value="running">运行中</option><option value="succeeded">已完成</option><option value="partial">部分完成</option><option value="failed">失败</option><option value="cancelled">已取消</option></select><button className={CONSOLE_COMPACT_SECONDARY_BUTTON_CLASS} onClick={() => void batchListQuery.refetch()}><RefreshCw className="h-3.5 w-3.5" />刷新</button></div></div></div></section>
          <section className={CONSOLE_PANEL_CLASS}><div className="card-body p-0"><QueryError error={batchListQuery.error} text="批量任务列表加载失败" />{!batchListQuery.isError && (batchListQuery.isFetching && !taskItems.length ? <div className="flex justify-center py-14"><span className="loading loading-spinner" /></div> : taskItems.length ? <div className="overflow-x-auto"><table className="table table-zebra table-sm"><thead><tr><th>创建时间</th><th>类型</th><th>任务 ID</th><th>状态</th><th>进度</th><th>操作</th></tr></thead><tbody>{taskItems.map((item) => <tr key={item.task_id}><td className="whitespace-nowrap">{item.created_at || '-'}</td><td>{TYPE_LABELS[item.query_type] || item.query_type}</td><td className="max-w-56 break-all font-mono text-xs">{item.task_id}</td><td><StatusBadge status={item.status} /></td><td>{(item.succeeded_count || 0) + (item.empty_count || 0) + (item.failed_count || 0) + (item.cancelled_count || 0)}/{item.total || 0}</td><td><div className="flex gap-2"><button className={CONSOLE_COMPACT_SECONDARY_BUTTON_CLASS} onClick={() => { setBatchTaskId(item.task_id); setTab('batch'); }}>查看</button>{['succeeded', 'partial', 'failed', 'cancelled'].includes(item.status) ? <><button className="btn btn-ghost btn-sm text-error" onClick={() => void deleteTask(item.task_id)} disabled={Boolean(busy)} aria-label="删除批量任务" title="删除批量任务"><Trash2 className="h-4 w-4" /></button><button className="btn btn-ghost btn-sm" onClick={() => void download({ format: 'json', task_id: item.task_id })} aria-label="导出 JSON" title="导出 JSON"><Download className="h-4 w-4" /></button><button className="btn btn-ghost btn-sm" onClick={() => void download({ format: 'xlsx', task_id: item.task_id })} aria-label="导出 Excel" title="导出 Excel"><Download className="h-4 w-4" /></button></> : <button className="btn btn-ghost btn-sm" onClick={() => void cancelTask(item.task_id, 'batch')} disabled={Boolean(busy)} aria-label="取消批量任务" title="取消批量任务"><XCircle className="h-4 w-4" /></button>}</div></td></tr>)}</tbody></table></div> : <EmptyState text="暂无批量任务" />)}<Pagination page={Number(taskData.page || taskPage)} size={Number(taskData.size || 20)} total={Number(taskData.total || 0)} onChange={setTaskPage} /></div></section>
        </div>
      ) : null}

      {tab === 'logs' ? (
        <section className={CONSOLE_PANEL_CLASS}>
          <div className="card-body p-0">
            <div className="flex flex-wrap items-end justify-between gap-3 border-b border-base-300 p-4">
              <div>
                <h2 className="card-title text-lg">系统日志</h2>
                <p className="mt-1 text-sm text-content-muted">仅展示 ICP 运行状态和脱敏后的错误信息。</p>
              </div>
              <div className="flex flex-wrap items-end gap-2">
                <label className="form-control gap-1">
                  <span className="label-text text-xs">级别</span>
                  <select className="select select-bordered select-sm" value={logLevel} onChange={(event) => { setLogLevel(event.target.value); setLogPage(1); }}>
                    <option value="">全部级别</option>
                    <option value="INFO">INFO</option>
                    <option value="WARNING">WARNING</option>
                    <option value="ERROR">ERROR</option>
                  </select>
                </label>
                <label className="form-control gap-1">
                  <span className="label-text text-xs">开始日期</span>
                  <input className="input input-bordered input-sm" type="date" value={logFrom} onChange={(event) => { setLogFrom(event.target.value); setLogPage(1); }} aria-label="日志开始日期" />
                </label>
                <label className="form-control gap-1">
                  <span className="label-text text-xs">结束日期</span>
                  <input className="input input-bordered input-sm" type="date" value={logTo} onChange={(event) => { setLogTo(event.target.value); setLogPage(1); }} aria-label="日志结束日期" />
                </label>
                <button className={CONSOLE_SECONDARY_BUTTON_CLASS} onClick={() => void logsQuery.refetch()}>
                  <RefreshCw className="h-4 w-4" />刷新
                </button>
                <button className={CONSOLE_DANGER_BUTTON_CLASS} onClick={() => void clearLogs()} disabled={Boolean(busy)}>
                  <Trash2 className="h-4 w-4" />清空
                </button>
              </div>
            </div>
            <QueryError error={logsQuery.error} text="系统日志加载失败" />
            {!logsQuery.isError && (logsQuery.isFetching && !logItems.length ? <div className="flex justify-center py-14"><span className="loading loading-spinner" /></div> : logItems.length ? <div className="overflow-x-auto"><table className="table table-zebra table-sm"><thead><tr><th>时间</th><th>级别</th><th>事件</th><th>消息</th></tr></thead><tbody>{logItems.map((item, index) => <tr key={`${item.created_at}-${index}`}><td className="whitespace-nowrap text-xs">{item.created_at || '-'}</td><td><StatusBadge status={item.level === 'WARNING' ? 'partial' : item.level === 'ERROR' ? 'failed' : 'succeeded'} /></td><td>{item.event || '-'}</td><td className="min-w-80 whitespace-pre-wrap break-words">{item.message || '-'}</td></tr>)}</tbody></table></div> : <EmptyState text="暂无 ICP 系统日志" />)}
            <Pagination page={Number(logData.page || logPage)} size={Number(logData.size || 50)} total={Number(logData.total || 0)} onChange={setLogPage} />
          </div>
        </section>
      ) : null}

      {tab === 'about' ? (
        <div className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_minmax(0,320px)]">
          <section className={CONSOLE_PANEL_CLASS}><div className="card-body gap-5"><QueryError error={aboutQuery.error} text="关于信息加载失败" /><div className="flex items-start gap-3"><div className="rounded-box bg-primary/10 p-3 text-primary"><BookOpen className="h-6 w-6" /></div><div><h2 className="card-title text-lg">关于 ICP 查询</h2><p className="mt-1 text-sm text-content-muted">将 ICP 备案查询能力整合到 ARL 现有任务和数据体系中。</p></div></div><div className="space-y-3 text-sm leading-6 text-content-muted"><p>查询、批量查询、历史、任务、日志和关于页面均由 ARL 原生 UI 提供，配置管理不在本模块开放。</p><p>查询结果独立保存，不会自动写入 ARL 的域名、站点或 IP 资产集合。</p>{aboutQuery.data?.data?.source ? <p>功能参考来源：<a className="link link-primary" href={aboutQuery.data.data.source} target="_blank" rel="noreferrer">{aboutQuery.data.data.source}</a></p> : null}</div></div></section>
          <section className={CONSOLE_PANEL_CLASS}><div className="card-body gap-3"><h2 className="card-title text-lg">当前状态</h2><div className="flex items-center justify-between text-sm"><span className="text-content-muted">适配方式</span><span className="badge badge-soft badge-success">ARL 原生</span></div><div className="flex items-center justify-between text-sm"><span className="text-content-muted">集成版本</span><span className="font-mono text-xs">{aboutQuery.data?.data?.integration_version || 'native-v1'}</span></div><div className="flex items-center justify-between text-sm"><span className="text-content-muted">独立容器</span><span>不需要</span></div><div className="flex items-center justify-between text-sm"><span className="text-content-muted">资产写回</span><span>关闭</span></div><div className="flex items-center justify-between text-sm"><span className="text-content-muted">任务队列</span><span className="font-mono text-xs">arlweb</span></div></div></section>
        </div>
      ) : null}

      {activeTask?.status === 'running' ? <div className="sr-only" aria-live="polite">任务正在运行</div> : null}
        </>
      ) : null}
    </div>
  );
}

export default IcpQueryView;
