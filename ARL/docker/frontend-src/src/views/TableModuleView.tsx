import React, {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  ChevronUp,
  ChevronsUpDown,
  Download,
  Eye,
  Play,
  RefreshCw,
  Search,
  X,
} from 'lucide-react';
import {
  buildFilterSignature,
  normalizeListData,
  normalizeRowIdValue,
  requestApi,
  sanitizeUiMessage,
  sleep,
} from '../api/client';
import { Modal } from '../components/ui/Modal';
import { StatusPill } from '../components/ui/StatusPill';
import {
  AI_DENOISE_MODULE_LABEL_MAP,
  TASK_DETAIL_TABS,
  TASK_REPORT_EXPORT_LABELS,
  TASK_REPORT_EXPORT_OPTIONS,
  canToggleHyperlink,
  getDefaultModulePageSize,
  getModuleById,
  isAiDenoiseModule,
  isDeleteAction,
  isHyperlinkEnabledColumn,
} from '../config/modules';
import { formatModuleCellValue } from '../domain/cells';
import { buildCidrPrefix } from '../domain/finger';
import {
  applyPathTemplate,
  deepClone,
  formatExternalFilterChipText,
  getValueByPath,
  humanizeField,
  isLikelyIdColumn,
  normalizeHttpHyperlink,
  normalizeValue,
  normalizeValueNoTruncate,
  truncateMiddleText,
} from '../domain/format';
import {
  buildTaskExecutionAccountingSummary,
  buildTaskExecutionDurationInfo,
  buildTaskServiceDurationSummary,
  extractTaskStatisticCounts,
  getAiPrioritySortWeight,
  getTaskProgressPercent,
  getTaskSortTimeByStatus,
  getTaskStatusSortWeight,
  normalizeTaskStatus,
} from '../domain/task';
import type {AiDenoiseConfigSnapshot, AiDenoiseResultItem, JsonValue, LoadRowsOptions, ModuleAction, ModuleConfig, ModuleListCacheEntry, ModuleSearchField, OpenModuleHandler, TaskReportExportFeedback, TaskReportExportFormat, TaskReportExportPhase} from '../domain/types';
import {
  buildWihEndpointDetailUrl,
  buildWihEndpointDisplayRequestPacket,
  buildWihEndpointResponsePacket,
  formatWihEndpointAiFillStatus,
  formatWihEndpointMetric,
  getWihRecordTypeTagClass,
  isSensitiveWihRow,
} from '../domain/wih';
import { PageHeader } from '../layout/PageHeader';
import { UNIFIED_SELECT_CLASS } from '../ui/classes';
import { ActionDialog } from './ActionDialog';

export function TableModuleView({
  module,
  token,
  onOpenModule,
  externalFilters,
  onClearExternalFilters,
  scrollResetToken = 0,
}: {
  module: ModuleConfig;
  token: string;
  onOpenModule: OpenModuleHandler;
  externalFilters?: JsonValue;
  onClearExternalFilters?: () => void;
  scrollResetToken?: number;
}) {
  const [rows, setRows] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [page, setPage] = useState(1);
  const [size, setSize] = useState(() => getDefaultModulePageSize(module.id, externalFilters));
  const [order, setOrder] = useState(module.defaultOrder || '');
  const [total, setTotal] = useState(0);
  const [quickFilter, setQuickFilter] = useState('');
  const [searchForm, setSearchForm] = useState<JsonValue>({});
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [dialogAction, setDialogAction] = useState<ModuleAction | null>(null);
  const [dialogPayload, setDialogPayload] = useState<JsonValue>({});
  const [riskDialogOpen, setRiskDialogOpen] = useState(false);
  const [riskDialogLoading, setRiskDialogLoading] = useState(false);
  const [riskDialogSubmitting, setRiskDialogSubmitting] = useState(false);
  const [riskDialogError, setRiskDialogError] = useState('');
  const [riskPolicies, setRiskPolicies] = useState<Array<{ policyId: string; policyName: string; pocCount: number }>>([]);
  const [riskPolicyId, setRiskPolicyId] = useState('');
  const [riskTaskName, setRiskTaskName] = useState('');
  const [riskResultSetId, setRiskResultSetId] = useState('');
  const [riskResultTotal, setRiskResultTotal] = useState(0);
  const [policyTaskDialogOpen, setPolicyTaskDialogOpen] = useState(false);
  const [policyTaskSubmitting, setPolicyTaskSubmitting] = useState(false);
  const [policyTaskError, setPolicyTaskError] = useState('');
  const [policyTaskPolicyId, setPolicyTaskPolicyId] = useState('');
  const [policyTaskPolicyName, setPolicyTaskPolicyName] = useState('');
  const [policyTaskTag, setPolicyTaskTag] = useState<'task' | 'risk_cruising'>('task');
  const [policyTaskName, setPolicyTaskName] = useState('');
  const [policyTaskTarget, setPolicyTaskTarget] = useState('');
  const [taskSchedulePolicyOptions, setTaskSchedulePolicyOptions] = useState<Array<{ label: string; value: string }>>([]);
  const [taskNameOptions, setTaskNameOptions] = useState<Array<{ label: string; value: string }>>([]);
  const [vulnCategoryOptions, setVulnCategoryOptions] = useState<Array<{ label: string; value: string }>>([]);
  const [taskDetailCounts, setTaskDetailCounts] = useState<Record<string, number>>({});
  const [taskDetailCountLoading, setTaskDetailCountLoading] = useState(false);
  const [expandedScopeRows, setExpandedScopeRows] = useState<Record<string, boolean>>({});
  const [expandedTaskScheduleTargetRows, setExpandedTaskScheduleTargetRows] = useState<Record<string, boolean>>({});
  const [expandedTaskOptionRows, setExpandedTaskOptionRows] = useState<Record<string, boolean>>({});
  const [expandedSiteHeaderRows, setExpandedSiteHeaderRows] = useState<Record<string, boolean>>({});
  const [expandedSiteFingerRows, setExpandedSiteFingerRows] = useState<Record<string, boolean>>({});
  const [hyperlinkEnabled, setHyperlinkEnabled] = useState(false);
  const [taskCompactMode, setTaskCompactMode] = useState(true);
  const [aiDenoiseConfig, setAiDenoiseConfig] = useState<AiDenoiseConfigSnapshot>({
    enable: true,
    moduleEnabled: true,
    promptId: '',
  });
  const [aiDenoiseConfigLoading, setAiDenoiseConfigLoading] = useState(false);
  const [aiDenoiseLoading, setAiDenoiseLoading] = useState(false);
  const [aiDenoiseResultMap, setAiDenoiseResultMap] = useState<Record<string, AiDenoiseResultItem>>({});
  const [aiDenoiseDetail, setAiDenoiseDetail] = useState<{
    rowId: string;
    rowTitle: string;
    analysis: AiDenoiseResultItem;
  } | null>(null);
  const [wihEndpointDetail, setWihEndpointDetail] = useState<{
    rowId: string;
    rowTitle: string;
    row: any;
  } | null>(null);
  const [riskRecordDetail, setRiskRecordDetail] = useState<{
    moduleId: string;
    rowId: string;
    rowTitle: string;
    row: any;
  } | null>(null);
  const [taskRowPendingActionMap, setTaskRowPendingActionMap] = useState<Record<string, string>>({});
  const [taskStopAndDeleteLoading, setTaskStopAndDeleteLoading] = useState(false);
  const [taskReportExportFeedback, setTaskReportExportFeedback] = useState<TaskReportExportFeedback | null>(null);
  const [taskReportExportMenu, setTaskReportExportMenu] = useState('');
  const [taskErrorDialog, setTaskErrorDialog] = useState<{
    taskId: string;
    taskName: string;
    target: string;
    logs: Array<{
      time: string;
      stage: string;
      message: string;
      traceback: string;
    }>;
  } | null>(null);
  const [screenshotPreview, setScreenshotPreview] = useState<{ url: string; title: string } | null>(null);
  const [deleteConfirmDialog, setDeleteConfirmDialog] = useState<{
    title: string;
    message: string;
    confirmText: string;
  } | null>(null);
  const deleteConfirmResolverRef = useRef<((confirmed: boolean) => void) | null>(null);
  const tableRootRef = useRef<HTMLDivElement | null>(null);
  const keepBottomAfterSizeChangeRef = useRef(false);
  const pendingRestoreScrollTopRef = useRef<number | null>(null);
  const moduleListStateCacheRef = useRef<Record<string, ModuleListCacheEntry>>({});
  const moduleListLoadedRef = useRef<Record<string, boolean>>({});
  const latestLoadRowsRequestIdRef = useRef(0);
  const activeModuleCacheKeyRef = useRef('');
  const taskDetailCountCacheRef = useRef<Record<string, Record<string, number>>>({});
  const taskSchedulePolicyOptionsCacheRef = useRef<Array<{ label: string; value: string }> | null>(null);
  const taskNameOptionsCacheRef = useRef<Array<{ label: string; value: string }> | null>(null);
  const vulnCategoryOptionsCacheRef = useRef<Record<string, Array<{ label: string; value: string }>>>({});
  const aiDenoiseConfigCacheRef = useRef<Record<string, AiDenoiseConfigSnapshot>>({});
  const activeExternalFilters = useMemo(
    () => (externalFilters && Object.keys(externalFilters).length > 0 ? externalFilters : {}),
    [externalFilters]
  );
  const hasExternalFilters = useMemo(() => Object.keys(activeExternalFilters).length > 0, [activeExternalFilters]);
  const activeExternalFilterSignature = useMemo(() => buildFilterSignature(activeExternalFilters), [activeExternalFilters]);
  const moduleCacheKey = useMemo(
    () => `${module.id}::${activeExternalFilterSignature}`,
    [module.id, activeExternalFilterSignature]
  );
  useEffect(() => {
    activeModuleCacheKeyRef.current = moduleCacheKey;
  }, [moduleCacheKey]);

  const hasList = Boolean(module.listPath);
  const hasAdvancedSearch = Array.isArray(module.searchFields) && module.searchFields.length > 0;
  const showHyperlinkToggle = canToggleHyperlink(module.id);
  const taskNameSearchText = String(searchForm?.name ?? '').trim();
  const aiAnalysisFilterValue = String(searchForm?.ai_analysis ?? '').trim();
  const hasSearchCriteria = useMemo(() => {
    if (hasExternalFilters) return true;
    if (!hasAdvancedSearch) {
      return Boolean(String(quickFilter || '').trim());
    }
    return (module.searchFields || []).some((field) => {
      const value = searchForm?.[field.key];
      if (value === null || value === undefined) return false;
      if (typeof value === 'string') return value.trim() !== '';
      if (typeof value === 'number') return Number.isFinite(value);
      if (typeof value === 'boolean') return value;
      return String(value).trim() !== '';
    });
  }, [hasAdvancedSearch, hasExternalFilters, module.searchFields, quickFilter, searchForm]);
  const isTaskTerminalStatus = (status: any) => ['done', 'stop', 'error'].includes(String(status || '').toLowerCase());
  const markTaskRowActionPending = (taskId: string, action: string) => {
    setTaskRowPendingActionMap((prev) => ({ ...prev, [taskId]: action }));
  };
  const clearTaskRowActionPending = (taskId: string) => {
    setTaskRowPendingActionMap((prev) => {
      if (!prev[taskId]) return prev;
      const next = { ...prev };
      delete next[taskId];
      return next;
    });
  };
  const displayRows = useMemo(() => {
    const filterableModule = isAiDenoiseModule(module.id);
    const preferredRowIdKey = module.rowIdKey || '_id';
    let sourceRows = rows;
    if (filterableModule && aiAnalysisFilterValue) {
      sourceRows = rows.filter((row, index) => {
        const rowKey =
          normalizeRowIdValue(row?.[preferredRowIdKey])
          || normalizeRowIdValue(row?._id)
          || normalizeRowIdValue(row?.id)
          || normalizeRowIdValue(row?.task_id)
          || normalizeRowIdValue(row?.job_id)
          || `${module.id}-row-${page}-${index + 1}`;
        const analysis = aiDenoiseResultMap[rowKey];
        if (!analysis) return aiAnalysisFilterValue === 'unanalyzed';

        const trustText = String(analysis.trust || '').trim().toLowerCase();
        const displayText = String(analysis.display_text || '').trim().toLowerCase();
        const riskText = String(analysis.risk_level || '').trim().toLowerCase();
        if (aiAnalysisFilterValue === 'unanalyzed') {
          return analysis.result_level === 'disabled' || String(analysis.display_text || '').includes('未分析');
        }
        if (aiAnalysisFilterValue === 'safe') {
          return analysis.result_level === 'safe';
        }
        if (aiAnalysisFilterValue === 'suspicious') {
          return analysis.result_level === 'suspicious';
        }
        if (aiAnalysisFilterValue === 'danger') {
          return analysis.result_level === 'danger';
        }
        if (aiAnalysisFilterValue === 'trusted') {
          return trustText.includes('可信') && !trustText.includes('误报');
        }
        if (aiAnalysisFilterValue === 'suspected_fp') {
          return trustText.includes('误报') || trustText.includes('suspected');
        }
        if (aiAnalysisFilterValue === 'high_value') {
          return displayText.includes('高价值') || trustText.includes('高价值') || riskText === '高';
        }
        if (aiAnalysisFilterValue === 'medium_value') {
          return displayText.includes('中价值') || trustText.includes('中价值') || riskText === '中';
        }
        if (aiAnalysisFilterValue === 'no_value') {
          return displayText.includes('无价值') || trustText.includes('无价值') || riskText === '无';
        }
        return true;
      });
    }

    const orderText = String(order || '').trim();
    const defaultOrderText = String(module.defaultOrder || '').trim();
    const usingDefaultOrder = !orderText || orderText === defaultOrderText;

    if (filterableModule && sourceRows.length > 1 && !aiAnalysisFilterValue && usingDefaultOrder) {
      sourceRows = sourceRows
        .map((row, index) => {
          const rowKey =
            normalizeRowIdValue(row?.[preferredRowIdKey])
            || normalizeRowIdValue(row?._id)
            || normalizeRowIdValue(row?.id)
            || normalizeRowIdValue(row?.task_id)
            || normalizeRowIdValue(row?.job_id)
            || `${module.id}-row-${page}-${index + 1}`;
          const analysis = aiDenoiseResultMap[rowKey];
          return {
            row,
            index,
            aiWeight: getAiPrioritySortWeight(analysis, module.id),
          };
        })
        .sort((a, b) => (a.aiWeight - b.aiWeight) || (a.index - b.index))
        .map((item) => item.row);
    }

    if (module.id !== 'task' || sourceRows.length <= 1) return sourceRows;
    if (hasSearchCriteria) return sourceRows;

    return sourceRows
      .map((row, index) => {
        const normalizedStatus = normalizeTaskStatus(row?.status);
        return {
          row,
          index,
          statusWeight: getTaskStatusSortWeight(normalizedStatus),
          status: normalizedStatus,
          sortTime: getTaskSortTimeByStatus(row, normalizedStatus),
        };
      })
      .sort((a, b) => {
        if (a.statusWeight !== b.statusWeight) return a.statusWeight - b.statusWeight;
        if (a.sortTime !== b.sortTime) return b.sortTime - a.sortTime;
        return a.index - b.index;
      })
      .map((item) => item.row);
  }, [
    aiAnalysisFilterValue,
    aiDenoiseResultMap,
    hasSearchCriteria,
    module.defaultOrder,
    module.id,
    module.rowIdKey,
    order,
    page,
    rows,
  ]);
  const [shouldInitialLoad, setShouldInitialLoad] = useState(false);

  const buildUniqueTextOptions = useCallback((values: any[]): Array<{ label: string; value: string }> => {
    const uniqueValues = Array.from(
      new Set(
        values
          .map((value) => String(value || '').trim())
          .filter((value) => value)
      )
    ).sort((a, b) => a.localeCompare(b, 'zh-CN'));

    return uniqueValues.map((value) => ({ label: value, value }));
  }, []);

  const resolveScrollableContainer = useCallback((): HTMLElement | null => {
    let cursor: HTMLElement | null = tableRootRef.current;
    while (cursor) {
      const style = window.getComputedStyle(cursor);
      const overflowY = style.overflowY;
      const canScroll = (overflowY === 'auto' || overflowY === 'scroll') && cursor.scrollHeight > cursor.clientHeight;
      if (canScroll) return cursor;
      cursor = cursor.parentElement;
    }
    if (document.scrollingElement instanceof HTMLElement) return document.scrollingElement;
    return document.documentElement;
  }, []);

  const rememberBottomAnchorBeforeSizeChange = useCallback(() => {
    const container = resolveScrollableContainer();
    if (!container) {
      keepBottomAfterSizeChangeRef.current = false;
      return;
    }
    const distanceToBottom = container.scrollHeight - container.clientHeight - container.scrollTop;
    keepBottomAfterSizeChangeRef.current = distanceToBottom <= 24;
  }, [resolveScrollableContainer]);

  const normalizeTaskErrorLog = useCallback((raw: any) => {
    if (!raw || typeof raw !== 'object') return null;
    const time = sanitizeUiMessage(String(raw?.time || '').trim(), 80) || '-';
    const stage = sanitizeUiMessage(String(raw?.stage || '').trim(), 120) || '-';
    const message = sanitizeUiMessage(String(raw?.message || '').trim(), 3000) || '未知异常';
    const traceback = sanitizeUiMessage(String(raw?.traceback || '').trim(), 12000) || '';
    return { time, stage, message, traceback };
  }, []);

  const buildTaskErrorLogs = useCallback((row: any) => {
    const logs: Array<{ time: string; stage: string; message: string; traceback: string }> = [];
    if (Array.isArray(row?.error_logs)) {
      row.error_logs.forEach((item: any) => {
        const normalized = normalizeTaskErrorLog(item);
        if (normalized) logs.push(normalized);
      });
    }

    const lastError = normalizeTaskErrorLog(row?.last_error);
    if (lastError) logs.push(lastError);

    if (logs.length === 0) {
      const fallbackMessage =
        sanitizeUiMessage(String(row?.error || row?.error_msg || row?.message || '').trim(), 3000) || '';
      if (fallbackMessage) {
        logs.push({
          time: '-',
          stage: '-',
          message: fallbackMessage,
          traceback: '',
        });
      }
    }

    const uniqMap = new Map<string, { time: string; stage: string; message: string; traceback: string }>();
    logs.forEach((item) => {
      const key = `${item.time}|${item.stage}|${item.message}|${item.traceback}`;
      if (!uniqMap.has(key)) uniqMap.set(key, item);
    });

    return Array.from(uniqMap.values());
  }, [normalizeTaskErrorLog]);

  const openTaskErrorDialog = useCallback((row: any) => {
    const taskId = String(row?._id || row?.task_id || '').trim();
    const taskName = sanitizeUiMessage(String(row?.name || '').trim(), 200) || '-';
    const target = sanitizeUiMessage(String(row?.target || '').trim(), 500) || '-';
    const logs = buildTaskErrorLogs(row);
    setTaskErrorDialog({
      taskId,
      taskName,
      target,
      logs,
    });
  }, [buildTaskErrorLogs]);

  const buildDefaultSearchForm = useCallback((): JsonValue => {
    if (!hasAdvancedSearch) return {};
    const next: JsonValue = {};
    (module.searchFields || []).forEach((field) => {
      next[field.key] = '';
    });
    return next;
  }, [hasAdvancedSearch, module.searchFields]);

  useEffect(() => {
    const defaultSize = getDefaultModulePageSize(module.id, activeExternalFilters);
    const cachedState = moduleListStateCacheRef.current[moduleCacheKey];
    const shouldResetScrollPosition = Number(scrollResetToken || 0) > 0;
    if (cachedState) {
      setRows(cachedState.rows || []);
      setTotal(Number(cachedState.total || 0));
      setPage(Math.max(1, Number(cachedState.page || 1)));
      setSize(Math.max(1, Number(cachedState.size || defaultSize)));
      setOrder(String(cachedState.order || module.defaultOrder || ''));
      setQuickFilter(String(cachedState.quickFilter || ''));
      setSearchForm(cachedState.searchForm ? deepClone(cachedState.searchForm) : buildDefaultSearchForm());
      setShouldInitialLoad(Boolean(hasList) && !Boolean(moduleListLoadedRef.current[moduleCacheKey]));
      pendingRestoreScrollTopRef.current = shouldResetScrollPosition
        ? 0
        : (Number.isFinite(Number(cachedState.scrollTop))
            ? Math.max(0, Number(cachedState.scrollTop))
            : null);
    } else {
      setRows([]);
      setTotal(0);
      setPage(1);
      setSize(defaultSize);
      setOrder(module.defaultOrder || '');
      setQuickFilter('');
      setSearchForm(buildDefaultSearchForm());
      setShouldInitialLoad(Boolean(hasList));
      pendingRestoreScrollTopRef.current = shouldResetScrollPosition ? 0 : null;
    }
    setLoading(false);
    setSelectedIds([]);
  }, [activeExternalFilters, buildDefaultSearchForm, hasList, module.defaultOrder, module.id, moduleCacheKey, scrollResetToken]);

  useEffect(() => {
    if (!hasList) return;
    const existingScrollTop = moduleListStateCacheRef.current[moduleCacheKey]?.scrollTop;
    moduleListStateCacheRef.current[moduleCacheKey] = {
      rows,
      total,
      page,
      size,
      order,
      quickFilter,
      searchForm: searchForm ? deepClone(searchForm) : {},
      scrollTop: Number.isFinite(Number(existingScrollTop)) ? Number(existingScrollTop) : 0,
    };
  }, [hasList, moduleCacheKey, order, page, quickFilter, rows, searchForm, size, total]);

  useEffect(() => {
    return () => {
      if (!hasList) return;
      const container = resolveScrollableContainer();
      if (!container) return;
      const currentState = moduleListStateCacheRef.current[moduleCacheKey] || {
        rows,
        total,
        page,
        size,
        order,
        quickFilter,
        searchForm: searchForm ? deepClone(searchForm) : {},
      };
      moduleListStateCacheRef.current[moduleCacheKey] = {
        ...currentState,
        scrollTop: Math.max(0, Number(container.scrollTop || 0)),
      };
    };
  }, [hasList, moduleCacheKey, order, page, quickFilter, resolveScrollableContainer, rows, searchForm, size, total]);

  useEffect(() => {
    setRiskDialogOpen(false);
    setRiskDialogError('');
    setRiskDialogLoading(false);
    setRiskDialogSubmitting(false);
    setPolicyTaskDialogOpen(false);
    setPolicyTaskSubmitting(false);
    setPolicyTaskError('');
    setExpandedScopeRows({});
    setExpandedTaskScheduleTargetRows({});
    setExpandedTaskOptionRows({});
    setExpandedSiteHeaderRows({});
    setExpandedSiteFingerRows({});
    setTaskRowPendingActionMap({});
    setTaskStopAndDeleteLoading(false);
    setTaskCompactMode(true);
    setHyperlinkEnabled(false);
    setTaskErrorDialog(null);
    setScreenshotPreview(null);
    setAiDenoiseResultMap({});
    setAiDenoiseDetail(null);
    setWihEndpointDetail(null);
  }, [module.id]);

  const renderTextWithHyperlink = useCallback((value: string): React.ReactNode => {
    const lines = String(value || '')
      .split(/\r?\n/)
      .map((item) => item.trim())
      .filter((item) => item && item !== '-');
    if (lines.length === 0) return '-';
    return lines.map((line, index) => {
      const href = normalizeHttpHyperlink(line);
      return (
        <React.Fragment key={`${index}-${line}`}>
          {href ? (
            <a
              href={href}
              target="_blank"
              rel="noopener noreferrer"
              className="text-accent hover:underline font-medium break-all"
            >
              {line}
            </a>
          ) : (
            line
          )}
          {index < lines.length - 1 ? <br /> : null}
        </React.Fragment>
      );
    });
  }, []);


  const closeDeleteConfirmDialog = useCallback((confirmed: boolean) => {
    const resolver = deleteConfirmResolverRef.current;
    deleteConfirmResolverRef.current = null;
    setDeleteConfirmDialog(null);
    if (resolver) resolver(confirmed);
  }, []);

  const askActionConfirm = useCallback((
    message: string,
    options: { title?: string; confirmText?: string } = {}
  ): Promise<boolean> => {
    const safeMessage = sanitizeUiMessage(message, 400) || '确认执行删除操作吗？';
    const safeTitle = sanitizeUiMessage(String(options.title || '确认操作'), 80) || '确认操作';
    const safeConfirmText = sanitizeUiMessage(String(options.confirmText || '确认'), 24) || '确认';
    return new Promise((resolve) => {
      deleteConfirmResolverRef.current = resolve;
      setDeleteConfirmDialog({
        title: safeTitle,
        message: safeMessage,
        confirmText: safeConfirmText,
      });
    });
  }, []);

  const askDeleteConfirm = useCallback((message: string, title = '确认删除'): Promise<boolean> => {
    return askActionConfirm(message, { title, confirmText: '确认删除' });
  }, [askActionConfirm]);

  useEffect(() => {
    if (!deleteConfirmDialog) return;
    const handleEsc = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return;
      event.preventDefault();
      closeDeleteConfirmDialog(false);
    };
    window.addEventListener('keydown', handleEsc);
    return () => window.removeEventListener('keydown', handleEsc);
  }, [closeDeleteConfirmDialog, deleteConfirmDialog]);

  useEffect(() => () => {
    if (deleteConfirmResolverRef.current) {
      deleteConfirmResolverRef.current(false);
      deleteConfirmResolverRef.current = null;
    }
  }, []);

  useEffect(() => {
    if (module.id !== 'task_schedule') {
      setTaskSchedulePolicyOptions([]);
      return;
    }

    if (taskSchedulePolicyOptionsCacheRef.current) {
      setTaskSchedulePolicyOptions(taskSchedulePolicyOptionsCacheRef.current);
      return;
    }

    let cancelled = false;
    const loadPolicyOptions = async () => {
      try {
        const response = await requestApi(token, '/policy/', {
          method: 'GET',
          query: { page: 1, size: 1000, order: 'name' },
        });
        const items = normalizeListData(response).items || [];
        const uniqueNames = Array.from(
          new Set(
            items
              .map((item: any) => String(item?.name || '').trim())
              .filter((name: string) => name)
          )
        );
        if (cancelled) return;
        const options = uniqueNames.map((name) => ({ label: name, value: name }));
        taskSchedulePolicyOptionsCacheRef.current = options;
        setTaskSchedulePolicyOptions(options);
      } catch {
        if (cancelled) return;
        setTaskSchedulePolicyOptions([]);
      }
    };

    void loadPolicyOptions();
    return () => {
      cancelled = true;
    };
  }, [module.id, token]);

  useEffect(() => {
    if (module.id !== 'task') {
      setTaskNameOptions([]);
      return;
    }

    if (taskNameOptionsCacheRef.current) {
      setTaskNameOptions(taskNameOptionsCacheRef.current);
      return;
    }

    let cancelled = false;
    const loadTaskNameOptions = async () => {
      try {
        const response = await requestApi(token, '/task/', {
          method: 'GET',
          query: { page: 1, size: 1000, order: 'name' },
        });
        const items = normalizeListData(response).items || [];
        const options = buildUniqueTextOptions(items.map((item: any) => item?.name));
        if (cancelled) return;
        taskNameOptionsCacheRef.current = options;
        setTaskNameOptions(options);
      } catch {
        if (cancelled) return;
        setTaskNameOptions([]);
      }
    };

    void loadTaskNameOptions();
    return () => {
      cancelled = true;
    };
  }, [buildUniqueTextOptions, module.id, token]);

  useEffect(() => {
    if (module.id !== 'task' || rows.length === 0) return;

    const rowOptions = buildUniqueTextOptions(rows.map((row) => row?.name));
    if (rowOptions.length === 0) return;

    setTaskNameOptions((prev) => {
      const merged = buildUniqueTextOptions([
        ...prev.map((option) => option.value),
        ...rowOptions.map((option) => option.value),
      ]);

      const hasChanged =
        merged.length !== prev.length ||
        merged.some((option, index) => option.value !== prev[index]?.value);

      if (!hasChanged) return prev;
      taskNameOptionsCacheRef.current = merged;
      return merged;
    });
  }, [buildUniqueTextOptions, module.id, rows]);

  useEffect(() => {
    if (module.id !== 'vuln') {
      setVulnCategoryOptions([]);
      return;
    }

    const cacheKey = `vuln_category::${activeExternalFilterSignature}`;
    const cached = vulnCategoryOptionsCacheRef.current[cacheKey];
    if (cached) {
      setVulnCategoryOptions(cached);
      return;
    }

    let cancelled = false;
    const loadVulnCategoryOptions = async () => {
      try {
        const response = await requestApi(token, '/vuln/', {
          method: 'GET',
          query: {
            page: 1,
            size: 1000,
            order: 'plg_type',
            ...activeExternalFilters,
          },
        });
        const items = normalizeListData(response).items || [];
        const options = buildUniqueTextOptions(items.map((item: any) => item?.plg_type));
        if (cancelled) return;
        vulnCategoryOptionsCacheRef.current[cacheKey] = options;
        setVulnCategoryOptions(options);
      } catch {
        if (cancelled) return;
        setVulnCategoryOptions([]);
      }
    };

    void loadVulnCategoryOptions();
    return () => {
      cancelled = true;
    };
  }, [activeExternalFilterSignature, activeExternalFilters, buildUniqueTextOptions, module.id, token]);

  useEffect(() => {
    if (module.id !== 'vuln' || rows.length === 0) return;

    const cacheKey = `vuln_category::${activeExternalFilterSignature}`;
    const rowOptions = buildUniqueTextOptions(rows.map((row) => row?.plg_type));
    if (rowOptions.length === 0) return;

    setVulnCategoryOptions((prev) => {
      const merged = buildUniqueTextOptions([
        ...prev.map((option) => option.value),
        ...rowOptions.map((option) => option.value),
      ]);

      const hasChanged =
        merged.length !== prev.length ||
        merged.some((option, index) => option.value !== prev[index]?.value);

      if (!hasChanged) return prev;
      vulnCategoryOptionsCacheRef.current[cacheKey] = merged;
      return merged;
    });
  }, [activeExternalFilterSignature, buildUniqueTextOptions, module.id, rows]);

  const isTaskDetailModule = useMemo(
    () => TASK_DETAIL_TABS.some((tab) => tab.id === module.id),
    [module.id]
  );
  const taskDetailCountCacheKey = useMemo(
    () => `task_detail_count::${activeExternalFilterSignature}`,
    [activeExternalFilterSignature]
  );

  useEffect(() => {
    if (!isTaskDetailModule) {
      setTaskDetailCounts({});
      setTaskDetailCountLoading(false);
      return;
    }

    const cachedCounts = taskDetailCountCacheRef.current[taskDetailCountCacheKey];
    if (cachedCounts) {
      setTaskDetailCounts(cachedCounts);
      setTaskDetailCountLoading(false);
      return;
    }

    let cancelled = false;
    const loadTaskDetailCounts = async () => {
      setTaskDetailCountLoading(true);
      try {
        const requests = TASK_DETAIL_TABS.map(async (tab) => {
          const tabModule = getModuleById(tab.id);
          if (!tabModule.listPath) return [tab.id, 0] as const;
          const response = await requestApi(token, tabModule.listPath, {
            method: 'GET',
            query: {
              page: 1,
              size: 1,
              ...activeExternalFilters,
            },
          });
          const normalized = normalizeListData(response);
          return [tab.id, Number(normalized.total || 0)] as const;
        });

        const entries = await Promise.all(requests);
        if (cancelled) return;
        const nextCounts: Record<string, number> = {};
        entries.forEach(([id, count]) => {
          nextCounts[id] = count;
        });
        taskDetailCountCacheRef.current[taskDetailCountCacheKey] = nextCounts;
        setTaskDetailCounts(nextCounts);
      } catch {
        if (cancelled) return;
        setTaskDetailCounts({});
      } finally {
        if (!cancelled) setTaskDetailCountLoading(false);
      }
    };

    void loadTaskDetailCounts();
    return () => {
      cancelled = true;
    };
  }, [isTaskDetailModule, token, activeExternalFilters, taskDetailCountCacheKey]);

  useEffect(() => {
    if (!taskErrorDialog) return;
    const handleEsc = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return;
      event.preventDefault();
      setTaskErrorDialog(null);
    };
    window.addEventListener('keydown', handleEsc);
    return () => window.removeEventListener('keydown', handleEsc);
  }, [taskErrorDialog]);

  useEffect(() => {
    if (!screenshotPreview) return;
    const handleEsc = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return;
      event.preventDefault();
      setScreenshotPreview(null);
    };
    window.addEventListener('keydown', handleEsc);
    return () => window.removeEventListener('keydown', handleEsc);
  }, [screenshotPreview]);

  useEffect(() => {
    if (!aiDenoiseDetail) return;
    const handleEsc = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return;
      event.preventDefault();
      setAiDenoiseDetail(null);
    };
    window.addEventListener('keydown', handleEsc);
    return () => window.removeEventListener('keydown', handleEsc);
  }, [aiDenoiseDetail]);

  useEffect(() => {
    if (!wihEndpointDetail) return;
    const handleEsc = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return;
      event.preventDefault();
      setWihEndpointDetail(null);
    };
    window.addEventListener('keydown', handleEsc);
    return () => window.removeEventListener('keydown', handleEsc);
  }, [wihEndpointDetail]);


  const getSearchFieldOptions = (field: ModuleSearchField): Array<{ label: string; value: string }> => {
    if (field.dynamicOptionsKey === 'policy_name') {
      return [{ label: '全部策略', value: '' }, ...taskSchedulePolicyOptions];
    }
    if (field.dynamicOptionsKey === 'vuln_category') {
      return [{ label: '全部类别', value: '' }, ...vulnCategoryOptions];
    }
    if (Array.isArray(field.options)) {
      return field.options;
    }
    return [{ label: '全部', value: '' }];
  };

  const getSearchFieldSuggestionOptions = (field: ModuleSearchField): Array<{ label: string; value: string }> => {
    if (field.dynamicOptionsKey === 'task_name') {
      return taskNameOptions;
    }
    return [];
  };

  const buildFilters = useCallback((): JsonValue => {
    const filters: JsonValue = {};
    if (hasAdvancedSearch) {
      (module.searchFields || []).forEach((field) => {
        if (field.key === 'ai_analysis') return;
        const raw = searchForm?.[field.key];
        if (raw === undefined || raw === null) return;
        const text = String(raw).trim();
        if (!text) return;
        if (field.inputType === 'number') {
          const parsed = Number(text);
          if (Number.isFinite(parsed)) {
            filters[field.key] = parsed;
          }
          return;
        }
        filters[field.key] = text;
      });
      return { ...activeExternalFilters, ...filters };
    }
    if (module.quickFilterKey && quickFilter.trim()) {
      filters[module.quickFilterKey] = quickFilter.trim();
    }
    return { ...activeExternalFilters, ...filters };
  }, [activeExternalFilters, hasAdvancedSearch, module.quickFilterKey, module.searchFields, quickFilter, searchForm]);

  const clearSearchFilters = useCallback(() => {
    if (hasAdvancedSearch) {
      const resetForm: JsonValue = {};
      (module.searchFields || []).forEach((field) => {
        resetForm[field.key] = '';
      });
      setSearchForm(resetForm);
    } else {
      setQuickFilter('');
    }
    setPage(1);
  }, [hasAdvancedSearch, module.searchFields]);

  const loadRows = useCallback(async (loadOptions: LoadRowsOptions = {}) => {
    if (!module.listPath) return;
    const nextPage = Number.isFinite(Number(loadOptions.page))
      ? Math.max(1, Math.floor(Number(loadOptions.page)))
      : page;
    const nextSize = Number.isFinite(Number(loadOptions.size))
      ? Math.max(1, Math.floor(Number(loadOptions.size)))
      : size;
    const nextOrder = typeof loadOptions.order === 'string' ? loadOptions.order : order;
    const filters = loadOptions.filters || buildFilters();
    const requestId = latestLoadRowsRequestIdRef.current + 1;
    latestLoadRowsRequestIdRef.current = requestId;
    const requestModuleCacheKey = moduleCacheKey;

    setLoading(true);
    setError('');
    setSuccess('');
    try {
      const query: JsonValue = {
        page: nextPage,
        size: nextSize,
        ...filters,
      };

      const orderValue = String(nextOrder || '').trim();
      if (orderValue) {
        query.order = orderValue;
      } else if (module.defaultOrder && !('order' in query)) {
        query.order = module.defaultOrder;
      }
      if (loadOptions.forceRefresh) {
        query._refresh = '1';
      }

      const response = await requestApi(token, module.listPath, { method: 'GET', query });
      if (
        requestId !== latestLoadRowsRequestIdRef.current
        || requestModuleCacheKey !== activeModuleCacheKeyRef.current
      ) {
        // 忽略旧模块/旧筛选条件/旧请求的迟到响应，避免列表串数据。
        return;
      }
      const normalized = normalizeListData(response);
      setRows(normalized.items);
      setTotal(normalized.total);
      setSelectedIds([]);
      moduleListLoadedRef.current[moduleCacheKey] = true;
      if (isTaskDetailModule) {
        const currentTotal = Number(normalized.total || 0);
        setTaskDetailCounts((prev) => ({ ...prev, [module.id]: currentTotal }));
        taskDetailCountCacheRef.current[taskDetailCountCacheKey] = {
          ...(taskDetailCountCacheRef.current[taskDetailCountCacheKey] || {}),
          [module.id]: currentTotal,
        };
      }
    } catch (err: any) {
      if (
        requestId !== latestLoadRowsRequestIdRef.current
        || requestModuleCacheKey !== activeModuleCacheKeyRef.current
      ) {
        return;
      }
      setError(err?.message || '加载失败');
      setRows([]);
      setTotal(0);
      moduleListLoadedRef.current[moduleCacheKey] = true;
    } finally {
      if (
        requestId === latestLoadRowsRequestIdRef.current
        && requestModuleCacheKey === activeModuleCacheKeyRef.current
      ) {
        setLoading(false);
      }
    }
  }, [
    buildFilters,
    isTaskDetailModule,
    module.defaultOrder,
    module.id,
    module.listPath,
    moduleCacheKey,
    order,
    page,
    size,
    taskDetailCountCacheKey,
    token,
  ]);

  useEffect(() => {
    if (!shouldInitialLoad || !hasList) return;
    setShouldInitialLoad(false);
    void loadRows();
  }, [hasList, loadRows, shouldInitialLoad]);

  const totalPages = Math.max(1, Math.ceil(total / size));
  const pageOptions = useMemo(
    () => Array.from({ length: totalPages }, (_, idx) => idx + 1),
    [totalPages]
  );

  const columns = useMemo(() => {
    if (module.columns && module.columns.length > 0) {
      if (module.id === 'task') {
        const nextColumns = [...module.columns];
        const progressIndex = nextColumns.indexOf('progress');
        const optionsIndex = nextColumns.indexOf('options_summary');
        if (progressIndex >= 0 && optionsIndex >= 0 && progressIndex > optionsIndex) {
          nextColumns.splice(progressIndex, 1);
          nextColumns.splice(optionsIndex, 0, 'progress');
        }
        // 简洁模式下隐藏统计、Task_Id、时间列与配置项列，聚焦任务核心信息。
        if (taskCompactMode) {
          return nextColumns.filter(
            (column) =>
              column !== 'statistic_summary'
              && column !== '_id'
              && column !== 'options_summary'
              && column !== 'start_time'
              && column !== 'end_time'
          );
        }
        return nextColumns;
      }
      return module.columns;
    }
    const first = rows[0];
    if (!first || typeof first !== 'object') return [];
    const keys = Object.keys(first);
    const ordered: string[] = [];
    if (keys.includes(module.rowIdKey || '_id')) {
      ordered.push(module.rowIdKey || '_id');
    }
    keys.forEach((key) => {
      if (!ordered.includes(key)) ordered.push(key);
    });
    return ordered.slice(0, 10);
  }, [module.columns, module.id, module.rowIdKey, rows, taskCompactMode]);

  const rowIdKey = module.rowIdKey || '_id';
  const getRowId = useCallback((row: any): string => {
    const primary = normalizeRowIdValue(row?.[rowIdKey]);
    if (primary) return primary;
    if (module.id === 'task') {
      const taskFallback = normalizeRowIdValue(row?.task_id) || normalizeRowIdValue(row?.id);
      if (taskFallback) return taskFallback;
    }
    return '';
  }, [module.id, rowIdKey]);
  const aiDenoiseModuleId = useMemo(
    () => (isAiDenoiseModule(module.id) ? module.id : null),
    [module.id]
  );
  const normalizeAiDenoiseResultLevel = useCallback((value: any): AiDenoiseResultItem['result_level'] => {
    const normalized = String(value || '').trim().toLowerCase();
    if (normalized === 'safe' || normalized === 'suspicious' || normalized === 'danger' || normalized === 'disabled') {
      return normalized as AiDenoiseResultItem['result_level'];
    }
    return 'safe';
  }, []);
  const buildAiDenoiseDisplayText = useCallback((
    resultLevel: AiDenoiseResultItem['result_level'],
    riskLevel: string,
    trust: string,
    certExpireDays?: number,
  ) => {
    if (!aiDenoiseModuleId) return '已分析';
    if (resultLevel === 'disabled') return '已关闭';

    if (aiDenoiseModuleId === 'site') {
      const mapping: Record<string, string> = {
        safe: '正常',
        suspicious: '可疑',
        danger: '危险',
      };
      return mapping[resultLevel] || '正常';
    }
    if (aiDenoiseModuleId === 'fileleak') {
      const mapping: Record<string, string> = {
        safe: '正常',
        suspicious: '可疑',
        danger: '危险',
      };
      return mapping[resultLevel] || '正常';
    }
    if (aiDenoiseModuleId === 'url') {
      const mapping: Record<string, string> = {
        safe: '安全',
        suspicious: '可疑',
        danger: '危险',
      };
      return mapping[resultLevel] || '安全';
    }
    if (aiDenoiseModuleId === 'cert') {
      const mapping: Record<string, string> = {
        safe: '安全',
        suspicious: '可疑',
        danger: '危险',
      };
      const base = mapping[resultLevel] || '安全';
      if (!Number.isFinite(Number(certExpireDays))) return base;
      const days = Number(certExpireDays);
      return days < 0 ? `${base}（已过期）` : `${base}（剩余${days}天）`;
    }
    if (aiDenoiseModuleId === 'vuln' || aiDenoiseModuleId === 'nuclei_result') {
      return `${riskLevel || '中'}/${trust || '可信'}`;
    }
    return '已分析';
  }, [aiDenoiseModuleId]);
  const normalizeAiDenoiseStringList = useCallback((value: any, maxItems = 8): string[] => {
    const rawList = Array.isArray(value) ? value : value ? [value] : [];
    const seen = new Set<string>();
    const items: string[] = [];
    rawList.forEach((item) => {
      if (items.length >= maxItems) return;
      const text = sanitizeUiMessage(item, 280);
      if (!text || seen.has(text)) return;
      seen.add(text);
      items.push(text);
    });
    return items;
  }, []);
  const extractJsonObjectFromText = useCallback((value: any): Record<string, any> | null => {
    const text = String(value || '').trim();
    if (!text) return null;
    let candidate = text;
    const fencedMatch = text.match(/```(?:json)?\s*([\s\S]*?)\s*```/i);
    if (fencedMatch && fencedMatch[1]) {
      candidate = fencedMatch[1].trim();
    }
    const start = candidate.indexOf('{');
    const end = candidate.lastIndexOf('}');
    if (start >= 0 && end > start) {
      candidate = candidate.slice(start, end + 1);
    }
    try {
      const parsed = JSON.parse(candidate);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        return parsed as Record<string, any>;
      }
    } catch {
      return null;
    }
    return null;
  }, []);
  const formatAiDialogueContent = useCallback((role: 'system' | 'user' | 'assistant' | 'tool', rawContent: string): string => {
    const safeContent = sanitizeUiMessage(rawContent, 3200) || '';
    if (!safeContent || role !== 'assistant') return safeContent;
    const parsed = extractJsonObjectFromText(safeContent);
    if (!parsed) return safeContent;

    const resultLevelMap: Record<string, string> = {
      safe: '正常',
      suspicious: '可疑',
      danger: '危险',
    };
    const normalizeList = (value: any, maxItems = 6): string[] => {
      const rawList = Array.isArray(value) ? value : value ? [value] : [];
      const seen = new Set<string>();
      const items: string[] = [];
      rawList.forEach((item) => {
        if (items.length >= maxItems) return;
        const text = sanitizeUiMessage(item, 260);
        if (!text || seen.has(text)) return;
        seen.add(text);
        items.push(text);
      });
      return items;
    };

    const rawLevel = String(parsed.result_level || parsed.level || parsed.status || '').trim().toLowerCase();
    const resultLevel = resultLevelMap[rawLevel] || sanitizeUiMessage(rawLevel, 24) || '-';
    const riskLevel = sanitizeUiMessage(parsed.risk_level || parsed.severity, 24) || '-';
    const trust = sanitizeUiMessage(parsed.trust || parsed.review_status, 24) || '-';
    const summary = sanitizeUiMessage(parsed.summary || parsed.analysis, 600) || '';
    const evidence = normalizeList(parsed.evidence ?? parsed.basis, 8);
    const suggestions = normalizeList(parsed.suggestions ?? parsed.advice, 8);
    const fingerResult = normalizeList(parsed.finger_result ?? parsed.finger, 12);

    const lines: string[] = [
      `结论：${resultLevel}`,
      `风险等级：${riskLevel}`,
      `可信度：${trust}`,
    ];
    if (summary) lines.push(`摘要：${summary}`);
    if (evidence.length > 0) {
      lines.push('分析依据：');
      evidence.forEach((item, index) => lines.push(`${index + 1}. ${item}`));
    }
    if (suggestions.length > 0) {
      lines.push('处置建议：');
      suggestions.forEach((item, index) => lines.push(`${index + 1}. ${item}`));
    }
    if (fingerResult.length > 0) {
      lines.push('AI修正指纹：');
      fingerResult.forEach((item, index) => lines.push(`${index + 1}. ${item}`));
    }
    return lines.join('\n');
  }, [extractJsonObjectFromText]);
  const normalizeAiDenoiseResultItem = useCallback((raw: any, rowKey: string): AiDenoiseResultItem => {
    const resultLevel = normalizeAiDenoiseResultLevel(raw?.result_level);
    const riskLevel = sanitizeUiMessage(String(raw?.risk_level || '中'), 24) || '中';
    const trust = sanitizeUiMessage(String(raw?.trust || '-'), 32) || '-';
    const certExpireDays = Number(raw?.cert_expire_days);
    const safeCertExpireDays = Number.isFinite(certExpireDays) ? certExpireDays : undefined;
    const displayText = sanitizeUiMessage(String(raw?.display_text || ''), 64)
      || buildAiDenoiseDisplayText(resultLevel, riskLevel, trust, safeCertExpireDays);
    const source = String(raw?.source || '').trim().toLowerCase();
    const dialogueRecordsRaw = Array.isArray(raw?.dialogue_records) ? raw.dialogue_records : [];
    const dialogueRecords = dialogueRecordsRaw
      .map((item: any) => {
        const roleText = String(item?.role || '').trim().toLowerCase();
        const role: 'system' | 'user' | 'assistant' | 'tool' =
          roleText === 'system' || roleText === 'user' || roleText === 'assistant' || roleText === 'tool'
            ? roleText
            : 'assistant';
        const content = sanitizeUiMessage(item?.content, 3200);
        if (!content) return null;
        return { role, content };
      })
      .filter((item: { role: 'system' | 'user' | 'assistant' | 'tool'; content: string } | null): item is { role: 'system' | 'user' | 'assistant' | 'tool'; content: string } => Boolean(item))
      .slice(0, 12);
    const summaryText = sanitizeUiMessage(String(raw?.summary || '暂无分析摘要'), 900) || '暂无分析摘要';
    const synthesizedAssistantContent = [
      `最终结果：${displayText || '-'}`,
      `摘要：${summaryText}`,
      ...(normalizeAiDenoiseStringList(raw?.evidence, 3).length > 0
        ? ['依据：', ...normalizeAiDenoiseStringList(raw?.evidence, 3).map((item, index) => `${index + 1}. ${item}`)]
        : []),
      ...(normalizeAiDenoiseStringList(raw?.suggestions, 3).length > 0
        ? ['建议：', ...normalizeAiDenoiseStringList(raw?.suggestions, 3).map((item, index) => `${index + 1}. ${item}`)]
        : []),
    ].join('\n');
    const normalizedDialogueRecords = (() => {
      if (dialogueRecords.length === 0) {
        return [{
          role: 'assistant' as const,
          content: synthesizedAssistantContent,
        }];
      }
      const hasAssistant = dialogueRecords.some((item) => item.role === 'assistant');
      if (!hasAssistant) {
        return [
          ...dialogueRecords,
          {
            role: 'assistant' as const,
            content: synthesizedAssistantContent,
          },
        ].slice(0, 12);
      }
      return dialogueRecords;
    })();
    const fingerResult = normalizeAiDenoiseStringList(raw?.finger_result, 12);

    return {
      row_key: rowKey,
      result_level: resultLevel,
      risk_level: riskLevel,
      trust,
      display_text: displayText,
      summary: summaryText,
      evidence: normalizeAiDenoiseStringList(raw?.evidence, 8),
      suggestions: normalizeAiDenoiseStringList(raw?.suggestions, 8),
      source: source === 'ai' ? 'ai' : source === 'disabled' ? 'disabled' : 'rule',
      prompt_id: sanitizeUiMessage(String(raw?.prompt_id || ''), 80),
      prompt_name: sanitizeUiMessage(String(raw?.prompt_name || ''), 120),
      note: sanitizeUiMessage(String(raw?.note || ''), 260),
      analyzed_at: sanitizeUiMessage(String(raw?.analyzed_at || ''), 64),
      cert_expire_at: sanitizeUiMessage(String(raw?.cert_expire_at || ''), 80),
      cert_expire_days: safeCertExpireDays,
      finger_result: fingerResult,
      dialogue_records: normalizedDialogueRecords,
    };
  }, [buildAiDenoiseDisplayText, normalizeAiDenoiseResultLevel, normalizeAiDenoiseStringList]);
  const buildAiDenoiseDisabledResult = useCallback((
    rowKey: string,
    summary?: string,
    displayText = '已关闭',
  ): AiDenoiseResultItem => {
    const message = sanitizeUiMessage(summary || '当前模块 AI 去噪未启用。', 260) || '当前模块 AI 去噪未启用。';
    const isDisabledBySwitch = displayText === '已关闭';
    return {
      row_key: rowKey,
      result_level: 'disabled',
      risk_level: '-',
      trust: '-',
      display_text: displayText,
      summary: message,
      evidence: [isDisabledBySwitch ? '当前模块或全局 AI 去噪开关关闭。' : 'AI 分析接口调用异常。'],
      suggestions: [isDisabledBySwitch ? '前往 AI 管理开启对应模块。' : '请稍后重试或检查 AI 管理配置与服务连通性。'],
      source: 'disabled',
      prompt_id: aiDenoiseConfig.promptId,
      prompt_name: '',
      note: message,
      analyzed_at: '',
      cert_expire_at: '',
      cert_expire_days: undefined,
    };
  }, [aiDenoiseConfig.promptId]);
  const buildAiDenoiseRowKey = useCallback((row: any, rowIndex: number): string => {
    const rowId = getRowId(row);
    if (rowId) return rowId;
    const candidates = [
      normalizeRowIdValue(row?._id),
      normalizeRowIdValue(row?.id),
      normalizeRowIdValue(row?.task_id),
      normalizeRowIdValue(row?.job_id),
    ].filter((item) => item);
    if (candidates.length > 0) return candidates[0];
    return `${module.id}-row-${page}-${rowIndex + 1}`;
  }, [getRowId, module.id, page]);
  const buildAiDenoiseRowTitle = useCallback((row: any, rowIndex: number): string => {
    const fallback = `第 ${(page - 1) * size + rowIndex + 1} 行`;
    if (!aiDenoiseModuleId) return fallback;
    if (aiDenoiseModuleId === 'fileleak' || aiDenoiseModuleId === 'url') {
      return sanitizeUiMessage(String(row?.url || ''), 260) || fallback;
    }
    if (aiDenoiseModuleId === 'wih_endpoint') {
      const methodText = sanitizeUiMessage(String(row?.method || '').toUpperCase(), 16);
      const urlText = sanitizeUiMessage(String(row?.url || ''), 240);
      return `${methodText || 'GET'} ${urlText || fallback}`.trim();
    }
    if (aiDenoiseModuleId === 'site') {
      return sanitizeUiMessage(String(row?.site || row?.url || row?.host || ''), 260) || fallback;
    }
    if (aiDenoiseModuleId === 'cert') {
      return sanitizeUiMessage(String(row?.host || row?.domain || row?.ip || ''), 260) || fallback;
    }
    if (aiDenoiseModuleId === 'vuln') {
      return sanitizeUiMessage(String(row?.vul_name || row?.target || ''), 260) || fallback;
    }
    if (aiDenoiseModuleId === 'nuclei_result') {
      return sanitizeUiMessage(String(row?.vuln_name || row?.rule_id || row?.target || ''), 260) || fallback;
    }
    return fallback;
  }, [aiDenoiseModuleId, page, size]);
  const buildAiDenoiseAnalyzeItem = useCallback((row: any, rowKey: string): Record<string, any> => {
    const base = { _row_key: rowKey, task_id: row?.task_id };
    if (!aiDenoiseModuleId) return base;
    if (aiDenoiseModuleId === 'site') {
      return {
        ...base,
        site: row?.site,
        url: row?.site,
        title: row?.title,
        status_code: row?.status_code ?? row?.status,
        headers: row?.headers,
        finger: row?.finger,
      };
    }
    if (aiDenoiseModuleId === 'fileleak') {
      return {
        ...base,
        url: row?.url,
        title: row?.title,
        status_code: row?.status_code,
        content_length: row?.content_length,
        source: row?.source,
      };
    }
    if (aiDenoiseModuleId === 'cert') {
      return {
        ...base,
        host: row?.host,
        domain: row?.domain,
        ip: row?.ip,
        cert: row?.cert,
        cert_summary: row?.cert_summary,
      };
    }
    if (aiDenoiseModuleId === 'url') {
      return {
        ...base,
        url: row?.url,
        title: row?.title,
        status_code: row?.status_code,
        content_length: row?.content_length,
        source: row?.source,
      };
    }
    if (aiDenoiseModuleId === 'wih_endpoint') {
      return {
        ...base,
        target: row?.target,
        site: row?.site,
        page_url: row?.page_url,
        url: row?.url,
        method: row?.method,
        status_code: row?.status_code,
        response_status: row?.response_status,
        response_size: row?.response_size,
        content_type: row?.content_type,
        body_kind: row?.body_kind,
        source_types: row?.source_types,
        request_template: row?.request_template,
      };
    }
    if (aiDenoiseModuleId === 'vuln') {
      return {
        ...base,
        vul_name: row?.vul_name,
        plg_type: row?.plg_type,
        app_name: row?.app_name,
        target: row?.target,
        credential: row?.credential,
        verify_data: row?.verify_data,
        verify_obj: row?.verify_obj,
        save_date: row?.save_date,
        vuln_severity: row?.vuln_severity,
      };
    }
    if (aiDenoiseModuleId === 'nuclei_result') {
      return {
        ...base,
        scanner_type: row?.scanner_type,
        rule_id: row?.rule_id,
        target: row?.target,
        vuln_url: row?.vuln_url,
        vuln_name: row?.vuln_name,
        vuln_severity: row?.vuln_severity,
        save_date: row?.save_date,
        verify_data: row?.verify_data,
      };
    }
    return base;
  }, [aiDenoiseModuleId]);
  const canOpenAiDenoiseDetail = useCallback((analysis: AiDenoiseResultItem): boolean => {
    if (!aiDenoiseModuleId) return false;
    return Boolean(analysis);
  }, [aiDenoiseModuleId]);
  const closeAiDenoiseDetail = useCallback(() => {
    setAiDenoiseDetail(null);
  }, []);
  const getAiDenoiseCellClass = useCallback((resultLevel: AiDenoiseResultItem['result_level'], clickable: boolean): string => {
    const base = clickable
      ? 'inline-flex items-center justify-center min-w-[92px] px-2.5 py-1 rounded-full border text-xs font-black transition hover:opacity-85'
      : 'inline-flex items-center justify-center min-w-[92px] px-2.5 py-1 rounded-full border text-xs font-black';
    if (resultLevel === 'danger') return `${base} border-error/40 bg-error/10 text-error`;
    if (resultLevel === 'suspicious') return `${base} border-warning/45 bg-warning/12 text-warning`;
    if (resultLevel === 'disabled') return `${base} border-base-300 bg-base-100/65 text-content-muted`;
    return `${base} border-emerald-400/35 bg-emerald-400/12 text-emerald-300`;
  }, []);
  const openAiDenoiseDetail = useCallback((row: any, rowIndex: number, currentAnalysis: AiDenoiseResultItem) => {
    if (!aiDenoiseModuleId) return;
    const rowKey = buildAiDenoiseRowKey(row, rowIndex);
    const rowTitle = buildAiDenoiseRowTitle(row, rowIndex);
    setAiDenoiseDetail({
      rowId: rowKey,
      rowTitle,
      analysis: currentAnalysis,
    });
  }, [
    aiDenoiseModuleId,
    buildAiDenoiseRowKey,
    buildAiDenoiseRowTitle,
  ]);
  const closeWihEndpointDetail = useCallback(() => {
    setWihEndpointDetail(null);
  }, []);
  const openWihEndpointDetail = useCallback((row: any, rowIndex: number) => {
    const rowId = getRowId(row) || `${rowIndex}`;
    const methodText = String(row?.method || '').trim().toUpperCase() || '-';
    const urlText = normalizeValueNoTruncate(row?.url);
    setWihEndpointDetail({
      rowId,
      rowTitle: `${methodText} ${urlText && urlText !== '-' ? urlText : normalizeValueNoTruncate(row?.target)}`,
      row,
    });
  }, [getRowId]);

  const closeRiskRecordDetail = useCallback(() => {
    setRiskRecordDetail(null);
  }, []);
  const openRiskRecordDetail = useCallback((moduleId: string, row: any, rowIndex: number) => {
    const rowId = getRowId(row) || `${rowIndex}`;
    const title = moduleId === 'nuclei_result'
      ? normalizeValueNoTruncate(row?.vuln_name)
      : normalizeValueNoTruncate(row?.vul_name);
    const fallback = normalizeValueNoTruncate(row?.rule_id) !== '-'
      ? normalizeValueNoTruncate(row?.rule_id)
      : normalizeValueNoTruncate(row?.target);
    setRiskRecordDetail({
      moduleId,
      rowId,
      rowTitle: `${title && title !== '-' ? title : fallback}`,
      row,
    });
  }, [getRowId]);

  useEffect(() => {
    if (!aiDenoiseModuleId) {
      setAiDenoiseConfig({ enable: true, moduleEnabled: true, promptId: '' });
      setAiDenoiseConfigLoading(false);
      return;
    }

    const cached = aiDenoiseConfigCacheRef.current[aiDenoiseModuleId];
    if (cached) {
      setAiDenoiseConfig(cached);
    }

    let cancelled = false;
    const loadAiDenoiseConfig = async () => {
      setAiDenoiseConfigLoading(true);
      try {
        const result = await requestApi(token, '/api_console/ai_config/', { method: 'GET' });
        if (cancelled) return;
        const aiConfig = (result?.data?.ai_config && typeof result.data.ai_config === 'object')
          ? result.data.ai_config
          : {};
        const moduleConfig = (aiConfig?.ai_denoise_modules && typeof aiConfig.ai_denoise_modules === 'object')
          ? aiConfig.ai_denoise_modules
          : {};
        const modulePromptIds = (aiConfig?.ai_denoise_prompt_ids && typeof aiConfig.ai_denoise_prompt_ids === 'object')
          ? aiConfig.ai_denoise_prompt_ids
          : {};
        const nextSnapshot: AiDenoiseConfigSnapshot = {
          enable: aiConfig?.ai_denoise_enable !== false,
          moduleEnabled: moduleConfig[aiDenoiseModuleId] !== false,
          promptId: sanitizeUiMessage(String(modulePromptIds[aiDenoiseModuleId] || ''), 80),
        };
        aiDenoiseConfigCacheRef.current[aiDenoiseModuleId] = nextSnapshot;
        setAiDenoiseConfig(nextSnapshot);
      } catch {
        if (cancelled) return;
        if (cached) {
          setAiDenoiseConfig(cached);
        } else {
          const fallbackSnapshot: AiDenoiseConfigSnapshot = {
            enable: true,
            moduleEnabled: true,
            promptId: '',
          };
          aiDenoiseConfigCacheRef.current[aiDenoiseModuleId] = fallbackSnapshot;
          setAiDenoiseConfig(fallbackSnapshot);
        }
      } finally {
        if (!cancelled) setAiDenoiseConfigLoading(false);
      }
    };

    void loadAiDenoiseConfig();
    return () => {
      cancelled = true;
    };
  }, [aiDenoiseModuleId, token]);

  useEffect(() => {
    if (!aiDenoiseModuleId) {
      setAiDenoiseLoading(false);
      setAiDenoiseResultMap({});
      return;
    }
    if (rows.length === 0) {
      setAiDenoiseLoading(false);
      setAiDenoiseResultMap({});
      return;
    }

    const rowEntries = rows.map((row, rowIndex) => {
      const rowKey = buildAiDenoiseRowKey(row, rowIndex);
      return {
        row,
        rowKey,
        payload: buildAiDenoiseAnalyzeItem(row, rowKey),
      };
    });

    if (!aiDenoiseConfig.enable || !aiDenoiseConfig.moduleEnabled) {
      const disabledMap: Record<string, AiDenoiseResultItem> = {};
      rowEntries.forEach((entry) => {
        disabledMap[entry.rowKey] = buildAiDenoiseDisabledResult(entry.rowKey);
      });
      setAiDenoiseResultMap(disabledMap);
      setAiDenoiseLoading(false);
      return;
    }

    let cancelled = false;
    const analyzeRowsByBatch = async () => {
      setAiDenoiseLoading(true);
      try {
        const mergedMap: Record<string, AiDenoiseResultItem> = {};
        const chunkSize = 100;
        for (let index = 0; index < rowEntries.length; index += chunkSize) {
          const chunk = rowEntries.slice(index, index + chunkSize);
          const result = await requestApi(token, '/api_console/ai_denoise/analyze/', {
            method: 'POST',
            body: {
              module_id: aiDenoiseModuleId,
              items: chunk.map((entry) => entry.payload),
              prefer_ai: false,
            },
          });
          if (cancelled) return;
          const resultItems = Array.isArray(result?.data?.items) ? result.data.items : [];
          resultItems.forEach((item: any, itemIndex: number) => {
            const fallbackRowKey = chunk[itemIndex]?.rowKey || '';
            const rowKey = String(item?.row_key || fallbackRowKey || '').trim();
            if (!rowKey) return;
            mergedMap[rowKey] = normalizeAiDenoiseResultItem(item, rowKey);
          });
        }
        if (cancelled) return;
        rowEntries.forEach((entry) => {
          if (!mergedMap[entry.rowKey]) {
            mergedMap[entry.rowKey] = normalizeAiDenoiseResultItem(
              {
                row_key: entry.rowKey,
                result_level: 'safe',
                risk_level: '低',
                trust: '-',
                display_text:
                  aiDenoiseModuleId === 'site'
                    ? '正常'
                    : aiDenoiseModuleId === 'fileleak'
                      ? '正常'
                      : aiDenoiseModuleId === 'url'
                        ? '安全'
                        : '已分析',
                summary: '本行暂未返回分析详情，请稍后刷新列表查看。',
                evidence: ['批量分析未返回该行详细结果。'],
                suggestions: ['稍后刷新列表或等待任务分析阶段完成后再查看。'],
                source: 'rule',
                prompt_id: aiDenoiseConfig.promptId,
                prompt_name: '',
                note: '批量分析暂未返回该行完整详情，建议稍后刷新。',
                analyzed_at: '',
              },
              entry.rowKey
            );
          }
        });
        setAiDenoiseResultMap(mergedMap);
      } catch (err: any) {
        if (cancelled) return;
        const errMessage = sanitizeUiMessage(err?.message || 'AI分析请求失败', 220) || 'AI分析请求失败';
        const failedMap: Record<string, AiDenoiseResultItem> = {};
        rowEntries.forEach((entry) => {
          failedMap[entry.rowKey] = buildAiDenoiseDisabledResult(
            entry.rowKey,
            `AI分析接口异常：${errMessage}`,
            '异常'
          );
        });
        setAiDenoiseResultMap(failedMap);
      } finally {
        if (!cancelled) setAiDenoiseLoading(false);
      }
    };

    void analyzeRowsByBatch();
    return () => {
      cancelled = true;
    };
  }, [
    aiDenoiseConfig.enable,
    aiDenoiseConfig.moduleEnabled,
    aiDenoiseConfig.promptId,
    aiDenoiseModuleId,
    buildAiDenoiseAnalyzeItem,
    buildAiDenoiseDisabledResult,
    buildAiDenoiseRowKey,
    normalizeAiDenoiseResultItem,
    rows,
    token,
  ]);

  const showIndexColumn = Boolean(module.showIndex);
  const getColumnLabel = (column: string) => module.columnLabels?.[column] || humanizeField(column);
  const isColumnSortable = useCallback((column: string) => {
    if (!Array.isArray(module.sortableColumns)) return false;
    return module.sortableColumns.includes(column);
  }, [module.sortableColumns]);
  const getColumnSortDirection = useCallback((column: string): 'asc' | 'desc' | null => {
    const current = String(order || '').trim();
    if (!current) return null;
    if (current === `-${column}`) return 'desc';
    if (current === column || current === `+${column}`) return 'asc';
    return null;
  }, [order]);
  const toggleColumnSort = useCallback((column: string) => {
    if (!isColumnSortable(column)) return;
    const current = String(order || '').trim();
    const nextOrder = current === `-${column}` ? column : `-${column}`;
    setOrder(nextOrder);
    setPage(1);
    void loadRows({ page: 1, order: nextOrder });
  }, [isColumnSortable, loadRows, order]);
  const shouldWrapCell = useCallback((moduleId: string, column: string) => {
    if (moduleId === 'task' && ['target', 'options_summary'].includes(column)) return true;
    if (moduleId === 'task_schedule' && column === 'target') return true;
    if (moduleId === 'asset_site' && ['headers', 'finger'].includes(column)) return true;
    if (moduleId === 'site' && ['headers', 'finger'].includes(column)) return true;
    if ((moduleId === 'domain' || moduleId === 'asset_domain') && column === 'ips') return true;
    if (moduleId === 'domain' && column === 'source') return true;
    if ((moduleId === 'ip' || moduleId === 'asset_ip') && ['port_info.port_id', 'domain'].includes(column)) return true;
    if (moduleId === 'asset_scope' && column === 'scope') return true;
    if (moduleId === 'cert' && column === 'cert_summary') return true;
    if (moduleId === 'service' && ['ip_port', 'service_info.product'].includes(column)) return true;
    if (moduleId === 'vuln' && column === 'credential') return true;
    if (moduleId === 'nuclei_result' && ['vuln_url', 'verify_data'].includes(column)) return true;
    if (moduleId === 'waf_host' && column === 'hit_rule') return true;
    if (moduleId === 'wih' && ['content', 'source', 'site'].includes(column)) return true;
    if (moduleId === 'wih_endpoint' && ['target', 'page_url'].includes(column)) return true;
    if (moduleId === 'github_result' && ['path', 'human_content'].includes(column)) return true;
    if (moduleId === 'github_monitor_result' && ['path', 'human_content'].includes(column)) return true;
    return false;
  }, []);

  const moduleActions = module.actions || [];
  const visibleActions = useMemo(() => {
    if (module.id === 'asset_site' || module.id === 'site') {
      return moduleActions.filter((action) => !['asset_site_save_result_set', 'site_save_result_set'].includes(action.id));
    }
    if (module.id === 'asset_scope') {
      const assetScopeVisibleActionIds = ['asset_scope_add', 'asset_scope_delete'];
      return assetScopeVisibleActionIds
        .map((id) => moduleActions.find((action) => action.id === id))
        .filter((action): action is ModuleAction => Boolean(action));
    }
    if (module.id === 'policy') {
      return moduleActions.filter((action) => action.id === 'policy_add');
    }
    if (module.id === 'task_schedule') {
      return moduleActions.filter((action) => ['task_schedule_add', 'task_schedule_stop', 'task_schedule_delete'].includes(action.id));
    }
    if (module.id === 'task') {
      const taskVisibleActionIds = [
        'create_task',
        'fofa_submit',
        'task_stop_batch',
        'task_delete_batch',
        'task_batch_export_domain',
        'task_batch_export_fileleak',
        'task_batch_export_ip',
        'task_batch_export_port',
        'task_batch_export_site',
        'task_batch_export_url',
      ];
      return taskVisibleActionIds
        .map((id) => moduleActions.find((action) => action.id === id))
        .filter((action): action is ModuleAction => Boolean(action));
    }
    if (module.id === 'github_task') {
      const githubTaskVisibleActionIds = ['github_task_add', 'github_task_stop', 'github_task_delete'];
      return githubTaskVisibleActionIds
        .map((id) => moduleActions.find((action) => action.id === id))
        .filter((action): action is ModuleAction => Boolean(action));
    }
    if (module.id === 'github_scheduler') {
      const githubSchedulerVisibleActionIds = ['github_scheduler_add', 'github_scheduler_stop', 'github_scheduler_delete'];
      return githubSchedulerVisibleActionIds
        .map((id) => moduleActions.find((action) => action.id === id))
        .filter((action): action is ModuleAction => Boolean(action));
    }
    return moduleActions;
  }, [module.id, moduleActions]);

  const policyEditAction = module.id === 'policy'
    ? moduleActions.find((action) => action.id === 'policy_edit') || null
    : null;
  const assetScopeAddScopeAction = module.id === 'asset_scope'
    ? moduleActions.find((action) => action.id === 'asset_scope_add_scope') || null
    : null;
  const assetScopeUpdateAction = module.id === 'asset_scope'
    ? moduleActions.find((action) => action.id === 'asset_scope_update') || null
    : null;
  const assetScopeAddSchedulerAction = module.id === 'asset_scope'
    ? moduleActions.find((action) => action.id === 'asset_scope_add_scheduler') || null
    : null;
  const assetScopeAddSiteMonitorAction = module.id === 'asset_scope'
    ? moduleActions.find((action) => action.id === 'asset_scope_add_site_monitor') || null
    : null;
  const assetScopeAddWihMonitorAction = module.id === 'asset_scope'
    ? moduleActions.find((action) => action.id === 'asset_scope_add_wih_monitor') || null
    : null;
  const githubSchedulerUpdateAction = module.id === 'github_scheduler'
    ? moduleActions.find((action) => action.id === 'github_scheduler_update') || null
    : null;
  const taskSyncAction = module.id === 'task'
    ? moduleActions.find((action) => action.id === 'task_sync') || null
    : null;

  const selectAllChecked = displayRows.length > 0 && selectedIds.length === displayRows.length;

  const openActionDialog = (action: ModuleAction, payloadOverrides?: JsonValue) => {
    const basePayload = deepClone(action.payloadTemplate || {});

    if (action.selectedField) {
      if (action.selectionMode === 'single') {
        basePayload[action.selectedField] = selectedIds[0] || '';
      } else if (action.selectionMode === 'multiple') {
        basePayload[action.selectedField] = selectedIds;
      }
    }

    const mergedPayload = payloadOverrides ? { ...basePayload, ...payloadOverrides } : basePayload;
    setDialogPayload(mergedPayload);
    setDialogAction(action);
  };

  const runAction = async (action: ModuleAction, payload: JsonValue, file?: File | null) => {
    setError('');
    setSuccess('');

    const selectionMode = action.selectionMode || 'none';
    let effectiveSelectedIds = [...selectedIds];
    const taskName = taskNameSearchText;
    if (module.id === 'task' && selectionMode === 'multiple' && effectiveSelectedIds.length === 0 && taskName) {
      const taskIdsByName = await fetchTaskIdsByName(taskName);
      if (taskIdsByName.length === 0) {
        throw new Error(`未找到任务名为“${taskName}”的任务`);
      }
      effectiveSelectedIds = taskIdsByName;
    }

    if (selectionMode === 'single' && effectiveSelectedIds.length !== 1) {
      throw new Error('该操作需要且仅需要选择一条记录');
    }
    if (selectionMode === 'multiple' && effectiveSelectedIds.length === 0) {
      if (module.id === 'task') {
        throw new Error('请先选择记录，或输入任务名后再执行批量操作');
      }
      throw new Error('请先选择至少一条记录');
    }

    if (action.selectedField) {
      if (selectionMode === 'single') {
        payload[action.selectedField] = effectiveSelectedIds[0];
      }
      if (selectionMode === 'multiple') {
        payload[action.selectedField] = effectiveSelectedIds;
      }
    }

    if (isDeleteAction(action)) {
      const selectedCount = selectionMode === 'none' ? 0 : effectiveSelectedIds.length;
      const countText = selectedCount > 0 ? `已选择 ${selectedCount} 条记录。` : '';
      const confirmed = await askDeleteConfirm(
        `将执行「${action.label}」。${countText}此操作不可恢复。`
      );
      if (!confirmed) return;
    }

    const resolvedPath = applyPathTemplate(action.path, payload);
    if (/\\{\\w+\\}/.test(resolvedPath)) {
      throw new Error('存在未填写的路径参数，请补全后再执行');
    }

    let body: JsonValue | FormData | undefined;
    let query: JsonValue | undefined;

    if (action.method === 'GET') {
      if (action.sendPayloadAsQuery) {
        query = payload;
      }
    } else {
      if (action.fileFieldName) {
        if (!file) throw new Error('请先选择文件');
        const formData = new FormData();
        formData.append(action.fileFieldName, file);
        Object.entries(payload).forEach(([key, value]) => {
          if (value === undefined || value === null) return;
          formData.append(key, typeof value === 'string' ? value : JSON.stringify(value));
        });
        body = formData;
      } else {
        body = payload;
      }
    }

    const result = await requestApi(token, resolvedPath, {
      method: action.method,
      body,
      query,
      download: Boolean(action.download),
    });

    if (action.download) {
      setSuccess(`已触发下载: ${result?.data?.fileName || '导出文件'}`);
    } else {
      setSuccess(result?.message ? `执行成功: ${result.message}` : '执行成功');
    }

    if (action.reloadAfter !== false && module.listPath) {
      await loadRows({ forceRefresh: true });
    }
  };

  const runExport = async () => {
    if (!module.exportPath) return;

    let payload: JsonValue = {};
    if (module.exportPath.includes('{task_id}')) {
      if (selectedIds.length !== 1) {
        setError('下载单任务报告需要选择 1 条任务记录');
        return;
      }
      payload = { task_id: selectedIds[0] };
    }

    const resolved = applyPathTemplate(module.exportPath, payload);
    try {
      setError('');
      const filters = buildFilters();
      await requestApi(token, resolved, {
        method: 'GET',
        query: module.exportPath.includes('{task_id}') ? undefined : filters,
        download: true,
      });
      setSuccess('导出完成，文件已开始下载');
    } catch (err: any) {
      setError(err?.message || '导出失败');
    }
  };

  const runAssetIpExtraExport = async (kind: 'ip' | 'domain') => {
    if (module.id !== 'asset_ip' && module.id !== 'ip') return;
    const path = module.id === 'asset_ip'
      ? (kind === 'ip' ? '/asset_ip/export_ip/' : '/asset_ip/export_domain/')
      : (kind === 'ip' ? '/ip/export_ip/' : '/ip/export_domain/');
    const label = kind === 'ip' ? 'IP列表' : '关联域名';
    try {
      setError('');
      await requestApi(token, path, {
        method: 'GET',
        query: buildFilters(),
        download: true,
      });
      setSuccess(`导出${label}完成，文件已开始下载`);
    } catch (err: any) {
      setError(err?.message || `导出${label}失败`);
    }
  };

  const copyTextToClipboard = useCallback(async (rawText: string, label = '内容') => {
    const text = String(rawText || '').trim();
    if (!text) {
      setError(`没有可复制的${label}`);
      return;
    }
    try {
      if (navigator?.clipboard?.writeText) {
        await navigator.clipboard.writeText(text);
      } else {
        const textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.setAttribute('readonly', 'readonly');
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
      }
      setSuccess(`${label}已复制`);
    } catch (err: any) {
      setError(err?.message || `${label}复制失败`);
    }
  }, []);

  const closeRiskDialog = useCallback(() => {
    if (riskDialogSubmitting) return;
    setRiskDialogOpen(false);
    setRiskDialogError('');
  }, [riskDialogSubmitting]);

  useEffect(() => {
    if (!riskDialogOpen) return;
    const handleEsc = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return;
      event.preventDefault();
      closeRiskDialog();
    };
    window.addEventListener('keydown', handleEsc);
    return () => window.removeEventListener('keydown', handleEsc);
  }, [closeRiskDialog, riskDialogOpen]);

  useEffect(() => {
    if (!success) return;
    const timer = window.setTimeout(() => setSuccess(''), 2200);
    return () => window.clearTimeout(timer);
  }, [success]);

  useEffect(() => {
    if (!taskReportExportMenu) return;

    const handlePointerDown = (event: MouseEvent) => {
      const target = event.target as HTMLElement | null;
      if (target?.closest?.('[data-task-report-export-menu="true"]')) return;
      setTaskReportExportMenu('');
    };

    const handleEsc = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return;
      setTaskReportExportMenu('');
    };

    window.addEventListener('mousedown', handlePointerDown);
    window.addEventListener('keydown', handleEsc);
    return () => {
      window.removeEventListener('mousedown', handlePointerDown);
      window.removeEventListener('keydown', handleEsc);
    };
  }, [taskReportExportMenu]);

  const openAssetSiteRiskDialog = async () => {
    if (module.id !== 'asset_site') return;
    setRiskDialogLoading(true);
    setRiskDialogError('');
    setError('');
    setSuccess('');
    try {
      const filters = buildFilters();
      const saveResult = await requestApi(token, '/asset_site/save_result_set/', {
        method: 'GET',
        query: filters,
      });
      const resultData = saveResult?.data || {};
      const resultSetId = String(resultData.result_set_id || '').trim();
      const resultTotal = Number(resultData.result_total || 0);
      if (!resultSetId) {
        throw new Error('生成结果集失败，请调整筛选条件后重试');
      }

      const policyResponse = await requestApi(token, '/policy/', {
        method: 'GET',
        query: { page: 1, size: 1000, order: '-_id' },
      });
      const policyItems = normalizeListData(policyResponse).items;
      const options = policyItems
        .map((item) => {
          const policyId = String(item?._id || item?.policy_id || '').trim();
          const policyName = String(item?.name || '').trim() || '未命名策略';
          const pocConfig = Array.isArray(item?.policy?.poc_config) ? item.policy.poc_config : [];
          if (!policyId || pocConfig.length === 0) return null;
          return {
            policyId,
            policyName,
            pocCount: pocConfig.length,
          };
        })
        .filter((item): item is { policyId: string; policyName: string; pocCount: number } => Boolean(item));

      if (options.length === 0) {
        throw new Error('未找到可用策略，请先在策略配置中启用 PoC 插件');
      }

      const first = options[0];
      setRiskPolicies(options);
      setRiskPolicyId(first.policyId);
      setRiskTaskName(`风险巡航任务-${first.policyName}`);
      setRiskResultSetId(resultSetId);
      setRiskResultTotal(resultTotal);
      setRiskDialogOpen(true);
    } catch (err: any) {
      setError(err?.message || '风险任务下发准备失败');
    } finally {
      setRiskDialogLoading(false);
    }
  };

  const submitAssetSiteRiskTask = async () => {
    if (module.id !== 'asset_site') return;
    const taskName = riskTaskName.trim();
    if (!riskPolicyId) {
      setRiskDialogError('请选择策略');
      return;
    }
    if (!taskName) {
      setRiskDialogError('请填写任务名称');
      return;
    }
    if (!riskResultSetId) {
      setRiskDialogError('结果集 ID 无效，请重新生成');
      return;
    }

    setRiskDialogSubmitting(true);
    setRiskDialogError('');
    setError('');
    setSuccess('');
    try {
      await requestApi(token, '/task/policy/', {
        method: 'POST',
        body: {
          name: taskName,
          task_tag: 'risk_cruising',
          target: '',
          policy_id: riskPolicyId,
          result_set_id: riskResultSetId,
        },
      });
      setRiskDialogOpen(false);
      setSuccess(`风险任务下发成功，目标站点 ${riskResultTotal} 条`);
    } catch (err: any) {
      setRiskDialogError(err?.message || '风险任务下发失败');
    } finally {
      setRiskDialogSubmitting(false);
    }
  };

  // 资产分组的行内动作复用统一 ActionDialog，避免出现无后端能力的空壳按钮。
  const openAssetScopeRowActionDialog = (
    action: ModuleAction | null,
    scopeId: string,
    row: any,
    overrides?: JsonValue,
  ) => {
    if (module.id !== 'asset_scope') return;
    if (!action || !scopeId) return;
    const defaultName = String(row?.name || '').trim();
    const defaultScope = Array.isArray(row?.scope_array)
      ? row.scope_array.map((item: any) => String(item || '').trim()).filter(Boolean).join('\n')
      : String(row?.scope || '').replace(/,/g, '\n').trim();
    const defaultBlackScope = Array.isArray(row?.black_scope_array)
      ? row.black_scope_array.map((item: any) => String(item || '').trim()).filter(Boolean).join('\n')
      : String(row?.black_scope || '').replace(/,/g, '\n').trim();
    openActionDialog(action, {
      scope_id: scopeId,
      name: defaultName || undefined,
      scope: defaultScope || undefined,
      black_scope: defaultBlackScope || undefined,
      ...overrides,
    });
  };

  const openPolicyTaskDialog = (row: any) => {
    if (module.id !== 'policy') return;
    const policyId = String(row?._id || row?.policy_id || '').trim();
    const policyName = String(row?.name || '').trim();
    if (!policyId) return;
    setPolicyTaskPolicyId(policyId);
    setPolicyTaskPolicyName(policyName || '策略');
    setPolicyTaskTag('task');
    setPolicyTaskName(`资产侦查任务-${policyName || '策略'}`);
    setPolicyTaskTarget('');
    setPolicyTaskError('');
    setPolicyTaskDialogOpen(true);
  };

  const closePolicyTaskDialog = useCallback(() => {
    if (policyTaskSubmitting) return;
    setPolicyTaskDialogOpen(false);
    setPolicyTaskError('');
  }, [policyTaskSubmitting]);

  useEffect(() => {
    if (!policyTaskDialogOpen) return;
    const handleEsc = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return;
      event.preventDefault();
      closePolicyTaskDialog();
    };
    window.addEventListener('keydown', handleEsc);
    return () => window.removeEventListener('keydown', handleEsc);
  }, [closePolicyTaskDialog, policyTaskDialogOpen]);

  const submitPolicyTask = async () => {
    if (module.id !== 'policy') return;
    const name = policyTaskName.trim();
    const normalizedTargets = policyTaskTarget
      .replace(/,/g, '\n')
      .split(/\r?\n/)
      .map((item) => item.trim())
      .filter((item) => item);

    if (!policyTaskPolicyId) {
      setPolicyTaskError('策略ID无效，请重新打开任务下发');
      return;
    }
    if (!name) {
      setPolicyTaskError('请填写任务名称');
      return;
    }
    if (normalizedTargets.length === 0) {
      setPolicyTaskError('请填写目标，支持一行一个');
      return;
    }

    setPolicyTaskSubmitting(true);
    setPolicyTaskError('');
    setError('');
    setSuccess('');
    try {
      await requestApi(token, '/task/policy/', {
        method: 'POST',
        body: {
          name,
          task_tag: policyTaskTag,
          target: normalizedTargets.join('\n'),
          policy_id: policyTaskPolicyId,
        },
      });
      setPolicyTaskDialogOpen(false);
      setSuccess('任务下发成功');
    } catch (err: any) {
      setPolicyTaskError(err?.message || '任务下发失败');
    } finally {
      setPolicyTaskSubmitting(false);
    }
  };

  const deletePolicyRow = async (policyId: string) => {
    if (module.id !== 'policy') return;
    if (!policyId) return;
    if (!(await askDeleteConfirm('将删除该策略。此操作不可恢复。'))) return;
    setError('');
    setSuccess('');
    try {
      const result = await requestApi(token, '/policy/delete/', {
        method: 'POST',
        body: {
          policy_id: [policyId],
        },
      });
      setSuccess(result?.message ? `删除成功: ${result.message}` : '删除成功');
      await loadRows({ forceRefresh: true });
    } catch (err: any) {
      setError(err?.message || '删除失败');
    }
  };

  const stopTaskScheduleRow = async (jobId: string) => {
    if (module.id !== 'task_schedule') return;
    if (!jobId) return;
    setError('');
    setSuccess('');
    try {
      const result = await requestApi(token, '/task_schedule/stop/', {
        method: 'POST',
        body: {
          _id: [jobId],
        },
      });
      setSuccess(result?.message ? `操作成功: ${result.message}` : '操作成功');
      await loadRows({ forceRefresh: true });
    } catch (err: any) {
      setError(err?.message || '操作失败');
    }
  };

  const recoverTaskScheduleRow = async (jobId: string) => {
    if (module.id !== 'task_schedule') return;
    if (!jobId) return;
    setError('');
    setSuccess('');
    try {
      const result = await requestApi(token, '/task_schedule/recover/', {
        method: 'POST',
        body: {
          _id: [jobId],
        },
      });
      setSuccess(result?.message ? `操作成功: ${result.message}` : '操作成功');
      await loadRows({ forceRefresh: true });
    } catch (err: any) {
      setError(err?.message || '操作失败');
    }
  };

  const deleteTaskScheduleRow = async (jobId: string) => {
    if (module.id !== 'task_schedule') return;
    if (!jobId) return;
    if (!(await askDeleteConfirm('将删除该计划任务。此操作不可恢复。'))) return;
    setError('');
    setSuccess('');
    try {
      const result = await requestApi(token, '/task_schedule/delete/', {
        method: 'POST',
        body: {
          _id: [jobId],
        },
      });
      setSuccess(result?.message ? `删除成功: ${result.message}` : '删除成功');
      await loadRows({ forceRefresh: true });
    } catch (err: any) {
      setError(err?.message || '删除失败');
    }
  };

  const stopGithubSchedulerRow = async (jobId: string) => {
    if (module.id !== 'github_scheduler') return;
    if (!jobId) return;
    setError('');
    setSuccess('');
    try {
      const result = await requestApi(token, '/github_scheduler/stop/', {
        method: 'POST',
        body: {
          _id: [jobId],
        },
      });
      setSuccess(result?.message ? `操作成功: ${result.message}` : '操作成功');
      await loadRows({ forceRefresh: true });
    } catch (err: any) {
      setError(err?.message || '操作失败');
    }
  };

  const recoverGithubSchedulerRow = async (jobId: string) => {
    if (module.id !== 'github_scheduler') return;
    if (!jobId) return;
    setError('');
    setSuccess('');
    try {
      const result = await requestApi(token, '/github_scheduler/recover/', {
        method: 'POST',
        body: {
          _id: [jobId],
        },
      });
      setSuccess(result?.message ? `操作成功: ${result.message}` : '操作成功');
      await loadRows({ forceRefresh: true });
    } catch (err: any) {
      setError(err?.message || '操作失败');
    }
  };

  const deleteGithubSchedulerRow = async (jobId: string) => {
    if (module.id !== 'github_scheduler') return;
    if (!jobId) return;
    if (!(await askDeleteConfirm('将删除该 GitHub 监控任务。此操作不可恢复。'))) return;
    setError('');
    setSuccess('');
    try {
      const result = await requestApi(token, '/github_scheduler/delete/', {
        method: 'POST',
        body: {
          _id: [jobId],
        },
      });
      setSuccess(result?.message ? `删除成功: ${result.message}` : '删除成功');
      await loadRows({ forceRefresh: true });
    } catch (err: any) {
      setError(err?.message || '删除失败');
    }
  };

  const stopGithubTaskRow = async (taskId: string) => {
    if (module.id !== 'github_task') return;
    if (!taskId) return;
    setError('');
    setSuccess('');
    try {
      const result = await requestApi(token, '/github_task/stop/', {
        method: 'POST',
        body: {
          _id: [taskId],
        },
      });
      setSuccess(result?.message ? `操作成功: ${result.message}` : '操作成功');
      await loadRows({ forceRefresh: true });
    } catch (err: any) {
      setError(err?.message || '操作失败');
    }
  };

  const deleteGithubTaskRow = async (taskId: string) => {
    if (module.id !== 'github_task') return;
    if (!taskId) return;
    if (!(await askDeleteConfirm('将删除该 GitHub 任务。此操作不可恢复。'))) return;
    setError('');
    setSuccess('');
    try {
      const result = await requestApi(token, '/github_task/delete/', {
        method: 'POST',
        body: {
          _id: [taskId],
        },
      });
      setSuccess(result?.message ? `删除成功: ${result.message}` : '删除成功');
      await loadRows({ forceRefresh: true });
    } catch (err: any) {
      setError(err?.message || '删除失败');
    }
  };

  const openTaskGlobalView = () => onOpenModule('site');

  const openTaskLocalView = (taskId: string) => {
    if (!taskId) return;
    onOpenModule('site', { task_id: taskId });
  };

  const fetchTaskIdsByName = useCallback(async (taskNameRaw: string) => {
    const taskName = String(taskNameRaw || '').trim();
    if (!taskName) return [];

    const response = await requestApi(token, '/task/', {
      method: 'GET',
      query: {
        page: 1,
        size: 10000,
        name: taskName,
        order: '-_id',
      },
    });

    const taskItems = normalizeListData(response).items || [];
    const matchedTaskItems = taskItems.filter((item: any) => String(item?.name || '').trim() === taskName);
    return Array.from(
      new Set(
        matchedTaskItems
          .map((item: any) => {
            return (
              normalizeRowIdValue(item?._id) ||
              normalizeRowIdValue(item?.task_id) ||
              normalizeRowIdValue(item?.id)
            );
          })
          .filter((id: string) => Boolean(id))
      )
    );
  }, [token]);

  const openTaskViewByName = async () => {
    if (module.id !== 'task') return;

    const taskName = taskNameSearchText;
    if (!taskName) {
      setError('请先输入任务名后再进行同名任务查看');
      return;
    }

    setError('');
    setSuccess('');

    try {
      const taskIds = await fetchTaskIdsByName(taskName);

      if (taskIds.length === 0) {
        setError(`未找到任务名为“${taskName}”的任务`);
        return;
      }

      // 使用逗号拼接 task_id，后端会转换为 $in 查询，展示该任务名下全部任务扫描结果。
      onOpenModule('site', { task_id: taskIds.join(',') });
      setSuccess(`已切换查看任务名“${taskName}”的 ${taskIds.length} 条扫描结果`);
    } catch (err: any) {
      setError(err?.message || '同名任务查看失败');
    }
  };

  const openGithubSchedulerDetail = (jobId: string) => {
    if (module.id !== 'github_scheduler') return;
    if (!jobId) return;
    onOpenModule('github_monitor_result', { github_scheduler_id: jobId });
  };

  const openGithubTaskDetail = (taskId: string) => {
    if (module.id !== 'github_task') return;
    if (!taskId) return;
    onOpenModule('github_result', { github_task_id: taskId });
  };

  const toggleTaskReportExportMenu = (menuKey: string) => {
    setTaskReportExportMenu((current) => (current === menuKey ? '' : menuKey));
  };

  const taskReportExportBusy = Boolean(
    taskReportExportFeedback
    && ['creating', 'queued', 'running', 'downloading'].includes(taskReportExportFeedback.phase)
  );

  const closeTaskReportExportFeedback = () => {
    setTaskReportExportFeedback((current) => {
      if (!current) return null;
      if (['success', 'error'].includes(current.phase)) {
        return null;
      }
      return current;
    });
  };

  const openTaskReportExportFeedback = (format: TaskReportExportFormat, taskCount: number) => {
    const formatLabel = TASK_REPORT_EXPORT_LABELS[format] || '表格';
    setTaskReportExportFeedback({
      phase: 'creating',
      progress: 8,
      title: `${formatLabel}报告导出`,
      summary: `正在创建${formatLabel}导出任务`,
      detail: taskCount > 1 ? `已提交 ${taskCount} 条任务，请稍候...` : '正在为当前任务准备导出文件，请稍候...',
      formatLabel,
      taskCount,
      jobId: '',
      fileName: '',
      error: '',
    });
    return formatLabel;
  };

  const updateTaskReportExportFeedback = (
    phase: TaskReportExportPhase,
    updates: Partial<TaskReportExportFeedback> = {},
  ) => {
    setTaskReportExportFeedback((current) => {
      if (!current) return current;

      const currentProgress = Number(current.progress || 0);
      let nextProgress = currentProgress;
      if (typeof updates.progress === 'number' && Number.isFinite(updates.progress)) {
        nextProgress = Math.min(100, Math.max(0, Math.round(updates.progress)));
      } else if (phase === 'queued') {
        nextProgress = currentProgress < 18 ? 18 : Math.min(currentProgress + 8, 34);
      } else if (phase === 'running') {
        nextProgress = currentProgress < 45 ? 45 : Math.min(currentProgress + 10, 88);
      } else if (phase === 'downloading') {
        nextProgress = Math.max(currentProgress, 96);
      } else if (phase === 'success') {
        nextProgress = 100;
      } else if (phase === 'error') {
        nextProgress = Math.max(currentProgress, 12);
      } else {
        nextProgress = Math.max(currentProgress, 8);
      }

      return {
        ...current,
        ...updates,
        phase,
        progress: nextProgress,
        error: phase === 'error' ? String(updates.error || current.error || '').trim() : '',
      };
    });
  };

  const resolveTaskReportExportIds = useCallback(async () => {
    if (module.id !== 'task') return [];
    if (selectedIds.length > 0) return [...selectedIds];

    const taskName = taskNameSearchText;
    if (!taskName) return [];

    return await fetchTaskIdsByName(taskName);
  }, [fetchTaskIdsByName, module.id, selectedIds, taskNameSearchText]);

  const runTaskBatchReportExport = async (format: TaskReportExportFormat) => {
    if (module.id !== 'task') return;
    if (taskReportExportBusy) {
      setError('已有报告导出任务进行中，请稍候');
      return;
    }

    setTaskReportExportMenu('');
    setError('');
    setSuccess('');

    let taskIds: string[] = [];
    try {
      taskIds = await resolveTaskReportExportIds();
    } catch (err: any) {
      setError(err?.message || '获取任务列表失败');
      return;
    }

    if (taskIds.length === 0) {
      setError('请先勾选任务，或输入任务名后再导出报告');
      return;
    }

    const formatLabel = openTaskReportExportFeedback(format, taskIds.length);
    try {
      await createExportJobAndDownload(taskIds, format);
      setSuccess(`${formatLabel}报告导出成功`);
    } catch (err: any) {
      const errorMessage = err?.message || '报告导出失败';
      updateTaskReportExportFeedback('error', {
        summary: `${formatLabel}报告导出失败`,
        detail: '导出任务未能完成，请根据错误信息排查后重试。',
        error: errorMessage,
      });
      setError(errorMessage);
    }
  };

  const waitForExportJob = async (
    jobId: string,
    {
      timeoutMs = 30 * 60 * 1000,
      intervalMs = 2000,
      onProgress,
    }: {
      timeoutMs?: number;
      intervalMs?: number;
      onProgress?: (phase: TaskReportExportPhase, payload?: { data?: any }) => void;
    } = {},
  ) => {
    const startedAt = Date.now();
    while (Date.now() - startedAt < timeoutMs) {
      const result = await requestApi(token, `/export/job/${jobId}`, {
        method: 'GET',
      });
      const data = result?.data || {};
      const status = String(data?.status || '').trim().toLowerCase();
      if (status === 'queued') {
        onProgress?.('queued', { data });
      }
      if (status === 'running') {
        onProgress?.('running', { data });
      }
      if (status === 'done') {
        return data;
      }
      if (status === 'error') {
        throw new Error(String(data?.error || '导出任务执行失败').trim() || '导出任务执行失败');
      }
      await sleep(intervalMs);
    }
    throw new Error('导出任务等待超时，请稍后在服务器侧检查导出状态');
  };

  const createExportJobAndDownload = async (taskIds: string[], format: TaskReportExportFormat) => {
    const createResult = await requestApi(token, '/export/job', {
      method: 'POST',
      body: {
        task_ids: taskIds,
        format,
      },
    });
    const jobId = String(createResult?.data?.job_id || '').trim();
    if (!jobId) {
      throw new Error('创建导出任务失败，未返回 job_id');
    }
    updateTaskReportExportFeedback('queued', {
      jobId,
      summary: '导出任务已创建，正在排队执行',
      detail: `导出任务 ID: ${jobId}`,
    });
    const exportJobInfo = await waitForExportJob(jobId, {
      onProgress: (phase, payload) => {
        const data = payload?.data || {};
        if (phase === 'queued') {
          updateTaskReportExportFeedback('queued', {
            jobId,
            summary: '导出任务排队中',
            detail: `导出任务 ID: ${jobId}`,
          });
          return;
        }
        if (phase === 'running') {
          updateTaskReportExportFeedback('running', {
            jobId,
            summary: '正在生成导出文件',
            detail: data?.started_at
              ? `任务开始时间: ${normalizeValue(data.started_at)}`
              : `导出任务 ID: ${jobId}`,
          });
        }
      },
    });
    updateTaskReportExportFeedback('downloading', {
      jobId,
      fileName: String(exportJobInfo?.filename || '').trim(),
      summary: '导出文件已生成，正在下载',
      detail: String(exportJobInfo?.filename || '').trim()
        ? `文件名: ${String(exportJobInfo.filename).trim()}`
        : `导出任务 ID: ${jobId}`,
    });
    const downloadResult = await requestApi(token, `/export/job/${jobId}/download`, {
      method: 'GET',
      download: true,
    });
    const downloadedFileName = String(downloadResult?.data?.fileName || exportJobInfo?.filename || '').trim();
    updateTaskReportExportFeedback('success', {
      jobId,
      fileName: downloadedFileName,
      summary: `${TASK_REPORT_EXPORT_LABELS[format] || '表格'}报告导出成功`,
      detail: downloadedFileName
        ? `文件已开始下载：${downloadedFileName}`
        : '文件已开始下载，请留意浏览器下载栏。',
      error: '',
    });
    return {
      jobId,
      fileName: downloadedFileName,
    };
  };

  const stopAndDeleteSelectedTasks = async () => {
    if (module.id !== 'task') return;
    if (taskStopAndDeleteLoading) return;

    const taskIds = Array.from(new Set(selectedIds.filter((item) => Boolean(item))));
    if (taskIds.length === 0) {
      setError('请先勾选需要停止并删除的任务');
      return;
    }

    const confirmed = await askDeleteConfirm(
      `将先停止再删除已勾选的 ${taskIds.length} 条任务，并清理资产搜索中的关联结果数据。此操作不可恢复。`,
      '确认停止并删除'
    );
    if (!confirmed) return;

    setTaskReportExportMenu('');
    setError('');
    setSuccess(`正在停止并删除 ${taskIds.length} 条任务，请稍候...`);
    setTaskStopAndDeleteLoading(true);
    try {
      await requestApi(token, '/task/batch_stop/', {
        method: 'POST',
        body: {
          task_id: taskIds,
        },
      });

      const result = await requestApi(token, '/task/delete/', {
        method: 'POST',
        body: {
          task_id: taskIds,
          del_task_data: true,
        },
      });
      await loadRows({ forceRefresh: true });
      setSelectedIds([]);
      setSuccess(result?.message ? `停止并删除成功: ${result.message}` : `停止并删除成功，共处理 ${taskIds.length} 条任务`);
    } catch (err: any) {
      setError(err?.message || '停止并删除失败');
    } finally {
      setTaskStopAndDeleteLoading(false);
    }
  };

  const stopTaskRow = async (taskId: string) => {
    if (module.id !== 'task') return;
    if (!taskId) return;
    if (taskRowPendingActionMap[taskId]) return;
    markTaskRowActionPending(taskId, 'stop');
    setError('');
    setSuccess('正在停止任务，请稍候...');
    try {
      const result = await requestApi(token, '/task/batch_stop/', {
        method: 'POST',
        body: {
          task_id: [taskId],
        },
      });
      await loadRows({ forceRefresh: true });
      setSuccess(result?.message ? `操作成功: ${result.message}` : '操作成功');
    } catch (err: any) {
      setError(err?.message || '操作失败');
    } finally {
      clearTaskRowActionPending(taskId);
    }
  };

  const deleteTaskRow = async (taskId: string) => {
    if (module.id !== 'task') return;
    if (!taskId) return;
    if (taskRowPendingActionMap[taskId]) return;
    if (!(await askDeleteConfirm('将删除该任务，并清理资产搜索中的关联结果数据。此操作不可恢复。'))) return;
    markTaskRowActionPending(taskId, 'delete');
    setError('');
    setSuccess('正在删除任务，请稍候...');
    try {
      const result = await requestApi(token, '/task/delete/', {
        method: 'POST',
        body: {
          task_id: [taskId],
          del_task_data: true,
        },
      });
      await loadRows({ forceRefresh: true });
      setSuccess(result?.message ? `删除成功: ${result.message}` : '删除成功');
    } catch (err: any) {
      setError(err?.message || '删除失败');
    } finally {
      clearTaskRowActionPending(taskId);
    }
  };

  const restartTaskRow = async (taskId: string) => {
    if (module.id !== 'task') return;
    if (!taskId) return;
    if (taskRowPendingActionMap[taskId]) return;
    if (!(await askActionConfirm('将重启该任务并创建新的执行实例，是否继续？', { title: '确认重启', confirmText: '确认重启' }))) {
      return;
    }
    markTaskRowActionPending(taskId, 'restart');
    setError('');
    setSuccess('正在重启任务，请稍候...');
    try {
      const result = await requestApi(token, '/task/restart/', {
        method: 'POST',
        body: {
          task_id: [taskId],
        },
      });
      await loadRows({ forceRefresh: true });
      // 刷新列表会重置提示文案，这里在刷新后补一条最终反馈。
      const restartedTaskIds = Array.isArray(result?.data?.restart_task_id)
        ? result.data.restart_task_id.map((item: any) => String(item || '').trim()).filter((item: string) => item)
        : [];
      const restartHint = taskNameSearchText ? '（当前有任务名筛选时，新任务可能被过滤）' : '';
      if (restartedTaskIds.length > 0) {
        setSuccess(`重启成功，已创建新任务: ${restartedTaskIds.join(', ')}${restartHint}`);
      } else {
        setSuccess(result?.message ? `重启成功: ${result.message}${restartHint}` : `重启成功，已创建新任务实例${restartHint}`);
      }
    } catch (err: any) {
      setError(err?.message || '重启失败');
    } finally {
      clearTaskRowActionPending(taskId);
    }
  };

  const exportTaskRow = async (taskId: string, format: TaskReportExportFormat = 'excel') => {
    if (module.id !== 'task') return;
    if (!taskId) return;
    if (taskRowPendingActionMap[taskId]) return;
    if (taskReportExportBusy) {
      setError('已有报告导出任务进行中，请稍候');
      return;
    }
    setTaskReportExportMenu('');
    markTaskRowActionPending(taskId, 'export');
    setError('');
    setSuccess('');
    const formatLabel = openTaskReportExportFeedback(format, 1);
    try {
      await createExportJobAndDownload([taskId], format);
      setSuccess(`${formatLabel}报告导出成功`);
    } catch (err: any) {
      const errorMessage = err?.message || '导出失败';
      updateTaskReportExportFeedback('error', {
        summary: `${formatLabel}报告导出失败`,
        detail: '导出任务未能完成，请根据错误信息排查后重试。',
        error: errorMessage,
      });
      setError(errorMessage);
    } finally {
      clearTaskRowActionPending(taskId);
    }
  };

  const syncTaskRow = async (taskId: string, row: any) => {
    if (module.id !== 'task') return;
    if (!taskId) return;
    if (taskRowPendingActionMap[taskId]) return;
    if (!isTaskTerminalStatus(row?.status)) {
      setError('任务未结束，暂不支持同步');
      return;
    }

    const scopeId = String(row?.scope_id || '').trim();
    if (scopeId) {
      setError('');
      setSuccess('正在同步任务数据，请稍候...');
      markTaskRowActionPending(taskId, 'sync');
      try {
        const result = await requestApi(token, '/task/sync/', {
          method: 'POST',
          body: {
            task_id: taskId,
            scope_id: scopeId,
          },
        });
        await loadRows({ forceRefresh: true });
        setSuccess(result?.message ? `同步成功: ${result.message}` : '同步成功');
      } catch (err: any) {
        setError(err?.message || '同步失败');
      } finally {
        clearTaskRowActionPending(taskId);
      }
      return;
    }

    if (!taskSyncAction) {
      setError('未找到任务同步动作配置');
      return;
    }
    openActionDialog(taskSyncAction, {
      task_id: taskId,
      scope_id: '',
    });
    setSuccess('请选择资产组后提交同步');
  };

  const selectionStatus =
    selectedIds.length > 0 ? `${selectedIds.length} 条已选择` : hasList ? '未选择记录' : '动作模式';
  const canUseTaskNameForReportExport = module.id === 'task' && selectedIds.length === 0 && Boolean(taskNameSearchText);
  const taskReportExportDisabled =
    module.id === 'task' && (taskReportExportBusy || (selectedIds.length === 0 && !canUseTaskNameForReportExport));
  const showTaskRowOperate = module.id === 'task';
  const showAssetScopeRowOperate = module.id === 'asset_scope';
  const showPolicyRowOperate = module.id === 'policy';
  const showTaskScheduleRowOperate = module.id === 'task_schedule';
  const showGithubTaskRowOperate = module.id === 'github_task';
  const showGithubSchedulerRowOperate = module.id === 'github_scheduler';
  const hasRowOperate =
    showTaskRowOperate ||
    showAssetScopeRowOperate ||
    showPolicyRowOperate ||
    showTaskScheduleRowOperate ||
    showGithubTaskRowOperate ||
    showGithubSchedulerRowOperate;
  const rowOperateGroupClass = 'inline-flex flex-nowrap items-center justify-center gap-2 min-w-max';
  const rowOperateButtonClass = 'px-3 py-1.5 rounded-lg border border-base-300 text-sm font-semibold hover:bg-base-100/70 transition shrink-0';
  const rowOperateButtonDisabledClass = `${rowOperateButtonClass} disabled:opacity-40 disabled:cursor-not-allowed`;
  const taskReportMenuItemClass =
    'block w-full text-left px-3 py-2 text-sm font-medium hover:bg-base-100/70 transition';
  const rowOperateColumnWidthClass = showAssetScopeRowOperate
    ? 'min-w-[760px]'
    : showTaskRowOperate
      ? 'min-w-[520px]'
      : showPolicyRowOperate
        ? 'min-w-[300px]'
        : showTaskScheduleRowOperate
          ? 'min-w-[220px]'
          : showGithubTaskRowOperate
            ? 'min-w-[220px]'
            : showGithubSchedulerRowOperate
              ? 'min-w-[300px]'
              : '';

  return (
    <div ref={tableRootRef} className="p-8 space-y-6">
      {success ? (
        <div className="fixed inset-x-0 top-5 z-[80] flex justify-center px-4 pointer-events-none">
          <div className="inline-flex w-full max-w-[30rem] items-center justify-center gap-2 rounded-xl border border-emerald-400/35 bg-emerald-400/12 px-4 py-3 text-sm font-semibold text-emerald-200 shadow-xl shadow-black/20 backdrop-blur-sm">
            <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-300" />
            <span className="whitespace-pre-wrap break-all text-center leading-relaxed">{success}</span>
          </div>
        </div>
      ) : null}
      <PageHeader
        title={module.label}
        description={module.description}
        actions={
          <>
            <StatusPill text={selectionStatus} type="info" />
            {error ? <StatusPill text={error} type="error" /> : null}
          </>
        }
      />

      {['scheduler', 'asset_scope', 'asset_site', 'asset_domain', 'asset_ip', 'asset_wih'].includes(module.id) ? (
        <div className="flex items-center gap-2">
          {[
            { id: 'scheduler', label: '资产监控' },
            { id: 'asset_scope', label: '资产分组' },
            { id: 'asset_site', label: '组站点' },
            { id: 'asset_domain', label: '组子域名' },
            { id: 'asset_ip', label: '组IP' },
            { id: 'asset_wih', label: '组WIH' },
          ].map((item) => (
            <button
              key={item.id}
              onClick={() => onOpenModule(item.id)}
              className={`px-4 py-2 rounded-xl border text-sm font-semibold transition ${
                module.id === item.id
                  ? 'border-accent bg-accent/10 text-accent'
                  : 'border-base-300 bg-base-100/35 text-base-content hover:text-base-content hover:bg-base-100/70'
              }`}
            >
              {item.label}
            </button>
          ))}
        </div>
      ) : null}
      {['site', 'domain', 'ip', 'cert', 'service', 'fileleak', 'url', 'vuln', 'nuclei_result', 'stat_finger', 'wih', 'wih_endpoint', 'waf_host'].includes(module.id) ? (
        <div className="flex items-center gap-2">
          {hasExternalFilters ? (
            <button
              onClick={() => onOpenModule('task', undefined, { resetScroll: true })}
              className="px-4 py-2.5 rounded-xl border text-sm font-bold transition inline-flex items-center gap-1.5 bg-brand-accent text-white border-accent shadow-sm hover:bg-accent/90 hover:shadow-md"
              title="返回任务管理"
            >
              <ChevronLeft className="w-4 h-4" />
              返回任务管理
            </button>
          ) : null}
          {TASK_DETAIL_TABS.map((item) => (
            <button
              key={item.id}
              onClick={() => onOpenModule(item.id, hasExternalFilters ? activeExternalFilters : undefined)}
              className={`px-4 py-2 rounded-xl border text-sm font-semibold transition ${
                module.id === item.id
                  ? 'border-accent bg-accent/10 text-accent'
                  : 'border-base-300 bg-base-100/35 text-base-content hover:text-base-content hover:bg-base-100/70'
              }`}
            >
              {`${item.label} - ${
                typeof taskDetailCounts[item.id] === 'number'
                  ? taskDetailCounts[item.id]
                  : taskDetailCountLoading
                    ? '...'
                    : 0
              }`}
            </button>
          ))}
        </div>
      ) : null}

      <div className="bg-base-200/35 border border-base-300 rounded-2xl p-4 space-y-4">
        {hasExternalFilters ? (
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs font-semibold text-base-content">查看筛选条件:</span>
            {Object.entries(activeExternalFilters).map(([key, value]) => (
              <span
                key={key}
                title={`${key}=${String(value ?? '')}`}
                className="text-xs px-2.5 py-1 rounded-lg border border-base-300 bg-base-100/60 font-mono max-w-[42rem] whitespace-pre-wrap break-all leading-relaxed"
              >
                {formatExternalFilterChipText(key, value)}
              </span>
            ))}
            {onClearExternalFilters ? (
              <button
                onClick={onClearExternalFilters}
                className="px-3 py-1.5 rounded-lg border border-base-300 text-xs font-semibold hover:bg-base-100/70 transition"
              >
                清除筛选
              </button>
            ) : null}
          </div>
        ) : null}
        {hasAdvancedSearch ? (
          <div className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
              {(module.searchFields || []).map((field) => (
                <div key={field.key} className="space-y-1">
                  <label className="text-xs font-bold text-base-content">{field.label}：</label>
                  {field.inputType === 'select' ? (
                    <div className="relative">
                      <select
                        value={String(searchForm?.[field.key] ?? '')}
                        className={UNIFIED_SELECT_CLASS}
                        onChange={(event) => {
                          const value = event.target.value;
                          setSearchForm((prev) => ({ ...prev, [field.key]: value }));
                        }}
                      >
                        {getSearchFieldOptions(field).map((option) => (
                          <option key={`${field.key}-${option.value}`} value={option.value}>
                            {option.label}
                          </option>
                        ))}
                      </select>
                      <ChevronDown className="w-4 h-4 text-base-content pointer-events-none absolute right-3 top-1/2 -translate-y-1/2" />
                    </div>
                  ) : (
                    (() => {
                      const suggestionOptions = getSearchFieldSuggestionOptions(field);
                      const datalistId =
                        suggestionOptions.length > 0 ? `search-suggestions-${module.id}-${field.key}` : undefined;

                      return (
                        <>
                          <input
                            list={datalistId}
                            type={field.inputType === 'number' ? 'number' : 'text'}
                            value={String(searchForm?.[field.key] ?? '')}
                            placeholder={field.placeholder}
                            className="w-full bg-base-100 border border-base-300 rounded-xl py-2.5 px-3 text-sm text-base-content placeholder:text-content-muted focus:outline-none focus:border-accent"
                            onChange={(event) => {
                              const value = event.target.value;
                              setSearchForm((prev) => ({ ...prev, [field.key]: value }));
                            }}
                            onKeyDown={(event) => {
                              if (event.key === 'Enter') {
                                event.preventDefault();
                                setPage(1);
                                void loadRows({ page: 1, forceRefresh: true });
                              }
                            }}
                          />
                          {datalistId ? (
                            <datalist id={datalistId}>
                              {suggestionOptions.map((option) => (
                                <option key={`${field.key}-${option.value}`} value={option.value}>
                                  {option.label}
                                </option>
                              ))}
                            </datalist>
                          ) : null}
                        </>
                      );
                    })()
                  )}
                </div>
              ))}
            </div>

            <div className="flex flex-wrap gap-2">
              {hasList ? (
                <button
                  onClick={() => {
                    setPage(1);
                    void loadRows({ page: 1, forceRefresh: true });
                  }}
                  className="px-4 py-2.5 rounded-xl border border-base-300 text-sm font-semibold hover:bg-base-100/70 transition flex items-center gap-2"
                  disabled={loading || !hasList}
                >
                  <Search className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
                  搜索
                </button>
              ) : null}
              {hasList ? (
                <button
                  onClick={clearSearchFilters}
                  className="px-4 py-2.5 rounded-xl border border-base-300 text-sm font-semibold hover:bg-base-100/70 transition flex items-center gap-2"
                  disabled={loading || !hasList}
                >
                  <RefreshCw className="w-4 h-4" />
                  {module.id === 'asset_site' ? '清除' : '重置'}
                </button>
              ) : null}
              {showHyperlinkToggle ? (
                <button
                  type="button"
                  onClick={() => setHyperlinkEnabled((prev) => !prev)}
                  className={`px-4 py-2.5 rounded-xl border text-sm font-semibold transition ${
                    hyperlinkEnabled
                      ? 'border-accent bg-accent/10 text-accent'
                      : 'border-base-300 text-base-content hover:text-base-content hover:bg-base-100/70'
                  }`}
                  title={hyperlinkEnabled ? '已开启超链接，点击关闭' : '默认关闭，点击开启超链接'}
                >
                  超链接
                </button>
              ) : null}
              {module.exportPath && module.id !== 'task' && module.id !== 'asset_scope' ? (
                <button
                  onClick={() => void runExport()}
                  className="px-4 py-2.5 rounded-xl border border-base-300 text-sm font-semibold hover:bg-base-100/70 transition flex items-center gap-2"
                >
                  <Download className="w-4 h-4" />
                  {module.id === 'asset_site' || module.id === 'site'
                    ? '导出站点'
                    : module.id === 'domain'
                      ? '导出子域名'
                      : module.id === 'asset_ip' || module.id === 'ip'
                        ? '导出IP端口'
                        : '导出'}
                </button>
              ) : null}
              {module.id === 'asset_site' ? (
                <button
                  onClick={() => void openAssetSiteRiskDialog()}
                  className="px-4 py-2.5 rounded-xl border border-base-300 text-sm font-semibold hover:bg-base-100/70 transition flex items-center gap-2"
                  disabled={riskDialogLoading}
                >
                  <Play className={`w-4 h-4 ${riskDialogLoading ? 'animate-spin' : ''}`} />
                  风险任务下发
                </button>
              ) : null}
              {module.id === 'task' ? (
                <button
                  onClick={openTaskGlobalView}
                  className="px-4 py-2.5 rounded-xl border border-base-300 text-sm font-semibold hover:bg-base-100/70 transition flex items-center gap-2"
                >
                  <Eye className="w-4 h-4" />
                  全局查看
                </button>
              ) : null}
              {module.id === 'task' ? (
                <button
                  onClick={() => void openTaskViewByName()}
                  disabled={!taskNameSearchText}
                  className="px-4 py-2.5 rounded-xl border border-base-300 text-sm font-semibold hover:bg-base-100/70 transition flex items-center gap-2 disabled:opacity-40 disabled:cursor-not-allowed"
                  title="使用上方“任务名”搜索框内容查看同名任务"
                >
                  <Eye className="w-4 h-4" />
                  同名任务查看
                </button>
              ) : null}
              {module.id === 'task' ? (
                <button
                  type="button"
                  onClick={() => setTaskCompactMode((prev) => !prev)}
                  className={`px-4 py-2.5 rounded-xl border text-sm font-semibold transition ${
                    taskCompactMode
                      ? 'border-accent bg-accent/10 text-accent'
                      : 'border-base-300 text-base-content hover:text-base-content hover:bg-base-100/70'
                  }`}
                  title={taskCompactMode ? '当前为简洁模式，点击切换完整模式' : '当前为完整模式，点击切换简洁模式'}
                >
                  {taskCompactMode ? '简洁模式' : '完整模式'}
                </button>
              ) : null}
              {module.id === 'asset_ip' || module.id === 'ip' ? (
                <button
                  onClick={() => void runAssetIpExtraExport('ip')}
                  className="px-4 py-2.5 rounded-xl border border-base-300 text-sm font-semibold hover:bg-base-100/70 transition flex items-center gap-2"
                >
                  <Download className="w-4 h-4" />
                  导出IP列表
                </button>
              ) : null}
              {module.id === 'asset_ip' || module.id === 'ip' ? (
                <button
                  onClick={() => void runAssetIpExtraExport('domain')}
                  className="px-4 py-2.5 rounded-xl border border-base-300 text-sm font-semibold hover:bg-base-100/70 transition flex items-center gap-2"
                >
                  <Download className="w-4 h-4" />
                  导出关联域名
                </button>
              ) : null}
            </div>
          </div>
        ) : (
          <div className="flex flex-col lg:flex-row gap-3">
            <div className="relative flex-1">
              <Search className="w-4 h-4 text-content-muted absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                value={quickFilter}
                onChange={(event) => {
                  setQuickFilter(event.target.value);
                  setPage(1);
                }}
                placeholder={module.quickFilterKey ? `快速筛选字段: ${module.quickFilterKey}` : '快速筛选'}
                className="w-full bg-base-100 border border-base-300 rounded-xl py-2.5 pl-9 pr-3 text-sm"
              />
            </div>

            <button
              onClick={() => void loadRows({ forceRefresh: true })}
              className="px-4 py-2.5 rounded-xl border border-base-300 text-sm font-semibold hover:bg-base-100/70 transition flex items-center gap-2"
              disabled={loading || !hasList}
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
              刷新
            </button>

            {module.exportPath && module.id !== 'task' ? (
              <button
                onClick={() => void runExport()}
                className="px-4 py-2.5 rounded-xl border border-base-300 text-sm font-semibold hover:bg-base-100/70 transition flex items-center gap-2"
              >
                <Download className="w-4 h-4" />
                导出
              </button>
            ) : null}
            {showHyperlinkToggle ? (
              <button
                type="button"
                onClick={() => setHyperlinkEnabled((prev) => !prev)}
                className={`px-4 py-2.5 rounded-xl border text-sm font-semibold transition ${
                  hyperlinkEnabled
                    ? 'border-accent bg-accent/10 text-accent'
                    : 'border-base-300 text-base-content hover:text-base-content hover:bg-base-100/70'
                }`}
                title={hyperlinkEnabled ? '已开启超链接，点击关闭' : '默认关闭，点击开启超链接'}
              >
                超链接
              </button>
            ) : null}
          </div>
        )}

        {visibleActions.length > 0 ? (
          <div className="flex flex-wrap gap-2 pt-1">
            {visibleActions.map((action) => {
              const needSingle = action.selectionMode === 'single';
              const needMultiple = action.selectionMode === 'multiple';
              const canUseTaskNameForBatch =
                module.id === 'task' && needMultiple && selectedIds.length === 0 && Boolean(taskNameSearchText);
              const disabled =
                (needSingle && selectedIds.length !== 1) ||
                (needMultiple && selectedIds.length === 0 && !canUseTaskNameForBatch);

              return (
                <button
                  key={action.id}
                  onClick={() => openActionDialog(action)}
                  disabled={disabled}
                  className="px-4 py-2.5 rounded-xl text-sm font-bold tracking-wide uppercase border border-base-300 hover:bg-base-100/70 disabled:opacity-40 disabled:cursor-not-allowed transition"
                >
                  {action.label}
                </button>
              );
            })}
            {module.id === 'task' ? (
              <button
                type="button"
                onClick={() => void stopAndDeleteSelectedTasks()}
                disabled={selectedIds.length === 0 || taskStopAndDeleteLoading}
                className="px-4 py-2.5 rounded-xl text-sm font-bold tracking-wide uppercase border border-base-300 hover:bg-base-100/70 disabled:opacity-40 disabled:cursor-not-allowed transition"
                title="先停止所选任务，再执行删除"
              >
                {taskStopAndDeleteLoading ? '停止并删除中...' : '停止并删除'}
              </button>
            ) : null}
            {module.id === 'task' ? (
              <div className="relative" data-task-report-export-menu="true">
                <button
                  type="button"
                  onClick={() => toggleTaskReportExportMenu('batch')}
                  disabled={taskReportExportDisabled}
                  className="px-4 py-2.5 rounded-xl text-sm font-bold tracking-wide uppercase border border-base-300 hover:bg-base-100/70 disabled:opacity-40 disabled:cursor-not-allowed transition flex items-center gap-2"
                >
                  <Download className="w-4 h-4" />
                  {taskReportExportBusy ? '报告导出中...' : '报告导出'}
                  <ChevronDown className={`w-4 h-4 transition ${taskReportExportMenu === 'batch' ? 'rotate-180' : ''}`} />
                </button>
                {taskReportExportMenu === 'batch' ? (
                  <div className="absolute right-0 top-full z-20 mt-2 min-w-[160px] overflow-hidden rounded-xl border border-base-300 bg-base-200 shadow-2xl">
                    {TASK_REPORT_EXPORT_OPTIONS.map((option) => (
                      <button
                        key={option.value}
                        type="button"
                        onClick={() => void runTaskBatchReportExport(option.value)}
                        className={taskReportMenuItemClass}
                      >
                        {option.label}
                      </button>
                    ))}
                  </div>
                ) : null}
              </div>
            ) : null}
            {module.id === 'asset_scope' && module.exportPath ? (
              <button
                onClick={() => void runExport()}
                className="px-4 py-2.5 rounded-xl text-sm font-bold tracking-wide uppercase border border-base-300 hover:bg-base-100/70 transition flex items-center gap-2"
              >
                <Download className="w-4 h-4" />
                批量导出
              </button>
            ) : null}
          </div>
        ) : null}
      </div>

      {hasList ? (
        <div className="bg-base-200/35 border border-base-300 rounded-2xl overflow-hidden">
          <div className="overflow-x-auto custom-scrollbar">
            <table className="w-full border-collapse text-sm md:text-[15px]">
              <thead className="bg-base-100/40 border-b border-base-300">
                <tr>
                  <th className="px-4 py-3 w-12 text-center">
                    <input
                      type="checkbox"
                      checked={selectAllChecked}
                      className="h-5 w-5 cursor-pointer rounded-md border border-base-300 bg-base-100"
                      onChange={(event) => {
                        if (event.target.checked) {
                          const ids = displayRows
                            .map((row) => getRowId(row))
                            .filter((value) => value);
                          setSelectedIds(ids);
                        } else {
                          setSelectedIds([]);
                        }
                      }}
                    />
                  </th>
                  {showIndexColumn ? (
                    <th className="px-4 py-3 text-sm font-black text-content-muted whitespace-nowrap text-center">序号</th>
                  ) : null}
                  {columns.map((column) => {
                    const sortable = isColumnSortable(column);
                    const direction = getColumnSortDirection(column);
                    return (
                      <th
                        key={column}
                        className="px-4 py-3 text-sm font-black text-content-muted whitespace-nowrap text-center"
                      >
                        {sortable ? (
                          <button
                            type="button"
                            onClick={() => toggleColumnSort(column)}
                            className="inline-flex items-center justify-center gap-1.5 hover:text-accent transition"
                            title={direction === 'desc' ? '当前降序，点击切换升序' : '点击按此列降序'}
                          >
                            <span>{getColumnLabel(column)}</span>
                            <span className={`inline-flex ${direction ? 'text-accent' : 'text-content-muted/70'}`}>
                              {direction === 'desc' ? (
                                <ChevronDown className="w-3.5 h-3.5" />
                              ) : direction === 'asc' ? (
                                <ChevronUp className="w-3.5 h-3.5" />
                              ) : (
                                <ChevronsUpDown className="w-3.5 h-3.5" />
                              )}
                            </span>
                          </button>
                        ) : (
                          getColumnLabel(column)
                        )}
                      </th>
                    );
                  })}
                  {hasRowOperate ? (
                    <th className={`px-4 py-3 text-sm font-black text-content-muted whitespace-nowrap text-center ${rowOperateColumnWidthClass}`}>操作</th>
                  ) : null}
                </tr>
              </thead>
              <tbody>
                {displayRows.map((row, rowIndex) => {
                  const id = getRowId(row);
                  const checked = selectedIds.includes(id);
                  const scopeExpandKey = id || `scope-row-${page}-${rowIndex}`;
                  const scheduleTargetExpandKey = id || `task-schedule-row-${page}-${rowIndex}`;
                  const taskOptionExpandKey = id || `task-option-row-${page}-${rowIndex}`;
                  const siteFingerExpandKey = id || `site-finger-row-${page}-${rowIndex}`;

                  return (
                    <tr key={id || Math.random()} className="border-b border-base-300/60 hover:bg-white/5 transition">
                      <td className="px-4 py-3 text-center align-middle">
                        <input
                          type="checkbox"
                          checked={checked}
                          className="h-5 w-5 cursor-pointer rounded-md border border-base-300 bg-base-100"
                          onChange={(event) => {
                            if (!id) return;
                            if (event.target.checked) {
                              setSelectedIds((prev) => [...new Set([...prev, id])]);
                            } else {
                              setSelectedIds((prev) => prev.filter((item) => item !== id));
                            }
                          }}
                        />
                      </td>
                      {showIndexColumn ? (
                        <td className="px-4 py-3 align-middle text-sm whitespace-nowrap text-center">
                          {(page - 1) * size + rowIndex + 1}
                        </td>
                      ) : null}
                      {columns.map((column) => {
                        const wrapCell = shouldWrapCell(module.id, column);
                        const baseClassName = wrapCell
                          ? 'px-4 py-3 align-top text-sm whitespace-pre-wrap break-all text-center leading-relaxed min-w-[220px] max-w-[560px]'
                          : 'px-4 py-3 align-middle text-sm whitespace-nowrap text-center';

                        if (column === 'ai_analysis' && aiDenoiseModuleId) {
                          const rowKey = buildAiDenoiseRowKey(row, rowIndex);
                          const analyzed = aiDenoiseResultMap[rowKey];
                          const moduleEnabled = aiDenoiseConfig.enable && aiDenoiseConfig.moduleEnabled;
                          const pending =
                            moduleEnabled
                            && (aiDenoiseConfigLoading || (aiDenoiseLoading && !Boolean(analyzed)));
                          const analysis = analyzed || (!moduleEnabled ? buildAiDenoiseDisabledResult(rowKey) : null);

                          if (pending) {
                            return (
                              <td key={column} className="px-4 py-3 align-middle text-sm text-center min-w-[150px]">
                                <div className="inline-flex items-center justify-center gap-1.5 text-content-muted">
                                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                                  <span className="text-xs font-semibold">分析中...</span>
                                </div>
                              </td>
                            );
                          }

                          if (!analysis) {
                            return (
                              <td key={column} className="px-4 py-3 align-middle text-sm text-center min-w-[150px]">
                                <span className="inline-flex items-center justify-center min-w-[92px] px-2.5 py-1 rounded-full border border-base-300 bg-base-100/65 text-xs font-semibold text-content-muted">
                                  待分析
                                </span>
                              </td>
                            );
                          }

                          const clickable = canOpenAiDenoiseDetail(analysis);
                          const cellClass = getAiDenoiseCellClass(analysis.result_level, clickable);
                          const contentTitle = analysis.summary || '查看 AI 分析详情';
                          return (
                            <td key={column} className="px-4 py-3 align-middle text-sm text-center min-w-[150px]">
                              {clickable ? (
                                <button
                                  type="button"
                                  onClick={() => void openAiDenoiseDetail(row, rowIndex, analysis)}
                                  className={cellClass}
                                  title={contentTitle}
                                >
                                  {analysis.display_text || '查看详情'}
                                </button>
                              ) : (
                                <span className={cellClass} title={contentTitle}>
                                  {analysis.display_text || '-'}
                                </span>
                              )}
                            </td>
                          );
                        }

                        if (module.id === 'asset_scope' && column === 'scope') {
                          const scopeText = formatModuleCellValue(module.id, column, row);
                          const scopeLines = scopeText
                            .split(/\r?\n/)
                            .map((item) => item.trim())
                            .filter((item) => item && item !== '-');
                          const collapseThreshold = 4;
                          const shouldCollapse = scopeLines.length > collapseThreshold;
                          const isExpanded = Boolean(expandedScopeRows[scopeExpandKey]);
                          const renderedText = shouldCollapse && !isExpanded
                            ? `${scopeLines.slice(0, collapseThreshold).join('\n')}\n...`
                            : (scopeLines.length > 0 ? scopeLines.join('\n') : '-');

                          return (
                            <td key={column} className="px-4 py-3 align-top text-sm text-center min-w-[260px] max-w-[640px]">
                              <div className="whitespace-pre-wrap break-all leading-relaxed">{renderedText}</div>
                              <div className="mt-2 flex flex-wrap items-center justify-center gap-3">
                                {shouldCollapse ? (
                                  <button
                                    onClick={() =>
                                      setExpandedScopeRows((prev) => ({
                                        ...prev,
                                        [scopeExpandKey]: !isExpanded,
                                      }))
                                    }
                                    className="text-xs font-semibold text-accent hover:underline"
                                  >
                                    {isExpanded ? '收起' : '显示全部'}
                                  </button>
                                ) : null}
                                <button
                                  type="button"
                                  onClick={() =>
                                    void copyTextToClipboard(scopeLines.length > 0 ? scopeLines.join('\n') : scopeText, '资产范围')
                                  }
                                  className="text-xs font-semibold text-accent hover:underline"
                                >
                                  复制
                                </button>
                              </div>
                            </td>
                          );
                        }

                        if (module.id === 'task_schedule' && column === 'target') {
                          const targetText = formatModuleCellValue(module.id, column, row);
                          const targetLines = targetText
                            .split(/\r?\n/)
                            .map((item) => item.trim())
                            .filter((item) => item && item !== '-');
                          const collapseThreshold = 4;
                          const shouldCollapse = targetLines.length > collapseThreshold;
                          const isExpanded = Boolean(expandedTaskScheduleTargetRows[scheduleTargetExpandKey]);
                          const renderedText = shouldCollapse && !isExpanded
                            ? `${targetLines.slice(0, collapseThreshold).join('\n')}\n...`
                            : (targetLines.length > 0 ? targetLines.join('\n') : '-');

                          return (
                            <td key={column} className="px-4 py-3 align-top text-sm text-center min-w-[260px] max-w-[640px]">
                              <div className="whitespace-pre-wrap break-all leading-relaxed font-mono text-center">{renderedText}</div>
                              {shouldCollapse ? (
                                <button
                                  onClick={() =>
                                    setExpandedTaskScheduleTargetRows((prev) => ({
                                      ...prev,
                                      [scheduleTargetExpandKey]: !isExpanded,
                                    }))
                                  }
                                  className="mt-2 block mx-auto text-xs font-semibold text-accent hover:underline"
                                >
                                  {isExpanded ? '收起' : '显示全部'}
                                </button>
                              ) : null}
                            </td>
                          );
                        }

                        if (module.id === 'task' && column === 'options_summary') {
                          const optionText = formatModuleCellValue(module.id, column, row);
                          const optionLines = optionText
                            .split(/\r?\n/)
                            .map((item) => item.trim())
                            .filter((item) => item && item !== '-');
                          const collapseThreshold = 3;
                          const shouldCollapse = optionLines.length > collapseThreshold;
                          const isExpanded = Boolean(expandedTaskOptionRows[taskOptionExpandKey]);
                          const renderedText = shouldCollapse && !isExpanded
                            ? `${optionLines.slice(0, collapseThreshold).join('\n')}\n...`
                            : (optionLines.length > 0 ? optionLines.join('\n') : '-');

                          return (
                            <td key={column} className="px-4 py-3 align-top text-sm text-center min-w-[260px] max-w-[640px]">
                              <div className="whitespace-pre-wrap break-all leading-relaxed text-center">{renderedText}</div>
                              {shouldCollapse ? (
                                <button
                                  onClick={() =>
                                    setExpandedTaskOptionRows((prev) => ({
                                      ...prev,
                                      [taskOptionExpandKey]: !isExpanded,
                                    }))
                                  }
                                  className="mt-2 block mx-auto text-xs font-semibold text-accent hover:underline"
                                >
                                  {isExpanded ? '收起' : '显示全部'}
                                </button>
                              ) : null}
                            </td>
                          );
                        }

                        if (module.id === 'wih' && column === 'record_type') {
                          const recordType = String(row?.record_type || '').trim();
                          const sensitive = isSensitiveWihRow(row);
                          return (
                            <td key={column} className="px-4 py-3 align-middle text-sm whitespace-nowrap text-center">
                              <span className={getWihRecordTypeTagClass(recordType, sensitive)}>
                                {recordType || '-'}
                              </span>
                            </td>
                          );
                        }

                        if (module.id === 'wih' && column === 'content') {
                          const sensitive = isSensitiveWihRow(row);
                          const contentText = formatModuleCellValue(module.id, column, row);
                          // 敏感记录在 WIH 中添加显著色块与标识，便于人工优先复核。
                          const contentClass = sensitive
                            ? 'whitespace-pre-wrap break-all leading-relaxed rounded-xl border border-error/45 bg-error/10 px-3 py-2'
                            : 'whitespace-pre-wrap break-all leading-relaxed';
                          return (
                            <td key={column} className="px-4 py-3 align-top text-sm text-center min-w-[260px] max-w-[680px]">
                              <div className={contentClass}>
                                {hyperlinkEnabled && isHyperlinkEnabledColumn(module.id, column)
                                  ? renderTextWithHyperlink(contentText)
                                  : contentText}
                              </div>
                              {sensitive ? (
                                <div className="mt-2 text-[11px] font-black text-error">敏感信息</div>
                              ) : null}
                            </td>
                          );
                        }

                        if (module.id === 'wih_endpoint' && column === 'method') {
                          const methodText = String(row?.method || '').trim().toUpperCase();
                          const tagClass =
                            methodText === 'POST'
                              ? 'inline-flex items-center px-2.5 py-1 rounded-lg border border-warning/60 bg-warning/15 text-warning text-xs font-bold'
                              : methodText === 'GET'
                                ? 'inline-flex items-center px-2.5 py-1 rounded-lg border border-emerald-400/45 bg-emerald-400/12 text-emerald-300 text-xs font-bold'
                                : 'inline-flex items-center px-2.5 py-1 rounded-lg border border-base-300 bg-base-100/50 text-content-muted text-xs font-bold';
                          return (
                            <td key={column} className="px-4 py-3 align-middle text-sm whitespace-nowrap text-center">
                              <span className={tagClass}>{methodText || '-'}</span>
                            </td>
                          );
                        }

                        if ((module.id === 'nuclei_result' || module.id === 'vuln') && column === 'detail_action') {
                          return (
                            <td key={column} className="px-4 py-3 align-middle text-sm whitespace-nowrap text-center">
                              <button
                                type="button"
                                onClick={() => openRiskRecordDetail(module.id, row, rowIndex)}
                                className="inline-flex items-center justify-center rounded-lg border border-base-300 bg-base-100/55 px-3 py-1.5 text-xs font-semibold text-accent hover:bg-base-100/80 transition"
                              >
                                查看详情
                              </button>
                            </td>
                          );
                        }

                        if (module.id === 'wih_endpoint' && column === 'detail_action') {
                          return (
                            <td key={column} className="px-4 py-3 align-middle text-sm whitespace-nowrap text-center">
                              <button
                                type="button"
                                onClick={() => openWihEndpointDetail(row, rowIndex)}
                                className="inline-flex items-center justify-center rounded-lg border border-base-300 bg-base-100/55 px-3 py-1.5 text-xs font-semibold text-accent hover:bg-base-100/80 transition"
                              >
                                查看详情
                              </button>
                            </td>
                          );
                        }








                        if (module.id === 'nuclei_result' && column === 'vuln_url') {
                          const vulnUrlRaw = normalizeValueNoTruncate(row?.vuln_url);
                          const targetRaw = normalizeValueNoTruncate(row?.target);
                          const displayUrl = (vulnUrlRaw && vulnUrlRaw !== '-' ? vulnUrlRaw : targetRaw) || '-';
                          return (
                            <td key={column} className="px-4 py-3 align-middle text-sm text-center min-w-[320px] max-w-[760px]">
                              <div className="min-h-[24px] flex items-center justify-center whitespace-pre-wrap break-all leading-relaxed text-center">
                                {hyperlinkEnabled && isHyperlinkEnabledColumn(module.id, column)
                                  ? renderTextWithHyperlink(displayUrl)
                                  : displayUrl}
                              </div>
                            </td>
                          );
                        }

                        if (module.id === 'nuclei_result' && column === 'verify_data') {
                          const verifyText = formatModuleCellValue(module.id, column, row);
                          const verifyRawText = normalizeValueNoTruncate(row?.verify_data);
                          const scannerType = String(row?.scanner_type || '').trim().toLowerCase();
                          const copyPayload = verifyRawText && verifyRawText !== '-' ? verifyRawText : verifyText;
                          const hasVerifyText = copyPayload && copyPayload !== '-';
                          const copyLabel = scannerType === 'afrog' ? 'afrog curl命令' : '验证信息';
                          return (
                            <td key={column} className="px-4 py-3 align-top text-sm text-center min-w-[300px] max-w-[760px]">
                              <div className="whitespace-pre-wrap break-all leading-relaxed rounded-xl border border-base-300 bg-base-100/40 px-3 py-2 font-mono text-left">
                                {verifyText}
                              </div>
                              {hasVerifyText ? (
                                <button
                                  type="button"
                                  onClick={() => void copyTextToClipboard(copyPayload, copyLabel)}
                                  className="mt-2 text-xs font-semibold text-accent hover:underline"
                                >
                                  复制
                                </button>
                              ) : null}
                            </td>
                          );
                        }

                        if (module.id === 'cip' && (column === 'ip_count' || column === 'domain_count')) {
                          const taskId = String(row?.task_id || '').trim();
                          const cidrPrefix = buildCidrPrefix(row?.cidr_ip);
                          const destinationModule = column === 'ip_count' ? 'ip' : 'domain';
                          const nextFilters: JsonValue = {};
                          if (taskId) nextFilters.task_id = taskId;
                          if (cidrPrefix) {
                            if (column === 'ip_count') {
                              nextFilters.ip = cidrPrefix;
                            } else {
                              nextFilters.ips = cidrPrefix;
                            }
                          }
                          return (
                            <td key={column} className="px-4 py-3 align-middle text-sm whitespace-nowrap text-center">
                              <button
                                type="button"
                                onClick={() => onOpenModule(destinationModule, nextFilters)}
                                className="text-accent hover:underline font-semibold"
                                title={column === 'ip_count' ? '跳转到IP并自动按C段筛选' : '跳转到子域名并自动按C段筛选'}
                              >
                                {formatModuleCellValue(module.id, column, row)}
                              </button>
                            </td>
                          );
                        }

                        if (module.id === 'task' && column === 'progress') {
                          return (
                            <td key={column} className="px-4 py-3 align-middle text-sm whitespace-nowrap text-center">
                              <div className="mx-auto w-[170px] space-y-1 text-left">
                                <div className="flex items-center justify-between gap-2 text-xs">
                                  <span className="font-semibold text-content-muted">进度</span>
                                  <span className="font-black text-white">{formatModuleCellValue(module.id, column, row)}</span>
                                </div>
                                <div className="h-2 bg-base-100 rounded-full border border-base-300 overflow-hidden">
                                  <div
                                    className="h-full bg-brand-accent rounded-full transition-all duration-300"
                                    style={{ width: `${getTaskProgressPercent(row)}%` }}
                                  />
                                </div>
                              </div>
                            </td>
                          );
                        }

                        if (module.id === 'task' && column === 'target') {
                          const targetText = formatModuleCellValue(module.id, column, row);
                          const copyPayload = normalizeValueNoTruncate(row?.target) || targetText;
                          const { siteCnt, domainCnt, ipCnt, urlCnt, vulnCnt, hasAny } = extractTaskStatisticCounts(row);
                          const wafSummary = row?.waf_skip_summary && typeof row.waf_skip_summary === 'object'
                            ? row.waf_skip_summary
                            : {};
                          const wafDetectedHostCount = Number(wafSummary?.detected_host_count || 0);
                          const wafBlockedHostCount = Number(wafSummary?.blocked_host_count || 0);
                          const wafBypassHostCount = Number(wafSummary?.bypass_success_host_count || 0);
                          const wafSkipRequestCount = Number(wafSummary?.skip_request_count || 0);
                          const wafObservedSiteCount = Number(wafSummary?.observed_site_count || 0);
                          const wafSkipSiteCount = Number(wafSummary?.skip_site_count || 0);
                          const hasWafSummary = (
                            wafDetectedHostCount > 0
                            || wafBlockedHostCount > 0
                            || wafBypassHostCount > 0
                            || wafSkipRequestCount > 0
                          );
                          const showTaskTargetStatTooltip = hasAny || hasWafSummary;
                          return (
                            <td key={column} className="px-4 py-3 align-middle text-sm text-center min-w-[220px] max-w-[560px]">
                              <div className="group relative flex items-start justify-center w-full gap-2">
                                <button
                                  type="button"
                                  onClick={() => openTaskLocalView(id)}
                                  className="text-accent hover:underline font-mono whitespace-pre-wrap break-all text-center inline-block flex-1 leading-relaxed"
                                  title="点击查看该任务详情"
                                >
                                  {targetText}
                                </button>
                                <button
                                  type="button"
                                  onClick={(event) => {
                                    event.stopPropagation();
                                    void copyTextToClipboard(copyPayload, '目标');
                                  }}
                                  className="inline-flex shrink-0 items-center justify-center rounded-lg border border-base-300 bg-base-100/55 px-3 py-1 text-xs font-semibold text-accent hover:bg-base-100/80 transition"
                                  title="复制目标"
                                >
                                  复制
                                </button>
                                {showTaskTargetStatTooltip ? (
                                  <div className="pointer-events-none invisible absolute left-1/2 top-full z-30 w-[320px] max-w-[82vw] -translate-x-1/2 pt-2 opacity-0 transition duration-150 group-hover:pointer-events-auto group-hover:visible group-hover:opacity-100">
                                    <div className="rounded-xl border border-base-300 bg-base-200/95 p-3 text-left shadow-2xl backdrop-blur-xl">
                                      <div className="text-xs font-black tracking-wide text-base-content">任务资产统计</div>
                                      <div className="mt-2 grid grid-cols-2 gap-2 text-[11px]">
                                        <div className="rounded-lg border border-base-300 bg-base-100/35 px-2.5 py-2">
                                          <div className="text-content-muted">站点</div>
                                          <div className="mt-1 text-sm font-semibold text-base-content">{siteCnt}</div>
                                        </div>
                                        <div className="rounded-lg border border-base-300 bg-base-100/35 px-2.5 py-2">
                                          <div className="text-content-muted">子域名</div>
                                          <div className="mt-1 text-sm font-semibold text-base-content">{domainCnt}</div>
                                        </div>
                                        <div className="rounded-lg border border-base-300 bg-base-100/35 px-2.5 py-2">
                                          <div className="text-content-muted">IP</div>
                                          <div className="mt-1 text-sm font-semibold text-base-content">{ipCnt}</div>
                                        </div>
                                        <div className="rounded-lg border border-base-300 bg-base-100/35 px-2.5 py-2">
                                          <div className="text-content-muted">URL</div>
                                          <div className="mt-1 text-sm font-semibold text-base-content">{urlCnt}</div>
                                        </div>
                                        <div className="rounded-lg border border-base-300 bg-base-100/35 px-2.5 py-2 col-span-2">
                                          <div className="text-content-muted">风险</div>
                                          <div className="mt-1 text-sm font-semibold text-base-content">{vulnCnt}</div>
                                        </div>
                                      </div>
                                      {hasWafSummary ? (
                                        <div className="mt-2 rounded-lg border border-base-300 bg-base-100/35 px-2.5 py-2 text-[11px]">
                                          <div className="text-content-muted">WAF识别概览</div>
                                          <div className="mt-1 text-base-content break-all">
                                            主机 {wafDetectedHostCount} / 站点 {wafObservedSiteCount} / 跳过主机 {wafBlockedHostCount} / 跳过站点 {wafSkipSiteCount} / 绕过 {wafBypassHostCount} / 请求 {wafSkipRequestCount}
                                          </div>
                                        </div>
                                      ) : null}
                                    </div>
                                  </div>
                                ) : null}
                              </div>
                            </td>
                          );
                        }

                        if (module.id === 'task' && column === 'status') {
                          const rawStatus = String(row?.status || '').trim().toLowerCase();
                          const statusText = formatModuleCellValue(module.id, column, row);
                          const durationDetail = buildTaskExecutionDurationInfo(row, Date.now());
                          const taskServiceDuration = buildTaskServiceDurationSummary(row);
                          const taskAccountingSummary = buildTaskExecutionAccountingSummary(row, Date.now());
                          const currentDurationLabel = durationDetail.durationLabel || '-';
                          const currentStartText = durationDetail.startText || '-';
                          const currentEndText = durationDetail.endText || '-';
                          const visibleStatusText = rawStatus === 'done' && currentDurationLabel !== '-'
                            ? `${statusText}（${currentDurationLabel}）`
                            : statusText;
                          const statusNode = rawStatus === 'error' ? (
                            <button
                              type="button"
                              onClick={() => openTaskErrorDialog(row)}
                              className="inline-flex items-center gap-1 text-error hover:underline font-semibold"
                              title="点击查看异常详情"
                            >
                              <AlertTriangle className="w-4 h-4" />
                              <span>{visibleStatusText}</span>
                            </button>
                          ) : (
                            <span>{visibleStatusText}</span>
                          );

                          return (
                            <td key={column} className="px-4 py-3 align-middle text-sm whitespace-nowrap text-center">
                              <div className="group relative inline-flex items-center justify-center">
                                {statusNode}
                                <div className="pointer-events-none invisible absolute left-1/2 top-full z-30 w-[420px] max-w-[82vw] -translate-x-1/2 pt-2 opacity-0 transition duration-150 group-hover:pointer-events-auto group-hover:visible group-hover:opacity-100">
                                  <div className="rounded-xl border border-base-300 bg-base-200/95 p-3 text-left shadow-2xl backdrop-blur-xl">
                                    <div className="text-xs font-black tracking-wide text-base-content">任务执行时间概览</div>
                                    <div className="mt-2 rounded-lg border border-base-300 bg-base-100/35 px-2.5 py-2">
                                      <div className="text-[11px] text-content-muted">当前任务执行时长</div>
                                      <div className="mt-1 text-sm font-semibold text-base-content">{currentDurationLabel}</div>
                                      <div className="mt-1 text-[11px] text-content-muted">开始：{currentStartText}</div>
                                      <div className="text-[11px] text-content-muted">结束：{currentEndText}</div>
                                    </div>
                                    <div className="mt-2 text-[11px] text-content-muted">
                                      已记录子任务阶段 {taskServiceDuration.totalStageCount} 个，可统计耗时 {taskServiceDuration.countedStageCount} 个
                                    </div>
                                    <div className="text-[11px] text-content-muted">
                                      子任务累计耗时：{taskServiceDuration.totalDurationLabel}
                                    </div>
                                    {taskServiceDuration.dedupApplied ? (
                                      <div className="text-[11px] text-content-muted">
                                        已自动排除父阶段重复统计
                                        {taskServiceDuration.skippedParentStageNames.length
                                          ? `：${taskServiceDuration.skippedParentStageNames.join('、')}`
                                          : ''}
                                      </div>
                                    ) : null}
                                    {taskAccountingSummary.currentStageVisible ? (
                                      <div className="text-[11px] text-content-muted">
                                        当前进行阶段：{taskAccountingSummary.currentStageName}
                                      </div>
                                    ) : null}
                                    {taskAccountingSummary.hasUncountedDuration ? (
                                      <div className="text-[11px] font-semibold text-amber-300">
                                        进行中阶段耗时（暂未计入累计）：{taskAccountingSummary.uncountedStageName} · {taskAccountingSummary.uncountedDurationLabel}
                                      </div>
                                    ) : null}
                                    {taskAccountingSummary.note ? (
                                      <div className="mt-1 text-[11px] text-content-muted">
                                        {taskAccountingSummary.note}
                                      </div>
                                    ) : null}
                                    <div className="mt-2 max-h-44 overflow-y-auto rounded-lg border border-base-300 bg-base-100/40 p-2 text-[11px] leading-relaxed text-base-content">
                                      {taskServiceDuration.entries.length > 0 ? (
                                        taskServiceDuration.entries.map((entry, lineIndex) => (
                                          <React.Fragment key={`${lineIndex}-${entry.stageName}`}>
                                            <div className="font-mono break-all">
                                              {`${lineIndex + 1}. ${entry.stageName}：${entry.elapsedLabel}${entry.countedInTotal ? '' : '（汇总阶段，未计入累计耗时）'}`}
                                            </div>
                                            {entry.detail ? (
                                              <div className="pl-4 text-content-muted break-all">
                                                {entry.detail}
                                              </div>
                                            ) : null}
                                          </React.Fragment>
                                        ))
                                      ) : (
                                        <div className="text-content-muted">暂无该任务子任务执行时间数据</div>
                                      )}
                                    </div>
                                  </div>
                                </div>
                              </div>
                            </td>
                          );
                        }

                        if (module.id === 'task' && column === 'name') {
                          return (
                            <td key={column} className={baseClassName}>
                              <button
                                onClick={() => openTaskLocalView(id)}
                                className="text-accent hover:underline text-center inline-block w-full"
                                title="点击查看该任务详情"
                              >
                                {formatModuleCellValue(module.id, column, row)}
                              </button>
                            </td>
                          );
                        }

                        if (module.id === 'task' && (column === 'start_time' || column === 'end_time')) {
                          return (
                            <td key={column} className="px-4 py-3 align-middle text-sm whitespace-nowrap text-center">
                              <span className="inline-block min-w-[19ch] font-mono tabular-nums">
                                {formatModuleCellValue(module.id, column, row)}
                              </span>
                            </td>
                          );
                        }

                        if ((module.id === 'asset_site' || module.id === 'site') && column === 'headers') {
                          const headerText = formatModuleCellValue(module.id, column, row);
                          const headerLines = String(headerText || '')
                            .split(/\r?\n/)
                            .map((item) => item.trim())
                            .filter((item) => item && item !== '-');
                          const collapseThreshold = 3;
                          const shouldCollapse = headerLines.length > collapseThreshold;
                          const siteHeaderExpandKey = id || `site-header-row-${page}-${rowIndex}`;
                          const isExpanded = Boolean(expandedSiteHeaderRows[siteHeaderExpandKey]);
                          const renderedText = shouldCollapse && !isExpanded
                            ? `${headerLines.slice(0, collapseThreshold).join('\n')}\n...`
                            : (headerLines.length > 0 ? headerLines.join('\n') : '-');

                          return (
                            <td
                              key={column}
                              className="px-4 py-3 align-middle text-sm text-center whitespace-pre-wrap break-all leading-relaxed min-w-[220px] max-w-[560px]"
                            >
                              <div>{renderedText}</div>
                              {shouldCollapse ? (
                                <button
                                  type="button"
                                  onClick={() =>
                                    setExpandedSiteHeaderRows((prev) => ({
                                      ...prev,
                                      [siteHeaderExpandKey]: !isExpanded,
                                    }))
                                  }
                                  className="mt-2 text-xs font-semibold text-accent hover:underline"
                                >
                                  {isExpanded ? '收起' : '展开'}
                                </button>
                              ) : null}
                            </td>
                          );
                        }

                        if ((module.id === 'asset_site' || module.id === 'site') && column === 'finger') {
                          const fingerText = formatModuleCellValue(module.id, column, row);
                          const fingerLines = fingerText
                            .split(/\r?\n/)
                            .map((item) => item.trim())
                            .filter((item) => item && item !== '-');
                          const collapseThreshold = 3;
                          const shouldCollapse = fingerLines.length > collapseThreshold;
                          const isExpanded = Boolean(expandedSiteFingerRows[siteFingerExpandKey]);
                          const renderedText = shouldCollapse && !isExpanded
                            ? `${fingerLines.slice(0, collapseThreshold).join('\n')}\n...`
                            : (fingerLines.length > 0 ? fingerLines.join('\n') : '-');
                          return (
                            <td
                              key={column}
                              className="px-4 py-3 align-middle text-sm text-center whitespace-pre-wrap break-all leading-relaxed min-w-[220px] max-w-[560px]"
                            >
                              <div>{renderedText}</div>
                              {shouldCollapse ? (
                                <button
                                  type="button"
                                  onClick={() =>
                                    setExpandedSiteFingerRows((prev) => ({
                                      ...prev,
                                      [siteFingerExpandKey]: !isExpanded,
                                    }))
                                  }
                                  className="mt-2 text-xs font-semibold text-accent hover:underline"
                                >
                                  {isExpanded ? '收起' : '展开'}
                                </button>
                              ) : null}
                            </td>
                          );
                        }

                        if (hyperlinkEnabled && isHyperlinkEnabledColumn(module.id, column)) {
                          const cellText = formatModuleCellValue(module.id, column, row);
                          return (
                            <td key={column} className={baseClassName}>
                              {renderTextWithHyperlink(cellText)}
                            </td>
                          );
                        }

                        if (isLikelyIdColumn(column)) {
                          const rawIdValue = getValueByPath(row, column);
                          const fullIdText = normalizeValue(rawIdValue);
                          const compactIdText = fullIdText === '-' ? '-' : truncateMiddleText(fullIdText, 38, 14, 12);
                          return (
                            <td key={column} className="px-4 py-3 align-middle text-sm whitespace-nowrap text-center">
                              <span
                                title={fullIdText}
                                className="inline-block max-w-[260px] truncate align-middle font-mono"
                              >
                                {compactIdText}
                              </span>
                            </td>
                          );
                        }

                        if (module.id === 'site' && column === 'screenshot') {
                          const screenshot = String(row?.screenshot || '').trim();
                          if (!screenshot) {
                            return (
                              <td key={column} className="px-4 py-3 align-middle text-sm whitespace-nowrap text-center">
                                -
                              </td>
                            );
                          }
                          let screenshotUrl = screenshot;
                          if (screenshot.startsWith('/image/')) {
                            screenshotUrl = `/api${screenshot}`;
                          } else if (!/^https?:\/\//i.test(screenshot)) {
                            const taskId = String(row?.task_id || '').trim();
                            if (taskId) {
                              screenshotUrl = `/api/image/${taskId}/${screenshot.replace(/^\/+/, '')}`;
                            }
                          }

                          return (
                            <td key={column} className="px-4 py-3 align-middle text-sm text-center min-w-[180px]">
                              <button
                                type="button"
                                onClick={() =>
                                  setScreenshotPreview({
                                    url: screenshotUrl,
                                    title: String(row?.site || row?.hostname || row?.title || '截图预览'),
                                  })
                                }
                                className="inline-flex items-center justify-center p-1 rounded-xl border border-transparent hover:border-accent/60 transition"
                                title="点击预览截图"
                              >
                                <img
                                  src={screenshotUrl}
                                  alt="screenshot"
                                  className="w-32 h-20 rounded-lg border border-base-300 object-cover bg-base-100"
                                  loading="lazy"
                                />
                              </button>
                            </td>
                          );
                        }

                        if (module.id === 'github_scheduler' && column === 'name') {
                          return (
                            <td key={column} className={baseClassName}>
                              <button
                                onClick={() => openGithubSchedulerDetail(id)}
                                className="text-accent hover:underline text-center inline-block w-full"
                                title="查看该监控任务结果"
                              >
                                {formatModuleCellValue(module.id, column, row)}
                              </button>
                            </td>
                          );
                        }

                        if (module.id === 'github_task' && column === 'name') {
                          return (
                            <td key={column} className={baseClassName}>
                              <button
                                onClick={() => openGithubTaskDetail(id)}
                                className="text-accent hover:underline text-center inline-block w-full"
                                title="查看该任务结果"
                              >
                                {formatModuleCellValue(module.id, column, row)}
                              </button>
                            </td>
                          );
                        }

                        if ((module.id === 'github_result' || module.id === 'github_monitor_result') && column === 'path') {
                          return (
                            <td
                              key={column}
                              className="px-4 py-3 align-middle text-sm text-center whitespace-pre-wrap break-all leading-relaxed min-w-[260px] max-w-[640px]"
                            >
                              {formatModuleCellValue(module.id, column, row)}
                            </td>
                          );
                        }

                        return (
                          <td key={column} className={baseClassName}>
                            {formatModuleCellValue(module.id, column, row)}
                          </td>
                        );
                      })}
                      {hasRowOperate ? (
                        <td className={`px-4 py-3 align-middle whitespace-nowrap text-center ${rowOperateColumnWidthClass}`}>
                          {showTaskRowOperate ? (
                            (() => {
                              const taskRowDone = isTaskTerminalStatus(row?.status);
                              const taskRowPendingAction = String(taskRowPendingActionMap[id] || '');
                              const taskRowPending = Boolean(taskRowPendingAction);
                              return (
                                <div className={rowOperateGroupClass}>
                                  <button
                                    onClick={() => void syncTaskRow(id, row)}
                                    disabled={taskRowPending || !taskRowDone}
                                    className={rowOperateButtonDisabledClass}
                                  >
                                    {taskRowPendingAction === 'sync' ? '同步中...' : '同步'}
                                  </button>
                                  <div className="relative" data-task-report-export-menu="true">
                                    <button
                                      type="button"
                                      onClick={() => toggleTaskReportExportMenu(`row:${id}`)}
                                      disabled={taskRowPending || taskReportExportBusy}
                                      className={`${rowOperateButtonDisabledClass} flex items-center gap-1`}
                                    >
                                      {taskRowPendingAction === 'export' || taskReportExportBusy ? '导出中...' : '导出'}
                                      <ChevronDown className={`w-4 h-4 transition ${taskReportExportMenu === `row:${id}` ? 'rotate-180' : ''}`} />
                                    </button>
                                    {taskReportExportMenu === `row:${id}` && !taskRowPending && !taskReportExportBusy ? (
                                      <div className="absolute right-0 top-full z-20 mt-2 min-w-[140px] overflow-hidden rounded-xl border border-base-300 bg-base-200 shadow-2xl">
                                        {TASK_REPORT_EXPORT_OPTIONS.map((option) => (
                                          <button
                                            key={option.value}
                                            type="button"
                                            onClick={() => void exportTaskRow(id, option.value)}
                                            className={taskReportMenuItemClass}
                                          >
                                            {option.label}
                                          </button>
                                        ))}
                                      </div>
                                    ) : null}
                                  </div>
                                  <button
                                    onClick={() => void stopTaskRow(id)}
                                    disabled={taskRowPending || taskRowDone}
                                    className={rowOperateButtonDisabledClass}
                                  >
                                    {taskRowPendingAction === 'stop' ? '停止中...' : '停止'}
                                  </button>
                                  <button
                                    onClick={() => void deleteTaskRow(id)}
                                    disabled={taskRowPending}
                                    className={rowOperateButtonDisabledClass}
                                  >
                                    {taskRowPendingAction === 'delete' ? '删除中...' : '删除'}
                                  </button>
                                  <button
                                    onClick={() => void restartTaskRow(id)}
                                    disabled={taskRowPending || !taskRowDone}
                                    className={rowOperateButtonDisabledClass}
                                  >
                                    {taskRowPendingAction === 'restart' ? '重启中...' : '重启'}
                                  </button>
                                </div>
                              );
                            })()
                          ) : null}
                          {showAssetScopeRowOperate ? (
                            <div className={rowOperateGroupClass}>
                              {assetScopeUpdateAction ? (
                                <button
                                  onClick={() => openAssetScopeRowActionDialog(assetScopeUpdateAction, id, row)}
                                  className={rowOperateButtonClass}
                                >
                                  编辑资产
                                </button>
                              ) : null}
                              {assetScopeAddScopeAction ? (
                                <button
                                  onClick={() => openAssetScopeRowActionDialog(assetScopeAddScopeAction, id, row, { scope: '' })}
                                  className={rowOperateButtonClass}
                                >
                                  添加资产分组范围
                                </button>
                              ) : null}
                              {assetScopeAddSchedulerAction ? (
                                <button
                                  onClick={() =>
                                    openAssetScopeRowActionDialog(assetScopeAddSchedulerAction, id, row, {
                                      domain: String(row?.scope || '').replace(/,/g, '\n'),
                                      name: `监控-${String(row?.name || '').trim() || id.slice(-6)}`,
                                    })
                                  }
                                  className={rowOperateButtonClass}
                                >
                                  添加监控任务
                                </button>
                              ) : null}
                              {assetScopeAddSiteMonitorAction ? (
                                <button
                                  onClick={() =>
                                    openAssetScopeRowActionDialog(assetScopeAddSiteMonitorAction, id, row, {
                                      name: `站点监控-${String(row?.name || '').trim() || id.slice(-6)}`,
                                    })
                                  }
                                  className={rowOperateButtonClass}
                                >
                                  添加站点监控任务
                                </button>
                              ) : null}
                              {assetScopeAddWihMonitorAction ? (
                                <button
                                  onClick={() =>
                                    openAssetScopeRowActionDialog(assetScopeAddWihMonitorAction, id, row, {
                                      name: `WIH监控-${String(row?.name || '').trim() || id.slice(-6)}`,
                                    })
                                  }
                                  className={rowOperateButtonClass}
                                >
                                  添加WIH监控任务
                                </button>
                              ) : null}
                            </div>
                          ) : null}
                          {showPolicyRowOperate ? (
                            <div className={rowOperateGroupClass}>
                              <button
                                onClick={() => openPolicyTaskDialog(row)}
                                className={rowOperateButtonClass}
                              >
                                任务下发
                              </button>
                              {policyEditAction ? (
                                <button
                                  onClick={() =>
                                    openActionDialog(policyEditAction, {
                                      policy_id: id,
                                      policy_data: {
                                        name: row?.name || '',
                                        desc: row?.desc || '',
                                        policy: row?.policy || {},
                                      },
                                    })
                                  }
                                  className={rowOperateButtonClass}
                                >
                                  编辑
                                </button>
                              ) : null}
                              <button
                                onClick={() => void deletePolicyRow(id)}
                                className={rowOperateButtonClass}
                              >
                                删除
                              </button>
                            </div>
                          ) : null}
                          {showTaskScheduleRowOperate ? (
                            <div className={rowOperateGroupClass}>
                              {String(row?.status || '').toLowerCase() === 'stop' ? (
                                <button
                                  onClick={() => void recoverTaskScheduleRow(id)}
                                  className={rowOperateButtonClass}
                                >
                                  恢复
                                </button>
                              ) : (
                                <button
                                  onClick={() => void stopTaskScheduleRow(id)}
                                  className={rowOperateButtonClass}
                                >
                                  停止
                                </button>
                              )}
                              <button
                                onClick={() => void deleteTaskScheduleRow(id)}
                                className={rowOperateButtonClass}
                              >
                                删除
                              </button>
                            </div>
                          ) : null}
                          {showGithubTaskRowOperate ? (
                            <div className={rowOperateGroupClass}>
                              <button
                                onClick={() => void stopGithubTaskRow(id)}
                                disabled={['done', 'stop', 'error'].includes(String(row?.status || '').toLowerCase())}
                                className={rowOperateButtonDisabledClass}
                              >
                                停止
                              </button>
                              <button
                                onClick={() => void deleteGithubTaskRow(id)}
                                className={rowOperateButtonClass}
                              >
                                删除
                              </button>
                            </div>
                          ) : null}
                          {showGithubSchedulerRowOperate ? (
                            <div className={rowOperateGroupClass}>
                              {githubSchedulerUpdateAction ? (
                                <button
                                  onClick={() =>
                                    openActionDialog(githubSchedulerUpdateAction, {
                                      _id: id,
                                      name: row?.name || '',
                                      keyword: row?.keyword || '',
                                      cron: row?.cron || '',
                                      dingding_notify: row?.dingding_notify !== false,
                                      kb_notify_enable: Boolean(row?.kb_notify_enable),
                                    })
                                  }
                                  className={rowOperateButtonClass}
                                >
                                  修改
                                </button>
                              ) : null}
                              {String(row?.status || '').toLowerCase() === 'stop' ? (
                                <button
                                  onClick={() => void recoverGithubSchedulerRow(id)}
                                  className={rowOperateButtonClass}
                                >
                                  恢复
                                </button>
                              ) : (
                                <button
                                  onClick={() => void stopGithubSchedulerRow(id)}
                                  className={rowOperateButtonClass}
                                >
                                  停止
                                </button>
                              )}
                              <button
                                onClick={() => void deleteGithubSchedulerRow(id)}
                                className={rowOperateButtonClass}
                              >
                                删除
                              </button>
                            </div>
                          ) : null}
                        </td>
                      ) : null}
                    </tr>
                  );
                })}
                {displayRows.length === 0 && !loading ? (
                  <tr>
                    <td
                      colSpan={Math.max(columns.length + 1 + (showIndexColumn ? 1 : 0) + (hasRowOperate ? 1 : 0), 2)}
                      className="px-4 py-10 text-center text-content-muted"
                    >
                      {module.id === 'fileleak'
                        ? '暂无数据。请确认任务已开启目录扫描，且目标未被 DNS 策略过滤。'
                        : '暂无数据'}
                    </td>
                  </tr>
                ) : null}
              </tbody>
            </table>
          </div>

          <div className="px-4 py-3 border-t border-base-300 bg-base-100/30 flex flex-col md:flex-row md:items-center md:justify-between gap-3">
            <div className="text-xs text-content-muted font-semibold">
              共 {total} 条，当前第 {page}/{totalPages} 页
            </div>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => {
                  const nextPage = Math.max(1, page - 1);
                  if (nextPage === page) return;
                  setPage(nextPage);
                  void loadRows({ page: nextPage });
                }}
                disabled={page <= 1}
                className="px-3.5 py-2 rounded-xl border border-base-300 text-sm disabled:opacity-40"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
              <div className="relative">
                <select
                  value={String(page)}
                  onChange={(event) => {
                    const nextPage = Number(event.target.value || 1);
                    if (!Number.isFinite(nextPage)) return;
                    const normalized = Math.max(1, Math.min(totalPages, Math.floor(nextPage)));
                    setPage(normalized);
                    void loadRows({ page: normalized });
                  }}
                  className={`${UNIFIED_SELECT_CLASS} w-auto min-w-[118px] py-2`}
                  title={`当前第 ${page} 页，共 ${totalPages} 页`}
                >
                  {pageOptions.map((option) => (
                    <option key={option} value={option}>
                      第 {option} 页
                    </option>
                  ))}
                </select>
                <ChevronDown className="w-4 h-4 text-content-muted pointer-events-none absolute right-3 top-1/2 -translate-y-1/2" />
              </div>
              <div className="relative">
                <select
                  value={size}
                  onChange={(event) => {
                    const nextSize = Number(event.target.value);
                    if (!Number.isFinite(nextSize) || nextSize <= 0) return;
                    // 切换每页条数前记录滚动锚点：若当前在底部，刷新后继续贴底。
                    rememberBottomAnchorBeforeSizeChange();
                    setSize(nextSize);
                    setPage(1);
                    void loadRows({ page: 1, size: nextSize });
                  }}
                  className={`${UNIFIED_SELECT_CLASS} w-auto min-w-[108px] py-2`}
                >
                  {[10, 20, 50, 100, 200, 500].map((option) => (
                    <option key={option} value={option}>
                      {option} / 页
                    </option>
                  ))}
                </select>
                <ChevronDown className="w-4 h-4 text-content-muted pointer-events-none absolute right-3 top-1/2 -translate-y-1/2" />
              </div>
              <button
                type="button"
                onClick={() => {
                  const nextPage = Math.min(totalPages, page + 1);
                  if (nextPage === page) return;
                  setPage(nextPage);
                  void loadRows({ page: nextPage });
                }}
                disabled={page >= totalPages}
                className="px-3.5 py-2 rounded-xl border border-base-300 text-sm disabled:opacity-40"
              >
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>
      ) : (
        <div className="bg-base-200/35 border border-base-300 rounded-2xl p-10 text-center text-content-muted text-sm">
          该模块为操作中心，无列表数据。请使用上方动作按钮执行。
        </div>
      )}

      {dialogAction ? (
        <ActionDialog
          token={token}
          action={dialogAction}
          initialPayload={dialogPayload}
          onClose={() => setDialogAction(null)}
          onSubmit={async (payload, file) => {
            await runAction(dialogAction, payload, file);
          }}
        />
      ) : null}

      {taskReportExportFeedback ? (
        <Modal open onClose={() => {
            if (!taskReportExportBusy) {
              closeTaskReportExportFeedback();
            }
          }} boxClass="w-full max-w-lg!">
            <div className="px-6 py-4 border-b border-base-300 flex items-center justify-between gap-3">
              <div className="min-w-0">
                <h4 className="text-lg font-black">{taskReportExportFeedback.title}</h4>
                <p className="text-xs text-content-muted mt-1 break-all">
                  {taskReportExportFeedback.jobId
                    ? `导出任务 ID: ${taskReportExportFeedback.jobId}`
                    : '正在初始化导出任务'}
                </p>
              </div>
              <button
                onClick={closeTaskReportExportFeedback}
                disabled={taskReportExportBusy}
                className="p-2 rounded-lg hover:bg-base-100/70 transition disabled:opacity-40"
                title={taskReportExportBusy ? '导出进行中，暂不可关闭' : '关闭'}
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-6 space-y-4">
              <div
                className={`rounded-xl border px-4 py-3 ${
                  taskReportExportFeedback.phase === 'error'
                    ? 'border-red-500/30 bg-red-500/10 text-red-200'
                    : taskReportExportFeedback.phase === 'success'
                      ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-200'
                      : 'border-accent/30 bg-accent/10 text-base-content'
                }`}
              >
                <div className="flex items-start gap-3">
                  <div className="mt-0.5 shrink-0">
                    {taskReportExportFeedback.phase === 'success' ? (
                      <CheckCircle2 className="w-5 h-5 text-emerald-300" />
                    ) : taskReportExportFeedback.phase === 'error' ? (
                      <AlertTriangle className="w-5 h-5 text-red-300" />
                    ) : (
                      <RefreshCw className="w-5 h-5 text-accent animate-spin" />
                    )}
                  </div>
                  <div className="min-w-0">
                    <p className="text-sm font-black break-all">{taskReportExportFeedback.summary}</p>
                    <p className="text-xs mt-1 break-all opacity-90">{taskReportExportFeedback.detail}</p>
                  </div>
                </div>
              </div>

              <div className="space-y-2">
                <div className="flex items-center justify-between text-xs font-semibold text-content-muted">
                  <span>导出进度</span>
                  <span>{taskReportExportFeedback.progress}%</span>
                </div>
                <div className="h-2.5 rounded-full border border-base-300 bg-base-100 overflow-hidden">
                  <div
                    className={`h-full rounded-full transition-all duration-500 ${
                      taskReportExportFeedback.phase === 'error'
                        ? 'bg-error'
                        : taskReportExportFeedback.phase === 'success'
                          ? 'bg-emerald-400'
                          : 'bg-brand-accent'
                    }`}
                    style={{ width: `${Math.max(0, Math.min(100, taskReportExportFeedback.progress))}%` }}
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3 text-xs">
                <div className="rounded-xl border border-base-300 bg-base-100/40 px-3 py-2">
                  <div className="text-content-muted">任务数量</div>
                  <div className="mt-1 font-semibold text-sm">{taskReportExportFeedback.taskCount}</div>
                </div>
                <div className="rounded-xl border border-base-300 bg-base-100/40 px-3 py-2">
                  <div className="text-content-muted">导出格式</div>
                  <div className="mt-1 font-semibold text-sm break-all">{taskReportExportFeedback.formatLabel}</div>
                </div>
              </div>

              {taskReportExportFeedback.fileName ? (
                <div className="rounded-xl border border-base-300 bg-base-100/40 px-3 py-2">
                  <div className="text-xs text-content-muted">导出文件</div>
                  <div className="mt-1 text-sm font-semibold break-all">{taskReportExportFeedback.fileName}</div>
                </div>
              ) : null}

              {taskReportExportFeedback.error ? (
                <div className="text-sm text-red-300 bg-red-500/10 border border-red-500/30 rounded-xl px-3 py-2 whitespace-pre-wrap break-all">
                  {taskReportExportFeedback.error}
                </div>
              ) : null}

              <div className="flex items-center justify-between gap-3">
                <p className="text-xs text-content-muted">
                  {taskReportExportBusy ? '导出进行中，请稍候...' : '导出流程已结束'}
                </p>
                <button
                  onClick={closeTaskReportExportFeedback}
                  disabled={taskReportExportBusy}
                  className="px-5 py-2.5 rounded-xl border border-base-300 text-sm font-semibold hover:bg-base-100/70 transition disabled:opacity-40"
                >
                  {taskReportExportFeedback.phase === 'error' ? '关闭' : '知道了'}
                </button>
              </div>
            </div>
        </Modal>
      ) : null}

      {riskDialogOpen ? (
        <Modal open onClose={closeRiskDialog} boxClass="w-full max-w-xl!">
            <div className="px-6 py-4 border-b border-base-300 flex items-center justify-between">
              <div>
                <h4 className="text-lg font-black">添加风险巡航任务</h4>
                <p className="text-xs text-content-muted mt-1">
                  已匹配站点 {riskResultTotal} 条，结果集 ID: {riskResultSetId}
                </p>
              </div>
              <button
                onClick={closeRiskDialog}
                disabled={riskDialogSubmitting}
                className="p-2 rounded-lg hover:bg-base-100/70 transition disabled:opacity-40"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-6 space-y-4">
              <div className="space-y-1">
                <label className="text-xs font-bold text-content-muted">策略</label>
                <div className="relative">
                  <select
                    value={riskPolicyId}
                    onChange={(event) => {
                      const nextPolicyId = event.target.value;
                      setRiskPolicyId(nextPolicyId);
                      const selectedPolicy = riskPolicies.find((item) => item.policyId === nextPolicyId);
                      if (!selectedPolicy) return;
                      if (!riskTaskName.trim() || riskTaskName.startsWith('风险巡航任务-')) {
                        setRiskTaskName(`风险巡航任务-${selectedPolicy.policyName}`);
                      }
                    }}
                    className={UNIFIED_SELECT_CLASS}
                    disabled={riskDialogSubmitting}
                  >
                    {riskPolicies.map((option) => (
                      <option key={option.policyId} value={option.policyId}>
                        {option.policyName} (PoC: {option.pocCount})
                      </option>
                    ))}
                  </select>
                  <ChevronDown className="w-4 h-4 text-content-muted pointer-events-none absolute right-3 top-1/2 -translate-y-1/2" />
                </div>
              </div>

              <div className="space-y-1">
                <label className="text-xs font-bold text-content-muted">任务名称</label>
                <input
                  value={riskTaskName}
                  onChange={(event) => setRiskTaskName(event.target.value)}
                  disabled={riskDialogSubmitting}
                  className="w-full rounded-xl border border-base-300 bg-base-100 px-3 py-2 text-sm"
                  placeholder="风险巡航任务-策略名"
                />
              </div>

              {riskDialogError ? (
                <div className="text-sm text-red-300 bg-red-500/10 border border-red-500/30 rounded-xl px-3 py-2">
                  {riskDialogError}
                </div>
              ) : null}

              <div className="flex justify-end gap-3">
                <button
                  onClick={closeRiskDialog}
                  disabled={riskDialogSubmitting}
                  className="px-5 py-2.5 rounded-xl border border-base-300 text-sm font-semibold hover:bg-base-100/70 transition disabled:opacity-40"
                >
                  取消
                </button>
                <button
                  onClick={() => void submitAssetSiteRiskTask()}
                  disabled={riskDialogSubmitting}
                  className="px-5 py-2.5 rounded-xl bg-brand-accent hover:opacity-90 transition text-sm font-black tracking-wider"
                >
                  {riskDialogSubmitting ? '下发中...' : '确认下发'}
                </button>
              </div>
            </div>
        </Modal>
      ) : null}

      {policyTaskDialogOpen ? (
        <Modal open onClose={closePolicyTaskDialog} boxClass="w-full max-w-2xl!">
            <div className="px-6 py-4 border-b border-base-300 flex items-center justify-between">
              <div>
                <h4 className="text-lg font-black">任务下发</h4>
                <p className="text-xs text-content-muted mt-1">策略：{policyTaskPolicyName || '-'}</p>
              </div>
              <button
                onClick={closePolicyTaskDialog}
                disabled={policyTaskSubmitting}
                className="p-2 rounded-lg hover:bg-base-100/70 transition disabled:opacity-40"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-6 space-y-4">
              <div className="space-y-1">
                <label className="text-xs font-bold text-content-muted">任务类型</label>
                <div className="relative">
                  <select
                    value={policyTaskTag}
                    onChange={(event) => {
                      const nextTag = event.target.value === 'risk_cruising' ? 'risk_cruising' : 'task';
                      setPolicyTaskTag(nextTag);
                      if (!policyTaskName.trim() || policyTaskName.includes('任务-')) {
                        setPolicyTaskName(
                          nextTag === 'risk_cruising'
                            ? `风险巡航任务-${policyTaskPolicyName || '策略'}`
                            : `资产侦查任务-${policyTaskPolicyName || '策略'}`
                        );
                      }
                    }}
                    className={UNIFIED_SELECT_CLASS}
                    disabled={policyTaskSubmitting}
                  >
                    <option value="task">资产侦查任务</option>
                    <option value="risk_cruising">风险巡航任务</option>
                  </select>
                  <ChevronDown className="w-4 h-4 text-content-muted pointer-events-none absolute right-3 top-1/2 -translate-y-1/2" />
                </div>
              </div>

              <div className="space-y-1">
                <label className="text-xs font-bold text-content-muted">任务名称</label>
                <input
                  value={policyTaskName}
                  onChange={(event) => setPolicyTaskName(event.target.value)}
                  disabled={policyTaskSubmitting}
                  className="w-full rounded-xl border border-base-300 bg-base-100 px-3 py-2 text-sm"
                  placeholder="请输入任务名称"
                />
              </div>

              <div className="space-y-1">
                <label className="text-xs font-bold text-content-muted">目标</label>
                <textarea
                  value={policyTaskTarget}
                  onChange={(event) => setPolicyTaskTarget(event.target.value)}
                  disabled={policyTaskSubmitting}
                  className="w-full min-h-[180px] rounded-xl border border-base-300 bg-base-100 px-3 py-2 text-sm font-mono"
                  placeholder={
                    policyTaskTag === 'risk_cruising'
                      ? '请输入确定的目标，不会进行端口扫描,如: http://10.0.1.1:8081/ 10.0.1.1:2222'
                      : '请输入目标，支持IP、IP段、域名'
                  }
                />
                <p className="text-xs text-content-muted">
                  {policyTaskTag === 'risk_cruising'
                    ? '请输入确定的目标，不会进行端口扫描,如: http://10.0.1.1:8081/ 10.0.1.1:2222'
                    : '请输入目标，支持IP、IP段、域名。支持一行一个。'}
                </p>
              </div>

              {policyTaskError ? (
                <div className="text-sm text-red-300 bg-red-500/10 border border-red-500/30 rounded-xl px-3 py-2">
                  {policyTaskError}
                </div>
              ) : null}

              <div className="flex justify-end gap-3">
                <button
                  onClick={closePolicyTaskDialog}
                  disabled={policyTaskSubmitting}
                  className="px-5 py-2.5 rounded-xl border border-base-300 text-sm font-semibold hover:bg-base-100/70 transition disabled:opacity-40"
                >
                  取消
                </button>
                <button
                  onClick={() => void submitPolicyTask()}
                  disabled={policyTaskSubmitting}
                  className="px-5 py-2.5 rounded-xl bg-brand-accent hover:opacity-90 transition text-sm font-black tracking-wider"
                >
                  {policyTaskSubmitting ? '下发中...' : '确认下发'}
                </button>
              </div>
            </div>
        </Modal>
      ) : null}

      {riskRecordDetail ? (() => {
        const detailRow = riskRecordDetail.row || {};
        const isNuclei = riskRecordDetail.moduleId === 'nuclei_result';
        const knownKeys = isNuclei
          ? ['scanner_type', 'rule_id', 'vuln_name', 'vuln_severity', 'severity', 'target', 'vuln_url', 'matched', 'extracted_results', 'save_date']
          : ['vul_name', 'plg_type', 'app_name', 'target', 'credential', 'save_date', 'source'];
        const usedKeys = new Set<string>([
          ...knownKeys,
          '_id', 'task_id', 'task_cid', 'time',
          'ai_analysis', 'ai_analysis_reason', 'ai_fill',
          'verify_data', 'request', 'headers',
        ]);
        const fields: Array<[string, string]> = [];
        knownKeys.forEach((key) => {
          const text = normalizeValueNoTruncate(detailRow[key]);
          if (text && text !== '-' && text !== '[]' && text !== '{}') {
            fields.push([humanizeField(key), text]);
          }
        });
        Object.keys(detailRow).forEach((key) => {
          if (usedKeys.has(key)) return;
          const value = detailRow[key];
          if (value === null || value === undefined || value === '') return;
          if (typeof value === 'object') return;
          const text = String(value);
          if (!text || text === '-') return;
          fields.push([humanizeField(key), text]);
        });
        const verifyRaw = normalizeValueNoTruncate(detailRow.verify_data);
        const verifyScanner = String(detailRow?.scanner_type || '').trim().toLowerCase();
        const verifyLabel = verifyScanner === 'afrog' ? 'afrog curl命令' : '验证报文';
        return (
          <Modal open onClose={closeRiskRecordDetail} boxClass="w-full max-w-5xl!">
              <div className="px-6 py-4 border-b border-base-300 flex items-start justify-between gap-3">
                <div className="space-y-1 min-w-0">
                  <h4 className="text-lg font-black">{isNuclei ? 'PoC风险详情' : '风险详情'}</h4>
                  <p className="text-sm font-semibold break-all">{riskRecordDetail.rowTitle || '-'}</p>
                </div>
                <button
                  type="button"
                  onClick={closeRiskRecordDetail}
                  className="p-2 rounded-lg hover:bg-base-100/70 transition"
                  title="关闭"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>
              <div className="p-6 space-y-4 max-h-[72vh] overflow-y-auto overflow-x-hidden custom-scrollbar">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  {fields.map(([label, text]) => (
                    <div key={label} className="rounded-xl border border-base-300 bg-base-100/40 px-4 py-3">
                      <div className="text-xs font-semibold text-content-muted mb-1">{label}</div>
                      <div className="text-sm break-all whitespace-pre-wrap">{text}</div>
                    </div>
                  ))}
                </div>
                {verifyRaw && verifyRaw !== '-' ? (
                  <div className="rounded-xl border border-base-300 bg-base-100/40 px-4 py-3">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-xs font-semibold text-content-muted">{verifyLabel}</span>
                      <button
                        type="button"
                        onClick={() => void copyTextToClipboard(verifyRaw, verifyLabel)}
                        className="text-xs font-semibold text-accent hover:underline"
                      >
                        复制
                      </button>
                    </div>
                    <pre className="whitespace-pre-wrap break-all leading-relaxed font-mono text-sm max-h-[40vh] overflow-auto">{verifyRaw}</pre>
                  </div>
                ) : null}
              </div>
          </Modal>
        );
      })() : null}

      {wihEndpointDetail ? (() => {
        const detailRow = wihEndpointDetail.row || {};
        const methodText = String(detailRow?.method || '').trim().toUpperCase() || '-';
        const detailUrl = buildWihEndpointDetailUrl(detailRow);
        const requestPacket = buildWihEndpointDisplayRequestPacket(detailRow);
        const responsePacket = buildWihEndpointResponsePacket(detailRow);
        const aiFillParams = Array.isArray(detailRow?.ai_fill_params) ? detailRow.ai_fill_params : [];
        const aiFillStatusText = formatWihEndpointAiFillStatus(detailRow);
        const urlLabel = methodText === 'GET' ? '带参数URL' : '请求URL';
        return (
          <Modal open onClose={closeWihEndpointDetail} boxClass="w-full max-w-5xl!">
              <div className="px-6 py-4 border-b border-base-300 flex items-start justify-between gap-3">
                <div className="space-y-1 min-w-0">
                  <h4 className="text-lg font-black">WIH接口详情</h4>
                  <p className="text-xs text-content-muted">仅展示 WIH 扫描阶段已落库的接口与请求模板。</p>
                  <p className="text-sm font-semibold break-all">{wihEndpointDetail.rowTitle || '-'}</p>
                </div>
                <button
                  type="button"
                  onClick={closeWihEndpointDetail}
                  className="p-2 rounded-lg hover:bg-base-100/70 transition"
                  title="关闭"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              <div className="p-6 space-y-4 max-h-[72vh] overflow-y-auto overflow-x-hidden custom-scrollbar">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="inline-flex items-center rounded-full border border-base-300 bg-base-100/60 px-2.5 py-1 text-xs font-semibold">
                    方法：{methodText}
                  </span>
                  <span className="inline-flex items-center rounded-full border border-base-300 bg-base-100/60 px-2.5 py-1 text-xs font-semibold">
                    状态码：{formatWihEndpointMetric(detailRow, 'status_code')}
                  </span>
                  <span className="inline-flex items-center rounded-full border border-base-300 bg-base-100/60 px-2.5 py-1 text-xs font-semibold">
                    响应大小：{formatWihEndpointMetric(detailRow, 'response_size')}
                  </span>
                  <span className="inline-flex items-center rounded-full border border-base-300 bg-base-100/60 px-2.5 py-1 text-xs font-semibold">
                    AI填充：{aiFillStatusText}
                  </span>
                </div>

                <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
                  <div className="rounded-xl border border-base-300 bg-base-100/35 p-4 space-y-2">
                    <div className="text-xs font-black tracking-wide text-base-content">目标</div>
                    <div className="text-sm break-all leading-relaxed">{renderTextWithHyperlink(normalizeValueNoTruncate(detailRow?.target))}</div>
                  </div>
                  <div className="rounded-xl border border-base-300 bg-base-100/35 p-4 space-y-2">
                    <div className="text-xs font-black tracking-wide text-base-content">页面URL</div>
                    <div className="text-sm break-all leading-relaxed">{renderTextWithHyperlink(normalizeValueNoTruncate(detailRow?.page_url))}</div>
                  </div>
                </div>

                <div className="rounded-xl border border-base-300 bg-base-100/35 p-4 space-y-2">
                  <div className="flex items-center justify-between gap-3">
                    <div className="text-xs font-black tracking-wide text-base-content">{urlLabel}</div>
                    {detailUrl && detailUrl !== '-' ? (
                      <button
                        type="button"
                        onClick={() => void copyTextToClipboard(detailUrl, urlLabel)}
                        className="text-xs font-semibold text-accent hover:underline"
                      >
                        复制
                      </button>
                    ) : null}
                  </div>
                  <div className="text-sm break-all leading-relaxed">{renderTextWithHyperlink(detailUrl)}</div>
                </div>

                <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
                  <div className="rounded-xl border border-base-300 bg-base-100/35 p-4 space-y-3">
                    <div className="text-xs font-black tracking-wide text-base-content">AI填充结果</div>
                    <div className="text-xs text-content-muted">
                      状态：{aiFillStatusText}
                      {normalizeValueNoTruncate(detailRow?.ai_fill_source) !== '-' ? ` / 来源：${normalizeValueNoTruncate(detailRow?.ai_fill_source)}` : ''}
                      {detailRow?.ai_fill_hint_only ? ' / 高风险，仅提示' : ''}
                    </div>
                    {normalizeValueNoTruncate(detailRow?.ai_fill_note) !== '-' ? (
                      <div className="text-sm whitespace-pre-wrap break-all leading-relaxed">
                        {normalizeValueNoTruncate(detailRow?.ai_fill_note)}
                      </div>
                    ) : null}
                    {aiFillParams.length > 0 ? (
                      <div className="space-y-2">
                        <div className="text-xs font-semibold text-content-muted">参数建议</div>
                        <div className="flex flex-wrap gap-2">
                          {aiFillParams.map((item: any, index: number) => {
                            const nameText = String(item?.name || '').trim() || `param_${index + 1}`;
                            const locationText = String(item?.location || '').trim() || '-';
                            const typeText = String(item?.type || '').trim() || '-';
                            const valueText = normalizeValueNoTruncate(item?.value);
                            return (
                              <span
                                key={`${nameText}-${index}`}
                                className="inline-flex items-center rounded-full border border-base-300 bg-base-100/70 px-2.5 py-1 text-xs font-semibold break-all"
                              >
                                {nameText} [{locationText}/{typeText}] = {valueText}
                              </span>
                            );
                          })}
                        </div>
                      </div>
                    ) : (
                      <div className="text-sm text-content-muted">当前没有生成可用的 AI 填充参数。</div>
                    )}
                    {normalizeValueNoTruncate(detailRow?.ai_fill_response_summary) !== '-' ? (
                      <div className="space-y-2">
                        <div className="text-xs font-semibold text-content-muted">测试响应摘要</div>
                        <div className="text-sm whitespace-pre-wrap break-all leading-relaxed">
                          {normalizeValueNoTruncate(detailRow?.ai_fill_response_summary)}
                        </div>
                      </div>
                    ) : null}
                  </div>
                  <div className="rounded-xl border border-base-300 bg-base-100/35 p-4 space-y-2">
                    <div className="text-xs font-black tracking-wide text-base-content">验证信息</div>
                    <div className="text-xs text-content-muted">
                      {normalizeValueNoTruncate(detailRow?.verification_note)}
                    </div>
                    {normalizeValueNoTruncate(detailRow?.verification_method) !== '-' ? (
                      <div className="text-xs text-content-muted">
                        探测方法：{normalizeValueNoTruncate(detailRow?.verification_method)}
                      </div>
                    ) : null}
                  </div>
                </div>

                <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
                  <div className="rounded-xl border border-base-300 bg-base-100/35 p-4 space-y-2">
                    <div className="flex items-center justify-between gap-3">
                      <div className="text-xs font-black tracking-wide text-base-content">请求报文</div>
                      {requestPacket && requestPacket !== '-' ? (
                        <button
                          type="button"
                          onClick={() => void copyTextToClipboard(requestPacket, '请求报文')}
                          className="text-xs font-semibold text-accent hover:underline"
                        >
                          复制
                        </button>
                      ) : null}
                    </div>
                    <pre className="max-h-[420px] overflow-auto rounded-xl border border-base-300 bg-base-100/70 p-4 text-xs leading-relaxed whitespace-pre-wrap break-all font-mono text-left">
                      {requestPacket || '-'}
                    </pre>
                  </div>
                  <div className="rounded-xl border border-base-300 bg-base-100/35 p-4 space-y-2">
                    <div className="flex items-center justify-between gap-3">
                      <div className="text-xs font-black tracking-wide text-base-content">回复报文</div>
                      {responsePacket && responsePacket !== '-' ? (
                        <button
                          type="button"
                          onClick={() => void copyTextToClipboard(responsePacket, '回复报文')}
                          className="text-xs font-semibold text-accent hover:underline"
                        >
                          复制
                        </button>
                      ) : null}
                    </div>
                    <pre className="max-h-[420px] overflow-auto rounded-xl border border-base-300 bg-base-100/70 p-4 text-xs leading-relaxed whitespace-pre-wrap break-all font-mono text-left">
                      {responsePacket || '-'}
                    </pre>
                  </div>
                </div>
              </div>

              <div className="px-6 py-4 border-t border-base-300 bg-base-100/30 flex justify-end">
                <button
                  type="button"
                  onClick={closeWihEndpointDetail}
                  className="px-5 py-2.5 rounded-xl border border-base-300 text-sm font-semibold hover:bg-base-100/70 transition"
                >
                  关闭
                </button>
              </div>
          </Modal>
        );
      })() : null}

      {aiDenoiseDetail ? (
        <Modal open onClose={closeAiDenoiseDetail} boxClass="w-full max-w-4xl!">
            <div className="px-6 py-4 border-b border-base-300 flex items-start justify-between gap-3">
              <div className="space-y-1 min-w-0">
                <h4 className="text-lg font-black">AI分析详情</h4>
                <p className="text-xs text-content-muted">
                  模块：{aiDenoiseModuleId ? AI_DENOISE_MODULE_LABEL_MAP[aiDenoiseModuleId] : '-'}
                </p>
                <p className="text-sm font-semibold break-all">目标：{aiDenoiseDetail.rowTitle || '-'}</p>
              </div>
              <button
                type="button"
                onClick={closeAiDenoiseDetail}
                className="p-2 rounded-lg hover:bg-base-100/70 transition"
                title="关闭"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-6 space-y-4 max-h-[72vh] overflow-y-auto overflow-x-hidden custom-scrollbar">
              <div className="flex flex-wrap items-center gap-2">
                <span className={getAiDenoiseCellClass(aiDenoiseDetail.analysis.result_level, false)}>
                  {aiDenoiseDetail.analysis.display_text || '-'}
                </span>
                <span className="inline-flex items-center rounded-full border border-base-300 bg-base-100/60 px-2.5 py-1 text-xs font-semibold">
                  {aiDenoiseModuleId === 'wih_endpoint' ? '价值等级' : '风险等级'}：{aiDenoiseDetail.analysis.risk_level || '-'}
                </span>
                <span className="inline-flex items-center rounded-full border border-base-300 bg-base-100/60 px-2.5 py-1 text-xs font-semibold">
                  {aiDenoiseModuleId === 'wih_endpoint' ? '价值标签' : '可信度'}：{aiDenoiseDetail.analysis.trust || '-'}
                </span>
                <span className="inline-flex items-center rounded-full border border-base-300 bg-base-100/60 px-2.5 py-1 text-xs font-semibold">
                  来源：{
                    aiDenoiseDetail.analysis.source === 'ai'
                      ? 'AI模型'
                      : aiDenoiseDetail.analysis.source === 'rule'
                        ? '规则'
                        : '已关闭'
                  }
                </span>
                {aiDenoiseDetail.analysis.analyzed_at ? (
                  <span className="inline-flex items-center rounded-full border border-base-300 bg-base-100/60 px-2.5 py-1 text-xs font-semibold">
                    分析时间：{aiDenoiseDetail.analysis.analyzed_at}
                  </span>
                ) : null}
                {aiDenoiseModuleId === 'cert' ? (
                  <span className="inline-flex items-center rounded-full border border-base-300 bg-base-100/60 px-2.5 py-1 text-xs font-semibold">
                    到期：{aiDenoiseDetail.analysis.cert_expire_at || '-'}
                    {Number.isFinite(Number(aiDenoiseDetail.analysis.cert_expire_days))
                      ? `（${Number(aiDenoiseDetail.analysis.cert_expire_days) < 0 ? '已过期' : `剩余${Number(aiDenoiseDetail.analysis.cert_expire_days)}天`}）`
                      : ''}
                  </span>
                ) : null}
              </div>

              <div className="text-xs text-content-muted">
                说明：此处仅展示扫描阶段已落库的分析结果，点击详情不会再次触发 AI 调用。
              </div>
              {aiDenoiseDetail.analysis.note ? (
                <div className="text-xs text-content-muted">
                  当前记录说明：{aiDenoiseDetail.analysis.note}
                </div>
              ) : null}
              {aiDenoiseDetail.analysis.prompt_name || aiDenoiseDetail.analysis.prompt_id ? (
                <div className="text-xs text-content-muted">
                  使用SOP：{aiDenoiseDetail.analysis.prompt_name || aiDenoiseDetail.analysis.prompt_id}
                </div>
              ) : null}

              <div className="rounded-xl border border-base-300 bg-base-100/35 p-4 space-y-2">
                <div className="text-xs font-black tracking-wide text-base-content">分析摘要</div>
                <div className="text-sm whitespace-pre-wrap break-all leading-relaxed">
                  {aiDenoiseDetail.analysis.summary || '-'}
                </div>
              </div>

              {aiDenoiseModuleId === 'site' ? (
                <div className="rounded-xl border border-base-300 bg-base-100/35 p-4 space-y-2">
                  <div className="text-xs font-black tracking-wide text-base-content">AI分析后的指纹结果</div>
                  {Array.isArray(aiDenoiseDetail.analysis.finger_result) && aiDenoiseDetail.analysis.finger_result.length > 0 ? (
                    <div className="flex flex-wrap gap-2">
                      {aiDenoiseDetail.analysis.finger_result.map((item, index) => (
                        <span
                          key={`${index}-${item}`}
                          className="inline-flex items-center rounded-full border border-base-300 bg-base-100/70 px-2.5 py-1 text-xs font-semibold"
                        >
                          {item}
                        </span>
                      ))}
                    </div>
                  ) : (
                    <div className="text-sm text-content-muted">暂无 AI 指纹修正结果</div>
                  )}
                </div>
              ) : null}

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="rounded-xl border border-base-300 bg-base-100/35 p-4 space-y-2">
                  <div className="text-xs font-black tracking-wide text-base-content">分析依据</div>
                  {aiDenoiseDetail.analysis.evidence.length > 0 ? (
                    <div className="space-y-1.5">
                      {aiDenoiseDetail.analysis.evidence.map((item, index) => (
                        <div key={`${index}-${item}`} className="text-sm leading-relaxed break-all">
                          {index + 1}. {item}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="text-sm text-content-muted">暂无依据</div>
                  )}
                </div>
                <div className="rounded-xl border border-base-300 bg-base-100/35 p-4 space-y-2">
                  <div className="text-xs font-black tracking-wide text-base-content">处置建议</div>
                  {aiDenoiseDetail.analysis.suggestions.length > 0 ? (
                    <div className="space-y-1.5">
                      {aiDenoiseDetail.analysis.suggestions.map((item, index) => (
                        <div key={`${index}-${item}`} className="text-sm leading-relaxed break-all">
                          {index + 1}. {item}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="text-sm text-content-muted">暂无建议</div>
                  )}
                </div>
              </div>

              <div className="rounded-xl border border-base-300 bg-base-100/35 p-4 space-y-2">
                <div className="text-xs font-black tracking-wide text-base-content">AI交互记录</div>
                {Array.isArray(aiDenoiseDetail.analysis.dialogue_records) && aiDenoiseDetail.analysis.dialogue_records.length > 0 ? (
                  <div className="space-y-2 max-h-[300px] overflow-auto">
                    {aiDenoiseDetail.analysis.dialogue_records.map((item, index) => {
                      const roleLabel =
                        item.role === 'system'
                          ? '系统'
                          : item.role === 'user'
                            ? '用户输入'
                            : item.role === 'tool'
                              ? '工具'
                              : 'AI回复';
                      const roleClass =
                        item.role === 'system'
                          ? 'border-base-300 bg-base-100/60 text-content-muted'
                          : item.role === 'user'
                            ? 'border-accent/35 bg-accent/10 text-base-content'
                            : item.role === 'tool'
                              ? 'border-warning/35 bg-warning/10 text-base-content'
                              : 'border-emerald-400/35 bg-emerald-400/10 text-base-content';
                      return (
                        <div key={`${index}-${item.role}`} className={`rounded-xl border px-3 py-2 ${roleClass}`}>
                          <div className="text-[11px] font-black tracking-wide mb-1">{roleLabel}</div>
                          <div className="text-sm whitespace-pre-wrap break-all leading-relaxed">
                            {formatAiDialogueContent(item.role, item.content)}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                ) : (
                  <div className="text-sm text-content-muted">暂无对话记录</div>
                )}
              </div>
            </div>

            <div className="px-6 py-4 border-t border-base-300 bg-base-100/30 flex justify-end">
              <button
                type="button"
                onClick={closeAiDenoiseDetail}
                className="px-5 py-2.5 rounded-xl border border-base-300 text-sm font-semibold hover:bg-base-100/70 transition"
              >
                关闭
              </button>
            </div>
        </Modal>
      ) : null}


      {taskErrorDialog ? (
        <Modal open onClose={() => setTaskErrorDialog(null)} boxClass="w-full max-w-5xl!">
            <div className="px-6 py-4 border-b border-base-300 flex items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <AlertTriangle className="w-5 h-5 text-error" />
                <h4 className="text-lg font-black">任务异常详情</h4>
              </div>
              <button
                onClick={() => setTaskErrorDialog(null)}
                className="p-2 rounded-lg hover:bg-base-100/70 transition"
                title="关闭"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="px-6 py-4 border-b border-base-300 bg-base-100/30 text-sm space-y-1">
              <div><span className="text-content-muted">任务名：</span>{taskErrorDialog.taskName}</div>
              <div><span className="text-content-muted">目标：</span><span className="font-mono break-all">{taskErrorDialog.target}</span></div>
              <div><span className="text-content-muted">Task_ID：</span><span className="font-mono">{taskErrorDialog.taskId || '-'}</span></div>
            </div>

            <div className="p-6 max-h-[72vh] overflow-y-auto overflow-x-hidden custom-scrollbar space-y-4">
              {taskErrorDialog.logs.length > 0 ? taskErrorDialog.logs.map((log, index) => (
                <div key={`${log.time}-${log.stage}-${index}`} className="rounded-xl border border-base-300 bg-base-100/40 p-4 space-y-3">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">
                    <div><span className="text-content-muted">时间：</span><span className="font-mono">{log.time || '-'}</span></div>
                    <div><span className="text-content-muted">阶段：</span><span className="font-mono">{log.stage || '-'}</span></div>
                  </div>
                  <div className="text-sm">
                    <span className="text-content-muted">异常说明：</span>
                    <div className="mt-1 whitespace-pre-wrap break-all leading-relaxed">{log.message || '-'}</div>
                  </div>
                  {log.traceback ? (
                    <div className="text-sm">
                      <span className="text-content-muted">日志信息：</span>
                      <pre className="mt-1 whitespace-pre-wrap break-all leading-relaxed font-mono text-xs bg-base-100/70 border border-base-300 rounded-lg p-3 overflow-auto">{log.traceback}</pre>
                    </div>
                  ) : null}
                </div>
              )) : (
                <div className="text-sm text-content-muted">
                  当前任务没有记录到详细异常日志（可能是历史任务或异常详情落库前的任务）。
                </div>
              )}
            </div>
        </Modal>
      ) : null}

      {deleteConfirmDialog ? (
        <Modal open onClose={() => closeDeleteConfirmDialog(false)} boxClass="w-full max-w-lg!">
            <div className="px-6 py-4 border-b border-base-300 flex items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <AlertTriangle className="w-5 h-5 text-amber-400" />
                <h4 className="text-lg font-black">{deleteConfirmDialog.title}</h4>
              </div>
              <button
                onClick={() => closeDeleteConfirmDialog(false)}
                className="p-2 rounded-lg hover:bg-base-100/70 transition"
                title="关闭"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="px-6 py-5 space-y-5">
              <p className="text-sm text-content-muted whitespace-pre-wrap break-all leading-relaxed">
                {deleteConfirmDialog.message}
              </p>
              <div className="flex justify-end gap-3">
                <button
                  onClick={() => closeDeleteConfirmDialog(false)}
                  className="px-5 py-2.5 rounded-xl border border-base-300 text-sm font-semibold hover:bg-base-100/70 transition"
                >
                  取消
                </button>
                <button
                  onClick={() => closeDeleteConfirmDialog(true)}
                  className="px-5 py-2.5 rounded-xl bg-error text-white text-sm font-black hover:opacity-90 transition"
                >
                  {deleteConfirmDialog.confirmText}
                </button>
              </div>
            </div>
        </Modal>
      ) : null}

      {screenshotPreview ? (
        <Modal open onClose={() => setScreenshotPreview(null)} boxClass="w-full max-w-6xl!">
            <div className="px-5 py-3 border-b border-base-300 flex items-center justify-between gap-3">
              <div className="text-sm font-semibold truncate">截图预览: {screenshotPreview.title}</div>
              <button
                type="button"
                onClick={() => setScreenshotPreview(null)}
                className="p-2 rounded-lg hover:bg-base-100/70 transition"
                title="关闭预览"
              >
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="p-4 max-h-[72vh] overflow-y-auto overflow-x-hidden custom-scrollbar bg-base-100/40">
              <img
                src={screenshotPreview.url}
                alt={screenshotPreview.title}
                className="mx-auto max-w-full h-auto rounded-xl border border-base-300 bg-base-100"
              />
            </div>
        </Modal>
      ) : null}
    </div>
  );
}
