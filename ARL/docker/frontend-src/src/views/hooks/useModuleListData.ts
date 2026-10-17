import { useCallback, useEffect, useRef, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
  buildFilterSignature,
  normalizeListData,
  requestApi,
} from '../../api/client';
import { LIVE_STATUS_MODULE_IDS } from '../../config/modules';
import { normalizeTaskStatus } from '../../domain/task';
import type { JsonValue, LoadRowsOptions, ModuleConfig } from '../../domain/types';

type ListSnapshot = { items: any[]; total: number };

export function useModuleListData({
  module,
  token,
  page,
  size,
  order,
  filters,
  hasList,
  shouldInitialLoad,
  setShouldInitialLoad,
  moduleCacheKey,
  isTaskDetailModule,
  taskDetailCountCacheKey,
  setError,
  setSuccess,
}: {
  module: ModuleConfig;
  token: string;
  page: number;
  size: number;
  order: string;
  filters: JsonValue;
  hasList: boolean;
  shouldInitialLoad: boolean;
  setShouldInitialLoad: (value: boolean) => void;
  moduleCacheKey: string;
  isTaskDetailModule: boolean;
  taskDetailCountCacheKey: string;
  setError: (value: string) => void;
  setSuccess: (value: string) => void;
}) {
  const queryClient = useQueryClient();
  const [manualLoading, setManualLoading] = useState(false);
  const latestRequestIdRef = useRef(0);
  const activeModuleCacheKeyRef = useRef(moduleCacheKey);
  const taskDetailCountOverridesRef = useRef<Record<string, Record<string, number>>>({});

  useEffect(() => {
    if (activeModuleCacheKeyRef.current === moduleCacheKey) return;
    latestRequestIdRef.current += 1;
    activeModuleCacheKeyRef.current = moduleCacheKey;
    setManualLoading(false);
  }, [moduleCacheKey]);

  const buildQueryKey = useCallback(
    (nextPage: number, nextSize: number, nextOrder: string, nextFilters: JsonValue) => [
      'module-list',
      token,
      module.id,
      nextPage,
      nextSize,
      String(nextOrder || '').trim(),
      buildFilterSignature(nextFilters),
    ] as const,
    [module.id, token],
  );

  const fetchList = useCallback(async ({
    nextPage,
    nextSize,
    nextOrder,
    nextFilters,
    forceRefresh = false,
  }: {
    nextPage: number;
    nextSize: number;
    nextOrder: string;
    nextFilters: JsonValue;
    forceRefresh?: boolean;
  }) => {
    if (!module.listPath) return { items: [], total: 0 };
    const query: JsonValue = { page: nextPage, size: nextSize, ...nextFilters };
    const orderValue = String(nextOrder || '').trim();
    if (orderValue) query.order = orderValue;
    else if (module.defaultOrder && !('order' in query)) query.order = module.defaultOrder;
    if (forceRefresh) query._refresh = '1';
    return normalizeListData(await requestApi(token, module.listPath, { method: 'GET', query }));
  }, [module.defaultOrder, module.listPath, token]);

  const queryKey = buildQueryKey(page, size, order, filters);
  const cachedSnapshot = queryClient.getQueryData<ListSnapshot>(queryKey);
  const hasLiveTaskRows = module.id === 'task'
    && (cachedSnapshot?.items || []).some((row: any) => {
      const status = normalizeTaskStatus(row?.status);
      return status === 'running' || status === 'waiting';
    });
  const listQuery = useQuery({
    queryKey,
    enabled: Boolean(hasList && (shouldInitialLoad || hasLiveTaskRows)),
    staleTime: LIVE_STATUS_MODULE_IDS.has(module.id) ? 0 : 30_000,
    refetchInterval: hasLiveTaskRows ? 15_000 : false,
    retry: 0,
    queryFn: () => fetchList({
      nextPage: page,
      nextSize: size,
      nextOrder: order,
      nextFilters: filters,
    }),
  });
  const rows = listQuery.data?.items || [];
  const total = Number(listQuery.data?.total || 0);
  const loading = manualLoading || listQuery.isFetching;

  useEffect(() => {
    if (!hasList || (!shouldInitialLoad && !hasLiveTaskRows) || listQuery.isFetching) return;
    if (listQuery.error) {
      setError(listQuery.error instanceof Error ? listQuery.error.message : '加载失败');
    } else if (listQuery.data) {
      setError('');
      if (isTaskDetailModule) {
        taskDetailCountOverridesRef.current[taskDetailCountCacheKey] = {
          ...(taskDetailCountOverridesRef.current[taskDetailCountCacheKey] || {}),
          [module.id]: Number(listQuery.data.total || 0),
        };
      }
    }
    setShouldInitialLoad(false);
  }, [
    hasList,
    hasLiveTaskRows,
    isTaskDetailModule,
    listQuery.data,
    listQuery.error,
    listQuery.isFetching,
    module.id,
    setError,
    setShouldInitialLoad,
    shouldInitialLoad,
    taskDetailCountCacheKey,
  ]);

  const loadRows = useCallback(async (loadOptions: LoadRowsOptions = {}) => {
    if (!module.listPath) return;
    const nextPage = Number.isFinite(Number(loadOptions.page))
      ? Math.max(1, Math.floor(Number(loadOptions.page)))
      : page;
    const nextSize = Number.isFinite(Number(loadOptions.size))
      ? Math.max(1, Math.floor(Number(loadOptions.size)))
      : size;
    const nextOrder = typeof loadOptions.order === 'string' ? loadOptions.order : order;
    const nextFilters = loadOptions.filters || filters;
    const requestId = latestRequestIdRef.current + 1;
    latestRequestIdRef.current = requestId;
    const requestModuleCacheKey = moduleCacheKey;

    setManualLoading(true);
    setError('');
    setSuccess('');
    const listQueryKey = buildQueryKey(nextPage, nextSize, nextOrder, nextFilters);
    try {
      if (loadOptions.forceRefresh) {
        queryClient.invalidateQueries({ queryKey: listQueryKey, refetchType: 'none' });
        queryClient.invalidateQueries({ queryKey: ['module-task-detail-counts', token], refetchType: 'none' });
      }
      const normalized = await queryClient.fetchQuery({
        queryKey: listQueryKey,
        staleTime: loadOptions.forceRefresh || LIVE_STATUS_MODULE_IDS.has(module.id) ? 0 : 30_000,
        queryFn: () => fetchList({
          nextPage,
          nextSize,
          nextOrder,
          nextFilters,
          forceRefresh: Boolean(loadOptions.forceRefresh),
        }),
      });
      if (
        requestId !== latestRequestIdRef.current
        || requestModuleCacheKey !== activeModuleCacheKeyRef.current
      ) return;

      if (isTaskDetailModule) {
        taskDetailCountOverridesRef.current[taskDetailCountCacheKey] = {
          ...(taskDetailCountOverridesRef.current[taskDetailCountCacheKey] || {}),
          [module.id]: Number(normalized.total || 0),
        };
        queryClient.invalidateQueries({ queryKey: ['module-task-detail-counts', token], refetchType: 'none' });
      }
    } catch (error) {
      if (
        requestId !== latestRequestIdRef.current
        || requestModuleCacheKey !== activeModuleCacheKeyRef.current
      ) return;
      setError((error as Error)?.message || '加载失败');
    } finally {
      if (
        requestId === latestRequestIdRef.current
        && requestModuleCacheKey === activeModuleCacheKeyRef.current
      ) setManualLoading(false);
    }
  }, [
    buildQueryKey,
    fetchList,
    filters,
    isTaskDetailModule,
    module.id,
    module.listPath,
    moduleCacheKey,
    order,
    page,
    queryClient,
    setError,
    setSuccess,
    size,
    taskDetailCountCacheKey,
    token,
  ]);

  return { rows, total, loading, loadRows, taskDetailCountOverridesRef };
}
