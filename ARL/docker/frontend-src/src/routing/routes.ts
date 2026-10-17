import { TASK_DETAIL_TABS, visibleModules } from '../config/modules';
import type { JsonValue } from '../domain/types';

type RouteFilters = Record<string, any>;

export type ResolvedModuleRoute = {
  moduleId: string;
  filters: RouteFilters;
};

const moduleIdBySlug = new Map(visibleModules.map((module) => [module.id.replaceAll('_', '-'), module.id]));
const taskDetailModuleIds = new Set(TASK_DETAIL_TABS.map((tab) => tab.id));
const externalFilterKeys = new Set([
  'task_id',
  'task_name',
  'scope_id',
  'result_set_id',
  ...visibleModules.flatMap((module) => (module.searchFields || []).map((field) => field.key)),
]);

function decodePathSegment(segment: string): string | null {
  try {
    return decodeURIComponent(segment);
  } catch {
    return null;
  }
}

function readExternalFilters(search: string): RouteFilters {
  const filters: RouteFilters = {};
  new URLSearchParams(search).forEach((value, key) => {
    if (!key.startsWith('x.') || key.length <= 2) return;
    const filterKey = key.slice(2);
    if (externalFilterKeys.has(filterKey)) filters[filterKey] = value;
  });
  return filters;
}

export function resolveModuleRoute(pathname: string, search = ''): ResolvedModuleRoute | null {
  const path = pathname.replace(/\/+$/, '') || '/';
  if (path === '/dashboard') return { moduleId: 'dashboard', filters: {} };

  const moduleMatch = path.match(/^\/modules\/([^/]+)$/);
  if (moduleMatch) {
    const slug = decodePathSegment(moduleMatch[1]);
    const moduleId = slug ? moduleIdBySlug.get(slug) : undefined;
    return moduleId ? { moduleId, filters: readExternalFilters(search) } : null;
  }

  const taskDetailMatch = path.match(/^\/tasks\/([^/]+)\/([^/]+)$/);
  if (!taskDetailMatch) return null;
  const taskId = decodePathSegment(taskDetailMatch[1]);
  const tabSlug = decodePathSegment(taskDetailMatch[2]);
  const moduleId = tabSlug ? moduleIdBySlug.get(tabSlug) : undefined;
  if (!taskId || !moduleId || !taskDetailModuleIds.has(moduleId)) return null;

  return {
    moduleId,
    filters: { ...readExternalFilters(search), task_id: taskId },
  };
}

export function buildModuleUrl(moduleId: string, filters?: JsonValue): string {
  const filterValues = filters && typeof filters === 'object' && !Array.isArray(filters)
    ? filters as Record<string, JsonValue>
    : {};
  const taskId = String(filterValues.task_id ?? '').trim();
  const hasTaskDetailRoute = Boolean(taskId && taskDetailModuleIds.has(moduleId));
  const path = moduleId === 'dashboard'
    ? '/dashboard'
    : hasTaskDetailRoute
      ? `/tasks/${encodeURIComponent(taskId)}/${moduleId.replaceAll('_', '-')}`
      : `/modules/${moduleId.replaceAll('_', '-')}`;
  const params = new URLSearchParams();

  Object.entries(filterValues).forEach(([key, value]) => {
    if (!externalFilterKeys.has(key)) return;
    if (key === 'task_id' && hasTaskDetailRoute) return;
    if (value === null || value === undefined || typeof value === 'object') return;
    const normalized = String(value).trim();
    if (normalized) params.set(`x.${key}`, normalized);
  });

  const search = params.toString();
  return search ? `${path}?${search}` : path;
}
