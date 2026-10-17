import type { ModuleConfig } from '../domain/types';

export type ModuleListUrlState = {
  page: number;
  size: number;
  order: string;
  quickFilter: string;
  searchForm: Record<string, string>;
};

function positiveInteger(value: string | null, fallback: number): number {
  if (!value) return fallback;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : fallback;
}

export function parseModuleListUrlState(
  search: string,
  module: ModuleConfig,
  defaultSize: number,
): ModuleListUrlState {
  const params = new URLSearchParams(search);
  const searchForm: Record<string, string> = {};
  (module.searchFields || []).forEach((field) => {
    searchForm[field.key] = params.get(field.key) || '';
  });

  return {
    page: positiveInteger(params.get('page'), 1),
    size: positiveInteger(params.get('size'), defaultSize),
    order: params.get('order') || module.defaultOrder || '',
    quickFilter: params.get('q') || '',
    searchForm,
  };
}

export function hasModuleListUrlState(search: string, module: ModuleConfig): boolean {
  const params = new URLSearchParams(search);
  return ['page', 'size', 'order', 'q', ...(module.searchFields || []).map((field) => field.key)]
    .some((key) => params.has(key));
}

export function buildModuleListSearch(
  currentSearch: string,
  module: ModuleConfig,
  state: ModuleListUrlState,
  defaultSize: number,
): string {
  const params = new URLSearchParams();
  new URLSearchParams(currentSearch).forEach((value, key) => {
    if (key.startsWith('x.')) params.set(key, value);
  });

  if (state.page > 1) params.set('page', String(state.page));
  if (state.size !== defaultSize) params.set('size', String(state.size));
  if (state.order && state.order !== (module.defaultOrder || '')) params.set('order', state.order);
  if (state.quickFilter.trim()) params.set('q', state.quickFilter.trim());
  (module.searchFields || []).forEach((field) => {
    const value = String(state.searchForm[field.key] || '').trim();
    if (value) params.set(field.key, value);
  });

  const query = params.toString();
  return query ? `?${query}` : '';
}
