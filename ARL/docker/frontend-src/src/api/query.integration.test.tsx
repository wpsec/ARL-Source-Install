// React Query × DataTable 数据流集成（计划 4 UI 验收·分页/筛选/错误态接线方式）。
// TableModuleView 为巨型消费方，此处以最小 harness 钉住同款协议：
// queryKey = [模块, token, buildFilterSignature(filters)] → 筛选变化即重取；
// 请求失败在 UI 呈现可脱敏消息而非白屏。
import { QueryClient, QueryClientProvider, useQuery } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { useState } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { DataTable } from '../components/ui/DataTable';
import { buildFilterSignature, normalizeListData, requestApi } from './client';

type Row = { id: string; name: string };

function resp(status: number, body: unknown) {
  const text = JSON.stringify(body);
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: new Headers({ 'content-type': 'application/json' }),
    text: async () => text,
  };
}

let failMode = false;

function mockFetch() {
  const calls: string[] = [];
  vi.stubGlobal('fetch', vi.fn(async (url: string) => {
    calls.push(url);
    if (failMode) {
      return resp(200, { code: 500, message: '服务异常 <b>500</b>' });
    }
    if (url.includes('search=abc')) {
      return resp(200, { code: 200, data: { items: [{ id: 'b1', name: 'FilteredRow' }], total: 1 } });
    }
    return resp(200, { code: 200, data: { items: [{ id: 'a1', name: 'BaseRow' }, { id: 'a2', name: 'SecondRow' }], total: 2 } });
  }));
  return calls;
}

function ListHarness() {
  const [filters, setFilters] = useState<Record<string, string>>({});
  const query = useQuery({
    queryKey: ['module-list', 'token-1', buildFilterSignature(filters)],
    queryFn: async () => {
      const data = await requestApi('token-1', '/host', { query: filters });
      return normalizeListData(data);
    },
    retry: 0,
  });
  return (
    <div>
      <button onClick={() => setFilters({ search: 'abc' })}>应用筛选</button>
      {query.isPending && <span>加载中…</span>}
      {query.isError && (
        <span role="alert">{(query.error as Error).message}</span>
      )}
      {query.data && (
        <DataTable
          columns={[{ key: 'name', header: '名称' }]}
          rows={query.data.items as Row[]}
          rowKey={(row: Row) => row.id}
        />
      )}
    </div>
  );
}

function renderHarness() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <ListHarness />
    </QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  failMode = false;
});

describe('列表数据流（查询→筛选→错误态）', () => {
  it('初始加载：pending→数据渲染进 DataTable', async () => {
    mockFetch();
    renderHarness();
    expect(screen.getByText('加载中…')).toBeTruthy();
    await waitFor(() => expect(screen.getByText('BaseRow')).toBeTruthy());
    expect(screen.getByText('SecondRow')).toBeTruthy();
    expect(screen.queryByText('加载中…')).toBeNull();
  });

  it('筛选变化：queryKey 改变触发重取并替换行集', async () => {
    const calls = mockFetch();
    renderHarness();
    await waitFor(() => expect(screen.getByText('BaseRow')).toBeTruthy());
    fireEvent.click(screen.getByRole('button', { name: '应用筛选' }));
    await waitFor(() => expect(screen.getByText('FilteredRow')).toBeTruthy());
    expect(calls.some((u) => u.includes('search=abc'))).toBe(true);
    expect(screen.queryByText('BaseRow')).toBeNull();
  });

  it('请求失败：错误消息脱敏后呈现，不渲染空表', async () => {
    failMode = true;
    mockFetch();
    renderHarness();
    await waitFor(() => expect(screen.getByRole('alert')).toBeTruthy());
    // sanitizeUiMessage 去除标签，仅保留文本。
    expect(screen.getByRole('alert').textContent).toBe('服务异常 500');
  });
});
