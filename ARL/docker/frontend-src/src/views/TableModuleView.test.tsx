// TableModuleView 列表页 smoke（计划 4）：以 task 模块验证列页数据流骨架——
// 请求参数、空态、错误态三类页面级证据；行操作/批量动作面留给授权环境 ui-smoke。
// Phase 3 追加：筛选选项/明细计数/AI 配置读取统一 React Query 的行为证据。
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { getModuleById } from '../config/modules';
import { installFetchMock } from '../test/fetchMock';
import { TableModuleView } from './TableModuleView';

function renderTaskView() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return renderViewWithClient(client);
}

function renderViewWithClient(client: QueryClient, moduleId = 'task') {
  return render(
    <QueryClientProvider client={client}>
      <TableModuleView
        module={getModuleById(moduleId)}
        token="tk-page"
        onOpenModule={vi.fn()}
        externalFilters={{}}
        onClearExternalFilters={vi.fn()}
        scrollResetToken={0}
        refreshSignal={0}
      />
    </QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('TableModuleView(task) 页面级', () => {
  it('页头渲染模块标题，列表请求带 Token 与分页参数，空集走 DataTable 空态', async () => {
    const calls = installFetchMock();
    renderTaskView();
    expect(screen.getByText('任务管理')).toBeTruthy();
    await waitFor(() => expect(screen.getByText('暂无数据')).toBeTruthy());
    const listCall = calls.find((c) => c.url.includes('/api/task/'));
    expect(listCall).toBeTruthy();
    expect(listCall!.token).toBe('tk-page');
    expect(listCall!.url).toContain('page=1');
  });

  it('列表接口 5xx：页头错误条呈现且不白屏', async () => {
    installFetchMock({
      routes: {
        '/task/': [500, { message: '数据库超时' }],
      },
    });
    renderTaskView();
    await waitFor(() => expect(screen.getByText('任务管理')).toBeTruthy());
    // setError 文案经 StatusPill 呈现（HTTP 500: 数据库超时）。
    await waitFor(() => expect(screen.getByText(/HTTP 500/)).toBeTruthy());
  });

  it('主列表在同一 QueryClient 内复用短期缓存，不因页面重挂载重复请求', async () => {
    const calls = installFetchMock();
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const first = renderViewWithClient(client, 'domain');
    const mainListCalls = () => calls.filter(
      (call) => call.url.includes('/api/domain/') && call.url.includes('size=50'),
    );
    await waitFor(() => expect(mainListCalls().length).toBe(1));
    first.unmount();
    renderViewWithClient(client, 'domain');
    await new Promise((resolve) => window.setTimeout(resolve, 60));
    expect(mainListCalls().length).toBe(1);
  });
});

describe('TableModuleView Phase 3 选项/共享读取（React Query）', () => {
  it('task_schedule 模块挂载即取策略名选项（order=name 全量）', async () => {
    const calls = installFetchMock();
    renderViewWithClient(new QueryClient({ defaultOptions: { queries: { retry: false } } }), 'task_schedule');
    await waitFor(() =>
      expect(calls.some((c) => c.url.includes('/api/policy/') && c.url.includes('order=name'))).toBe(true),
    );
  });

  it('AI 去噪模块（site）挂载即共享读取 ai_config', async () => {
    const calls = installFetchMock();
    renderViewWithClient(new QueryClient({ defaultOptions: { queries: { retry: false } } }), 'site');
    await waitFor(() => expect(calls.some((c) => c.url.includes('/ai_config/'))).toBe(true));
  });

  it('同一 QueryClient 重挂载：staleTime 内选项不重复请求（替代原 cacheRef 语义）', async () => {
    const calls = installFetchMock();
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const first = renderViewWithClient(client, 'task_schedule');
    await waitFor(() =>
      expect(calls.filter((c) => c.url.includes('/api/policy/')).length).toBe(1),
    );
    first.unmount();
    renderViewWithClient(client, 'task_schedule');
    await new Promise((resolve) => window.setTimeout(resolve, 50));
    expect(calls.filter((c) => c.url.includes('/api/policy/')).length).toBe(1);
  });
});
