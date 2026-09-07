// TableModuleView 列表页 smoke（计划 4）：以 task 模块验证列页数据流骨架——
// 请求参数、空态、错误态三类页面级证据；行操作/批量动作面留给授权环境 ui-smoke。
// Phase 3 追加：筛选选项/明细计数/AI 配置读取统一 React Query 的行为证据。
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
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

describe('TableModuleView Phase 3 缓存/去重覆盖', () => {
  const sizeOneGets = (calls: Array<{ url: string }>) =>
    calls.filter((c) => c.url.includes('size=1') && !c.url.includes('size=10')).length;
  const nameQueryGets = (calls: Array<{ url: string }>) =>
    calls.filter((c) => c.url.includes('size=10000') && c.url.includes('name=n1')).length;
  const countBy = (calls: Array<{ url: string; method: string }>, method: string, fragment: string) =>
    calls.filter((c) => c.method === method && c.url.includes(fragment)).length;
  // 任务名查询与主列表共用 /api/task/：返回一条 n1 任务供同名/导出链路命中。
  const TASK_N1_ROUTES = {
    '/api/task/': [200, { code: 200, data: { items: [{ name: 'n1', _id: 't1', status: 'done' }], total: 1, page: 1, size: 20 } }],
  } as Record<string, [number, unknown]>;

  it('明细 tab 计数走共享查询：重挂载命中缓存不重复探测', async () => {
    const calls = installFetchMock();
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const first = renderViewWithClient(client, 'site');
    await waitFor(() => expect(sizeOneGets(calls)).toBeGreaterThanOrEqual(7));
    const afterFirst = sizeOneGets(calls);
    first.unmount();
    renderViewWithClient(client, 'site');
    await new Promise((resolve) => window.setTimeout(resolve, 60));
    // staleTime 30s 内 size=1 探测不重发（替代原 cacheRef 的缓存职责）。
    expect(sizeOneGets(calls)).toBe(afterFirst);
  });

  it('同名任务查看：fetchQuery 按名称键去重，二次点击复用缓存', async () => {
    const onOpenModule = vi.fn();
    const calls = installFetchMock({ routes: TASK_N1_ROUTES });
    render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <TableModuleView
          module={getModuleById('task')}
          token="tk-page"
          onOpenModule={onOpenModule}
          externalFilters={{}}
          onClearExternalFilters={vi.fn()}
          scrollResetToken={0}
          refreshSignal={0}
        />
      </QueryClientProvider>,
    );
    // 任务名输入直写 searchForm.name（taskNameSearchText），无需点“搜索”即激活同名链路。
    fireEvent.change(
      screen.getByPlaceholderText('请输入或选择任务名（用于搜索/同名查看/批量操作）'),
      { target: { value: 'n1' } },
    );
    const viewByNameBtn = screen.getByRole('button', { name: '同名任务查看' });
    await waitFor(() => expect(viewByNameBtn.hasAttribute('disabled')).toBe(false));
    fireEvent.click(viewByNameBtn);
    await waitFor(() => expect(nameQueryGets(calls)).toBe(1));
    fireEvent.click(viewByNameBtn);
    await new Promise((resolve) => window.setTimeout(resolve, 60));
    expect(nameQueryGets(calls)).toBe(1);
    expect(onOpenModule).toHaveBeenLastCalledWith('site', { task_id: 't1' });
  });

  it('报告导出复用同名任务查询：名称键不重发，导出事务链路完整', async () => {
    (URL as unknown as { createObjectURL: (b: unknown) => string }).createObjectURL = vi.fn(() => 'blob:x');
    (URL as unknown as { revokeObjectURL: (u: string) => void }).revokeObjectURL = vi.fn();
    const calls = installFetchMock({
      routes: {
        ...TASK_N1_ROUTES,
        '/export/job/j1/download': [200, { ok: true }, { 'content-type': 'application/octet-stream' }],
        '/export/job/j1': [200, { code: 200, data: { status: 'done', filename: 'report.xlsx' } }],
        '/export/job': [200, { code: 200, data: { job_id: 'j1' } }],
      },
    });
    render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <TableModuleView
          module={getModuleById('task')}
          token="tk-page"
          onOpenModule={vi.fn()}
          externalFilters={{}}
          onClearExternalFilters={vi.fn()}
          scrollResetToken={0}
          refreshSignal={0}
        />
      </QueryClientProvider>,
    );
    // 任务名输入直写 searchForm.name（taskNameSearchText），无需点“搜索”即激活同名链路。
    fireEvent.change(
      screen.getByPlaceholderText('请输入或选择任务名（用于搜索/同名查看/批量操作）'),
      { target: { value: 'n1' } },
    );
    const viewByNameBtn = screen.getByRole('button', { name: '同名任务查看' });
    await waitFor(() => expect(viewByNameBtn.hasAttribute('disabled')).toBe(false));
    fireEvent.click(viewByNameBtn);
    await waitFor(() => expect(nameQueryGets(calls)).toBe(1));

    const exportBtn = screen.getByRole('button', { name: /报告导出/ });
    await waitFor(() => expect(exportBtn.hasAttribute('disabled')).toBe(false));
    fireEvent.click(exportBtn);
    fireEvent.click(await screen.findByRole('button', { name: '表格格式' }));
    await waitFor(() => expect(countBy(calls, 'POST', '/export/job')).toBe(1));
    // 反馈文案在 success 条与导出弹窗中跨节点拆分，做存在性断言即可。
    await waitFor(() => expect(document.body.textContent).toContain('导出成功'));
    // 导出前的 id 解析命中同名查看的 fetchQuery 缓存：size=10000 仍只有 1 次。
    expect(nameQueryGets(calls)).toBe(1);
  });
});
