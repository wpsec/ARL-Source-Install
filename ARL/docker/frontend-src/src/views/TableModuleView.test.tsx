// TableModuleView 列表页 smoke（计划 4）：以 task 模块验证列页数据流骨架——
// 请求参数、空态、错误态三类页面级证据；行操作/批量动作面留给授权环境 ui-smoke。
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { getModuleById } from '../config/modules';
import { installFetchMock } from '../test/fetchMock';
import { TableModuleView } from './TableModuleView';

function renderTaskView() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
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
});
