// 应用壳页面级测试（计划 4）：鉴权流转、退出、修改密码 Modal 与全局 Esc。
// 主区视图（Dashboard lazy）用通用 mock 兜住，断言只钉壳层稳定元素，
// 不与各视图数据形状强耦合。
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import App from './App';
import { installFetchMock, makeHttpResponse, setViteDefineGlobals } from './test/fetchMock';

beforeAll(() => {
  setViteDefineGlobals();
});

beforeEach(() => {
  localStorage.clear();
  window.history.replaceState({}, '', '/');
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function renderApp() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <App />
    </QueryClientProvider>,
  );
}

describe('App 鉴权流转', () => {
  it('无 token 时渲染登录页', () => {
    installFetchMock();
    renderApp();
    expect(screen.getByPlaceholderText('请输入用户名')).toBeTruthy();
    expect(screen.queryByText('新建任务')).toBeNull();
  });

  it('登录成功：写入 token 并切换到应用壳', async () => {
    const calls = installFetchMock({
      routes: {
        '/user/login': [200, { code: 200, data: { token: 'tk-abc', username: 'alice' } }],
      },
    });
    renderApp();
    fireEvent.change(screen.getByPlaceholderText('请输入用户名'), { target: { value: 'alice' } });
    fireEvent.change(screen.getByPlaceholderText('请输入密码'), { target: { value: 'pw' } });
    fireEvent.click(screen.getByRole('button', { name: '登录系统' }));

    await waitFor(() => expect(screen.getByText('alice')).toBeTruthy());
    expect(localStorage.getItem('arl-token')).toBe('tk-abc');
    expect(screen.getByTitle('退出')).toBeTruthy();
    const loginCall = calls.find((c) => c.url.includes('/user/login'));
    expect(loginCall?.method).toBe('POST');
  });

  it('登录失败：错误条呈现且停留在登录页', async () => {
    // 用业务 400 而非 401（401 会触发 requestApi 的 reload 定时器，非本用例目标）。
    installFetchMock({
      routes: {
        '/user/login': [200, { code: 400, message: '用户名或密码错误' }],
      },
    });
    renderApp();
    fireEvent.click(screen.getByRole('button', { name: '登录系统' }));
    await waitFor(() => expect(screen.getByText('用户名或密码错误')).toBeTruthy());
    expect(screen.getByPlaceholderText('请输入用户名')).toBeTruthy();
    expect(localStorage.getItem('arl-token')).toBeNull();
  });

  it('预置 token 直达应用壳；点退出回登录页并清本地态', async () => {
    const calls = installFetchMock();
    localStorage.setItem('arl-token', 'tk-existing');
    localStorage.setItem('arl-username', 'bob');
    renderApp();
    await waitFor(() => expect(screen.getByText('bob')).toBeTruthy());

    fireEvent.click(screen.getByTitle('退出'));
    await waitFor(() => expect(screen.getByPlaceholderText('请输入用户名')).toBeTruthy());
    expect(localStorage.getItem('arl-token')).toBeNull();
    expect(calls.some((c) => c.url.includes('/user/logout'))).toBe(true);
  });

  it('系统监控摘要位于顶部用户操作栏，紧邻用户名左侧', async () => {
    localStorage.setItem('arl-token', 'tk-existing');
    localStorage.setItem('arl-username', 'bob');
    installFetchMock();
    renderApp();

    await waitFor(() => expect(screen.getByRole('region', { name: '系统监控摘要' })).toBeTruthy());
    const monitor = screen.getByRole('region', { name: '系统监控摘要' });
    const userActionBar = monitor.parentElement;
    expect(userActionBar?.className).toContain('shrink-0');
    expect(userActionBar?.className).toContain('w-auto');
    expect(userActionBar?.querySelector('[title="修改密码"]')).toBeTruthy();
    expect(userActionBar?.textContent).toContain('bob');
    expect(monitor.nextElementSibling?.textContent).toContain('bob');
  });

  it('修改密码 Modal：按钮打开 dialog，全局 Esc 关闭', async () => {
    localStorage.setItem('arl-token', 'tk-existing');
    installFetchMock();
    renderApp();
    await waitFor(() => expect(screen.getByTitle('修改密码')).toBeTruthy());

    fireEvent.click(screen.getByTitle('修改密码'));
    await waitFor(() => expect(document.querySelector('dialog[open]')).toBeTruthy());
    expect(screen.getByPlaceholderText('旧密码')).toBeTruthy();

    // MainShell 的 window keydown 处理路径（组件层键盘行为归 Modal.test，
    // 原生 Esc 链路归 ui-smoke 浏览器阶段）。
    fireEvent.keyDown(window, { key: 'Escape' });
    await waitFor(() => expect(document.querySelector('dialog[open]')).toBeNull());
  });

  it('修改密码提交期间阻止关闭按钮和 Escape，失败后恢复关闭', async () => {
    localStorage.setItem('arl-token', 'tk-existing');
    installFetchMock();
    const defaultFetch = globalThis.fetch;
    let resolveChangeRequest!: (response: ReturnType<typeof makeHttpResponse>) => void;
    vi.stubGlobal('fetch', vi.fn((url: string, init?: RequestInit) => {
      if (url.includes('/user/change_pass')) {
        return new Promise<ReturnType<typeof makeHttpResponse>>((resolve) => {
          resolveChangeRequest = resolve;
        });
      }
      return defaultFetch(url, init);
    }));
    renderApp();
    await waitFor(() => expect(screen.getByTitle('修改密码')).toBeTruthy());

    fireEvent.click(screen.getByTitle('修改密码'));
    fireEvent.click(screen.getByRole('button', { name: '提交并重新登录' }));
    await waitFor(() => expect(resolveChangeRequest).toBeTruthy());

    const closeButton = screen.getByRole('button', { name: '关闭弹窗' }) as HTMLButtonElement;
    const dialog = document.querySelector('dialog[open]') as HTMLDialogElement;
    expect(closeButton.disabled).toBe(true);
    fireEvent.click(closeButton);
    fireEvent.keyDown(window, { key: 'Escape' });
    const cancelEvent = new Event('cancel', { cancelable: true });
    fireEvent(dialog, cancelEvent);
    expect(cancelEvent.defaultPrevented).toBe(true);
    expect(dialog.open).toBe(true);

    await act(async () => {
      resolveChangeRequest(makeHttpResponse(200, { code: 400, message: '修改密码失败' }));
    });
    await screen.findByText('修改密码失败');
    expect(closeButton.disabled).toBe(false);
    fireEvent.click(closeButton);
    await waitFor(() => expect(document.querySelector('dialog[open]')).toBeNull());
  });

  it('全局新建任务提交期间 Escape 不会绕过弹窗 loading guard', async () => {
    localStorage.setItem('arl-token', 'tk-existing');
    installFetchMock({
      routes: {
        '/api_console/scan_config/': [200, {
          code: 200,
          data: {
            scan_config: { domain_dict: '/dict/domain.txt', file_leak_dict: '/dict/file.txt' },
            available_domain_dicts: [{ label: 'domain', path: '/dict/domain.txt', source: 'custom', exists: true }],
            available_file_leak_dicts: [{ label: 'file', path: '/dict/file.txt', source: 'custom', exists: true }],
          },
        }],
      },
    });
    const defaultFetch = globalThis.fetch;
    let resolveTaskRequest!: (response: ReturnType<typeof makeHttpResponse>) => void;
    vi.stubGlobal('fetch', vi.fn((url: string, init?: RequestInit) => {
      if (init?.method === 'POST' && url.includes('/task/')) {
        return new Promise<ReturnType<typeof makeHttpResponse>>((resolve) => {
          resolveTaskRequest = resolve;
        });
      }
      return defaultFetch(url, init);
    }));
    renderApp();
    await screen.findByRole('heading', { name: '我的仪表盘' });

    fireEvent.click(screen.getAllByRole('button', { name: '新建任务' }).at(-1)!);
    await waitFor(() => expect(document.querySelector('dialog[open]')).toBeTruthy());
    fireEvent.click(screen.getByRole('button', { name: '执行' }));
    await waitFor(() => expect(resolveTaskRequest).toBeTruthy());

    fireEvent.keyDown(window, { key: 'Escape' });
    expect(document.querySelector('dialog[open]')).toBeTruthy();

    await act(async () => {
      resolveTaskRequest(makeHttpResponse(200, { code: 200, data: {} }));
    });
    await waitFor(() => expect(document.querySelector('dialog[open]')).toBeNull());
  });

  it('侧边栏切换视图会写入激活模块（localStorage 持久化）', async () => {
    localStorage.setItem('arl-token', 'tk-existing');
    installFetchMock();
    renderApp();
    await waitFor(() => expect(screen.getByTitle('退出')).toBeTruthy());
    const assetNav = screen.getByRole('button', { name: '资产搜索' });
    fireEvent.click(assetNav);
    await waitFor(() => expect(localStorage.getItem('arl-active-module')).toBe('site'));
    expect(window.location.pathname).toBe('/modules/site');
  });

  it('刷新后恢复任务明细筛选，避免已落库结果退回全局列表', async () => {
    localStorage.setItem('arl-token', 'tk-existing');
    localStorage.setItem('arl-username', 'bob');
    localStorage.setItem('arl-active-module', 'service');
    localStorage.setItem('arl-active-module-filters', JSON.stringify({ service: { task_id: 'task-1' } }));
    const calls = installFetchMock();
    renderApp();

    await waitFor(() => {
      const serviceCall = calls.find((call) => call.url.includes('/api/service/'));
      expect(serviceCall?.url).toContain('task_id=task-1');
    });
    expect(window.location.pathname).toBe('/tasks/task-1/service');
  });

  it('直接访问任务详情路由会恢复 task_id 筛选', async () => {
    window.history.replaceState({}, '', '/tasks/task-direct/site');
    localStorage.setItem('arl-token', 'tk-existing');
    const calls = installFetchMock();
    renderApp();

    await waitFor(() => {
      const siteCall = calls.find((call) => call.url.includes('/api/site/'));
      expect(siteCall?.url).toContain('task_id=task-direct');
    });
    expect(window.location.pathname).toBe('/tasks/task-direct/site');
  });

  it('同名任务查看后清除筛选会退出同名任务结果视图', async () => {
    window.history.replaceState({}, '', '/modules/task');
    localStorage.setItem('arl-token', 'tk-existing');
    const calls = installFetchMock();
    renderApp();

    await waitFor(() => expect(screen.getByRole('heading', { name: '任务管理' })).toBeTruthy());
    fireEvent.change(
      screen.getByPlaceholderText('请输入或选择任务名（用于搜索/同名查看/批量操作）'),
      { target: { value: 'same-name-task' } },
    );
    fireEvent.click(screen.getByRole('button', { name: '同名任务查看' }));

    await waitFor(() => {
      expect(window.location.pathname).toBe('/modules/site');
      expect(window.location.search).toContain('x.task_name=same-name-task');
    });
    await waitFor(() => expect(calls.some((call) => (
      call.url.includes('/api/site/') && call.url.includes('task_name=same-name-task')
    ))).toBe(true));
    const callsBeforeClear = calls.length;
    fireEvent.click(screen.getByRole('button', { name: '清除筛选' }));

    await waitFor(() => {
      expect(screen.queryByRole('button', { name: '清除筛选' })).toBeNull();
      expect(window.location.pathname).toBe('/modules/site');
      expect(window.location.search).toBe('');
    });
    await waitFor(() => expect(calls.slice(callsBeforeClear).some((call) => (
      call.url.includes('/api/site/') && !call.url.includes('task_name=same-name-task')
    ))).toBe(true));
  });

  it('列表筛选、页码和分页大小在 URL 中恢复', async () => {
    window.history.replaceState({}, '', '/modules/task?page=2&size=20&status=running');
    localStorage.setItem('arl-token', 'tk-existing');
    installFetchMock();
    renderApp();

    await waitFor(() => expect(screen.getByRole('heading', { name: '任务管理' })).toBeTruthy());
    expect((screen.getByLabelText('状态：') as HTMLSelectElement).value).toBe('running');
    expect(window.location.search).toContain('page=2');
    expect(window.location.search).toContain('size=20');
    expect(window.location.search).toContain('status=running');
  });

  it('无效模块地址回到仪表盘', async () => {
    window.history.replaceState({}, '', '/modules/not-a-module');
    localStorage.setItem('arl-token', 'tk-existing');
    installFetchMock();
    renderApp();

    await waitFor(() => expect(window.location.pathname).toBe('/dashboard'));
    expect(screen.getByRole('heading', { name: '我的仪表盘' })).toBeTruthy();
  });
});
