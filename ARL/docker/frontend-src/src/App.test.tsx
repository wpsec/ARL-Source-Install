// 应用壳页面级测试（计划 4）：鉴权流转、退出、修改密码 Modal 与全局 Esc。
// 主区视图（Dashboard lazy）用通用 mock 兜住，断言只钉壳层稳定元素，
// 不与各视图数据形状强耦合。
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import App from './App';
import { installFetchMock, setViteDefineGlobals } from './test/fetchMock';

beforeAll(() => {
  setViteDefineGlobals();
});

beforeEach(() => {
  localStorage.clear();
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

  it('侧边栏切换视图会写入激活模块（localStorage 持久化）', async () => {
    localStorage.setItem('arl-token', 'tk-existing');
    installFetchMock();
    renderApp();
    await waitFor(() => expect(screen.getByTitle('退出')).toBeTruthy());
    const assetNav = screen.getByRole('button', { name: '资产搜索' });
    fireEvent.click(assetNav);
    await waitFor(() => expect(localStorage.getItem('arl-active-module')).toBe('site'));
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
  });
});
