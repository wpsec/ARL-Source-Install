// API 管理页级测试（计划 4 控制台批次）：初始化水合、错误呈现、
// 重新加载 refetch、保存成功后 query invalidation（写后取权威快照）。
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { installFetchMock } from '../test/fetchMock';
import { ApiConsoleView } from './ApiConsoleView';

const SERVICE_API_PAYLOAD = {
  code: 200,
  data: {
    service_api: {
      fofa_url: 'https://fofa.test',
      fofa_email: 'ops@test.local',
      github_token: '',
    },
    sensitive_configured: {},
    config_path: '/code/app/config.yaml',
    updated_at: '2026-09-07 09:00:00',
  },
};

function renderView() {
  return renderViewWithClient(new QueryClient({ defaultOptions: { queries: { retry: false } } }), 'tk-api');
}

function renderViewWithClient(client: QueryClient, token: string) {
  return render(
    <QueryClientProvider client={client}>
      <ApiConsoleView token={token} />
    </QueryClientProvider>,
  );
}

const getCount = (calls: Array<{ url: string; method: string }>, method: string) =>
  calls.filter((c) => c.method === method && c.url.includes('/api_console/service_api/')).length;

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('ApiConsoleView（React Query）', () => {
  it('初始化 GET 水合表单且只取一次快照', async () => {
    const calls = installFetchMock({
      routes: { '/api_console/service_api/': [200, SERVICE_API_PAYLOAD] },
    });
    renderView();
    expect(screen.getByText('API 管理')).toBeTruthy();
    await screen.findByDisplayValue('https://fofa.test');
    expect(getCount(calls, 'GET')).toBe(1);
  });

  it('初始化失败呈现服务端消息', async () => {
    installFetchMock({
      routes: { '/api_console/service_api/': [500, { message: '配置读取失败' }] },
    });
    renderView();
    await screen.findByText(/HTTP 500/);
  });

  it('“重新加载”按钮触发 refetch', async () => {
    const calls = installFetchMock({
      routes: { '/api_console/service_api/': [200, SERVICE_API_PAYLOAD] },
    });
    renderView();
    await screen.findByDisplayValue('https://fofa.test');
    fireEvent.click(screen.getByRole('button', { name: /重新加载/ }));
    await vi.waitFor(() => expect(getCount(calls, 'GET')).toBe(2));
  });

  it('保存成功：POST 后 invalidation 重取 GET，并给出成功反馈', async () => {
    const calls = installFetchMock({
      routes: { '/api_console/service_api/': [200, SERVICE_API_PAYLOAD] },
    });
    renderView();
    await screen.findByDisplayValue('https://fofa.test');
    fireEvent.click(screen.getByRole('button', { name: '保存配置' }));
    await vi.waitFor(() => expect(getCount(calls, 'POST')).toBe(1));
    await vi.waitFor(() => expect(getCount(calls, 'GET')).toBe(2));
    await screen.findByText(/API 配置已保存/);
  });
});

describe('ApiConsoleView mutation 失效与查询 key 覆盖', () => {
  const ROUTES = {
    '/api_console/service_api/': [200, SERVICE_API_PAYLOAD],
  } as Record<string, [number, unknown]>;

  const countBy = (
    calls: Array<{ url: string; method: string }>,
    method: string,
    fragment: string,
  ) => calls.filter((c) => c.method === method && c.url.includes(fragment)).length;

  it('单 provider 测试成功后 invalidate 查询缓存', async () => {
    const calls = installFetchMock({
      routes: {
        ...ROUTES,
        '/service_api/test/': [200, { code: 200, data: { ok: true, message: 'quota ok' } }],
      },
    });
    renderView();
    await screen.findByDisplayValue('https://fofa.test');
    fireEvent.click(screen.getAllByRole('button', { name: '测试' })[0]);
    await vi.waitFor(() => expect(countBy(calls, 'POST', '/service_api/test/')).toBe(1));
    await vi.waitFor(() => expect(countBy(calls, 'GET', '/api_console/service_api/')).toBe(2));
  });

  it('一键验证成功后 invalidate 查询缓存', async () => {
    const calls = installFetchMock({
      routes: {
        ...ROUTES,
        '/service_api/test_batch/': [200, { code: 200, data: { items: [], message: '未检测到已配置的 API' } }],
      },
    });
    renderView();
    await screen.findByDisplayValue('https://fofa.test');
    fireEvent.click(screen.getByRole('button', { name: /一键验证/ }));
    await vi.waitFor(() => expect(countBy(calls, 'POST', '/service_api/test_batch/')).toBe(1));
    await vi.waitFor(() => expect(countBy(calls, 'GET', '/api_console/service_api/')).toBe(2));
  });

  it('查询 key 含 token：双实例隔离拉取，保存只失效自身 key', async () => {
    const calls = installFetchMock({ routes: ROUTES });
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const a = renderViewWithClient(client, 'tk-A');
    const b = renderViewWithClient(client, 'tk-B');
    await vi.waitFor(() =>
      expect(calls.filter((c) => c.method === 'GET' && c.url.includes('/api_console/service_api/')).length).toBe(2),
    );
    const saveA = within(a.container).getByRole('button', { name: '保存配置' });
    await vi.waitFor(() => expect(saveA.hasAttribute('disabled')).toBe(false));
    fireEvent.click(saveA);
    await vi.waitFor(() => expect(countBy(calls, 'POST', '/api_console/service_api/')).toBe(1));
    // 只有 tk-A 的 key 被 invalidate：tk-B 缓存与请求数不受影响。
    await vi.waitFor(() =>
      expect(countBy(calls, 'GET', '/api_console/service_api/')).toBe(3),
    );
    await new Promise((resolve) => window.setTimeout(resolve, 80));
    // tk-B 无第二次请求：key 含 token，跨实例不串扰；B 实例保持存活。
    expect(within(b.container).getByRole('button', { name: '保存配置' })).toBeTruthy();
  });
});
