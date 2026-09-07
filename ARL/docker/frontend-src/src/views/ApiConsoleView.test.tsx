// API 管理页级测试（计划 4 控制台批次）：初始化水合、错误呈现、
// 重新加载 refetch、保存成功后 query invalidation（写后取权威快照）。
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
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
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <ApiConsoleView token="tk-api" />
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
