// 钉钉集成页级测试（计划 4 控制台批次）：初始化水合、错误呈现、
// 保存与连通性测试成功后的 query invalidation；workspaces/nodes 按需读不在本批。
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { installFetchMock } from '../test/fetchMock';
import { DingtalkIntegrationView } from './DingtalkIntegrationView';

const DINGTALK_PAYLOAD = {
  code: 200,
  data: {
    config: {
      enable: true,
      base_url: 'https://api.dingtalk.test',
      corp_id: 'corp-1',
      kb_timeout: 20,
      ssl_cert_notify_days: 45,
    },
    sensitive_configured: {},
    runtime_status: { kb_enable: true },
    config_path: '/code/app/config.yaml',
    updated_at: '2026-09-07 09:30:00',
  },
};

function renderView() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <DingtalkIntegrationView token="tk-ding" />
    </QueryClientProvider>,
  );
}

const getCount = (calls: Array<{ url: string; method: string }>, method: string) =>
  calls.filter((c) => c.method === method && c.url.includes('/dingtalk_api/config/')).length;

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('DingtalkIntegrationView（React Query）', () => {
  it('初始化 GET 水合非敏感表单字段', async () => {
    const calls = installFetchMock({
      routes: { '/dingtalk_api/config/': [200, DINGTALK_PAYLOAD] },
    });
    renderView();
    expect(screen.getByText('钉钉集成')).toBeTruthy();
    await screen.findByDisplayValue('45');
    expect(getCount(calls, 'GET')).toBe(1);
  });

  it('初始化失败呈现服务端消息', async () => {
    installFetchMock({
      routes: { '/dingtalk_api/config/': [500, { message: '钉钉配置不可读' }] },
    });
    renderView();
    await screen.findByText(/HTTP 500/);
  });

  it('保存成功：POST 后 invalidation 重取 GET', async () => {
    const calls = installFetchMock({
      routes: { '/dingtalk_api/config/': [200, DINGTALK_PAYLOAD] },
    });
    renderView();
    await screen.findByDisplayValue('45');
    fireEvent.click(screen.getByRole('button', { name: '保存配置' }));
    await vi.waitFor(() => expect(getCount(calls, 'POST')).toBe(1));
    await vi.waitFor(() => expect(getCount(calls, 'GET')).toBe(2));
  });

  it('连通性测试成功：POST test 后 invalidation 重取 config GET', async () => {
    const calls = installFetchMock({
      routes: {
        '/dingtalk_api/config/': [200, DINGTALK_PAYLOAD],
        '/dingtalk_api/test/': [200, { code: 200, data: { ok: true } }],
      },
    });
    renderView();
    await screen.findByDisplayValue('45');
    const getConfigGets = () => calls.filter((c) => c.method === 'GET' && c.url.includes('/dingtalk_api/config/')).length;
    fireEvent.click(screen.getByRole('button', { name: /测试连通性/ }));
    await vi.waitFor(() =>
      expect(calls.some((c) => c.method === 'POST' && c.url.includes('/dingtalk_api/test/'))).toBe(true),
    );
    await vi.waitFor(() => expect(getConfigGets()).toBe(2));
    await screen.findByText('钉钉连通性测试完成');
  });
});
