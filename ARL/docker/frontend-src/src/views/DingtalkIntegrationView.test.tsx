// 钉钉集成页级测试（计划 4 控制台批次）：初始化水合、错误呈现、
// 保存与连通性测试成功后的 query invalidation；workspaces/nodes 按需读不在本批。
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
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
  return renderViewWithClient(new QueryClient({ defaultOptions: { queries: { retry: false } } }), 'tk-ding');
}

function renderViewWithClient(client: QueryClient, token: string) {
  return render(
    <QueryClientProvider client={client}>
      <DingtalkIntegrationView token={token} />
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

describe('DingtalkIntegrationView reveal 与查询 key 覆盖', () => {
  const ROUTES = {
    '/dingtalk_api/config/': [200, DINGTALK_PAYLOAD],
  } as Record<string, [number, unknown]>;

  const countBy = (
    calls: Array<{ url: string; method: string }>,
    method: string,
    fragment: string,
  ) => calls.filter((c) => c.method === method && c.url.includes(fragment)).length;

  it('reveal 鉴权读不触发 config 查询失效（行为锁定：明文展示不被脱敏重取冲掉）', async () => {
    const calls = installFetchMock({
      routes: {
        ...ROUTES,
        '/dingtalk_api/reveal/': [200, {
          code: 200,
          data: {
            config: { ...DINGTALK_PAYLOAD.data.config, app_key: 'PLAIN-KEY-1' },
            sensitive_configured: { app_key: true },
          },
        }],
      },
    });
    renderView();
    await screen.findByDisplayValue('45');
    fireEvent.click(screen.getByRole('button', { name: '显示敏感配置' }));
    fireEvent.change(screen.getByPlaceholderText('请输入当前登录账号'), { target: { value: 'admin' } });
    fireEvent.change(screen.getByPlaceholderText('请输入当前登录密码'), { target: { value: 'pw-input' } });
    fireEvent.click(screen.getByRole('button', { name: '验证并显示' }));
    await vi.waitFor(() => expect(countBy(calls, 'POST', '/dingtalk_api/reveal/')).toBe(1));
    // 关键断言：reveal 后 config GET 仍为 1——它刻意不走查询缓存。
    await new Promise((resolve) => window.setTimeout(resolve, 60));
    expect(countBy(calls, 'GET', '/dingtalk_api/config/')).toBe(1);
  });

  it('查询 key 含 token：双实例隔离拉取，保存只失效自身 key', async () => {
    const calls = installFetchMock({ routes: ROUTES });
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const a = renderViewWithClient(client, 'tk-A');
    renderViewWithClient(client, 'tk-B');
    await vi.waitFor(() => expect(countBy(calls, 'GET', '/dingtalk_api/config/')).toBe(2));
    const saveA = within(a.container).getByRole('button', { name: '保存配置' });
    await vi.waitFor(() => expect(saveA.hasAttribute('disabled')).toBe(false));
    fireEvent.click(saveA);
    await vi.waitFor(() => expect(countBy(calls, 'POST', '/dingtalk_api/config/')).toBe(1));
    // 仅 tk-A 的 key 被 invalidate 重取；tk-B 不受影响（稳定在 3 总数：2 初始 + 1 重取）。
    await vi.waitFor(() => expect(countBy(calls, 'GET', '/dingtalk_api/config/')).toBe(3));
    await new Promise((resolve) => window.setTimeout(resolve, 80));
    expect(countBy(calls, 'GET', '/dingtalk_api/config/')).toBe(3);
  });
});
