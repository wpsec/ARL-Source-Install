// AI 管理页级测试（计划 4 工作台批次·仅数据层迁移回归）：
// 挂载即 config + usage(stats/logs) 快照；保存后 config invalidation；
// AI 测试后 usage invalidation；“刷新统计”= usage refetch。弹窗交互语义不在本批。
// 时序口径：等数据水合（而非 fetch 发起）后再交互——fetching 期间按钮 disabled。
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { installFetchMock } from '../test/fetchMock';
import { ConfigAiManagementPanel } from './AiConsoleView';

const AI_CONFIG_PAYLOAD = {
  code: 200,
  data: {
    ai_config: { provider: 'openai', model: 'gpt-mini', enable: true },
    provider_presets: [],
    sensitive_configured: {},
    config_path: '/code/app/config.yaml',
    updated_at: 'AI-CFG-2026-09-07',
  },
};

const USAGE_STATS_PAYLOAD = {
  code: 200,
  data: { all_time: { request_count: 9 }, last_24h: {}, last_7d: {}, window_days: 7, updated_at: 'U-2026' },
};

const USAGE_LOGS_PAYLOAD = {
  code: 200,
  data: { items: [], total: 0, available_scenes: [], updated_at: 'U-2026' },
};

function renderView() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <ConfigAiManagementPanel token="tk-ai" />
    </QueryClientProvider>,
  );
}

const countBy = (
  calls: Array<{ url: string; method: string }>,
  method: string,
  fragment: string,
) => calls.filter((c) => c.method === method && c.url.includes(fragment)).length;

const ROUTES = {
  '/api_console/ai_config/': [200, AI_CONFIG_PAYLOAD],
  '/api_console/ai_usage/stats/': [200, USAGE_STATS_PAYLOAD],
  '/api_console/ai_usage/logs/': [200, USAGE_LOGS_PAYLOAD],
} as Record<string, [number, unknown]>;

async function waitConfigHydrated() {
  await screen.findByText('AI-CFG-2026-09-07');
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('ConfigAiManagementPanel（React Query）', () => {
  it('挂载并行拉取配置与用量快照，各取一次', async () => {
    const calls = installFetchMock({ routes: ROUTES });
    renderView();
    await waitConfigHydrated();
    await vi.waitFor(() => expect(countBy(calls, 'GET', '/ai_usage/stats/')).toBe(1));
    await vi.waitFor(() => expect(countBy(calls, 'GET', '/ai_usage/logs/')).toBe(1));
    expect(countBy(calls, 'GET', '/ai_config/')).toBe(1);
  });

  it('保存成功：POST 配置后 invalidation 重取 config GET', async () => {
    const calls = installFetchMock({ routes: ROUTES });
    renderView();
    await waitConfigHydrated();
    fireEvent.click(screen.getByRole('button', { name: '保存配置' }));
    await vi.waitFor(() => expect(countBy(calls, 'POST', '/ai_config/')).toBe(1));
    await vi.waitFor(() => expect(countBy(calls, 'GET', '/ai_config/')).toBe(2));
    await screen.findByText(/AI 管理配置已保存/);
  });

  it('AI 测试完成：POST 后 usage 前缀 invalidation 重取统计', async () => {
    const calls = installFetchMock({
      routes: {
        ...ROUTES,
        '/ai_config/test/': [200, { code: 200, data: { ok: true, message: 'pong' } }],
      },
    });
    renderView();
    await waitConfigHydrated();
    await vi.waitFor(() => expect(countBy(calls, 'GET', '/ai_usage/stats/')).toBe(1));
    fireEvent.click(screen.getByRole('button', { name: 'AI测试' }));
    await vi.waitFor(() => expect(countBy(calls, 'POST', '/ai_config/test/')).toBe(1));
    await vi.waitFor(() => expect(countBy(calls, 'GET', '/ai_usage/stats/')).toBe(2));
    await vi.waitFor(() => expect(countBy(calls, 'GET', '/ai_usage/logs/')).toBe(2));
  });

  it('“刷新统计”按钮触发 usage refetch', async () => {
    const calls = installFetchMock({ routes: ROUTES });
    renderView();
    await waitConfigHydrated();
    const refreshBtn = screen.getByRole('button', { name: /刷新统计/ });
    // 等 usage 首轮 fetch 完成（fetching 期间按钮 disabled，click 会被忽略）。
    await vi.waitFor(() => expect(refreshBtn.hasAttribute('disabled')).toBe(false));
    fireEvent.click(refreshBtn);
    await vi.waitFor(() => expect(countBy(calls, 'GET', '/ai_usage/stats/')).toBe(2));
  });
});
