// 仪表盘页级测试（计划 4 工作台批次）：聚合主快照水合、明细回退模式、
// 10s 日志轮询、暂停/继续（继续立即补帧）、双败错误呈现。
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { installFetchMock } from '../test/fetchMock';
import { DashboardView } from './DashboardView';

const DASHBOARD_PAYLOAD = {
  code: 200,
  data: {
    stats: {
      task_total: 12,
      active_tasks: 3,
      new_assets_today: 5,
      asset_site_total: 55,
      asset_scope_total: 2,
      task_schedule_total: 1,
      vuln_total: 7,
      github_task_total: 0,
      domain_total: 100,
      ip_total: 20,
      service_total: 30,
      url_total: 40,
    },
    asset_trend_7d: [{ name: '09-01', assets: 4, vulns: 1 }],
    risk_distribution: [{ name: '高危', value: 7 }],
    network_trend: [],
    recent_logs: [],
    last_updated: 'DS-T-10:00',
  },
};

const RECENT_LOGS_PAYLOAD = {
  code: 200,
  data: { recent_logs: [{ level: 'INFO', source: 'SCAN', msg: '轮询日志帧', time: '' }] },
};

function renderView() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <DashboardView token="tk-dash" onOpenModule={vi.fn()} onQuickCreateTask={vi.fn()} />
    </QueryClientProvider>,
  );
}

const logsCount = (calls: Array<{ url: string }>) =>
  calls.filter((c) => c.url.includes('/console/recent_logs')).length;

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe('DashboardView（React Query）', () => {
  it('聚合主快照水合卡片，资产总数无需逐类 count 请求', async () => {
    const calls = installFetchMock({
      routes: { '/console/dashboard': [200, DASHBOARD_PAYLOAD] },
    });
    renderView();
    await vi.waitFor(() => expect(screen.getByText('DS-T-10:00')).toBeTruthy());
    expect(screen.getByText('我的仪表盘')).toBeTruthy();
    expect(screen.getByText('总计 12')).toBeTruthy();
    expect(screen.getByText('总计 7')).toBeTruthy();
    // stats 已带 domain_total 等字段：不再发 /domain/ 等明细 count。
    expect(calls.some((c) => c.url.includes('/domain/'))).toBe(false);
  });

  it('聚合接口失败自动回退明细聚合，呈现兼容模式提示且不打错误条', async () => {
    const calls = installFetchMock({
      routes: { '/console/dashboard': [500, { message: '聚合不可用' }] },
    });
    renderView();
    await vi.waitFor(() => expect(screen.getByText(/兼容模式/)).toBeTruthy());
    expect(calls.some((c) => c.url.includes('/domain/'))).toBe(true);
    expect(screen.queryByText(/HTTP 500/)).toBeNull();
  });

  it('扫描日志 10s 轮询', async () => {
    const calls = installFetchMock({
      routes: { '/console/recent_logs': [200, RECENT_LOGS_PAYLOAD] },
    });
    renderView();
    await vi.waitFor(() => expect(logsCount(calls)).toBe(1));
    await vi.advanceTimersByTimeAsync(10000);
    await vi.waitFor(() => expect(logsCount(calls)).toBe(2));
  });

  it('暂停停止轮询；继续立即补一帧', async () => {
    const calls = installFetchMock({
      routes: {
        '/console/recent_logs': [200, RECENT_LOGS_PAYLOAD],
        '/console/dashboard': [200, DASHBOARD_PAYLOAD],
      },
    });
    renderView();
    await vi.waitFor(() => expect(screen.getByText('DS-T-10:00')).toBeTruthy());
    await vi.waitFor(() => expect(logsCount(calls)).toBe(1));

    fireEvent.click(screen.getByRole('button', { name: '暂停' }));
    await vi.advanceTimersByTimeAsync(12000);
    expect(logsCount(calls)).toBe(1);

    fireEvent.click(screen.getByRole('button', { name: '继续' }));
    await vi.advanceTimersByTimeAsync(200);
    expect(logsCount(calls)).toBe(2);
  });

  it('聚合与回退双失败时呈现错误条', async () => {
    installFetchMock({
      routes: {
        '/console/dashboard': [500, { message: '聚合不可用' }],
        '/api/': [500, { message: '服务不可用' }],
      },
    });
    renderView();
    await vi.waitFor(() => expect(screen.getByText(/HTTP 500/)).toBeTruthy());
  });
});
