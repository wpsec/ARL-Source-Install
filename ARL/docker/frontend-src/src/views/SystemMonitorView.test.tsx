// 系统监控页级测试（计划 4 监控批次）：主查询水合、3s 轮询、
// 主查询失败回退 dashboard、双失败错误呈现、刷新按钮 refetch。
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { installFetchMock, makeHttpResponse } from '../test/fetchMock';
import { SystemMonitorView } from './SystemMonitorView';

const MONITOR_PAYLOAD = {
  code: 200,
  data: {
    resource: {
      cpu_percent: 12.5,
      cpu_count: 8,
      memory_percent: 40,
      memory_used: '3.2 GiB',
      memory_total: '8 GiB',
      disk_percent: 61,
      disk_used: '61 GiB',
      disk_total: '100 GiB',
      network_rate_in_kbps: 10,
      network_rate_out_kbps: 5,
      network_rate_total_kbps: 15,
    },
    history_24h: [{ time: '10:00', cpu: 10, ram: 30, disk: 60, net_in: 1, net_out: 2, net: 3 }],
    updated_at: '2026-09-07 12:00:00',
  },
};

const DASHBOARD_FALLBACK_PAYLOAD = {
  code: 200,
  data: {
    device_info: { cpu: { percent: '35.5', count: 4 }, memory: { percent: '50' }, disk: { percent: '20' } },
    network_trend: [],
    last_updated: 'FB-2026-09-07',
  },
};

function newClient() {
  return new QueryClient({ defaultOptions: { queries: { retry: false } } });
}

function renderView(client = newClient()) {
  return render(
    <QueryClientProvider client={client}>
      <SystemMonitorView token="tk-mon" />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe('SystemMonitorView（React Query 轮询）', () => {
  it('主查询渲染资源快照与更新时间', async () => {
    const calls = installFetchMock({
      routes: { '/console/system_monitor/': [200, MONITOR_PAYLOAD] },
    });
    renderView();
    await vi.waitFor(() => expect(screen.getByText('2026-09-07 12:00:00')).toBeTruthy());
    expect(screen.getByText('系统监控')).toBeTruthy();
    expect(calls.some((c) => c.url.includes('/console/system_monitor/'))).toBe(true);
    // 回退查询保持关闭：不发 dashboard 请求。
    expect(calls.some((c) => c.url.includes('/console/dashboard'))).toBe(false);
  });

  it('3s 轮询：refetchInterval 触发第二次主查询', async () => {
    const calls = installFetchMock({
      routes: { '/console/system_monitor/': [200, MONITOR_PAYLOAD] },
    });
    renderView();
    await vi.waitFor(() => expect(calls.filter((c) => c.url.includes('system_monitor')).length).toBe(1));
    await vi.advanceTimersByTimeAsync(3000);
    await vi.waitFor(() => expect(calls.filter((c) => c.url.includes('system_monitor')).length).toBe(2));
  });

  it('主查询失败自动回退 dashboard 快照', async () => {
    const calls = installFetchMock({
      routes: {
        '/console/system_monitor/': [500, { message: '监控接口不可用' }],
        '/console/dashboard': [200, DASHBOARD_FALLBACK_PAYLOAD],
      },
    });
    renderView();
    await vi.waitFor(() => expect(screen.getByText('FB-2026-09-07')).toBeTruthy());
    expect(calls.some((c) => c.url.includes('/console/dashboard'))).toBe(true);
    // 主查询失败但回退成功：不呈现错误条（与迁移前语义一致）。
    expect(screen.queryByText(/HTTP 500/)).toBeNull();
  });

  it('双失败呈现错误消息', async () => {
    installFetchMock({
      routes: {
        '/console/system_monitor/': [500, { message: '监控接口不可用' }],
        '/console/dashboard': [500, { message: '概览也不可用' }],
      },
    });
    renderView();
    await vi.waitFor(() => expect(screen.getByText(/HTTP 500/)).toBeTruthy());
  });

  it('刷新按钮触发 refetch', async () => {
    const calls = installFetchMock({
      routes: { '/console/system_monitor/': [200, MONITOR_PAYLOAD] },
    });
    renderView();
    // 等首轮数据落地（fetch 发起时按钮仍 disabled=isFetching）。
    await vi.waitFor(() => expect(screen.getByText('2026-09-07 12:00:00')).toBeTruthy());
    fireEvent.click(screen.getByRole('button', { name: /刷新/ }));
    await vi.advanceTimersByTimeAsync(200);
    expect(calls.filter((c) => c.url.includes('system_monitor')).length).toBe(2);
  });
});

describe('SystemMonitorView 失效与恢复覆盖', () => {
  const monitorGets = (calls: Array<{ url: string }>) =>
    calls.filter((c) => c.url.includes('/console/system_monitor/')).length;

  it('外部 invalidate 触发主查询重取', async () => {
    const calls = installFetchMock({
      routes: { '/console/system_monitor/': [200, MONITOR_PAYLOAD] },
    });
    const client = newClient();
    renderView(client);
    // 必须等首轮数据落地（fetching 中的 invalidate 会被进行中的请求合并吞掉）。
    await vi.waitFor(() => expect(screen.getByText('2026-09-07 12:00:00')).toBeTruthy());
    expect(monitorGets(calls)).toBe(1);
    void client.invalidateQueries({ queryKey: ['system-monitor', 'tk-mon'] });
    await vi.waitFor(() => expect(monitorGets(calls)).toBe(2));
  });

  it('主接口故障恢复后，快照优先级自动切回主数据（让位于回退的正确性）', async () => {
    let monitorOk = false;
    vi.stubGlobal('fetch', vi.fn(async (url: string) => {
      if (url.includes('/console/system_monitor/')) {
        return makeHttpResponse(monitorOk ? 200 : 500, monitorOk ? MONITOR_PAYLOAD : { message: '不可用' });
      }
      if (url.includes('/console/dashboard')) {
        return makeHttpResponse(200, DASHBOARD_FALLBACK_PAYLOAD);
      }
      return makeHttpResponse(200, { code: 200, data: {} });
    }));
    const client = newClient();
    renderView(client);
    await vi.waitFor(() => expect(screen.getByText('FB-2026-09-07')).toBeTruthy());

    monitorOk = true;
    await client.invalidateQueries({ queryKey: ['system-monitor', 'tk-mon'] });
    await vi.waitFor(() => expect(screen.getByText('2026-09-07 12:00:00')).toBeTruthy());
    expect(screen.queryByText('FB-2026-09-07')).toBeNull();
    expect(screen.queryByText(/HTTP 500/)).toBeNull();
  });
});
