import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { installFetchMock } from '../test/fetchMock';
import { SystemMonitorMiniWidget } from './SystemMonitorMiniWidget';

const MONITOR_PAYLOAD = {
  code: 200,
  data: {
    resource: {
      cpu_percent: 24.5,
      memory_percent: 48.2,
      network_rate_total_kbps: 15,
      network_total_sent: '1.2 GB',
      network_total_recv: '3.4 GB',
      process_count: 86,
    },
    history_24h: [
      { time: '10:00', cpu: 20, ram: 44, net: 10 },
      { time: '10:15', cpu: 24.5, ram: 48.2, net: 15 },
    ],
  },
};

function renderWidget(onOpen = vi.fn()) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return {
    onOpen,
    ...render(
      <QueryClientProvider client={client}>
        <SystemMonitorMiniWidget token="tk-monitor" onOpen={onOpen} />
      </QueryClientProvider>,
    ),
  };
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('SystemMonitorMiniWidget', () => {
  it('展示三项折线指标和三个累计统计', async () => {
    const calls = installFetchMock({ routes: { '/console/system_monitor/': [200, MONITOR_PAYLOAD] } });
    renderWidget();

    await vi.waitFor(() => expect(screen.getByText('24.5%')).toBeTruthy());
    expect(screen.getByText('48.2%')).toBeTruthy();
    expect(screen.getByText('15.0 KB/s')).toBeTruthy();
    expect(screen.getByText('1.2 GB')).toBeTruthy();
    expect(screen.getByText('3.4 GB')).toBeTruthy();
    expect(screen.getByText('86')).toBeTruthy();
    expect(screen.getByText('累计发送')).toBeTruthy();
    expect(screen.getByText('累计接收')).toBeTruthy();
    expect(screen.getByText('进程数量')).toBeTruthy();
    expect(screen.getByText('CPU').className).toContain('shrink-0');
    expect(screen.getByText('CPU').parentElement?.className).toContain('justify-between');
    expect(screen.getByRole('group', { name: 'CPU、内存与网速' }).className).toContain('rounded-box');
    expect(screen.getByRole('region', { name: '系统监控摘要' }).className).toContain('shrink-0');
    expect(screen.queryByTestId('system-monitor-icon')).toBeNull();
    expect(screen.queryByText('实时运行')).toBeNull();
    expect(screen.queryByText('系统监控')).toBeNull();
    expect(calls.some((call) => call.url.includes('/console/system_monitor/'))).toBe(true);
  });

  it('点击外链打开完整系统监控页', async () => {
    const onOpen = vi.fn();
    installFetchMock({ routes: { '/console/system_monitor/': [200, MONITOR_PAYLOAD] } });
    renderWidget(onOpen);

    await vi.waitFor(() => expect(screen.getByText('24.5%')).toBeTruthy());
    fireEvent.click(screen.getByRole('button', { name: '打开系统监控' }));
    expect(onOpen).toHaveBeenCalledTimes(1);
  });

  it('监控接口失败时保留布局并显示占位值', async () => {
    installFetchMock({ routes: { '/console/system_monitor/': [500, { message: '不可用' }] } });
    renderWidget();

    await vi.waitFor(() => expect(screen.getAllByText('--')).toHaveLength(3));
    expect(screen.getByText('CPU')).toBeTruthy();
    expect(screen.queryByLabelText('资源状态不可用')).toBeNull();
  });
});
