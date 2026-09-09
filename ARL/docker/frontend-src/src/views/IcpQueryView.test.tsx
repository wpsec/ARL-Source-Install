import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { installFetchMock } from '../test/fetchMock';
import { IcpQueryView } from './IcpQueryView';

const META_PAYLOAD = {
  code: 200,
  data: {
    types: [
      { value: 'web', label: '网站备案', service_type: 1, black: false },
    ],
    max_items: 200,
    page_size: 26,
  },
};

const COMPLETED_TASK = {
  code: 200,
  data: {
    task_id: 'task-1',
    task_kind: 'single',
    query_type: 'web',
    status: 'succeeded',
    total: 1,
    queued_count: 0,
    running_count: 0,
    succeeded_count: 1,
    empty_count: 0,
    failed_count: 0,
    cancelled_count: 0,
    items: [{ item_id: 'item-1', keyword: 'example.com', status: 'succeeded', result_count: 1 }],
  },
};

function renderView() {
  return render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <IcpQueryView token="tk-icp" />
    </QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('IcpQueryView', () => {
  it('展示六个功能标签页，配置管理不出现在页面', async () => {
    renderView();

    expect(screen.getByRole('tab', { name: '查询' })).toBeTruthy();
    expect(screen.getByRole('tab', { name: '批量查询' })).toBeTruthy();
    expect(screen.getByRole('tab', { name: '查询历史' })).toBeTruthy();
    expect(screen.getByRole('tab', { name: '批量任务' })).toBeTruthy();
    expect(screen.getByRole('tab', { name: '系统日志' })).toBeTruthy();
    expect(screen.getByRole('tab', { name: '关于' })).toBeTruthy();
    expect(screen.queryByText('配置管理')).toBeNull();
  });

  it('单次查询完成后支持结果行详情展开', async () => {
    const calls = installFetchMock({
      routes: {
        '/icp/meta': [200, META_PAYLOAD],
        '/icp/query/task-1/results': [200, {
          code: 200,
          data: {
            items: [{ record_type: 'web', company_name: '测试主体', domain: 'example.com' }],
            total: 1,
            page: 1,
            size: 26,
          },
        }],
        '/icp/query/task-1': [200, COMPLETED_TASK],
        '/icp/query': [200, { code: 200, data: { task_id: 'task-1' } }],
      },
    });
    renderView();

    fireEvent.change(screen.getByPlaceholderText('请输入域名、主体名称或应用名称'), { target: { value: 'example.com' } });
    fireEvent.click(screen.getByRole('button', { name: '查询' }));
    await screen.findByText('example.com');
    fireEvent.click(screen.getByRole('button', { name: '展开' }));
    expect(screen.getByText(/"company_name": "测试主体"/)).toBeTruthy();
    expect(calls.some((call) => call.url.includes('/icp/query/task-1/results'))).toBe(true);
  });

  it('日志标签页提交级别和日期范围筛选', async () => {
    const calls = installFetchMock({ routes: { '/icp/meta': [200, META_PAYLOAD] } });
    renderView();

    fireEvent.click(screen.getByRole('tab', { name: '系统日志' }));
    const startDate = await screen.findByLabelText('日志开始日期');
    const endDate = screen.getByLabelText('日志结束日期');
    fireEvent.change(startDate, { target: { value: '2026-09-08' } });
    fireEvent.change(endDate, { target: { value: '2026-09-08' } });
    fireEvent.change(screen.getByRole('combobox', { name: '级别' }), { target: { value: 'ERROR' } });

    await vi.waitFor(() => {
      const logCalls = calls.filter((call) => call.url.includes('/icp/logs'));
      const logCall = logCalls[logCalls.length - 1];
      expect(logCall?.url).toContain('level=ERROR');
      expect(logCall?.url).toContain('created_from=2026-09-08');
      expect(logCall?.url).toContain('created_to=2026-09-08');
    });
  });

  it('总开关闭用态不展示可操作页面', async () => {
    installFetchMock({
      routes: {
        '/icp/meta': [200, { code: 200, data: { enabled: false, types: [], max_items: 200, page_size: 26 } }],
      },
    });
    renderView();

    expect(await screen.findByText('ICP 查询当前已关闭')).toBeTruthy();
    expect(screen.getByRole('tab', { name: '查询' }).hasAttribute('disabled')).toBe(true);
  });

  it('历史接口失败时展示错误状态', async () => {
    installFetchMock({
      routes: {
        '/icp/meta': [200, META_PAYLOAD],
        '/icp/history': [400, { code: 400, message: '历史服务不可用', data: {} }],
      },
    });
    renderView();

    fireEvent.click(screen.getByRole('tab', { name: '查询历史' }));

    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain('查询历史加载失败');
    expect(alert.textContent).toContain('历史服务不可用');
  });
});
