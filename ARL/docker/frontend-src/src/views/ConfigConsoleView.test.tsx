// 配置管理页级测试（计划 4·初始化读取迁移 React Query 的回归锚点）：
// 快照水合、加载失败呈现、手动重新加载 = query.refetch、保存/上传 mutation 行为保留。
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { installFetchMock } from '../test/fetchMock';
import { ConfigConsoleView } from './ConfigConsoleView';

const SCAN_CONFIG_PAYLOAD = {
  code: 200,
  data: {
    scan_config: {
      domain_dict: '/code/app/dicts/domain/custom.txt',
      file_leak_dict: '/code/app/dicts/file_leak/custom.txt',
      domain_brute_concurrent: 360,
      alt_dns_concurrent: 1408,
      web_gunicorn_workers: 4,
      black_ips: ['127.0.0.0/8', '10.0.0.0/8'],
      dns_resolvers: ['223.5.5.5'],
    },
    available_domain_dicts: [
      { label: 'custom', path: '/code/app/dicts/domain/custom.txt', source: 'custom', exists: true, size: 10 },
    ],
    available_file_leak_dicts: [
      { label: 'custom', path: '/code/app/dicts/file_leak/custom.txt', source: 'custom', exists: true, size: 10 },
    ],
    config_path: '/code/app/config.yaml',
    updated_at: '2026-09-07 10:00:00',
  },
};

function renderView() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <ConfigConsoleView token="tk-cfg" />
    </QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('ConfigConsoleView 初始化读取（React Query）', () => {
  it('GET 快照水合表单：数字输入与多行文本取服务端值', async () => {
    const calls = installFetchMock({
      routes: { '/api_console/scan_config/': [200, SCAN_CONFIG_PAYLOAD] },
    });
    renderView();
    expect(screen.getByText('配置管理')).toBeTruthy();
    await waitFor(() => expect(calls.filter((c) => c.url.includes('scan_config') && c.method === 'GET')).toHaveLength(1));
    // alt_dns_concurrent=1408 / web_gunicorn_workers=4 水合到输入框。
    await screen.findByDisplayValue('1408');
    await screen.findByDisplayValue('4');
    // black_ips 数组按 \n 拼接进水合 textarea。
    await waitFor(() => {
      const el = document.getElementById('config-black-ips') as HTMLTextAreaElement | null;
      expect(el, 'black_ips textarea 未渲染').toBeTruthy();
      expect(el!.value).toBe('127.0.0.0/8\n10.0.0.0/8');
    });
    // 单查询源：挂载只发一次 GET（React Query 去重，StrictMode 安全）。
    expect(calls.filter((c) => c.method === 'GET')).toHaveLength(1);
  });

  it('加载失败呈现服务端消息，不静默空表单', async () => {
    installFetchMock({
      routes: { '/scan_config/': [500, { message: '配置读取失败' }] },
    });
    renderView();
    await waitFor(() => expect(screen.getByText(/HTTP 500/)).toBeTruthy());
    expect(screen.getByText('配置管理')).toBeTruthy();
  });

  it('“重新加载”按钮触发 query refetch', async () => {
    const calls = installFetchMock({
      routes: { '/api_console/scan_config/': [200, SCAN_CONFIG_PAYLOAD] },
    });
    renderView();
    await screen.findByDisplayValue('1408');
    fireEvent.click(screen.getByRole('button', { name: /重新加载/ }));
    await waitFor(() =>
      expect(calls.filter((c) => c.method === 'GET' && c.url.includes('scan_config'))).toHaveLength(2),
    );
  });

  it('保存 mutation 保留：POST 提交 + 成功反馈 + 重启提示 Modal', async () => {
    const calls = installFetchMock({
      // GET 与 POST 同路径共用快照响应（saveScanConfig 消费 data.scan_config 回写）。
      routes: {
        '/api_console/scan_config/': [200, SCAN_CONFIG_PAYLOAD],
      },
    });
    renderView();
    await screen.findByDisplayValue('1408');
    fireEvent.click(screen.getByRole('button', { name: '保存配置' }));
    await waitFor(() =>
      expect(calls.some((c) => c.method === 'POST' && c.url.includes('/api_console/scan_config/'))).toBe(true),
    );
    await waitFor(() => expect(screen.getByText(/扫描配置已保存/)).toBeTruthy());
    await waitFor(() => expect(screen.getByText('需要重启容器')).toBeTruthy());
  });

  it('上传 mutation 保留：未选文件时给校验错误且不发请求', async () => {
    const calls = installFetchMock({
      routes: { '/api_console/scan_config/': [200, SCAN_CONFIG_PAYLOAD] },
    });
    renderView();
    await screen.findByDisplayValue('1408');
    fireEvent.click(screen.getByRole('button', { name: '上传域名爆破字典' }));
    await waitFor(() => expect(screen.getByText('请先选择要上传的字典文件')).toBeTruthy());
    expect(calls.some((c) => c.url.includes('upload'))).toBe(false);
  });
});
