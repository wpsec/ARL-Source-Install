// ActionDialog 数据层测试（计划 4 Phase 3）：新建任务弹窗的字典选项读取迁移
// React Query 后的行为证据——水合、payload 默认补齐、缓存复用、失败呈现。
// 提交/文件上传等 mutation 通道不在本批改动范围，仅做存在性冒烟。
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { installFetchMock } from '../test/fetchMock';
import { ActionDialog } from './ActionDialog';

const SCAN_CONFIG_PAYLOAD = {
  code: 200,
  data: {
    scan_config: {
      domain_dict: '/code/app/dicts/domain/default.txt',
      file_leak_dict: '/code/app/dicts/file_leak/default.txt',
    },
    available_domain_dicts: [
      { label: 'big2w', path: '/code/app/dicts/domain/domain_2w.txt', source: 'builtin', exists: true, size: 100 },
      { label: 'default', path: '/code/app/dicts/domain/default.txt', source: 'custom', exists: true, size: 10 },
    ],
    available_file_leak_dicts: [
      { label: 'leak2k', path: '/code/app/dicts/file_leak/file_top_2000.txt', source: 'builtin', exists: true, size: 50 },
    ],
  },
};

const CREATE_TASK_ACTION = {
  id: 'create_task',
  label: '新建任务',
  method: 'POST',
  path: '/task/',
} as any;

const GENERIC_ARRAY_ACTION = {
  id: 'generic_array_action',
  label: '通用动作',
  method: 'POST',
  path: '/generic/',
} as any;

function renderDialog(client: QueryClient) {
  return render(
    <QueryClientProvider client={client}>
      <ActionDialog
        token="tk-action"
        action={CREATE_TASK_ACTION}
        initialPayload={{}}
        onClose={vi.fn()}
        onSubmit={vi.fn(async () => {})}
      />
    </QueryClientProvider>,
  );
}

function renderGenericArrayDialog(client: QueryClient) {
  return render(
    <QueryClientProvider client={client}>
      <ActionDialog
        token="tk-action"
        action={GENERIC_ARRAY_ACTION}
        initialPayload={{ targets: ['alpha.example', 'beta.example'] }}
        onClose={vi.fn()}
        onSubmit={vi.fn(async () => {})}
      />
    </QueryClientProvider>,
  );
}

function newClient() {
  return new QueryClient({ defaultOptions: { queries: { retry: false } } });
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('ActionDialog 字典选项读取（React Query）', () => {
  it('新建任务底部操作栏保持可见结构', async () => {
    installFetchMock({
      routes: { '/api_console/scan_config/': [200, SCAN_CONFIG_PAYLOAD] },
    });
    renderDialog(newClient());

    const footer = await screen.findByTestId('action-dialog-footer');
    expect(footer.className).toContain('shrink-0');
    expect(footer.className).toContain('border-t');
    expect(footer.parentElement?.classList.contains('arl-modal-box')).toBe(true);
    expect(screen.getByRole('button', { name: '取消' })).toBeTruthy();
    expect(screen.getByRole('button', { name: '执行' })).toBeTruthy();
  });

  it('通用数组字段以多行文本框回显', () => {
    renderGenericArrayDialog(newClient());
    const textarea = screen.getByPlaceholderText('多个值请换行输入') as HTMLTextAreaElement;
    expect(textarea.value).toBe('alpha.example\nbeta.example');
  });

  it('水合选项列表并按“大字典优先”补齐 payload 默认值', async () => {
    const calls = installFetchMock({
      routes: { '/api_console/scan_config/': [200, SCAN_CONFIG_PAYLOAD] },
    });
    renderDialog(newClient());
    await screen.findByText(/big2w \[builtin\]/);
    await vi.waitFor(() => {
      const dictSelect = screen
        .getAllByRole('combobox')
        .find((select) =>
          Array.from((select as HTMLSelectElement).options).some(
            (option) => option.value === '/code/app/dicts/domain/domain_2w.txt',
          ),
        ) as HTMLSelectElement | undefined;
      expect(dictSelect, '域名字典 select 未渲染').toBeTruthy();
      expect(dictSelect!.value).toBe('/code/app/dicts/domain/domain_2w.txt');
    });
  });

  it('关闭后重开弹窗：staleTime 内命中查询缓存，不重复请求', async () => {
    const calls = installFetchMock({
      routes: { '/api_console/scan_config/': [200, SCAN_CONFIG_PAYLOAD] },
    });
    const client = newClient();
    const first = renderDialog(client);
    await screen.findByText(/big2w \[builtin\]/);
    first.unmount();
    renderDialog(client);
    await screen.findByText(/big2w \[builtin\]/);
    expect(calls.filter((c) => c.url.includes('/scan_config/'))).toHaveLength(1);
  });

  it('选项读取失败：错误条呈现且表单不被静默清空伪装', async () => {
    installFetchMock({
      routes: { '/api_console/scan_config/': [500, { message: '字典接口异常' }] },
    });
    renderDialog(newClient());
    await vi.waitFor(() => expect(screen.getAllByText(/HTTP 500/).length).toBeGreaterThan(0));
    expect(screen.queryByText(/big2w/)).toBeNull();
  });
});
