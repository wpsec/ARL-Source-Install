// DataTable 状态面契约（计划 4 UI 验收·表格/空态/加载态/虚拟滚动）。
// 分页与筛选属于消费方（TableModuleView）语义，在 api/query.integration.test.tsx
// 以 harness 方式覆盖数据流；此处钉死组件自身的渲染分支。
import { render } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { DataTable, type DataTableColumn } from './DataTable';

// react-virtual 的 measureElement 依赖 ResizeObserver；jsdom 无实现时给空壳，
// 让虚拟分支在“测结构不测测高”的口径下稳定运行。
if (!('ResizeObserver' in globalThis)) {
  (globalThis as Record<string, unknown>).ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  };
}

type Row = { id: string; name: string | string[]; status?: string };

const columns: Array<DataTableColumn<Row>> = [
  { key: 'name', header: '名称', getValue: (row) => row.name },
  { key: 'status', header: '状态', render: (row) => <b>{row.status ?? '-'}</b> },
  { key: 'missing', header: '缺失列' },
];

function makeRows(count: number): Row[] {
  return Array.from({ length: count }, (_, i) => ({ id: `r${i}`, name: `行${i}` }));
}

function getBodyRowCount(container: HTMLElement): number {
  return container.querySelectorAll('tbody tr').length;
}

describe('DataTable', () => {
  it('loading 优先于行数据（防竞态闪烁）', () => {
    const { container, queryByText } = render(
      <DataTable columns={columns} rows={makeRows(3)} rowKey={(r) => r.id} loading />,
    );
    expect(queryByText('加载中…')).toBeTruthy();
    expect(getBodyRowCount(container)).toBe(1);
  });

  it('空集合显示默认与自定义 emptyText', () => {
    const { container, queryByText } = render(
      <DataTable columns={columns} rows={[]} rowKey={(r) => r.id} />,
    );
    expect(queryByText('暂无数据')).toBeTruthy();

    const second = render(
      <DataTable columns={columns} rows={[]} rowKey={(r) => r.id} emptyText="无匹配结果" />,
    );
    expect(second.queryByText('无匹配结果')).toBeTruthy();
    expect(container.querySelector('table')).toBeTruthy();
  });

  it('≤ 阈值时全量渲染，getValue/render/缺字段回退都按列定义', () => {
    const { container } = render(
      <DataTable
        columns={columns}
        rows={[{ id: 'a', name: 'Alpha', status: 'ok' }, { id: 'b', name: 'Beta' }]}
        rowKey={(r) => r.id}
      />,
    );
    expect(getBodyRowCount(container)).toBe(2);
    const text = container.textContent ?? '';
    expect(text).toContain('Alpha');
    expect(text).toContain('ok');
    // missing 列无 getValue/render，按 key 取不到 → '-'
    expect(container.querySelectorAll('tbody td').length).toBe(6);
    const missingCells = Array.from(container.querySelectorAll('tbody tr')).map(
      (tr) => tr.children[2]?.textContent,
    );
    expect(missingCells.every((cell) => cell === '-')).toBe(true);
  });

  it('默认文本单元格保留多值换行并允许折行', () => {
    const { container } = render(
      <DataTable
        columns={columns}
        rows={[{ id: 'multi', name: 'Alpha\nBeta' }]}
        rowKey={(r) => r.id}
      />,
    );
    const value = container.querySelector('tbody tr td span');
    expect(value?.textContent).toBe('Alpha\nBeta');
    expect(value?.className).toContain('whitespace-pre-wrap');
  });

  it('默认数组单元格统一按行展示', () => {
    const { container } = render(
      <DataTable
        columns={columns}
        rows={[{ id: 'multi-array', name: ['Alpha', 'Beta'] }]}
        rowKey={(r) => r.id}
      />
    );
    const value = container.querySelector('tbody tr td span');
    expect(value?.textContent).toBe('Alpha\nBeta');
    expect(value?.className).toContain('whitespace-pre-wrap');
  });

  it('> 阈值进入虚拟滚动：内部滚动容器出现且 DOM 行数收敛', () => {
    const { container } = render(
      <DataTable columns={columns} rows={makeRows(201)} rowKey={(r) => r.id} />,
    );
    const scroller = container.firstElementChild as HTMLElement;
    expect(scroller.className).toContain('overflow-y-auto');
    expect(getBodyRowCount(container)).toBeLessThan(201);
  });

  it('阈值边界（200 行）保持普通渲染', () => {
    const { container } = render(
      <DataTable columns={columns} rows={makeRows(200)} rowKey={(r) => r.id} />,
    );
    const scroller = container.firstElementChild as HTMLElement;
    expect(scroller.className).not.toContain('overflow-y-auto');
    expect(getBodyRowCount(container)).toBe(200);
  });

  it('tableClass 透传、zebra 可关', () => {
    const { container } = render(
      <DataTable columns={columns} rows={makeRows(1)} rowKey={(r) => r.id} zebra={false} tableClass="text-xs" />,
    );
    const table = container.querySelector('table')!;
    expect(table.className).toContain('text-xs');
    expect(table.className).not.toContain('table-zebra');
  });
});
