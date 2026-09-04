import type { ReactNode } from 'react';

/**
 * 列定义驱动的数据表（docs/04 组件映射：替代 columns 字符串魔法 + 手写 table）。
 * 纵向滚动交给页面 main（单滚动源）；超宽仅横向 overflow-x-auto。
 * 行数 >200 的虚拟滚动在 Phase 4 接入（@tanstack/react-virtual）。
 */
export type DataTableColumn<Row> = {
  key: string;
  header: ReactNode;
  render?: (row: Row, index: number) => ReactNode;
  headerClass?: string;
  cellClass?: string;
  getValue?: (row: Row) => unknown;
};

export function DataTable<Row extends Record<string, any>>({
  columns,
  rows,
  rowKey,
  loading = false,
  emptyText = '暂无数据',
  zebra = true,
  dense = false,
}: {
  columns: Array<DataTableColumn<Row>>;
  rows: Row[];
  rowKey: (row: Row, index: number) => string;
  loading?: boolean;
  emptyText?: ReactNode;
  zebra?: boolean;
  dense?: boolean;
}) {
  const cellPad = dense ? 'px-3 py-2' : 'px-4 py-3';
  return (
    <div className="overflow-x-auto custom-scrollbar">
      <table className={`table text-sm md:text-[15px] ${zebra ? 'table-zebra' : ''}`}>
        <thead className="bg-base-100/40 border-b border-base-300">
          <tr>
            {columns.map((column) => (
              <th
                key={column.key}
                className={`${cellPad} text-sm font-black whitespace-nowrap ${
                  column.headerClass ?? 'text-content-muted text-center'
                }`}
              >
                {column.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {loading ? (
            <tr>
              <td colSpan={columns.length} className={`${cellPad} text-center text-content-muted`}>
                加载中…
              </td>
            </tr>
          ) : rows.length === 0 ? (
            <tr>
              <td colSpan={columns.length} className={`${cellPad} text-center text-content-muted`}>
                {emptyText}
              </td>
            </tr>
          ) : (
            rows.map((row, index) => (
              <tr key={rowKey(row, index)} className="border-b border-base-300/50">
                {columns.map((column) => (
                  <td key={column.key} className={`${cellPad} ${column.cellClass ?? 'text-center'}`}>
                    {column.render
                      ? column.render(row, index)
                      : String(
                          column.getValue ? column.getValue(row) : (row[column.key] ?? '-'),
                        )
                      }
                  </td>
                ))}
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}
