import { Fragment, useRef } from 'react';
import type { ReactNode } from 'react';
import { useVirtualizer } from '@tanstack/react-virtual';

/** 超过该行数启用虚拟滚动（docs/04：超长列表 >200 虚拟滚动）。 */
const VIRTUALIZE_THRESHOLD = 200;

/**
 * 列定义驱动的数据表（docs/04 组件映射：替代 columns 字符串魔法 + 手写 table）。
 * 默认纵向滚动交给页面 main（单滚动源）；超宽仅横向 overflow-x-auto。
 * 行数 >200 时进入内部虚拟滚动白名单（有确定高度来源 + custom-scrollbar）。
 */
export type DataTableColumn<Row> = {
  key: string;
  header: ReactNode;
  render?: (row: Row, index: number) => ReactNode;
  headerClass?: string;
  cellClass?: string;
  getValue?: (row: Row) => unknown;
};

export function DataTable<Row extends object>({
  columns,
  rows,
  rowKey,
  loading = false,
  emptyText = '暂无数据',
  zebra = true,
  dense = false,
  tableClass = '',
  virtualizedMaxHeightClass = 'max-h-[72vh]',
  renderHeader,
  renderRow,
}: {
  columns: Array<DataTableColumn<Row>>;
  rows: Row[];
  rowKey: (row: Row, index: number) => string;
  loading?: boolean;
  emptyText?: ReactNode;
  zebra?: boolean;
  dense?: boolean;
  /** 追加到 table 元素的尺寸类（如 text-xs 密集表）。 */
  tableClass?: string;
  /** 虚拟模式下的内部滚动高度来源（白名单要求确定高度）。 */
  virtualizedMaxHeightClass?: string;
  /** 页面级表格需要保留列排序、选择和业务操作时，自定义表头。 */
  renderHeader?: () => ReactNode;
  /** 页面级表格需要保留复杂单元格交互时，自定义行；仍由 DataTable 统一承载列表和虚拟滚动。 */
  renderRow?: (row: Row, index: number) => ReactNode;
}) {
  const cellPad = dense ? 'px-3 py-2' : 'px-4 py-3';
  const parentRef = useRef<HTMLDivElement>(null);
  const shouldVirtualize = !loading && rows.length > VIRTUALIZE_THRESHOLD;
  const rowVirtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => (dense ? 38 : 46),
    overscan: 10,
    enabled: shouldVirtualize,
  });

  const renderCells = (row: Row, index: number) =>
    columns.map((column) => (
      <td key={column.key} className={`${cellPad} ${column.cellClass ?? 'text-center'}`}>
        {column.render
          ? column.render(row, index)
          : String(column.getValue ? column.getValue(row) : ((row as Record<string, unknown>)[column.key] ?? '-'))
        }
      </td>
    ));

  const virtualItems = shouldVirtualize ? rowVirtualizer.getVirtualItems() : [];
  const virtualTotal = shouldVirtualize ? rowVirtualizer.getTotalSize() : 0;
  const firstStart = virtualItems.length ? virtualItems[0].start : 0;
  const lastEnd = virtualItems.length ? virtualItems[virtualItems.length - 1].end : 0;

  return (
    <div
      ref={parentRef}
      className={`overflow-x-auto custom-scrollbar${shouldVirtualize ? ` overflow-y-auto ${virtualizedMaxHeightClass}` : ''}`}
    >
      <table className={`table text-sm md:text-[15px] ${zebra ? 'table-zebra' : ''} ${tableClass}`}>
        <thead className="bg-base-200 border-b border-base-300">
          {renderHeader ? renderHeader() : (
            <tr>
              {columns.map((column) => (
                <th
                  key={column.key}
                  className={`${cellPad} text-sm font-semibold whitespace-nowrap ${
                    column.headerClass ?? 'text-base-content/60 text-center'
                  }`}
                >
                  {column.header}
                </th>
              ))}
            </tr>
          )}
        </thead>
        <tbody>
          {loading ? (
            <tr>
              <td colSpan={columns.length} className={`${cellPad} text-center text-base-content/60`}>
                <span className="inline-flex items-center gap-2">
                  <span className="loading loading-spinner loading-xs" />
                  加载中…
                </span>
              </td>
            </tr>
          ) : rows.length === 0 ? (
            <tr>
              <td colSpan={columns.length} className={`${cellPad} text-center text-base-content/60`}>
                {emptyText}
              </td>
            </tr>
          ) : shouldVirtualize ? (
            <>
              {firstStart > 0 ? (
                <tr aria-hidden style={{ height: firstStart }}>
                  <td colSpan={columns.length} className="!p-0 !border-0" />
                </tr>
              ) : null}
              {virtualItems.map((virtualRow) => {
                const index = virtualRow.index;
                const row = rows[index];
                if (renderRow) return <Fragment key={rowKey(row, index)}>{renderRow(row, index)}</Fragment>;
                return (
                  <tr
                    key={rowKey(row, index)}
                    data-index={index}
                    ref={rowVirtualizer.measureElement}
                    className="border-b border-base-300/50 hover:bg-base-200/60 transition-colors"
                  >
                    {renderCells(row, index)}
                  </tr>
                );
              })}
              {virtualTotal - lastEnd > 0 ? (
                <tr aria-hidden style={{ height: virtualTotal - lastEnd }}>
                  <td colSpan={columns.length} className="!p-0 !border-0" />
                </tr>
              ) : null}
            </>
          ) : (
            rows.map((row, index) => renderRow ? (
              <Fragment key={rowKey(row, index)}>{renderRow(row, index)}</Fragment>
            ) : (
              <tr key={rowKey(row, index)} className="border-b border-base-300/50 hover:bg-base-200/60 transition-colors">
                {renderCells(row, index)}
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}
