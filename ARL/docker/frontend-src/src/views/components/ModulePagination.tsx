import { ChevronDown, ChevronLeft, ChevronRight } from 'lucide-react';
import { CONSOLE_ICON_BUTTON_CLASS, UNIFIED_SELECT_CLASS } from '../../ui/classes';

export function ModulePagination({
  total,
  page,
  totalPages,
  pageOptions,
  size,
  onPageChange,
  onPageSizeChange,
}: {
  total: number;
  page: number;
  totalPages: number;
  pageOptions: number[];
  size: number;
  onPageChange: (page: number) => void;
  onPageSizeChange: (size: number) => void;
}) {
  return (
    <div className="flex flex-col gap-3 border-t border-base-300 bg-base-100 px-4 py-3 md:flex-row md:items-center md:justify-between">
      <div className="text-xs font-semibold text-content-muted">
        共 {total} 条，当前第 {page}/{totalPages} 页
      </div>
      <div className="flex min-w-0 flex-wrap items-center gap-2">
        <button
          type="button"
          aria-label="上一页"
          onClick={() => onPageChange(Math.max(1, page - 1))}
          disabled={page <= 1}
          className={`${CONSOLE_ICON_BUTTON_CLASS} disabled:opacity-40`}
        >
          <ChevronLeft className="h-4 w-4" />
        </button>
        <div className="relative">
          <select
            aria-label="当前页"
            value={String(page)}
            onChange={(event) => {
              const nextPage = Number(event.target.value || 1);
              if (!Number.isFinite(nextPage)) return;
              onPageChange(Math.max(1, Math.min(totalPages, Math.floor(nextPage))));
            }}
            className={`${UNIFIED_SELECT_CLASS} w-auto min-w-[118px] py-2`}
            title={`当前第 ${page} 页，共 ${totalPages} 页`}
          >
            {pageOptions.map((option) => <option key={option} value={option}>第 {option} 页</option>)}
          </select>
          <ChevronDown className="pointer-events-none absolute right-3 top-1/2 h-4 w-4 -translate-y-1/2 text-content-muted" />
        </div>
        <div className="relative">
          <select
            aria-label="每页条数"
            value={size}
            onChange={(event) => {
              const nextSize = Number(event.target.value);
              if (!Number.isFinite(nextSize) || nextSize <= 0) return;
              onPageSizeChange(nextSize);
            }}
            className={`${UNIFIED_SELECT_CLASS} w-auto min-w-[108px] py-2`}
          >
            {[10, 20, 50, 100, 200, 500].map((option) => <option key={option} value={option}>{option} / 页</option>)}
          </select>
          <ChevronDown className="pointer-events-none absolute right-3 top-1/2 h-4 w-4 -translate-y-1/2 text-content-muted" />
        </div>
        <button
          type="button"
          aria-label="下一页"
          onClick={() => onPageChange(Math.min(totalPages, page + 1))}
          disabled={page >= totalPages}
          className={`${CONSOLE_ICON_BUTTON_CLASS} disabled:opacity-40`}
        >
          <ChevronRight className="h-4 w-4" />
        </button>
      </div>
    </div>
  );
}
