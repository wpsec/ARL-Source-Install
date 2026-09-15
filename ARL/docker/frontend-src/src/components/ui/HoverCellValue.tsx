import type {ReactNode} from 'react';

type HoverCellValueProps = {
  display: ReactNode;
  fullText: string;
  label?: string;
  onCopy: (text: string, label: string) => void | Promise<void>;
  showHover?: boolean;
  className?: string;
  displayClassName?: string;
  panelClassName?: string;
};

/**
 * 固定列只展示紧凑预览，完整内容放在可聚焦的悬浮面板中，避免长文本撑开表格。
 * 复制始终使用未截断的原文，避免浏览器 title 无法选取和复制不完整内容。
 */
export function HoverCellValue({
  display,
  fullText,
  label = '内容',
  onCopy,
  showHover = true,
  className = '',
  displayClassName = '',
  panelClassName = '',
}: HoverCellValueProps) {
  const copyText = String(fullText ?? '');
  const hasContent = copyText.trim() !== '' && copyText.trim() !== '-';
  const canInspect = showHover && hasContent;
  const displayNode = (
    <div
      tabIndex={canInspect ? 0 : undefined}
      aria-label={canInspect ? `查看${label}完整内容` : undefined}
      className={`min-w-0 max-w-full ${canInspect ? 'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/45 focus-visible:ring-offset-1 focus-visible:ring-offset-base-100' : ''} ${displayClassName}`}
    >
      {display}
    </div>
  );

  if (!canInspect) return displayNode;

  return (
    <div className={`group relative inline-block min-w-0 max-w-full align-middle ${className}`}>
      {displayNode}
      <div className="pointer-events-none invisible absolute left-1/2 top-full z-30 w-[420px] max-w-[82vw] -translate-x-1/2 pt-2 opacity-0 transition duration-150 group-hover:pointer-events-auto group-hover:visible group-hover:opacity-100 group-focus-within:pointer-events-auto group-focus-within:visible group-focus-within:opacity-100">
        <div className={`rounded-box border border-base-300 bg-base-200 p-3 text-left shadow-lg ${panelClassName}`}>
          <div className="flex items-center justify-between gap-3">
            <div className="text-xs font-black tracking-wide text-base-content">{label}完整内容</div>
            <button
              type="button"
              aria-label={`复制${label}`}
              onClick={() => void onCopy(copyText, label)}
              className="btn btn-ghost btn-xs shrink-0 text-accent"
            >
              复制
            </button>
          </div>
          <div className="mt-2 max-h-52 overflow-y-auto rounded-box border border-base-300 bg-base-100 p-2 text-xs leading-relaxed text-base-content whitespace-pre-wrap break-all">
            {copyText}
          </div>
        </div>
      </div>
    </div>
  );
}
