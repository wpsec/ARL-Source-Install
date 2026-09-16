import {createPortal} from 'react-dom';
import {isValidElement, useCallback, useEffect, useLayoutEffect, useRef, useState} from 'react';
import type {ReactNode} from 'react';

type HoverCellValueProps = {
  display: ReactNode;
  fullText: string;
  label?: string;
  onCopy?: (text: string, label: string) => void | Promise<void>;
  showHover?: boolean;
  /** 展开/收起类预览即使尚未完成布局测量，也必须允许查看原文。 */
  forceHover?: boolean;
  className?: string;
  displayClassName?: string;
  panelClassName?: string;
};

type PanelPosition = {
  top: number;
  left: number;
};

const VIEWPORT_PADDING = 8;
const PANEL_GAP = 8;
const PANEL_WIDTH = 420;

function getDisplayText(node: ReactNode): string {
  if (node === null || node === undefined || typeof node === 'boolean') return '';
  if (typeof node === 'string' || typeof node === 'number' || typeof node === 'bigint') {
    return String(node);
  }
  if (Array.isArray(node)) return node.map(getDisplayText).join('');
  if (!isValidElement(node)) return '';
  return getDisplayText((node.props as {children?: ReactNode}).children);
}

const clamp = (value: number, minimum: number, maximum: number) =>
  Math.min(Math.max(value, minimum), Math.max(minimum, maximum));

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
  forceHover = false,
  className = '',
  displayClassName = '',
  panelClassName = '',
}: HoverCellValueProps) {
  const copyText = String(fullText ?? '');
  const normalizedCopyText = copyText.trim();
  const hasContent = normalizedCopyText !== '' && normalizedCopyText !== '-';
  const displayText = getDisplayText(display).trim();
  const hasPreviewDifference = displayText !== normalizedCopyText;
  const [isOverflowing, setIsOverflowing] = useState(false);
  const canInspect = showHover && hasContent && (forceHover || isOverflowing || hasPreviewDifference);
  const triggerRef = useRef<HTMLDivElement>(null);
  const panelRef = useRef<HTMLDivElement>(null);
  const closeTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [panelOpen, setPanelOpen] = useState(false);
  const [panelPosition, setPanelPosition] = useState<PanelPosition>({top: VIEWPORT_PADDING, left: VIEWPORT_PADDING});

  const measureOverflow = useCallback(() => {
    const trigger = triggerRef.current;
    if (!trigger) return;

    const elements = [trigger, ...Array.from(trigger.querySelectorAll<HTMLElement>('*'))];
    const overflowing = elements.some((element) => {
      // 尚未布局的虚拟列表节点会返回 0；此时交给 ResizeObserver 在布局完成后重测。
      if (element.clientWidth === 0 && element.clientHeight === 0) return false;
      return element.scrollWidth > element.clientWidth + 1 || element.scrollHeight > element.clientHeight + 1;
    });
    setIsOverflowing((previous) => (previous === overflowing ? previous : overflowing));
  }, []);

  useLayoutEffect(() => {
    if (!showHover || !hasContent) {
      setIsOverflowing(false);
      return undefined;
    }
    measureOverflow();
    const trigger = triggerRef.current;
    if (!trigger || typeof ResizeObserver === 'undefined') return undefined;

    const observer = new ResizeObserver(measureOverflow);
    observer.observe(trigger);
    return () => observer.disconnect();
  }, [displayClassName, displayText, forceHover, hasContent, measureOverflow, showHover]);

  const clearCloseTimer = () => {
    if (closeTimerRef.current === null) return;
    clearTimeout(closeTimerRef.current);
    closeTimerRef.current = null;
  };

  const openPanel = () => {
    clearCloseTimer();
    setPanelOpen(true);
  };

  const scheduleClose = () => {
    clearCloseTimer();
    closeTimerRef.current = setTimeout(() => {
      closeTimerRef.current = null;
      setPanelOpen(false);
    }, 160);
  };

  useEffect(() => () => clearCloseTimer(), []);

  useLayoutEffect(() => {
    if (!panelOpen || !triggerRef.current) return undefined;

    const updatePanelPosition = () => {
      const triggerRect = triggerRef.current?.getBoundingClientRect();
      if (!triggerRect) return;

      const panelRect = panelRef.current?.getBoundingClientRect();
      const panelWidth = panelRect?.width || Math.min(PANEL_WIDTH, window.innerWidth * 0.82);
      const panelHeight = panelRect?.height || 0;
      const left = clamp(
        triggerRect.left + (triggerRect.width - panelWidth) / 2,
        VIEWPORT_PADDING,
        window.innerWidth - panelWidth - VIEWPORT_PADDING,
      );
      const belowTop = triggerRect.bottom + PANEL_GAP;
      const canPlaceAbove = panelHeight > 0
        && triggerRect.top - panelHeight - PANEL_GAP >= VIEWPORT_PADDING;
      const preferredTop = canPlaceAbove && belowTop + panelHeight > window.innerHeight - VIEWPORT_PADDING
        ? triggerRect.top - panelHeight - PANEL_GAP
        : belowTop;
      const top = panelHeight > 0
        ? clamp(preferredTop, VIEWPORT_PADDING, window.innerHeight - panelHeight - VIEWPORT_PADDING)
        : Math.max(VIEWPORT_PADDING, preferredTop);

      setPanelPosition((previous) => (
        previous.top === top && previous.left === left
          ? previous
          : {top, left}
      ));
    };

    updatePanelPosition();
    window.addEventListener('resize', updatePanelPosition);
    window.addEventListener('scroll', updatePanelPosition, true);
    return () => {
      window.removeEventListener('resize', updatePanelPosition);
      window.removeEventListener('scroll', updatePanelPosition, true);
    };
  }, [panelOpen]);

  const displayNode = (
    <div
      ref={triggerRef}
      tabIndex={canInspect ? 0 : undefined}
      aria-label={canInspect ? `查看${label}完整内容` : undefined}
      aria-expanded={canInspect ? panelOpen : undefined}
      onFocus={canInspect ? openPanel : undefined}
      onBlur={canInspect ? scheduleClose : undefined}
      onKeyDown={canInspect ? (event) => {
        if (event.key === 'Escape') {
          clearCloseTimer();
          setPanelOpen(false);
        }
      } : undefined}
      className={`arl-table-cell-content block w-full ${canInspect ? 'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/45 focus-visible:ring-offset-1 focus-visible:ring-offset-base-100' : ''} ${displayClassName}`}
    >
      {display}
    </div>
  );

  if (!canInspect) return displayNode;

  const panel = panelOpen ? (
    <div
      ref={panelRef}
      style={{top: panelPosition.top, left: panelPosition.left}}
      onMouseEnter={openPanel}
      onMouseLeave={scheduleClose}
      onFocusCapture={openPanel}
      onBlurCapture={scheduleClose}
      onKeyDown={(event) => {
        if (event.key === 'Escape') {
          clearCloseTimer();
          setPanelOpen(false);
        }
      }}
      className="fixed z-[100] w-[420px] max-w-[82vw]"
    >
      <div className={`rounded-box border border-base-300 bg-base-200 p-3 text-left shadow-lg ${panelClassName}`}>
        <div className="flex items-center justify-between gap-3">
          <div className="text-xs font-black tracking-wide text-base-content">{label}完整内容</div>
          {onCopy ? (
            <button
              type="button"
              aria-label={`复制${label}`}
              onClick={() => void onCopy(copyText, label)}
              className="btn btn-ghost btn-xs shrink-0 text-accent"
            >
              复制
            </button>
          ) : null}
        </div>
        <div className="mt-2 max-h-52 overflow-y-auto rounded-box border border-base-300 bg-base-100 p-2 text-xs leading-relaxed text-base-content whitespace-pre-wrap break-all">
          {copyText}
        </div>
      </div>
    </div>
  ) : null;

  return (
    <div
      onMouseEnter={openPanel}
      onMouseLeave={scheduleClose}
      className={`arl-table-cell-content relative block w-full align-middle ${className}`}
    >
      {displayNode}
      {typeof document === 'undefined' ? null : createPortal(panel, document.body)}
    </div>
  );
}
