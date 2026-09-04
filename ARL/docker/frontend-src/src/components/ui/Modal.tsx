import { useEffect, useRef, type ReactNode } from 'react';

/**
 * 全站唯一弹窗实现（docs/04 组件映射）：原生 <dialog> 获得焦点陷阱、Esc、
 * inert 背景行为；遮罩点击关闭由 target===dialog 判定。
 * 内容滚动不在本组件发生——body 用 Phase0 统一的 max-h-[72vh] 白名单滚动类，
 * 避免 modal-box 与内容区双滚动条。
 */
export function Modal({
  open,
  onClose,
  children,
  boxClass = 'max-w-lg!',
  dismissable = true,
  labelledBy,
}: {
  open: boolean;
  onClose: () => void;
  children: ReactNode;
  /** 宽度等 box 级覆写（如 "max-w-5xl!"），感叹号后缀确保压过 daisy 默认 max-width。 */
  boxClass?: string;
  dismissable?: boolean;
  labelledBy?: string;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const boxRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    if (open && !el.open) {
      el.showModal();
    } else if (!open && el.open) {
      el.close();
    }
  }, [open]);

  // 无障碍名：打开时把 box 内首个标题挂给 dialog，19 个调用点无需逐个传 labelledBy。
  useEffect(() => {
    if (!open) return;
    const el = ref.current;
    const heading = boxRef.current?.querySelector('h4, h3, [data-modal-title]');
    if (!el || !heading) return;
    if (!heading.id) heading.id = `modal-title-${Math.random().toString(36).slice(2, 8)}`;
    el.setAttribute('aria-labelledby', heading.id);
  }, [open]);

  return (
    <dialog
      ref={ref}
      className="modal"
      aria-labelledby={labelledBy}
      onClose={() => {
        // Esc/外部关闭统一走父级状态收敛（open 仍为 true 时说明是原生路径触发）
        if (open) onClose();
      }}
      onClick={(event) => {
        if (dismissable && event.target === ref.current) onClose();
      }}
    >
      <div ref={boxRef} className={`arl-modal-box ${boxClass}`}>{children}</div>
    </dialog>
  );
}
