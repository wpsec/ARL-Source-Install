import type { ReactNode } from 'react';

/**
 * 勾选卡片（docs/04 组件映射：替代 CONSOLE_CHECKBOX_CARD_CLASS 手写样式）。
 * daisy 语义：label + input[type=checkbox].checkbox；选中态描边提亮。
 */
export const CHECKBOX_CARD_CLASS =
  'flex items-center gap-2 rounded-xl border border-base-300 bg-base-100 px-3 h-10 text-sm cursor-pointer transition hover:border-accent/60';

export function CheckboxCard({
  checked,
  onChange,
  label,
  hint,
  disabled = false,
  className = '',
}: {
  checked: boolean;
  onChange: (next: boolean) => void;
  label: ReactNode;
  hint?: ReactNode;
  disabled?: boolean;
  className?: string;
}) {
  return (
    <label className={`${CHECKBOX_CARD_CLASS}${checked ? ' border-accent/70' : ''} ${className}`}>
      <input
        type="checkbox"
        className="checkbox checkbox-sm shrink-0"
        checked={checked}
        disabled={disabled}
        onChange={(event) => onChange(event.target.checked)}
      />
      <span className="min-w-0 flex-1 truncate">{label}</span>
      {hint ? <span className="text-[11px] text-content-muted">{hint}</span> : null}
    </label>
  );
}
