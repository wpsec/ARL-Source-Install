import type { ReactNode } from 'react';

/** 配置表单行单一来源：label + 控件的间距/字号只在这里定义（docs/04 组件映射 FormRow）。 */
export function FormRow({
  label,
  hint,
  required = false,
  children,
  className = '',
}: {
  label: ReactNode;
  hint?: ReactNode;
  required?: boolean;
  children: ReactNode;
  className?: string;
}) {
  return (
    <label className={`block space-y-1 ${className}`}>
      <span className="text-xs font-bold text-base-content">
        {label}
        {required ? <span className="text-error ms-1">*</span> : null}
      </span>
      {children}
      {hint ? <span className="block text-[11px] leading-relaxed text-content-muted">{hint}</span> : null}
    </label>
  );
}
