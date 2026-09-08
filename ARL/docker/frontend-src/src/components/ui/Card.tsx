import type { ReactNode } from 'react';

/** 卡片面单一来源：卡片容器类只在此定义（docs/04 组件映射 Card）。 */
export const CARD_SHELL_CLASS = 'card bg-base-200 border border-base-300 rounded-box shadow-sm';

export function Card({
  children,
  className = '',
  padded = false,
}: {
  children: ReactNode;
  className?: string;
  padded?: boolean;
}) {
  return (
    <div className={`${CARD_SHELL_CLASS}${padded ? ' p-4' : ''} ${className}`}>
      {children}
    </div>
  );
}
