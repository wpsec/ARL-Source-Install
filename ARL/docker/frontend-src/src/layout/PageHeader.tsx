import type { ReactNode } from 'react';

/**
 * 全站页头单一来源（docs/04 Phase 0 页头统一）。
 * 标题/描述/操作区对齐规则只在这里定义，禁止各页再手写 h2 组合。
 */
export function PageHeader({
  title,
  description,
  actions,
}: {
  title: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <div className="flex flex-col xl:flex-row xl:items-end xl:justify-between gap-4">
      <div>
        <h2 className="text-4xl font-black tracking-tight">{title}</h2>
        {description ? <p className="text-brand-text-muted mt-2 text-sm">{description}</p> : null}
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  );
}
