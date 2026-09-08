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
    <header className="flex flex-col xl:flex-row xl:items-start xl:justify-between gap-4">
      <div className="min-w-0">
        <h1 className="break-words text-2xl font-semibold tracking-tight">{title}</h1>
        {description ? <p className="text-sm text-content-muted mt-1.5 max-w-3xl">{description}</p> : null}
      </div>
      {actions ? <div className="flex w-full flex-wrap items-center gap-2 xl:w-auto">{actions}</div> : null}
    </header>
  );
}
