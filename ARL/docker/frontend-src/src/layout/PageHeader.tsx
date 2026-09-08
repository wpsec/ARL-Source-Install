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
    <header className="flex min-w-0 flex-col gap-4 border-b border-base-300/80 pb-5 xl:flex-row xl:items-end xl:justify-between">
      <div className="min-w-0 flex-1">
        <h1 className="break-words text-2xl font-black tracking-tight">{title}</h1>
        {description ? <p className="min-w-0 max-w-3xl break-words text-sm text-content-muted mt-1.5">{description}</p> : null}
      </div>
      {actions ? <div className="flex min-w-0 w-full max-w-full flex-wrap items-center gap-2 xl:w-auto xl:justify-end">{actions}</div> : null}
    </header>
  );
}
