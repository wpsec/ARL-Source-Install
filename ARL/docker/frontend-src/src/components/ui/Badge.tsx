import type { ReactNode } from 'react';

/**
 * 状态/等级彩色小字统一 badge（docs/04 组件映射）。
 * severity→色只在此处定义一次，各页不得再手写色映射。
 */
export type BadgeTone = 'success' | 'error' | 'warning' | 'info' | 'neutral' | 'primary';

const BADGE_TONE_CLASS: Record<BadgeTone, string> = {
  success: 'badge-success',
  error: 'badge-error',
  warning: 'badge-warning',
  info: 'badge-info',
  neutral: 'badge-neutral',
  primary: 'badge-primary',
};

/** 漏洞/风险等级到 tone 的唯一映射；未知等级按 info 处理。 */
export function severityTone(value: unknown): BadgeTone {
  const text = String(value ?? '').toLowerCase();
  if (['critical', '严重', '高危', 'high'].some((k) => text.includes(k))) return 'error';
  if (['medium', '中危', '中风险'].some((k) => text.includes(k))) return 'warning';
  if (['low', '低危', '低风险'].some((k) => text.includes(k))) return 'info';
  if (['safe', '正常', '安全'].some((k) => text.includes(k))) return 'success';
  return 'neutral';
}

export function Badge({
  tone = 'neutral',
  children,
  className = '',
  title,
}: {
  tone?: BadgeTone;
  children: ReactNode;
  className?: string;
  title?: string;
}) {
  return (
    <span
      title={title}
      className={`badge badge-soft border-current/30 text-xs font-bold ${BADGE_TONE_CLASS[tone]} ${className}`}
    >
      {children}
    </span>
  );
}
