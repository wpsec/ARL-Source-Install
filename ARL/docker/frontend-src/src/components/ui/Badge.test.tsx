import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { Badge, severityTone } from './Badge';

describe('Badge', () => {
  it('未知等级使用可读的 neutral 状态', () => {
    expect(severityTone('未识别状态')).toBe('neutral');
    render(<Badge>未识别状态</Badge>);

    const badge = screen.getByText('未识别状态');
    expect(badge.className).toContain('badge-neutral');
    expect(badge.className).toContain('badge-soft');
  });

  it('风险等级映射到对应语义色', () => {
    expect(severityTone('critical')).toBe('error');
    expect(severityTone('medium')).toBe('warning');
    expect(severityTone('low')).toBe('info');
    expect(severityTone('safe')).toBe('success');
  });
});
