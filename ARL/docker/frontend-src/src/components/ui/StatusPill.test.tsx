// 渲染冒烟：验证 testing-library+jsdom 接线可用，并钉 done 家族文案透传。
import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { StatusPill } from './StatusPill';

describe('StatusPill', () => {
  it('渲染文本与 title 提示', () => {
    render(<StatusPill text="done_degraded" type="info" />);
    const pill = screen.getByText('done_degraded');
    expect(pill).toBeTruthy();
    expect(pill.className).not.toContain('truncate');
    expect(pill.closest('[title="done_degraded"]')).toBeTruthy();
  });

  it('紧凑模式限制宽度并通过 title 保留完整文本', () => {
    const status = 'wih_urlfinder_sensitive_scan_task_processing_stage';
    render(<StatusPill text={status} type="info" compact />);
    const text = screen.getByText(status);
    const pill = text.closest('[title]');

    expect(pill?.getAttribute('title')).toBe(status);
    expect(pill?.className).toContain('max-w-full');
    expect(text.className).toContain('truncate');
  });
});
