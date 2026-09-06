// 渲染冒烟：验证 testing-library+jsdom 接线可用，并钉 done 家族文案透传。
import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { StatusPill } from './StatusPill';

describe('StatusPill', () => {
  it('渲染文本与 title 提示', () => {
    render(<StatusPill text="done_degraded" type="info" />);
    const pill = screen.getByText('done_degraded');
    expect(pill).toBeTruthy();
    expect(pill.closest('[title="done_degraded"]')).toBeTruthy();
  });
});
