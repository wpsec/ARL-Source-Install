import {act, cleanup, fireEvent, render, screen} from '@testing-library/react';
import {afterEach, describe, expect, it, vi} from 'vitest';
import {HoverCellValue} from './HoverCellValue';

afterEach(cleanup);

describe('HoverCellValue', () => {
  it('展示完整内容并将未截断文本交给复制回调', () => {
    const onCopy = vi.fn();
    const fullText = `https://example.com/${'long-path/'.repeat(8)}`;

    render(
      <HoverCellValue
        display="https://example.com/long..."
        fullText={fullText}
        label="URL"
        onCopy={onCopy}
      />,
    );

    const trigger = screen.getByLabelText('查看URL完整内容');
    expect(screen.queryByText(fullText)).toBeNull();
    fireEvent.focus(trigger);
    expect(screen.getByText(fullText)).toBeTruthy();
    const panel = screen.getByText('URL完整内容').parentElement?.parentElement?.parentElement;
    expect(panel?.className).toContain('fixed');
    expect(panel?.parentElement).toBe(document.body);
    fireEvent.click(screen.getByRole('button', {name: '复制URL'}));
    expect(onCopy).toHaveBeenCalledWith(fullText, 'URL');
  });

  it('按实际布局溢出开启悬浮，而不是按文本长度猜测', () => {
    const originalClientWidth = Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'clientWidth');
    const originalScrollWidth = Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'scrollWidth');
    Object.defineProperty(HTMLElement.prototype, 'clientWidth', { configurable: true, value: 80 });
    Object.defineProperty(HTMLElement.prototype, 'scrollWidth', { configurable: true, value: 160 });

    try {
      render(
        <HoverCellValue
          display="短文本"
          fullText="短文本"
          label="标题"
        />,
      );
      expect(screen.getByLabelText('查看标题完整内容')).toBeTruthy();
    } finally {
      if (originalClientWidth) Object.defineProperty(HTMLElement.prototype, 'clientWidth', originalClientWidth);
      else delete (HTMLElement.prototype as HTMLElement & {clientWidth?: number}).clientWidth;
      if (originalScrollWidth) Object.defineProperty(HTMLElement.prototype, 'scrollWidth', originalScrollWidth);
      else delete (HTMLElement.prototype as HTMLElement & {scrollWidth?: number}).scrollWidth;
    }
  });

  it('检测多行内容的实际高度截断', () => {
    const descriptors = {
      clientWidth: Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'clientWidth'),
      scrollWidth: Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'scrollWidth'),
      clientHeight: Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'clientHeight'),
      scrollHeight: Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'scrollHeight'),
    };
    Object.defineProperty(HTMLElement.prototype, 'clientWidth', { configurable: true, value: 160 });
    Object.defineProperty(HTMLElement.prototype, 'scrollWidth', { configurable: true, value: 160 });
    Object.defineProperty(HTMLElement.prototype, 'clientHeight', { configurable: true, value: 20 });
    Object.defineProperty(HTMLElement.prototype, 'scrollHeight', { configurable: true, value: 100 });

    try {
      render(
        <HoverCellValue
          display={<div className="max-h-5 overflow-hidden">{'第一行\n第二行\n第三行'}</div>}
          fullText={'第一行\n第二行\n第三行'}
          label="响应体"
        />,
      );
      expect(screen.getByLabelText('查看响应体完整内容')).toBeTruthy();
    } finally {
      Object.entries(descriptors).forEach(([key, descriptor]) => {
        if (descriptor) Object.defineProperty(HTMLElement.prototype, key, descriptor);
        else delete (HTMLElement.prototype as HTMLElement & Record<string, number | undefined>)[key];
      });
    }
  });

  it('完整显示短文本时不生成悬浮触发器，收起内容可显式强制查看', () => {
    const { container, rerender } = render(
      <HoverCellValue display="短文本" fullText="短文本" label="标题" />,
    );
    expect(container.querySelector('[aria-label="查看标题完整内容"]')).toBeNull();

    rerender(
      <HoverCellValue
        display="短文本..."
        fullText={'短文本\n第二行'}
        label="标题"
        forceHover
      />,
    );
    const trigger = screen.getByLabelText('查看标题完整内容');
    fireEvent.focus(trigger);
    expect(document.body.textContent).toContain('短文本\n第二行');
    expect(screen.queryByRole('button', {name: '复制标题'})).toBeNull();
    fireEvent.keyDown(trigger, {key: 'Escape'});
    expect(screen.queryByText('标题完整内容')).toBeNull();
  });

  it('鼠标悬浮延迟打开，并保留离开缓冲时间', () => {
    vi.useFakeTimers();
    try {
      render(
        <HoverCellValue
          display="短文本..."
          fullText="这是完整内容"
          label="标题"
          forceHover
        />,
      );
      const trigger = screen.getByLabelText('查看标题完整内容');

      fireEvent.mouseEnter(trigger);
      expect(screen.queryByText('标题完整内容')).toBeNull();
      act(() => vi.advanceTimersByTime(259));
      expect(screen.queryByText('标题完整内容')).toBeNull();
      act(() => vi.advanceTimersByTime(1));
      expect(screen.getByText('标题完整内容')).toBeTruthy();

      fireEvent.mouseLeave(trigger);
      act(() => vi.advanceTimersByTime(359));
      expect(screen.getByText('标题完整内容')).toBeTruthy();
      act(() => vi.advanceTimersByTime(1));
      expect(screen.queryByText('标题完整内容')).toBeNull();
    } finally {
      vi.useRealTimers();
    }
  });
});
