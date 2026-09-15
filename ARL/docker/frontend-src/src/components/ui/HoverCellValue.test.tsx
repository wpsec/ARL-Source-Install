import {fireEvent, render, screen} from '@testing-library/react';
import {describe, expect, it, vi} from 'vitest';
import {HoverCellValue} from './HoverCellValue';

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

    expect(screen.getByText(fullText)).toBeTruthy();
    fireEvent.click(screen.getByRole('button', {name: '复制URL'}));
    expect(onCopy).toHaveBeenCalledWith(fullText, 'URL');
  });
});
