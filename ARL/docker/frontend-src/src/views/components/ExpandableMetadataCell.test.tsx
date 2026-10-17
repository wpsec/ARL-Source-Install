import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { useState } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ExpandableMetadataCell } from './ExpandableMetadataCell';

afterEach(cleanup);

describe('ExpandableMetadataCell', () => {
  it('折叠长元数据并在展开后显示完整内容', () => {
    function Harness() {
      const [expanded, setExpanded] = useState(false);
      return (
        <table>
          <tbody>
            <tr>
              <ExpandableMetadataCell
                text={'第一行\n第二行\n第三行\n第四行'}
                copyText={'第一行\n第二行\n第三行\n第四行'}
                label="响应头"
                expanded={expanded}
                onToggle={() => setExpanded((previous) => !previous)}
                onCopy={vi.fn()}
              />
            </tr>
          </tbody>
        </table>
      );
    }

    render(
      <Harness />,
    );
    const expandButton = screen.getByRole('button', { name: '展开' });
    expect(expandButton.getAttribute('aria-expanded')).toBe('false');
    fireEvent.click(expandButton);
    const collapseButton = screen.getByRole('button', { name: '收起' });
    expect(collapseButton.getAttribute('aria-expanded')).toBe('true');
    expect(collapseButton.closest('td')?.textContent).toContain('第四行');
  });
});
