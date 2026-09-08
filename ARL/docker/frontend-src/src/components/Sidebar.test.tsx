import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ThemeProvider } from '../context/ThemeContext';
import Sidebar from './Sidebar';

function renderSidebar(activeView = 'dashboard') {
  return render(
    <ThemeProvider>
      <Sidebar
        activeView={activeView}
        onViewChange={vi.fn()}
        onNewScan={vi.fn()}
      />
    </ThemeProvider>,
  );
}

beforeEach(() => {
  localStorage.clear();
  vi.stubGlobal('__ARL_VERSION__', '0.0-test-sidebar');
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('Sidebar 整行菜单布局', () => {
  it('选中态按钮和文字区域都占满菜单行', () => {
    renderSidebar();

    const activeButton = screen.getByRole('button', { name: '仪表盘' });
    const activeLabel = activeButton.querySelector('span');

    expect(activeButton.getAttribute('aria-current')).toBe('page');
    expect(activeButton.className).toContain('arl-sidebar-nav-item');
    expect(activeButton.className).not.toContain('btn');
    expect(activeButton.className).toContain('w-full');
    expect(activeButton.className).toContain('lg:!w-full');
    expect(activeButton.className).toContain('min-w-0');
    expect(activeLabel?.className).toContain('w-full');
    expect(activeLabel?.className).toContain('flex-1');
    expect(activeLabel?.className).toContain('lg:flex');
    expect(activeLabel?.className).toContain('self-stretch');
    expect(activeLabel?.className).toContain('justify-start');
    expect(activeButton.parentElement?.className).toContain('w-full');
  });

  it('非选中项不复用选中态标记', () => {
    renderSidebar('tasks');

    expect(screen.getByRole('button', { name: '任务管理' }).getAttribute('aria-current')).toBe('page');
    expect(screen.getByRole('button', { name: '仪表盘' }).getAttribute('aria-current')).toBeNull();
  });
});
