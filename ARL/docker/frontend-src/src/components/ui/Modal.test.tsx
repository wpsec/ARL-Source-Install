// Modal 行为契约（计划 4 UI 验收·弹窗与键盘路径）。
// 说明：jsdom 不模拟 UA 原生 Esc→cancel→close 链路，键盘行为的浏览器端证据由
// scripts/ui-smoke.sh（真实浏览器项）覆盖；此处钉死组件自身逻辑：
// open 同步、backdrop 判定、dismissable、close 事件收敛、aria-labelledby 挂载。
import { fireEvent, render } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { Modal } from './Modal';

function getDialog(container: HTMLElement): HTMLDialogElement {
  const dialog = container.querySelector('dialog');
  expect(dialog).toBeTruthy();
  return dialog as HTMLDialogElement;
}

describe('Modal', () => {
  it('open=true 时以 showModal 打开并渲染内容', () => {
    const { container } = render(
      <Modal open onClose={() => {}}>
        <h4>标题</h4>
      </Modal>,
    );
    const dialog = getDialog(container);
    expect(dialog.open).toBe(true);
    expect(dialog.querySelector('h4')?.textContent).toBe('标题');
  });

  it('open=false 时保持关闭', () => {
    const { container } = render(
      <Modal open={false} onClose={() => {}}>
        <span>x</span>
      </Modal>,
    );
    expect(getDialog(container).open).toBe(false);
  });

  it('点击 backdrop（target 即 dialog）触发 onClose', () => {
    const onClose = vi.fn();
    const { container } = render(
      <Modal open onClose={onClose}>
        <span>x</span>
      </Modal>,
    );
    fireEvent.click(getDialog(container));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('点击 box 内容不触发关闭', () => {
    const onClose = vi.fn();
    const { container } = render(
      <Modal open onClose={onClose}>
        <div data-testid="inner">内容</div>
      </Modal>,
    );
    fireEvent.click(container.querySelector('[data-testid="inner"]')!);
    expect(onClose).not.toHaveBeenCalled();
  });

  it('dismissable=false 时 backdrop 点击不关闭', () => {
    const onClose = vi.fn();
    const { container } = render(
      <Modal open onClose={onClose} dismissable={false}>
        <span>x</span>
      </Modal>,
    );
    fireEvent.click(getDialog(container));
    expect(onClose).not.toHaveBeenCalled();
  });

  it('原生 close 事件（Esc/外部关闭的结果）在 open 仍为 true 时收敛到 onClose', () => {
    const onClose = vi.fn();
    const { container } = render(
      <Modal open onClose={onClose}>
        <span>x</span>
      </Modal>,
    );
    fireEvent(getDialog(container), new Event('close'));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('组件主动关闭后 close 事件不再重复回调', () => {
    const onClose = vi.fn();
    const { container, rerender } = render(
      <Modal open onClose={onClose}>
        <span>x</span>
      </Modal>,
    );
    rerender(
      <Modal open={false} onClose={onClose}>
        <span>x</span>
      </Modal>,
    );
    fireEvent(getDialog(container), new Event('close'));
    expect(onClose).not.toHaveBeenCalled();
  });

  it('打开时自动把首个标题挂为 aria-labelledby', () => {
    const { container } = render(
      <Modal open onClose={() => {}}>
        <h4 id="section-title">会话设置</h4>
      </Modal>,
    );
    const dialog = getDialog(container);
    expect(dialog.getAttribute('aria-labelledby')).toBeTruthy();
    expect(document.getElementById(dialog.getAttribute('aria-labelledby')!)?.textContent).toBe('会话设置');
  });

  it('显式 labelledBy 优先于自动挂载', () => {
    const { container } = render(
      <>
        <h2 id="outside-title">外部标题</h2>
        <Modal open onClose={() => {}} labelledBy="outside-title">
          <h4>内部标题</h4>
        </Modal>
      </>,
    );
    expect(getDialog(container).getAttribute('aria-labelledby')).toBe('outside-title');
  });
});
