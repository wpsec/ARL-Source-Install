// vitest setup：jsdom 30 未实现 <dialog> 的 showModal/close 行为，补齐最小语义，
// 使组件契约测试可运行。真实浏览器的 Esc/backdrop 原生链路归 scripts/ui-smoke.sh 覆盖。
interface DialogLike extends HTMLElement {
  open: boolean;
  showModal(): void;
  close(): void;
}

const proto = (globalThis as Record<string, any>).HTMLDialogElement?.prototype as
  | DialogLike
  | undefined;

if (proto) {
  const openDesc = Object.getOwnPropertyDescriptor(proto, 'open');
  if (!openDesc?.get) {
    Object.defineProperty(proto, 'open', {
      get(this: HTMLElement) {
        return this.hasAttribute('open');
      },
      set(this: HTMLElement, value: boolean) {
        if (value) this.setAttribute('open', '');
        else this.removeAttribute('open');
      },
      configurable: true,
    });
  }
  if (typeof proto.showModal !== 'function') {
    proto.showModal = function (this: DialogLike) {
      if (this.open) throw new Error('InvalidStateError: dialog already open');
      this.open = true;
    };
  }
  if (typeof proto.close !== 'function') {
    proto.close = function (this: DialogLike) {
      if (!this.open) return;
      this.open = false;
      this.dispatchEvent(new Event('close'));
    };
  }
}
