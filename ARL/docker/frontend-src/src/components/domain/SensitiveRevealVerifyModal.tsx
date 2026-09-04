import { X } from 'lucide-react';
import { CONSOLE_INPUT_CLASS } from '../../ui/classes';
import { Modal } from '../ui/Modal';

export type SensitiveRevealVerifyModalProps = {
  open: boolean;
  title: string;
  username: string;
  password: string;
  loading: boolean;
  error: string;
  onClose: () => void;
  onConfirm: () => void;
  onUsernameChange: (value: string) => void;
  onPasswordChange: (value: string) => void;
};

export function SensitiveRevealVerifyModal(props: SensitiveRevealVerifyModalProps) {
  if (!props.open) return null;

  return (
    <Modal open onClose={props.onClose} boxClass="w-full max-w-md!">
        <div className="px-6 py-4 border-b border-base-300 flex items-center justify-between gap-3">
          <div>
            <h4 className="text-lg font-black">{props.title}</h4>
            <p className="text-xs text-content-muted mt-1">请输入当前登录账号和密码后显示敏感 key。</p>
          </div>
          <button
            type="button"
            onClick={props.onClose}
            className="p-2 rounded-lg hover:bg-base-100/70 transition"
            title="关闭"
          >
            <X className="w-5 h-5" />
          </button>
        </div>
        <div className="p-6 space-y-3">
          <div className="space-y-1">
            <label className="text-xs font-bold text-content-muted block">登录账号</label>
            <input
              value={props.username}
              onChange={(event) => props.onUsernameChange(event.target.value)}
              className={CONSOLE_INPUT_CLASS}
              placeholder="请输入当前登录账号"
              autoComplete="username"
            />
          </div>
          <div className="space-y-1">
            <label className="text-xs font-bold text-content-muted block">登录密码</label>
            <input
              type="password"
              value={props.password}
              onChange={(event) => props.onPasswordChange(event.target.value)}
              className={CONSOLE_INPUT_CLASS}
              placeholder="请输入当前登录密码"
              autoComplete="current-password"
              onKeyDown={(event) => {
                if (event.key === 'Enter' && !props.loading) {
                  event.preventDefault();
                  props.onConfirm();
                }
              }}
            />
          </div>
          {props.error ? (
            <div className="text-xs text-error bg-error/10 border border-error/30 rounded-lg px-3 py-2">
              {props.error}
            </div>
          ) : null}
        </div>
        <div className="px-6 py-4 border-t border-base-300 flex justify-end gap-2 bg-base-100/30">
          <button
            type="button"
            onClick={props.onClose}
            className="px-4 py-2 rounded-xl border border-base-300 text-sm font-semibold hover:bg-base-100/70 transition"
            disabled={props.loading}
          >
            取消
          </button>
          <button
            type="button"
            onClick={props.onConfirm}
            className="px-4 py-2 rounded-xl bg-brand-accent text-white text-sm font-black hover:opacity-90 transition disabled:opacity-60"
            disabled={props.loading}
          >
            {props.loading ? '验证中...' : '验证并显示'}
          </button>
        </div>
    </Modal>
  );
}
