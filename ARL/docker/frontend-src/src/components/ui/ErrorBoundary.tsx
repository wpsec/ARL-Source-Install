import React from 'react';
import type { ReactNode } from 'react';
import { CONSOLE_ALERT_ERROR_CLASS } from '../../ui/classes';

type Props = { children: ReactNode };
type State = { error: Error | null };

/**
 * 视图级错误边界（review 修复：Suspense 外缺边界导致 chunk 加载失败/页面异常整屏白）。
 * 调用方必须给 boundary 传 key（如 activeModuleId），模块切换即重置错误态；
 * 重试按钮走整页刷新——chunk 404（发版后旧 hash 失效）只有刷新能拿到新 index.html。
 */
export class ViewErrorBoundary extends React.Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    // 保留控制台证据供排障；不吞异常语义（组件树已降级到 fallback UI）
    console.error('[ViewErrorBoundary]', error, info.componentStack);
  }

  render() {
    if (this.state.error) {
      return (
        <div className="p-8">
          <div className="card card-border bg-base-200 border-base-300 shadow-sm max-w-lg mx-auto">
            <div className="card-body p-6 space-y-4">
              <div role="alert" className={CONSOLE_ALERT_ERROR_CLASS}>
                <span className="font-black">页面加载失败</span>
              </div>
              <p className="text-sm text-base-content/60 break-all">{this.state.error.message || String(this.state.error)}</p>
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={() => window.location.reload()}
                  className="btn btn-primary"
                >
                  刷新重试
                </button>
              </div>
            </div>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}
