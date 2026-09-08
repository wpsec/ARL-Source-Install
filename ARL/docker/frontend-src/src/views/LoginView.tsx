import { useState } from 'react';
import { Lock, User } from 'lucide-react';
import BrandLogo from '../components/BrandLogo';
import { CONSOLE_ALERT_ERROR_CLASS, CONSOLE_INPUT_CLASS, CONSOLE_PRIMARY_BUTTON_CLASS } from '../ui/classes';

export function LoginView({
  onLogin,
  loading,
  error,
}: {
  onLogin: (username: string, password: string) => Promise<void>;
  loading: boolean;
  error: string;
}) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');

  return (
    <main className="arl-app relative w-full min-w-0 min-h-screen overflow-hidden bg-base-100 text-base-content flex items-center justify-center p-4 sm:p-8">
      <div className="theme-atmosphere-layer-login pointer-events-none absolute inset-0 z-0" aria-hidden="true" />
      <div className="card relative z-10 min-w-0 w-full max-w-xl border border-base-300 bg-base-200 shadow-sm">
        <div className="card-body min-w-0 p-6 sm:p-10">
          <div className="flex min-w-0 flex-col items-start gap-4 mb-8 sm:flex-row sm:items-center">
            {/* 登录页与侧边栏复用同一品牌 Logo，避免出现两套不一致样式 */}
            <BrandLogo size="lg" />
            <div className="min-w-0">
              <h1 className="break-words text-xl sm:text-2xl font-semibold tracking-tight leading-tight">
                互联网资产自动化收集系统
              </h1>
              <p className="text-sm text-content-muted mt-1">
                版本：{__ARL_VERSION__}
              </p>
            </div>
          </div>

          <form
            className="min-w-0 space-y-6"
            autoComplete="off"
            onSubmit={async (event) => {
              event.preventDefault();
              await onLogin(username, password);
            }}
          >
            <div className="space-y-2">
              <label className="label py-0 text-sm font-medium">用户名</label>
              <div className="relative min-w-0">
                <User className="w-5 h-5 text-content-muted absolute left-4 top-1/2 -translate-y-1/2" />
                <input
                  name="arl_username"
                  value={username}
                  onChange={(event) => setUsername(event.target.value)}
                  autoComplete="off"
                  className={`${CONSOLE_INPUT_CLASS} pl-12 text-base`}
                  placeholder="请输入用户名"
                />
              </div>
            </div>

            <div className="space-y-2">
              <label className="label py-0 text-sm font-medium">密码</label>
              <div className="relative min-w-0">
                <Lock className="w-5 h-5 text-content-muted absolute left-4 top-1/2 -translate-y-1/2" />
                <input
                  type="password"
                  name="arl_password"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  autoComplete="new-password"
                  className={`${CONSOLE_INPUT_CLASS} pl-12 text-base`}
                  placeholder="请输入密码"
                />
              </div>
            </div>

            {error ? (
              <div role="alert" className={`${CONSOLE_ALERT_ERROR_CLASS} py-3`}>
                {error}
              </div>
            ) : null}

            <button
              type="submit"
              disabled={loading}
              className={`${CONSOLE_PRIMARY_BUTTON_CLASS} w-full text-base`}
            >
              {loading ? '登录中...' : '登录系统'}
            </button>
          </form>
        </div>
      </div>
    </main>
  );
}
