import { useState } from 'react';
import { Lock, User } from 'lucide-react';
import BrandLogo from '../components/BrandLogo';

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
    <div className="min-h-screen bg-base-100 text-base-content flex items-center justify-center p-4 relative overflow-hidden">
      <div className="absolute inset-0 theme-atmosphere-layer-login pointer-events-none" />

      <div className="relative z-10 w-full max-w-3xl bg-base-200/50 border border-base-300 backdrop-blur-xl rounded-[2rem] p-12 sm:p-14 shadow-2xl">
        <div className="flex items-start sm:items-center gap-4 mb-10">
          {/* 登录页与侧边栏复用同一品牌 Logo，避免出现两套不一致样式 */}
          <BrandLogo size="lg" />
          <div className="min-w-0">
            <h1 className="text-xl sm:text-3xl md:text-[2.15rem] font-black tracking-tight leading-tight sm:whitespace-nowrap">
              互联网资产自动化收集系统
            </h1>
            <p className="text-base text-content-muted font-semibold mt-1">
              版本：{__ARL_VERSION__}
            </p>
          </div>
        </div>

        <form
          className="space-y-6"
          autoComplete="off"
          onSubmit={async (event) => {
            event.preventDefault();
            await onLogin(username, password);
          }}
        >
          <div className="space-y-2">
            <label className="text-sm font-black text-content-muted uppercase tracking-wider">用户名</label>
            <div className="relative">
              <User className="w-5 h-5 text-content-muted absolute left-4 top-1/2 -translate-y-1/2" />
              <input
                name="arl_username"
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                autoComplete="off"
                className="w-full bg-base-100 border border-base-300 rounded-xl py-4 pl-14 pr-4 text-lg focus:outline-none focus:border-accent"
                placeholder="请输入用户名"
              />
            </div>
          </div>

          <div className="space-y-2">
            <label className="text-sm font-black text-content-muted uppercase tracking-wider">密码</label>
            <div className="relative">
              <Lock className="w-5 h-5 text-content-muted absolute left-4 top-1/2 -translate-y-1/2" />
              <input
                type="password"
                name="arl_password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                autoComplete="new-password"
                className="w-full bg-base-100 border border-base-300 rounded-xl py-4 pl-14 pr-4 text-lg focus:outline-none focus:border-accent"
                placeholder="请输入密码"
              />
            </div>
          </div>

          {error ? (
            <div className="text-sm text-error bg-error/10 border border-error/30 rounded-xl px-4 py-2.5">
              {error}
            </div>
          ) : null}

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-brand-accent hover:opacity-90 disabled:opacity-60 transition px-6 py-4 rounded-xl font-black text-lg shadow-lg shadow-accent/20"
          >
            {loading ? '登录中...' : '登录系统'}
          </button>
        </form>
      </div>
    </div>
  );
}
