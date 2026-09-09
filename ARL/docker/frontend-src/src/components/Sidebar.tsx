import React from 'react';
import { LayoutDashboard, Globe, ShieldAlert, Settings, Activity, Search, Plus, Terminal, Palette, Zap, Heart, Cpu, Layers, FileText, Shield, Github, MessageSquare, Key, Monitor, Sparkles, FileSearch } from 'lucide-react';
import { motion } from 'motion/react';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';
import { useTheme, ThemeType } from '../context/ThemeContext';
import { CONSOLE_PRIMARY_BUTTON_CLASS } from '../ui/classes';
import BrandLogo from './BrandLogo';

declare const __ARL_VERSION__: string;

function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

interface SidebarProps {
  activeView: string;
  onViewChange: (view: string) => void;
  onNewScan: () => void;
}

export default function Sidebar({ activeView, onViewChange, onNewScan }: SidebarProps) {
  const { theme, setTheme } = useTheme();

  const themes: { id: ThemeType; label: string; color: string }[] = [
    { id: 'nord', label: '北欧极光', color: 'var(--theme-swatch-nord)' },
    { id: 'midnight', label: '午夜科技', color: 'var(--theme-swatch-midnight)' },
    { id: 'slate', label: '灯塔石墨', color: 'var(--theme-swatch-slate)' },
    { id: 'titanium', label: '钛金黑', color: 'var(--theme-swatch-titanium)' },
    { id: 'sandstone', label: '砂岩白', color: 'var(--theme-swatch-sandstone)' },
  ];

  const navGroups = [
    {
      label: '核心功能',
      color: 'text-primary',
      items: [
        { id: 'dashboard', label: '仪表盘', icon: LayoutDashboard },
        { id: 'tasks', label: '任务管理', icon: Activity },
        { id: 'assets', label: '资产搜索', icon: Search },
        { id: 'icp_query', label: 'ICP 查询', icon: FileSearch },
        { id: 'asset_monitor', label: '资产监控', icon: Monitor },
        { id: 'groups', label: '资产分组', icon: Layers },
        { id: 'monitoring', label: '系统监控', icon: Cpu },
      ]
    },
    {
      label: '扫描与漏洞',
      color: 'text-secondary',
      items: [
        { id: 'policies', label: '策略配置', icon: FileText },
        { id: 'fingerprints', label: '指纹管理', icon: Zap },
        { id: 'pocs', label: 'PoC信息', icon: Shield },
        { id: 'schedules', label: '计划任务', icon: Activity },
      ]
    },
    {
      label: 'GitHub 监控',
      color: 'text-primary',
      items: [
        { id: 'github_monitor', label: 'GitHub 监控', icon: Github },
        { id: 'github_mgmt', label: 'GitHub 管理', icon: Settings },
      ]
    },
    {
      label: '集成与通知',
      color: 'text-warning',
      items: [
        { id: 'api_mgmt', label: 'API 管理', icon: Key },
        { id: 'dingtalk', label: '钉钉集成', icon: MessageSquare },
        { id: 'config_mgmt', label: '配置管理', icon: Settings },
        { id: 'ai_mgmt', label: 'AI 管理', icon: Sparkles },
      ]
    }
  ];

  return (
    <aside className="arl-sidebar relative z-10 w-16 lg:w-56 xl:w-60 2xl:w-64 shrink-0 border-r border-base-300 bg-base-200 h-screen flex flex-col overflow-y-auto custom-scrollbar">
      <div className="flex justify-center px-2 py-4 lg:block lg:px-4 lg:py-4 xl:px-5 xl:py-5 border-b border-base-300">
        {/* 统一品牌标识：所有主题固定高对比，不跟随主题色变暗 */}
        <BrandLogo size="md" compactBelowLg />
      </div>

      <div className="px-1.5 py-3 lg:px-3 xl:px-4 xl:py-4">
        <motion.button 
          whileHover={{ scale: 1.02 }}
          whileTap={{ scale: 0.98 }}
          onClick={onNewScan}
          className={`${CONSOLE_PRIMARY_BUTTON_CLASS} w-full justify-center gap-0 shadow-sm lg:justify-start lg:gap-2`}
          title="新建任务"
        >
          <Plus className="w-4 h-4" strokeWidth={2.5} />
          <span className="hidden lg:inline">新建任务</span>
        </motion.button>
      </div>

      <nav className="flex-1 px-1.5 py-2 space-y-5 lg:px-3 xl:px-4">
        {navGroups.map((group) => (
          <div key={group.label}>
            <h3 className={cn("hidden px-3 mb-2 text-[11px] font-semibold leading-4 tracking-wide opacity-80 lg:block", group.color)}>
              {group.label}
            </h3>
            <ul className="flex w-full list-none flex-col space-y-1 p-0">
              {group.items.map((item) => (
                <li
                  key={item.id}
                  className={cn(
                    "arl-sidebar-nav-row flex w-full min-w-0 rounded-box",
                    activeView === item.id ? "arl-sidebar-nav-row-active" : "hover:bg-base-300/60",
                  )}
                >
                  <button
                    onClick={() => onViewChange(item.id)}
                    className={cn(
                      "arl-sidebar-nav-item group flex min-h-10 !w-full !min-w-0 !max-w-none !flex-[1_1_100%] !basis-0 cursor-pointer items-center justify-center overflow-hidden rounded-box border border-transparent px-0 py-0 text-sm font-medium transition-colors focus-visible:outline-none lg:justify-start lg:gap-3 lg:px-3",
                      activeView === item.id
                        ? "!bg-transparent font-semibold !text-primary"
                        : "!bg-transparent text-content-muted hover:bg-transparent hover:text-base-content",
                    )}
                    title={item.label}
                    aria-label={item.label}
                    aria-current={activeView === item.id ? 'page' : undefined}
                  >
                    <item.icon className="w-4 h-4 shrink-0" />
                    <span className="hidden min-w-0 !w-full !flex-1 self-stretch items-center justify-start text-left lg:flex">{item.label}</span>
                  </button>
                </li>
              ))}
            </ul>
          </div>
        ))}

      </nav>

      <div className="p-2 lg:p-3 xl:p-4 border-t border-base-300 space-y-4">
        <div className="space-y-2">
          <div className="flex items-center justify-center gap-2 px-0 text-content-muted lg:justify-start lg:px-2">
            <Palette className="w-3.5 h-3.5" />
            <span className="hidden text-xs font-semibold lg:inline">主题定制</span>
          </div>
          <div className="flex flex-wrap justify-center gap-2 px-0 lg:justify-start lg:px-2" role="group" aria-label="主题定制">
            {themes.map((t) => (
              <motion.button
                key={t.id}
                whileHover={{ scale: 1.2 }}
                whileTap={{ scale: 0.9 }}
                onClick={() => setTheme(t.id)}
                title={t.label}
                className={cn(
                  "w-6 h-6 rounded-full transition-all border-2",
                  theme === t.id ? "border-base-content scale-110 shadow-lg" : "border-transparent opacity-60 hover:opacity-100"
                )}
                  style={{ backgroundColor: t.color }}
                  aria-label={t.label}
                  aria-pressed={theme === t.id}
                />
            ))}
          </div>
        </div>

        <div className="card hidden border border-base-300 bg-base-100 shadow-sm lg:block">
          <div className="card-body p-3 gap-1">
            <span className="text-xs font-semibold">互联网资产自动化收集系统</span>
            <div className="flex items-center gap-1 min-w-0">
              <span className="text-[10px] text-content-muted shrink-0">系统版本：</span>
              <span className="text-[10px] text-content-muted tracking-wide truncate">
                {__ARL_VERSION__}
              </span>
            </div>
          </div>
        </div>
      </div>
    </aside>
  );
}
