import React from 'react';
import { LayoutDashboard, Globe, ShieldAlert, Settings, Activity, Search, Plus, Terminal, Palette, Zap, Heart, Cpu, Layers, FileText, Shield, Github, MessageSquare, Key, Monitor } from 'lucide-react';
import { motion } from 'motion/react';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';
import { useTheme, ThemeType } from '../context/ThemeContext';
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
    { id: 'nord', label: '北欧极光', color: 'bg-[#9abbd7]' },
    { id: 'midnight', label: '午夜科技', color: 'bg-[#8da3e6]' },
    { id: 'slate', label: '专业灰蓝', color: 'bg-[#76b9e2]' },
    { id: 'titanium', label: '钛金黑', color: 'bg-[#88a3cc]' },
    { id: 'sandstone', label: '砂岩白', color: 'bg-[#74685e]' },
  ];

  const navGroups = [
    {
      label: '核心功能',
      color: 'text-brand-accent',
      items: [
        { id: 'dashboard', label: '仪表盘', icon: LayoutDashboard },
        { id: 'tasks', label: '任务管理', icon: Activity },
        { id: 'assets', label: '资产搜索', icon: Search },
        { id: 'asset_monitor', label: '资产监控', icon: Monitor },
        { id: 'groups', label: '资产分组', icon: Layers },
        { id: 'monitoring', label: '系统监控', icon: Cpu },
      ]
    },
    {
      label: '扫描与漏洞',
      color: 'text-brand-secondary',
      items: [
        { id: 'policies', label: '策略配置', icon: FileText },
        { id: 'fingerprints', label: '指纹管理', icon: Zap },
        { id: 'pocs', label: 'PoC信息', icon: Shield },
        { id: 'schedules', label: '计划任务', icon: Activity },
      ]
    },
    {
      label: 'GitHub 监控',
      color: 'text-brand-accent',
      items: [
        { id: 'github_monitor', label: 'GitHub 监控', icon: Github },
        { id: 'github_mgmt', label: 'GitHub 管理', icon: Settings },
      ]
    },
    {
      label: '集成与通知',
      color: 'text-brand-warning',
      items: [
        { id: 'api_mgmt', label: 'API 管理', icon: Key },
        { id: 'dingtalk', label: '钉钉集成', icon: MessageSquare },
        { id: 'config_mgmt', label: '配置管理', icon: Settings },
      ]
    }
  ];

  return (
    <div className="w-64 border-r border-brand-border h-screen flex flex-col bg-brand-bg/50 backdrop-blur-xl overflow-y-auto custom-scrollbar">
      <div className="p-8 flex items-center gap-4">
        {/* 统一品牌标识：所有主题固定高对比，不跟随主题色变暗 */}
        <BrandLogo size="md" />
      </div>

      <div className="px-6 py-2">
        <motion.button 
          whileHover={{ scale: 1.02, backgroundColor: '#292524' }}
          whileTap={{ scale: 0.98 }}
          onClick={onNewScan}
          className="w-full bg-fixed-dark text-fixed-white font-black py-4 px-6 rounded-2xl flex items-center justify-center gap-3 transition-all shadow-2xl shadow-black/20"
        >
          <Plus className="w-5 h-5 text-fixed-white stroke-[3px]" />
          <span className="text-fixed-white text-base tracking-tight">新建任务</span>
        </motion.button>
      </div>

      <nav className="flex-1 px-4 py-8 space-y-10">
        {navGroups.map((group) => (
          <div key={group.label} className="space-y-3">
            <h3 className={cn("px-4 text-[11px] font-black uppercase tracking-[0.15em] opacity-90", group.color)}>
              {group.label}
            </h3>
            <div className="space-y-1">
              {group.items.map((item) => (
                <motion.button
                  key={item.id}
                  whileHover={{ x: 4 }}
                  onClick={() => onViewChange(item.id)}
                  className={cn(
                    "w-full flex items-center gap-3 px-4 py-2.5 rounded-xl transition-all text-sm font-semibold group",
                    activeView === item.id
                      ? "bg-brand-accent/10 text-brand-accent"
                      : "text-brand-text hover:text-brand-text hover:bg-brand-card/50"
                  )}
                >
                  <item.icon className={cn("w-4 h-4 transition-colors", activeView === item.id ? "text-brand-accent" : "text-brand-text group-hover:text-brand-text")} />
                  {item.label}
                </motion.button>
              ))}
            </div>
          </div>
        ))}

      </nav>

      <div className="p-6 border-t border-brand-border space-y-6">
        <div className="space-y-3">
          <div className="flex items-center gap-2 px-2">
            <Palette className="w-3 h-3 text-brand-text" />
            <span className="text-[10px] font-black text-brand-text uppercase tracking-widest">主题定制</span>
          </div>
          <div className="flex flex-wrap gap-2 px-2">
            {themes.map((t) => (
              <motion.button
                key={t.id}
                whileHover={{ scale: 1.2 }}
                whileTap={{ scale: 0.9 }}
                onClick={() => setTheme(t.id)}
                title={t.label}
                className={cn(
                  "w-6 h-6 rounded-lg transition-all border-2",
                  t.color,
                  theme === t.id ? "border-white scale-110 shadow-lg" : "border-transparent opacity-60 hover:opacity-100"
                )}
              />
            ))}
          </div>
        </div>

        <div className="p-3 bg-brand-card/30 rounded-2xl border border-brand-border space-y-1.5">
          <span className="text-xs font-semibold text-brand-text block">ARL互联网资产自动化收集系统</span>
          <div className="flex items-center gap-1 min-w-0">
            <span className="text-[10px] text-brand-text shrink-0 opacity-85">系统版本：</span>
            <span className="text-[10px] text-brand-text tracking-wide truncate opacity-85">
              {__ARL_VERSION__}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
