import React from 'react';
import { LayoutDashboard, Globe, ShieldAlert, Settings, Activity, Search, Plus, Terminal, Palette, Zap, Heart, Cpu, Layers, FileText, Shield, Github, MessageSquare, Key, Monitor } from 'lucide-react';
import { motion } from 'motion/react';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';
import { useTheme, ThemeType } from '../context/ThemeContext';

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
    { id: 'nord', label: '北欧极光', color: 'bg-[#88c0d0]' },
    { id: 'midnight', label: '午夜科技', color: 'bg-[#6366f1]' },
    { id: 'slate', label: '专业灰蓝', color: 'bg-[#38bdf8]' },
    { id: 'titanium', label: '钛金黑', color: 'bg-[#3b82f6]' },
    { id: 'sandstone', label: '砂岩白', color: 'bg-[#44403c]' },
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
        <motion.div 
          whileHover={{ rotate: 360 }}
          transition={{ duration: 0.8, ease: "easeInOut" }}
          className="relative group cursor-pointer"
        >
          <div className="w-12 h-12 bg-brand-accent rounded-2xl flex items-center justify-center shadow-[0_0_40px_rgba(var(--brand-accent-rgb),0.8)] overflow-hidden">
            <svg viewBox="0 0 24 24" className="w-8 h-8 text-white fill-current drop-shadow-[0_0_15px_rgba(255,255,255,1)]">
              <path d="M12 2L9 4v2h6V4l-3-2zm-2 5h4l1 12H9l1-12zm-1 14h6v1H9v-1z" />
              <motion.circle 
                cx="12" cy="9" r="1.5" 
                className="text-brand-secondary"
                animate={{ opacity: [0.6, 1, 0.6] }}
                transition={{ repeat: Infinity, duration: 1.5 }}
              />
            </svg>
            <div className="absolute inset-0 bg-gradient-to-tr from-white/40 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />
          </div>
          <div className="absolute -top-1 -right-1 w-4 h-4 bg-brand-secondary rounded-full border-2 border-brand-bg animate-ping" />
        </motion.div>
        <div className="flex flex-col">
          <span className="font-black text-2xl tracking-tighter leading-none text-white drop-shadow-[0_0_20px_rgba(255,255,255,0.6)]">ARL</span>
          <span className="text-[10px] text-brand-accent font-black tracking-[0.3em] uppercase mt-1 drop-shadow-[0_0_15px_rgba(var(--brand-accent-rgb),0.7)]">Lighthouse</span>
        </div>
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
            <h3 className={cn("px-4 text-[11px] font-black uppercase tracking-[0.15em] opacity-40", group.color)}>
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
                      : "text-brand-text-muted hover:text-white hover:bg-brand-card/50"
                  )}
                >
                  <item.icon className={cn("w-4 h-4 transition-colors", activeView === item.id ? "text-brand-accent" : "text-brand-text-muted group-hover:text-white")} />
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
            <Palette className="w-3 h-3 text-brand-text-muted" />
            <span className="text-[10px] font-black text-brand-text-muted uppercase tracking-widest">主题定制</span>
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
          <span className="text-xs font-semibold text-white block">ARL互联网资产自动化收集系统加强版</span>
          <div className="flex items-center gap-1 min-w-0">
            <span className="text-[10px] text-brand-text-muted shrink-0">Github地址：</span>
            <a
              href="https://github.com/wpsec/ARL-Source-Install"
              target="_blank"
              rel="noreferrer"
              className="text-[10px] text-brand-text-muted tracking-wide truncate hover:text-brand-accent transition-colors"
            >
              点击跳转
            </a>
          </div>
        </div>
      </div>
    </div>
  );
}
