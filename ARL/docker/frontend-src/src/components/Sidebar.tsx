import React from 'react';
import { LayoutDashboard, Globe, ShieldAlert, Settings, Activity, Search, Plus, Terminal, Palette, Zap, Heart, Cpu } from 'lucide-react';
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
    { id: 'midnight', label: '午夜科技', color: 'bg-[#6366f1]' },
    { id: 'slate', label: '专业灰蓝', color: 'bg-[#38bdf8]' },
    { id: 'nord', label: '北欧极光', color: 'bg-[#88c0d0]' },
    { id: 'deepsea', label: '深海探测', color: 'bg-[#00b4d8]' },
    { id: 'forest', label: '森林卫士', color: 'bg-[#10b981]' },
    { id: 'crimson', label: '绯红之刃', color: 'bg-[#e11d48]' },
    { id: 'cyberpunk', label: '赛博朋克', color: 'bg-[#ff00ff]' },
    { id: 'minimalist', label: '极简白昼', color: 'bg-[#0f172a]' },
  ];

  const navGroups = [
    {
      label: '核心功能',
      color: 'text-brand-accent',
      items: [
        { id: 'dashboard', label: '仪表盘', icon: LayoutDashboard },
        { id: 'tasks', label: '任务管理', icon: Activity },
        { id: 'assets', label: '资产搜索', icon: Search },
        { id: 'monitoring', label: '系统监控', icon: Cpu },
        { id: 'groups', label: '资产分组', icon: ShieldAlert },
      ]
    },
    {
      label: '扫描与漏洞',
      color: 'text-brand-secondary',
      items: [
        { id: 'policies', label: '策略配置', icon: Settings },
        { id: 'fingerprints', label: '指纹管理', icon: Terminal },
        { id: 'pocs', label: 'PoC信息', icon: ShieldAlert },
        { id: 'schedules', label: '计划任务', icon: Activity },
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
          <div className="w-12 h-12 bg-brand-accent rounded-2xl flex items-center justify-center shadow-[0_0_25px_rgba(var(--brand-accent),0.5)] overflow-hidden">
            <svg viewBox="0 0 24 24" className="w-8 h-8 text-white fill-current">
              <path d="M12 2L9 4v2h6V4l-3-2zm-2 5h4l1 12H9l1-12zm-1 14h6v1H9v-1z" />
              <motion.circle 
                cx="12" cy="9" r="1.5" 
                className="text-brand-secondary"
                animate={{ opacity: [0.4, 1, 0.4] }}
                transition={{ repeat: Infinity, duration: 2 }}
              />
            </svg>
            <div className="absolute inset-0 bg-gradient-to-tr from-white/20 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />
          </div>
          <div className="absolute -top-1 -right-1 w-4 h-4 bg-brand-secondary rounded-full border-2 border-brand-bg animate-ping" />
        </motion.div>
        <div className="flex flex-col">
          <span className="font-black text-2xl tracking-tighter leading-none text-white">ARL</span>
          <span className="text-[10px] text-brand-accent font-bold tracking-[0.2em] uppercase mt-1">Lighthouse</span>
        </div>
      </div>

      <div className="px-6 py-2">
        <motion.button 
          whileHover={{ scale: 1.02 }}
          whileTap={{ scale: 0.98 }}
          onClick={onNewScan}
          className="w-full bg-white text-brand-bg font-bold py-3 px-4 rounded-2xl flex items-center justify-center gap-2 transition-all shadow-xl shadow-brand-accent/20"
        >
          <Plus className="w-4 h-4" />
          新建任务
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

        <div className="px-4 space-y-3">
          <h3 className="text-[11px] font-black uppercase tracking-[0.15em] opacity-40 text-brand-danger">
            系统状态
          </h3>
          <div className="bg-brand-card/30 rounded-2xl p-4 border border-brand-border">
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2">
                <Heart className="w-3 h-3 text-brand-danger animate-pulse" />
                <span className="text-[10px] font-bold text-white">健康运行中</span>
              </div>
              <span className="text-[10px] font-mono text-brand-text-muted">99%</span>
            </div>
            <div className="h-1 bg-brand-bg rounded-full overflow-hidden">
              <motion.div 
                initial={{ width: 0 }}
                animate={{ width: '99%' }}
                className="h-full bg-brand-danger"
              />
            </div>
          </div>
        </div>
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

        <div className="flex items-center gap-3 p-2 bg-brand-card/30 rounded-2xl border border-brand-border">
          <div className="w-8 h-8 rounded-full bg-gradient-to-br from-brand-accent to-blue-500 shadow-lg shadow-brand-accent/20" />
          <div className="flex flex-col">
            <span className="text-xs font-semibold text-white">管理员</span>
            <span className="text-[10px] text-brand-text-muted uppercase tracking-wider">专业版计划</span>
          </div>
        </div>
      </div>
    </div>
  );
}
