import React from 'react';
import { 
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  AreaChart, Area, Cell
} from 'recharts';
import { Shield, Globe, Activity, AlertTriangle, ArrowUpRight, ArrowDownRight, Terminal, Zap } from 'lucide-react';
import { motion } from 'motion/react';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

const data = [
  { name: '周一', assets: 400, vulns: 24 },
  { name: '周二', assets: 600, vulns: 18 },
  { name: '周三', assets: 500, vulns: 32 },
  { name: '周四', assets: 900, vulns: 45 },
  { name: '周五', assets: 1200, vulns: 28 },
  { name: '周六', assets: 1500, vulns: 12 },
  { name: '周日', assets: 1800, vulns: 8 },
];

const riskData = [
  { name: '高危', value: 45, color: '#ef4444' },
  { name: '中危', value: 120, color: '#f59e0b' },
  { name: '低危', value: 280, color: '#3b82f6' },
  { name: '信息', value: 540, color: '#64748b' },
];

const networkData = [
  { time: '13:40', in: 120, out: 80 },
  { time: '13:41', in: 450, out: 120 },
  { time: '13:42', in: 300, out: 200 },
  { time: '13:43', in: 900, out: 400 },
  { time: '13:44', in: 600, out: 300 },
  { time: '13:45', in: 800, out: 500 },
];

export default function Dashboard() {
  const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: {
        staggerChildren: 0.1
      }
    }
  };

  const itemVariants = {
    hidden: { y: 20, opacity: 0 },
    visible: {
      y: 0,
      opacity: 1
    }
  };

  return (
    <motion.div 
      variants={containerVariants}
      initial="hidden"
      animate="visible"
      className="p-8 space-y-10"
    >
      <div className="flex justify-between items-end">
        <motion.div variants={itemVariants}>
          <h2 className="text-6xl font-black text-white tracking-tighter leading-none mb-2">系统概览</h2>
          <p className="text-brand-text-muted font-medium">互联网资产自动化收集系统 · 实时监控中</p>
        </motion.div>
        <motion.div variants={itemVariants} className="text-right">
          <p className="text-xs font-black text-brand-accent uppercase tracking-widest">最后更新</p>
          <p className="text-sm font-mono text-white">2026-03-05 13:42:10</p>
        </motion.div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {[
          { title: "总资产数", value: "12,842", change: "+12.5%", isUp: true, icon: Globe, color: "text-brand-accent" },
          { title: "活跃任务", value: "24", change: "+2", isUp: true, icon: Activity, color: "text-brand-secondary" },
          { title: "高危漏洞", value: "45", change: "-5.2%", isUp: false, icon: AlertTriangle, color: "text-brand-danger" },
          { title: "今日新增", value: "156", change: "+18.4%", isUp: true, icon: Shield, color: "text-brand-warning" },
        ].map((stat, i) => (
          <motion.div key={i} variants={itemVariants} whileHover={{ y: -5 }} className="bg-brand-card/30 backdrop-blur-md border border-brand-border p-6 rounded-3xl hover:border-brand-accent/50 transition-all group shadow-xl shadow-black/20">
            <div className="flex justify-between items-start mb-4">
              <div className={cn("p-3 rounded-2xl bg-brand-bg border border-brand-border group-hover:scale-110 transition-transform", stat.color)}>
                <stat.icon className="w-6 h-6" />
              </div>
              <div className={cn("flex items-center gap-1 text-xs font-bold px-2 py-1 rounded-full", stat.isUp ? "text-emerald-400 bg-emerald-400/10" : "text-brand-danger bg-brand-danger/10")}>
                {stat.isUp ? <ArrowUpRight className="w-3 h-3" /> : <ArrowDownRight className="w-3 h-3" />}
                {stat.change}
              </div>
            </div>
            <h3 className="text-brand-text-muted text-xs font-black uppercase tracking-widest mb-1">{stat.title}</h3>
            <p className="text-3xl font-black text-white tracking-tighter">{stat.value}</p>
          </motion.div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <motion.div variants={itemVariants} className="lg:col-span-2 bg-brand-card/30 backdrop-blur-md border border-brand-border p-8 rounded-3xl shadow-xl shadow-black/20">
          <h3 className="text-xl font-black text-white tracking-tight mb-8">资产增长趋势 (7日)</h3>
          <div className="h-[300px]">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={data}>
                <defs>
                  <linearGradient id="colorAssets" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="var(--brand-accent)" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="var(--brand-accent)" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--brand-border)" vertical={false} />
                <XAxis dataKey="name" stroke="var(--brand-text-muted)" fontSize={12} tickLine={false} axisLine={false} dy={10} />
                <YAxis stroke="var(--brand-text-muted)" fontSize={12} tickLine={false} axisLine={false} />
                <Tooltip contentStyle={{ backgroundColor: 'var(--brand-card)', border: '1px solid var(--brand-border)', borderRadius: '16px' }} itemStyle={{ color: '#fff' }} />
                <Area type="monotone" dataKey="assets" stroke="var(--brand-accent)" strokeWidth={4} fillOpacity={1} fill="url(#colorAssets)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </motion.div>

        <motion.div variants={itemVariants} className="bg-brand-card/30 backdrop-blur-md border border-brand-border p-8 rounded-3xl shadow-xl shadow-black/20">
          <h3 className="text-xl font-black text-white tracking-tight mb-8">风险等级分布</h3>
          <div className="h-[300px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={riskData} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke="var(--brand-border)" horizontal={false} />
                <XAxis type="number" hide />
                <YAxis dataKey="name" type="category" stroke="var(--brand-text-muted)" fontSize={12} tickLine={false} axisLine={false} />
                <Tooltip cursor={{fill: 'transparent'}} contentStyle={{ backgroundColor: 'var(--brand-card)', border: '1px solid var(--brand-border)', borderRadius: '16px' }} />
                <Bar dataKey="value" radius={[0, 8, 8, 0]} barSize={32}>
                  {riskData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </motion.div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        <motion.div variants={itemVariants} whileHover={{ scale: 1.01 }} className="bg-brand-card/30 backdrop-blur-md border border-brand-border p-6 rounded-3xl flex flex-col shadow-xl shadow-black/20">
          <div className="flex items-center gap-3 mb-6">
            <div className="p-2 bg-brand-secondary/10 rounded-xl">
              <Activity className="w-5 h-5 text-brand-secondary" />
            </div>
            <h3 className="text-xl font-black text-white tracking-tight">系统监控</h3>
          </div>
          <div className="space-y-6 flex-1">
            <div>
              <div className="flex justify-between text-[10px] font-black text-brand-text-muted uppercase tracking-widest mb-2">
                <span>CPU 负载</span>
                <span className="text-white">12%</span>
              </div>
              <div className="h-1.5 bg-brand-bg rounded-full overflow-hidden border border-brand-border">
                <motion.div initial={{ width: 0 }} animate={{ width: '12%' }} className="h-full bg-brand-accent rounded-full shadow-[0_0_10px_rgba(var(--brand-accent),0.5)]" />
              </div>
            </div>
            <div>
              <div className="flex justify-between text-[10px] font-black text-brand-text-muted uppercase tracking-widest mb-2">
                <span>内存占用</span>
                <span className="text-white">26%</span>
              </div>
              <div className="h-1.5 bg-brand-bg rounded-full overflow-hidden border border-brand-border">
                <motion.div initial={{ width: 0 }} animate={{ width: '26%' }} className="h-full bg-brand-secondary rounded-full shadow-[0_0_10px_rgba(var(--brand-secondary),0.5)]" />
              </div>
            </div>
            <div className="h-32 mt-4">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={networkData}>
                  <Area type="monotone" dataKey="in" stroke="var(--brand-accent)" fill="var(--brand-accent)" fillOpacity={0.1} strokeWidth={2} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>
        </motion.div>

        <motion.div variants={itemVariants} whileHover={{ scale: 1.01 }} className="bg-brand-card/30 backdrop-blur-md border border-brand-border p-6 rounded-3xl flex flex-col shadow-xl shadow-black/20">
          <div className="flex items-center gap-3 mb-6">
            <div className="p-2 bg-brand-warning/10 rounded-xl">
              <Shield className="w-5 h-5 text-brand-warning" />
            </div>
            <h3 className="text-xl font-black text-white tracking-tight">ARL 引擎</h3>
          </div>
          <div className="flex-1 flex flex-col justify-center items-center">
            <div className="relative mb-6">
              <div className="w-20 h-20 rounded-full border-4 border-brand-warning/20" />
              <motion.div animate={{ rotate: 360 }} transition={{ repeat: Infinity, duration: 2, ease: "linear" }} className="absolute inset-0 w-20 h-20 rounded-full border-4 border-brand-warning border-t-transparent" />
              <div className="absolute inset-0 flex items-center justify-center">
                <Zap className="w-8 h-8 text-brand-warning fill-brand-warning/20" />
              </div>
            </div>
            <div className="text-center space-y-1 mb-6">
              <p className="text-sm font-black text-white">核心引擎 v2.8.5</p>
              <p className="text-[10px] text-brand-text-muted font-bold uppercase tracking-widest">集群状态: 优 (3/3 节点在线)</p>
            </div>
            <div className="w-full grid grid-cols-2 gap-2">
              <div className="p-3 bg-brand-bg/50 rounded-2xl border border-brand-border text-center">
                <p className="text-[10px] font-black text-brand-text-muted uppercase mb-1">并发数</p>
                <p className="text-lg font-black text-white">1,240</p>
              </div>
              <div className="p-3 bg-brand-bg/50 rounded-2xl border border-brand-border text-center">
                <p className="text-[10px] font-black text-brand-text-muted uppercase mb-1">健康度</p>
                <p className="text-lg font-black text-emerald-400">99.2%</p>
              </div>
            </div>
          </div>
        </motion.div>

        <motion.div variants={itemVariants} whileHover={{ scale: 1.01 }} className="bg-brand-card/30 backdrop-blur-md border border-brand-border p-6 rounded-3xl flex flex-col shadow-xl shadow-black/20">
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-brand-accent/10 rounded-xl">
                <Terminal className="w-5 h-5 text-brand-accent" />
              </div>
              <h3 className="text-xl font-black text-white tracking-tight">实时日志</h3>
            </div>
            <button className="text-[10px] font-black text-brand-accent uppercase tracking-widest hover:underline">查看全部</button>
          </div>
          <div className="flex-1 bg-black/20 rounded-2xl p-4 font-mono text-[10px] space-y-3 overflow-hidden">
            {[
              { level: 'INFO', msg: '任务 [TASK-882] 完成', color: 'text-emerald-400' },
              { level: 'WARN', msg: '识别到未知框架', color: 'text-brand-warning' },
              { level: 'CRIT', msg: '高危漏洞 CVE-2024', color: 'text-brand-danger' },
              { level: 'INFO', msg: '定时巡检已启动', color: 'text-brand-secondary' },
              { level: 'INFO', msg: '管理员登录成功', color: 'text-emerald-400' },
            ].map((log, i) => (
              <motion.div key={i} initial={{ x: -10, opacity: 0 }} animate={{ x: 0, opacity: 1 }} transition={{ delay: i * 0.1 }} className="flex gap-2 border-b border-white/5 pb-2 last:border-0">
                <span className={cn("font-black shrink-0 w-8", log.color)}>{log.level}</span>
                <span className="text-white/60 truncate">{log.msg}</span>
              </motion.div>
            ))}
          </div>
        </motion.div>
      </div>
    </motion.div>
  );
}
