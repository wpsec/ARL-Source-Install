import React from 'react';
import { 
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  LineChart, Line
} from 'recharts';
import { Activity, Cpu, Database, HardDrive, Network, Server } from 'lucide-react';

const performanceData = [
  { time: '00:00', cpu: 12, ram: 24, net: 100 },
  { time: '04:00', cpu: 15, ram: 25, net: 150 },
  { time: '08:00', cpu: 45, ram: 40, net: 800 },
  { time: '12:00', cpu: 32, ram: 38, net: 600 },
  { time: '16:00', cpu: 55, ram: 45, net: 1200 },
  { time: '20:00', cpu: 28, ram: 35, net: 400 },
  { time: '23:59', cpu: 18, ram: 30, net: 200 },
];

const MonitorCard = ({ title, value, icon: Icon, color, children }: any) => (
  <div className="bg-brand-card/30 backdrop-blur-md border border-brand-border p-6 rounded-3xl">
    <div className="flex justify-between items-center mb-6">
      <div className="flex items-center gap-3">
        <div className={`p-2 rounded-xl bg-brand-bg border border-brand-border ${color}`}>
          <Icon className="w-5 h-5" />
        </div>
        <h3 className="text-sm font-black text-white uppercase tracking-widest">{title}</h3>
      </div>
      <span className="text-2xl font-black text-white tracking-tighter">{value}</span>
    </div>
    {children}
  </div>
);

export default function SystemMonitor() {
  return (
    <div className="p-8 space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-700">
      <div className="flex justify-between items-end">
        <div>
          <h2 className="text-6xl font-black text-white tracking-tighter leading-none mb-2">系统监控</h2>
          <p className="text-brand-text-muted font-medium text-sm tracking-wide">实时监控 ARL 核心基础设施的 CPU、内存及网络流量状态</p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <MonitorCard title="CPU 核心" value="12%" icon={Cpu} color="text-brand-accent">
          <div className="h-2 bg-brand-bg rounded-full overflow-hidden border border-brand-border">
            <div className="h-full bg-brand-accent w-[12%]" />
          </div>
        </MonitorCard>
        <MonitorCard title="内存占用" value="4.2 / 16 GB" icon={Database} color="text-brand-secondary">
          <div className="h-2 bg-brand-bg rounded-full overflow-hidden border border-brand-border">
            <div className="h-full bg-brand-secondary w-[26%]" />
          </div>
        </MonitorCard>
        <MonitorCard title="网络流量" value="1.2 MB/s" icon={Network} color="text-emerald-400">
          <div className="h-2 bg-brand-bg rounded-full overflow-hidden border border-brand-border">
            <div className="h-full bg-emerald-400 w-[15%]" />
          </div>
        </MonitorCard>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-brand-card/30 backdrop-blur-md border border-brand-border p-8 rounded-3xl">
          <h3 className="text-xl font-black text-white tracking-tight mb-8">资源使用历史 (24h)</h3>
          <div className="h-[300px]">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={performanceData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                <XAxis dataKey="time" stroke="#64748b" fontSize={12} tickLine={false} axisLine={false} />
                <YAxis stroke="#64748b" fontSize={12} tickLine={false} axisLine={false} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '16px' }}
                />
                <Line type="monotone" dataKey="cpu" stroke="#6366f1" strokeWidth={3} dot={false} />
                <Line type="monotone" dataKey="ram" stroke="#0ea5e9" strokeWidth={3} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="bg-brand-card/30 backdrop-blur-md border border-brand-border p-8 rounded-3xl">
          <h3 className="text-xl font-black text-white tracking-tight mb-8">网络流量历史 (24h)</h3>
          <div className="h-[300px]">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={performanceData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                <XAxis dataKey="time" stroke="#64748b" fontSize={12} tickLine={false} axisLine={false} />
                <YAxis stroke="#64748b" fontSize={12} tickLine={false} axisLine={false} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '16px' }}
                />
                <Area type="monotone" dataKey="net" stroke="#10b981" fill="#10b981" fillOpacity={0.1} strokeWidth={3} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

    </div>
  );
}
