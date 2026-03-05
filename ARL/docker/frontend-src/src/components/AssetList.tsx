import React from 'react';
import { Search, Filter, MoreHorizontal, Download, Globe, Activity, ShieldAlert } from 'lucide-react';
import { Asset } from '../types';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

const mockAssets: Asset[] = [
  { id: '1', domain: 'api.example.com', ip: '192.168.1.1', port: 443, service: 'HTTPS', status: 'active', lastScan: '2024-03-04 10:00', tags: ['生产环境', '外部'] },
  { id: '2', domain: 'dev.example.com', ip: '192.168.1.2', port: 8080, service: 'HTTP-Proxy', status: 'vulnerable', lastScan: '2024-03-04 11:30', tags: ['开发环境', '内部'] },
  { id: '3', domain: 'mail.example.com', ip: '192.168.1.3', port: 25, service: 'SMTP', status: 'active', lastScan: '2024-03-04 09:15', tags: ['基础设施'] },
  { id: '4', domain: 'vpn.example.com', ip: '192.168.1.4', port: 1194, service: 'OpenVPN', status: 'inactive', lastScan: '2024-03-03 18:45', tags: ['接入'] },
  { id: '5', domain: 'blog.example.com', ip: '192.168.1.5', port: 443, service: 'HTTPS', status: 'active', lastScan: '2024-03-04 12:00', tags: ['市场'] },
  { id: '6', domain: 'staging.example.com', ip: '192.168.1.6', port: 443, service: 'HTTPS', status: 'active', lastScan: '2024-03-04 08:00', tags: ['预发'] },
];

export default function AssetList() {
  return (
    <div className="p-8 space-y-10 animate-in fade-in slide-in-from-bottom-4 duration-700">
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-6">
        <div>
          <h2 className="text-6xl font-black text-white tracking-tighter leading-none mb-2">资产搜索</h2>
          <p className="text-brand-text-muted font-medium">管理和检索系统中发现的所有互联网资产</p>
        </div>
        <div className="flex items-center gap-3">
          <button className="bg-brand-card/50 border border-brand-border text-white px-6 py-3 rounded-2xl font-bold text-sm hover:bg-brand-card transition-all flex items-center gap-2">
            <Filter className="w-4 h-4" />
            高级筛选
          </button>
          <button className="bg-brand-accent text-white px-6 py-3 rounded-2xl font-bold text-sm hover:opacity-90 transition-all flex items-center gap-2 shadow-lg shadow-brand-accent/20">
            <Download className="w-4 h-4" />
            导出数据
          </button>
        </div>
      </div>

      <div className="bg-brand-card/30 backdrop-blur-md border border-brand-border rounded-3xl overflow-hidden">
        <div className="p-6 border-b border-brand-border bg-brand-bg/20">
          <div className="relative">
            <Search className="absolute left-4 top-1/2 -translate-y-1/2 text-brand-text-muted w-5 h-5" />
            <input 
              type="text" 
              placeholder="搜索域名、IP、服务或指纹..."
              className="w-full bg-brand-bg/50 border border-brand-border rounded-2xl py-4 pl-12 pr-4 text-white placeholder:text-brand-text-muted focus:outline-none focus:border-brand-accent transition-all font-medium"
            />
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-brand-border bg-brand-bg/10">
                <th className="px-6 py-5 text-xs font-black text-brand-text-muted uppercase tracking-widest">资产名称</th>
                <th className="px-6 py-5 text-xs font-black text-brand-text-muted uppercase tracking-widest">网络信息</th>
                <th className="px-6 py-5 text-xs font-black text-brand-text-muted uppercase tracking-widest">服务/端口</th>
                <th className="px-6 py-5 text-xs font-black text-brand-text-muted uppercase tracking-widest">状态</th>
                <th className="px-6 py-5 text-xs font-black text-brand-text-muted uppercase tracking-widest">最后扫描</th>
                <th className="px-6 py-5 text-xs font-black text-brand-text-muted uppercase tracking-widest">操作</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-brand-border">
              {mockAssets.map((asset) => (
                <tr key={asset.id} className="hover:bg-white/5 transition-colors group">
                  <td className="px-6 py-5">
                    <div className="flex flex-col">
                      <span className="text-white font-bold group-hover:text-brand-accent transition-colors">{asset.domain}</span>
                      <div className="flex gap-1 mt-1">
                        {asset.tags.map(tag => (
                          <span key={tag} className="text-[10px] bg-brand-accent/10 text-brand-accent px-1.5 py-0.5 rounded font-bold uppercase tracking-tighter">
                            {tag}
                          </span>
                        ))}
                      </div>
                    </div>
                  </td>
                  <td className="px-6 py-5">
                    <span className="text-sm font-mono text-brand-text-muted group-hover:text-white transition-colors">{asset.ip}</span>
                  </td>
                  <td className="px-6 py-5">
                    <div className="flex flex-wrap gap-2">
                      <span className="text-xs bg-brand-card border border-brand-border text-white px-2 py-1 rounded-lg font-mono">
                        {asset.service}:{asset.port}
                      </span>
                    </div>
                  </td>
                  <td className="px-6 py-5">
                    <div className="flex items-center gap-2">
                      <div className={cn(
                        "w-2 h-2 rounded-full",
                        asset.status === 'active' ? "bg-emerald-500 shadow-[0_0_12px_rgba(16,185,129,0.6)]" :
                        asset.status === 'vulnerable' ? "bg-brand-danger shadow-[0_0_12px_rgba(239,68,68,0.6)]" :
                        "bg-brand-text-muted"
                      )} />
                      <span className={cn(
                        "text-xs font-bold uppercase tracking-wider",
                        asset.status === 'active' ? "text-emerald-400" :
                        asset.status === 'vulnerable' ? "text-brand-danger" :
                        "text-brand-text-muted"
                      )}>
                        {asset.status === 'active' ? '在线' : asset.status === 'vulnerable' ? '存在风险' : '离线'}
                      </span>
                    </div>
                  </td>
                  <td className="px-6 py-5">
                    <span className="text-xs text-brand-text-muted font-medium">{asset.lastScan}</span>
                  </td>
                  <td className="px-6 py-5">
                    <button className="p-2 hover:bg-brand-accent/20 rounded-xl transition-all text-brand-text-muted hover:text-brand-accent">
                      <MoreHorizontal className="w-5 h-5" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        
        <div className="p-6 border-t border-brand-border flex justify-between items-center bg-brand-bg/20">
          <span className="text-xs font-bold text-brand-text-muted uppercase tracking-widest">显示 6 条，共 12,842 条资产</span>
          <div className="flex gap-2">
            <button className="px-4 py-2 rounded-xl border border-brand-border text-xs font-bold text-brand-text-muted hover:bg-brand-card transition-all disabled:opacity-30" disabled>上一页</button>
            <button className="px-4 py-2 rounded-xl bg-brand-accent text-white text-xs font-bold shadow-lg shadow-brand-accent/20">1</button>
            <button className="px-4 py-2 rounded-xl border border-brand-border text-xs font-bold text-brand-text-muted hover:bg-brand-card transition-all">2</button>
            <button className="px-4 py-2 rounded-xl border border-brand-border text-xs font-bold text-brand-text-muted hover:bg-brand-card transition-all">下一页</button>
          </div>
        </div>
      </div>
    </div>
  );
}
