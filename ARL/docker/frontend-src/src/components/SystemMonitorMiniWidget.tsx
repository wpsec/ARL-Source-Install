import { useQuery } from '@tanstack/react-query';
import { Activity, ArrowDown, ArrowUp, Cpu, Database, Network, ExternalLink } from 'lucide-react';
import { requestApi } from '../api/client';
import { formatPercent, normalizeValue, parseNumericValue } from '../domain/format';
import { CONSOLE_ICON_BUTTON_CLASS } from '../ui/classes';

const MONITOR_POLL_INTERVAL_MS = 3000;

type MonitorPoint = {
  time?: string;
  cpu?: number;
  ram?: number;
  net?: number;
};

type SystemMonitorMiniWidgetProps = {
  token: string;
  onOpen: () => void;
};

function clampPercent(value: any): number {
  const parsed = parseNumericValue(value);
  return Math.min(100, Math.max(0, parsed ?? 0));
}

function formatNetworkRate(value: any): string {
  const rate = Math.max(0, parseNumericValue(value) ?? 0);
  if (rate >= 1024) return `${(rate / 1024).toFixed(1)} MB/s`;
  return `${rate.toFixed(1)} KB/s`;
}

function buildSparklinePoints(data: MonitorPoint[], dataKey: 'cpu' | 'ram' | 'net'): string {
  const values = data.map((point) => Math.max(0, parseNumericValue(point[dataKey]) ?? 0));
  if (values.length === 0) return '';

  const width = 76;
  const height = 28;
  const padding = 2;
  const min = Math.min(...values);
  const max = Math.max(...values);
  const range = max - min;

  return values.map((value, index) => {
    const x = values.length === 1
      ? width / 2
      : padding + (index / (values.length - 1)) * (width - padding * 2);
    const normalized = range === 0 ? 0.5 : (value - min) / range;
    const y = height - padding - normalized * (height - padding * 2);
    return `${x.toFixed(2)},${y.toFixed(2)}`;
  }).join(' ');
}

function Sparkline({ data, dataKey, color }: { data: MonitorPoint[]; dataKey: 'cpu' | 'ram' | 'net'; color: string }) {
  const points = buildSparklinePoints(data, dataKey);
  const lastPoint = points.split(' ').at(-1)?.split(',') || [];

  return (
    <div className="h-6 min-w-0 w-full" aria-hidden="true">
      <svg viewBox="0 0 76 28" className="h-full w-full overflow-visible" focusable="false">
        <polyline points={points} fill="none" stroke={color} strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" />
        {lastPoint.length === 2 ? <circle cx={lastPoint[0]} cy={lastPoint[1]} r="2" fill={color} /> : null}
      </svg>
    </div>
  );
}

function MetricRow({
  icon: Icon,
  label,
  value,
  data,
  dataKey,
  color,
  withDivider = false,
}: {
  icon: typeof Cpu;
  label: string;
  value: string;
  data: MonitorPoint[];
  dataKey: 'cpu' | 'ram' | 'net';
  color: string;
  withDivider?: boolean;
}) {
  return (
    <div className={`flex h-full min-w-0 flex-1 items-center gap-1.5 px-2 xl:px-2.5 ${withDivider ? 'border-r border-base-300' : ''}`}>
      <Icon className="h-3.5 w-3.5 shrink-0" style={{ color }} />
      <div className="min-w-0 flex-1">
        <div className="grid grid-cols-[2.25rem_minmax(0,1fr)] items-baseline gap-x-1.5">
          <span className="w-9 shrink-0 whitespace-nowrap text-[10px] font-semibold leading-3 text-content-muted">{label}</span>
          <span className="min-w-0 truncate text-right text-[11px] font-bold leading-3 tabular-nums" style={{ color }}>{value}</span>
        </div>
        <div className="mt-0.5">
          <Sparkline data={data} dataKey={dataKey} color={color} />
        </div>
      </div>
    </div>
  );
}

export function SystemMonitorMiniWidget({ token, onOpen }: SystemMonitorMiniWidgetProps) {
  const monitorQuery = useQuery({
    queryKey: ['system-monitor', token],
    queryFn: async () => {
      const response = await requestApi(token, '/console/system_monitor/', { method: 'GET' });
      const data = response?.data || {};
      if (!data?.resource || typeof data.resource !== 'object') {
        throw new Error('系统监控数据为空');
      }
      return data;
    },
    enabled: Boolean(token),
    refetchInterval: MONITOR_POLL_INTERVAL_MS,
    refetchIntervalInBackground: false,
    retry: 0,
  });

  const resource = monitorQuery.data?.resource || {};
  const cpuPercent = clampPercent(resource.cpu_percent);
  const memoryPercent = clampPercent(resource.memory_percent);
  const networkRate = Math.max(0, parseNumericValue(resource.network_rate_total_kbps) ?? 0);
  const history = Array.isArray(monitorQuery.data?.history_24h)
    ? monitorQuery.data.history_24h.slice(-20)
    : [];
  const chartData: MonitorPoint[] = history.length > 0
    ? history
    : [{ cpu: cpuPercent, ram: memoryPercent, net: networkRate }];
  return (
    <section className="hidden shrink-0 items-center gap-1.5 lg:flex" aria-label="系统监控摘要">
      <div
        className="flex h-11 w-[380px] shrink-0 overflow-hidden rounded-box border border-base-300 bg-base-100 xl:w-[420px] 2xl:w-[456px]"
        role="group"
        aria-label="CPU、内存与网速"
      >
        <MetricRow icon={Cpu} label="CPU" value={monitorQuery.data ? formatPercent(cpuPercent) : '--'} data={chartData} dataKey="cpu" color="var(--brand-accent)" withDivider />
        <MetricRow icon={Database} label="内存" value={monitorQuery.data ? formatPercent(memoryPercent) : '--'} data={chartData} dataKey="ram" color="var(--brand-secondary)" withDivider />
        <MetricRow icon={Network} label="网速" value={monitorQuery.data ? formatNetworkRate(networkRate) : '--'} data={chartData} dataKey="net" color="var(--brand-warning)" />
      </div>

      <div className="hidden xl:grid h-11 shrink-0 grid-cols-3 items-center gap-3 rounded-box border border-base-300 bg-base-100 px-3">
        <div className="min-w-[3.5rem] text-center">
          <div className="flex items-center justify-center gap-1 text-content-muted">
            <ArrowUp className="h-3 w-3" />
            <span className="text-[10px] font-semibold leading-3">发送</span>
          </div>
          <p className="whitespace-nowrap text-[11px] font-bold leading-3 tabular-nums">{normalizeValue(resource.network_total_sent)}</p>
        </div>
        <div className="min-w-[3.5rem] text-center">
          <div className="flex items-center justify-center gap-1 text-content-muted">
            <ArrowDown className="h-3 w-3" />
            <span className="text-[10px] font-semibold leading-3">接收</span>
          </div>
          <p className="whitespace-nowrap text-[11px] font-bold leading-3 tabular-nums">{normalizeValue(resource.network_total_recv)}</p>
        </div>
        <div className="min-w-[3.5rem] text-center">
          <div className="flex items-center justify-center gap-1 text-content-muted">
            <Activity className="h-3 w-3" />
            <span className="text-[10px] font-semibold leading-3">进程</span>
          </div>
          <p className="whitespace-nowrap text-[11px] font-bold leading-3 tabular-nums">{normalizeValue(resource.process_count)}</p>
        </div>
      </div>

      <button
        type="button"
        onClick={onOpen}
        className={CONSOLE_ICON_BUTTON_CLASS}
        title="打开系统监控"
        aria-label="打开系统监控"
      >
        <ExternalLink className="h-3.5 w-3.5" />
      </button>
    </section>
  );
}

export default SystemMonitorMiniWidget;
