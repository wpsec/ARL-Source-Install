import { formatPercent, normalizeValue, parseNumericValue } from './format';

export function formatCpuSummary(deviceInfo: any): string {
  const cpu = deviceInfo?.cpu;
  if (!cpu || typeof cpu !== 'object' || Array.isArray(cpu)) return normalizeValue(cpu);
  const count = parseNumericValue(cpu.count);
  const percent = formatPercent(cpu.percent);

  if (count !== null && percent !== '-') return `${Math.round(count)}核 / ${percent}`;
  if (count !== null) return `${Math.round(count)}核`;
  return percent;
}

export function formatUsageSummary(value: any): string {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return normalizeValue(value);
  const used = normalizeValue(value.used);
  const total = normalizeValue(value.total);
  const percent = formatPercent(value.percent);
  const usedTotal = used !== '-' || total !== '-' ? `${used}/${total}` : '-';

  if (usedTotal !== '-' && percent !== '-') return `${usedTotal} (${percent})`;
  if (usedTotal !== '-') return usedTotal;
  return percent;
}
