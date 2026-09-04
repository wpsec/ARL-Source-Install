import type {JsonValue} from './types';

export function normalizeHttpHyperlink(value: any): string {
  const text = String(value ?? '').trim();
  if (!text || text === '-') return '';
  if (!/^https?:\/\//i.test(text)) return '';
  try {
    const parsed = new URL(text);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return '';
    return parsed.toString();
  } catch {
    return '';
  }
}

export function truncateText(value: string, max = 120): string {
  if (value.length <= max) return value;
  return `${value.slice(0, max)}...`;
}

export function truncateMiddleText(value: string, max = 48, head = 18, tail = 16): string {
  const text = String(value ?? '').trim();
  if (!text) return '-';
  if (text.length <= max) return text;
  const safeHead = Math.max(6, Math.min(head, Math.floor((max - 3) / 2)));
  const safeTail = Math.max(4, Math.min(tail, max - safeHead - 3));
  return `${text.slice(0, safeHead)}...${text.slice(-safeTail)}`;
}

export function isLikelyIdColumn(column: string): boolean {
  const key = String(column || '').toLowerCase();
  if (!key) return false;
  return key === '_id' || key.endsWith('_id') || key === 'taskid' || key === 'job_id';
}

export function formatExternalFilterChipText(key: string, value: any): string {
  const keyText = String(key || '').trim();
  const valueText = String(value ?? '').trim();
  if (!valueText) return `${keyText}=-`;

  if (isLikelyIdColumn(keyText)) {
    const parts = valueText.replace(/,/g, ' ').split(/\s+/).filter((item) => item);
    if (parts.length > 1) {
      return `${keyText}=${truncateMiddleText(parts[0], 32, 12, 10)} ... 共${parts.length}项`;
    }
    return `${keyText}=${truncateMiddleText(valueText, 44, 20, 18)}`;
  }

  return `${keyText}=${truncateMiddleText(valueText, 64, 28, 26)}`;
}

export function normalizeValue(value: any): string {
  if (value === null || value === undefined) return '-';
  if (typeof value === 'string') return truncateText(value);
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  if (Array.isArray(value)) {
    if (value.length === 0) return '-';
    const normalized = value
      .map((item) => {
        if (item === null || item === undefined) return '';
        if (typeof item === 'string' || typeof item === 'number' || typeof item === 'boolean') {
          return String(item);
        }
        return JSON.stringify(item);
      })
      .filter((item) => item)
      .join(', ');
    return truncateText(normalized || '-');
  }
  if (typeof value === 'object') return truncateText(JSON.stringify(value));
  return truncateText(String(value));
}

export function normalizeValueNoTruncate(value: any): string {
  if (value === null || value === undefined) return '-';
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  if (Array.isArray(value)) {
    if (value.length === 0) return '-';
    const normalized = value
      .map((item) => {
        if (item === null || item === undefined) return '';
        if (typeof item === 'string' || typeof item === 'number' || typeof item === 'boolean') {
          return String(item);
        }
        try {
          return JSON.stringify(item);
        } catch {
          return String(item);
        }
      })
      .filter((item) => item)
      .join(', ');
    return normalized || '-';
  }
  if (typeof value === 'object') {
    try {
      return JSON.stringify(value);
    } catch {
      return String(value);
    }
  }
  return String(value);
}

export function getValueByPath(source: any, path: string): any {
  if (!path || source === null || source === undefined) return undefined;
  if (!path.includes('.')) return source?.[path];
  const segments = path.split('.');
  let cursor: any = source;
  for (const segment of segments) {
    if (cursor === null || cursor === undefined) return undefined;
    if (Array.isArray(cursor)) {
      cursor = cursor
        .map((item) => {
          if (item && typeof item === 'object') return item[segment];
          return undefined;
        })
        .flatMap((item) => (Array.isArray(item) ? item : [item]))
        .filter((item) => item !== undefined && item !== null);
      continue;
    }
    if (typeof cursor !== 'object') return undefined;
    cursor = cursor[segment];
  }
  return cursor;
}

export function formatDateTimeCell(value: any): string {
  if (value === null || value === undefined) return '-';
  const text = String(value).trim();
  if (!text || text === '-') return '-';

  // 统一展示为 YYYY-MM-DD HH:mm:ss，避免不同来源时间字符串长度不一致。
  const directMatch = text.match(/^(\d{4}-\d{2}-\d{2})[T\s](\d{2}:\d{2}:\d{2})/);
  if (directMatch) {
    return `${directMatch[1]} ${directMatch[2]}`;
  }

  const parsed = new Date(text);
  if (!Number.isNaN(parsed.getTime())) {
    const year = parsed.getFullYear();
    const month = String(parsed.getMonth() + 1).padStart(2, '0');
    const day = String(parsed.getDate()).padStart(2, '0');
    const hour = String(parsed.getHours()).padStart(2, '0');
    const minute = String(parsed.getMinutes()).padStart(2, '0');
    const second = String(parsed.getSeconds()).padStart(2, '0');
    return `${year}-${month}-${day} ${hour}:${minute}:${second}`;
  }

  return truncateText(text, 32);
}

export function parseDateTimeToTimestamp(value: any): number | null {
  if (value === null || value === undefined) return null;

  if (typeof value === 'number' && Number.isFinite(value)) {
    if (value > 1e12) return Math.floor(value);
    if (value > 1e9) return Math.floor(value * 1000);
    return null;
  }

  const text = String(value).trim();
  if (!text || text === '-') return null;

  const directMatch = text.match(/^(\d{4})-(\d{2})-(\d{2})[T\s](\d{2}):(\d{2}):(\d{2})/);
  if (directMatch) {
    const parsed = new Date(
      Number(directMatch[1]),
      Number(directMatch[2]) - 1,
      Number(directMatch[3]),
      Number(directMatch[4]),
      Number(directMatch[5]),
      Number(directMatch[6])
    ).getTime();
    if (!Number.isNaN(parsed)) return parsed;
  }

  const parsed = Date.parse(text);
  if (!Number.isNaN(parsed)) return parsed;
  return null;
}

export function formatDurationSecondsLabel(totalSeconds: number | null): string {
  if (totalSeconds === null || !Number.isFinite(totalSeconds) || totalSeconds < 0) return '-';
  if (totalSeconds > 0 && totalSeconds < 1) return '<1秒';
  const seconds = Math.floor(totalSeconds);
  if (seconds < 60) return `${seconds}秒`;
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const remainSeconds = seconds % 60;
  const parts: string[] = [];
  if (days > 0) parts.push(`${days}天`);
  if (hours > 0) parts.push(`${hours}小时`);
  if (minutes > 0) parts.push(`${minutes}分`);
  if (remainSeconds > 0 || parts.length === 0) parts.push(`${remainSeconds}秒`);
  return parts.join('');
}

export function parseNumericValue(value: any): number | null {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string') {
    const raw = value.trim().replace(/%$/, '');
    if (!raw) return null;
    const parsed = Number(raw);
    if (Number.isFinite(parsed)) return parsed;
  }
  return null;
}

export function formatPercent(value: any): string {
  const numeric = parseNumericValue(value);
  if (numeric === null) return '-';
  return `${numeric.toFixed(1)}%`;
}

export function deepClone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value));
}

export function toDatetimeLocalValue(value: any): string {
  const text = String(value ?? '').trim();
  if (!text) return '';
  const directMatch = text.match(/^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2})(?::\d{2})?$/);
  if (directMatch) {
    return `${directMatch[1]}T${directMatch[2]}`;
  }
  return '';
}

export function fromDatetimeLocalValue(value: string): string {
  const text = String(value ?? '').trim();
  if (!text) return '';
  const localMatch = text.match(/^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2})(?::(\d{2}))?$/);
  if (localMatch) {
    return `${localMatch[1]} ${localMatch[2]}:${localMatch[3] || '00'}`;
  }
  const spaceMatch = text.match(/^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2})(?::(\d{2}))?$/);
  if (spaceMatch) {
    return `${spaceMatch[1]} ${spaceMatch[2]}:${spaceMatch[3] || '00'}`;
  }
  return text;
}

export const fieldLabelMap: Record<string, string> = {
  name: '名称',
  target: '目标',
  policy_id: '策略ID',
  scope_id: '资产组ID',
  task_id: '任务ID',
  task_ids: '任务ID列表',
  job_id: '监控任务ID',
  keyword: '关键字',
  query: '查询语句',
  domain: '域名',
  site: '站点',
  interval: '间隔(秒)',
  cron: 'Cron表达式',
  start_date: '开始时间',
  schedule_type: '计划类型',
  task_tag: '任务标签',
  del_task_data: '删除关联数据',
  force_refresh_token: '强制刷新Token',
  workbook_id: '工作簿ID',
  sheet_name: '工作表',
  markdown_content: 'Markdown内容',
  operator_id: '操作人ID',
  parent_node_id: '父节点ID',
  workspace_id: '空间ID',
  notify_enable: '启用通知',
  notify_kb_enable: '推送知识库',
  dingding_notify: '钉钉通知',
  kb_notify_enable: '知识库通知',
  domain_brute: '域名爆破',
  domain_brute_type: '爆破字典类型',
  domain_dict: '域名爆破字典',
  file_leak_dict: '目录扫描字典',
  port_scan: '端口扫描',
  port_scan_type: '端口扫描类型',
  port_custom: '自定义端口',
  service_detection: '服务识别',
  service_brute: '弱口令爆破',
  os_detection: '操作系统识别',
  site_identify: '站点识别',
  site_capture: '站点截图',
  file_leak: '目录扫描',
  search_engines: '搜索引擎调用',
  site_spider: '站点爬虫',
  arl_search: 'ARL 历史查询',
  alt_dns: 'DNS字典智能生成',
  ssl_cert: 'SSL 证书获取',
  dns_query_plugin: '测绘引擎查询',
  skip_scan_cdn_ip: '跳过CDN',
  nuclei_scan: 'nuclei 调用',
  afrog_scan: 'afrog 调用',
  findvhost: 'Host 碰撞',
  web_info_hunter: 'WIH 调用',
  smart_skip_waf: '跳过WAF',
  ai_denoise: 'AI去噪分析',
};

export function humanizeField(path: string): string {
  const direct = fieldLabelMap[path];
  if (direct) return direct;
  const key = path.split('.').pop() || path;
  if (fieldLabelMap[key]) return fieldLabelMap[key];
  return key
    .replace(/_/g, ' ')
    .replace(/([a-z])([A-Z])/g, '$1 $2')
    .replace(/^./, (s) => s.toUpperCase());
}

export function applyPathTemplate(path: string, payload: JsonValue): string {
  return path.replace(/\{(\w+)\}/g, (_, key) => encodeURIComponent(String(payload[key] ?? '')));
}
