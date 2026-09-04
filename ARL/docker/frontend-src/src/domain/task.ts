import { sanitizeUiMessage } from '../api/client';
import {
  fieldLabelMap,
  formatDateTimeCell,
  formatDurationSecondsLabel,
  humanizeField,
  normalizeValue,
  parseDateTimeToTimestamp,
} from './format';
import type {AiDenoiseResultItem} from './types';

export const TASK_RUNNING_STAGE_LABELS: Record<string, string> = {
  domain_brute: '域名爆破',
  alt_dns: '字典生成',
  port_scan: '端口扫描',
  ssl_cert: 'SSL证书',
  npoc_service_detection: '服务识别',
  search_engines: '搜索引擎',
  findvhost: 'Host碰撞',
  fetch_site: '站点探测',
  site_spider: '站点爬虫',
  site_identify: '站点识别',
  site_capture: '站点截图',
  file_leak: '目录扫描',
  poc_run: 'PoC扫描',
  nuclei_scan: 'Nuclei扫描',
  afrog_scan: 'afrog扫描',
  web_info_hunter: 'WIH扫描',
  nuclei_scan_retry: 'Nuclei补跑',
};

export function normalizeTaskStatus(rawStatus: any): 'waiting' | 'running' | 'done' | 'stop' | 'error' {
  const rawText = String(rawStatus ?? '').trim();
  const normalized = rawText.toLowerCase();
  if (!normalized) return 'running';
  if (normalized === 'waiting') return 'waiting';
  if (normalized === 'running') return 'running';
  if (normalized === 'done') return 'done';
  if (normalized === 'stop') return 'stop';
  if (normalized === 'error') return 'error';
  if (/^\w+\s+\d+\/\d+$/i.test(normalized)) return 'running';
  if (normalized.includes('done') || normalized.includes('finish') || normalized.includes('success')) return 'done';
  if (normalized.includes('stop') || normalized.includes('cancel')) return 'stop';
  if (normalized.includes('error') || normalized.includes('fail')) return 'error';
  if (normalized.includes('run') || normalized.includes('wait') || normalized.includes('queue') || normalized.includes('start')) {
    return 'running';
  }
  return 'running';
}

export function getTaskStatusSortWeight(rawStatus: any): number {
  const normalizedStatus = normalizeTaskStatus(rawStatus);
  if (normalizedStatus === 'running') return 0;
  if (normalizedStatus === 'done') return 1;
  if (normalizedStatus === 'waiting') return 2;
  if (normalizedStatus === 'error' || normalizedStatus === 'stop') return 3;
  return 5;
}

export function getTaskSortTimeByStatus(row: any, normalizedStatus: ReturnType<typeof normalizeTaskStatus>): number {
  const resolveTimestamp = (keys: string[]): number => {
    for (const key of keys) {
      const ts = parseDateTimeToTimestamp(row?.[key]);
      if (ts !== null && Number.isFinite(ts)) return ts;
    }
    return 0;
  };

  if (normalizedStatus === 'done') {
    return resolveTimestamp(['end_time', 'update_time', 'start_time', 'create_time']);
  }
  if (normalizedStatus === 'running') {
    return resolveTimestamp(['start_time', 'create_time', 'update_time', 'end_time']);
  }
  if (normalizedStatus === 'waiting') {
    return resolveTimestamp(['create_time', 'update_time', 'start_time', 'end_time']);
  }
  return resolveTimestamp(['end_time', 'update_time', 'start_time', 'create_time']);
}

export function getAiPrioritySortWeight(
  analysis: AiDenoiseResultItem | undefined,
  moduleId: string
): number {
  if (!analysis) return 1000;
  const levelWeightMap: Record<AiDenoiseResultItem['result_level'], number> = {
    danger: 0,
    suspicious: 1,
    safe: 2,
    disabled: 4,
  };
  const sourceWeightMap: Record<AiDenoiseResultItem['source'], number> = {
    ai: 0,
    rule: 1,
    disabled: 2,
  };
  let weight = levelWeightMap[analysis.result_level] * 10 + sourceWeightMap[analysis.source] * 2;
  if (moduleId === 'vuln' || moduleId === 'nuclei_result') {
    const trust = String(analysis.trust || '').toLowerCase();
    if (trust.includes('误报') || trust.includes('suspected')) weight += 3;
    if (trust.includes('可信') || trust.includes('trusted')) weight -= 1;
  }
  return weight;
}

export function getTaskStatusLabel(rawStatus: any, options: { showRunningStage?: boolean } = {}): string {
  const rawText = String(rawStatus ?? '').trim();
  const showRunningStage = Boolean(options.showRunningStage);
  if (!rawText) return '未知';
  const normalized = rawText.toLowerCase();
  if (/^\w+\s+\d+\/\d+$/i.test(normalized)) return rawText;
  const normalizedStatus = normalizeTaskStatus(rawStatus);
  if (normalizedStatus === 'waiting') return '等待中';
  if (normalizedStatus === 'running') {
    if (showRunningStage) {
      const stageLabel = TASK_RUNNING_STAGE_LABELS[normalized] || rawText.replace(/_/g, ' ');
      if (stageLabel) return `运行中（${stageLabel}）`;
    }
    return '运行中';
  }
  if (normalizedStatus === 'done') return '已完成';
  if (normalizedStatus === 'stop') return '已停止';
  if (normalizedStatus === 'error') return '异常';
  if (showRunningStage) {
    const stageLabel = TASK_RUNNING_STAGE_LABELS[normalized] || rawText.replace(/_/g, ' ');
    if (stageLabel) return `运行中（${stageLabel}）`;
  }
  // 保持筛选兼容：未知阶段状态仍归类为“运行中”。
  return '运行中';
}

export function getTaskTypeLabel(rawType: any): string {
  const mapping: Record<string, string> = {
    domain: '域名任务',
    ip: 'IP任务',
    risk_cruising: '风险巡航任务',
    fofa: '测绘任务',
    asset_site_add: '添加站点任务',
    asset_site_update: '站点更新任务',
    asset_wih_update: 'WIH更新任务',
  };
  const normalized = String(rawType ?? '').toLowerCase();
  return mapping[normalized] || normalizeValue(rawType);
}

export function extractTaskStatisticCounts(row: any): {
  siteCnt: number;
  domainCnt: number;
  ipCnt: number;
  urlCnt: number;
  vulnCnt: number;
  hasAny: boolean;
} {
  const stat = row?.statistic;
  if (!stat || typeof stat !== 'object' || Array.isArray(stat)) {
    return {
      siteCnt: 0,
      domainCnt: 0,
      ipCnt: 0,
      urlCnt: 0,
      vulnCnt: 0,
      hasAny: false,
    };
  }

  const siteCnt = Number(stat.site_cnt || 0);
  const domainCnt = Number(stat.domain_cnt || 0);
  const ipCnt = Number(stat.ip_cnt || 0);
  const urlCnt = Number(stat.url_cnt || 0);
  const vulnCnt = Number(stat.vuln_cnt || 0);
  const hasAny = [siteCnt, domainCnt, ipCnt, urlCnt, vulnCnt].some((item) => Number(item || 0) > 0);

  return {
    siteCnt,
    domainCnt,
    ipCnt,
    urlCnt,
    vulnCnt,
    hasAny,
  };
}

export function buildTaskStatisticSummary(row: any): string {
  const stat = row?.statistic;
  const wafSummary = row?.waf_skip_summary && typeof row.waf_skip_summary === 'object' ? row.waf_skip_summary : {};
  const wafDetectedHostCount = Number(wafSummary?.detected_host_count || 0);
  const wafBlockedHostCount = Number(wafSummary?.blocked_host_count || 0);
  const wafBypassHostCount = Number(wafSummary?.bypass_success_host_count || 0);
  const wafSkipRequestCount = Number(wafSummary?.skip_request_count || 0);
  const wafObservedSiteCount = Number(wafSummary?.observed_site_count || 0);
  const wafSkipSiteCount = Number(wafSummary?.skip_site_count || 0);

  if (!stat || typeof stat !== 'object' || Array.isArray(stat)) {
    if (wafDetectedHostCount > 0 || wafBlockedHostCount > 0 || wafSkipRequestCount > 0 || wafBypassHostCount > 0) {
      return `WAF识别:主机${wafDetectedHostCount} 站点${wafObservedSiteCount} 跳过主机${wafBlockedHostCount} 跳过站点${wafSkipSiteCount} 绕过${wafBypassHostCount} 请求${wafSkipRequestCount}`;
    }
    return '-';
  }
  const { siteCnt, domainCnt, ipCnt, vulnCnt } = extractTaskStatisticCounts(row);
  let summary = `站点:${siteCnt} 域名:${domainCnt} IP:${ipCnt} 风险:${vulnCnt}`;
  if (wafDetectedHostCount > 0 || wafBlockedHostCount > 0 || wafSkipRequestCount > 0 || wafBypassHostCount > 0) {
    summary += ` WAF识别:主机${wafDetectedHostCount}/站点${wafObservedSiteCount}/跳过主机${wafBlockedHostCount}/跳过站点${wafSkipSiteCount}/绕过${wafBypassHostCount}/请求${wafSkipRequestCount}`;
  }
  return summary;
}

export function buildTaskOptionsSummary(row: any): string {
  const options = row?.options;
  if (!options || typeof options !== 'object' || Array.isArray(options)) return '-';
  const enabled = Object.entries(options)
    .filter(([, value]) => value === true)
    .map(([key]) => fieldLabelMap[key] || humanizeField(key));
  if (enabled.length === 0) return '未开启可选项';
  return enabled.map((label, index) => `${index + 1}. ${label}`).join('\n');
}

export const TASK_SERVICE_STAGE_LABEL_MAP: Record<string, string> = {
  domain_brute: '域名爆破',
  dns_query_plugin: '测绘引擎查询',
  arl_search: 'ARL历史查询',
  alt_dns: 'DNS字典智能生成',
  ip_query_plugin: 'IP测绘补充',
  port_scan: '端口扫描',
  ssl_cert: 'SSL证书获取',
  cert_query_plugin: '证书关联查询',
  find_site: '站点识别',
  site_spider: '站点爬虫',
  site_capture: '站点截图',
  file_leak: '目录扫描',
  nuclei_scan: 'Nuclei扫描',
  afrog: 'afrog扫描',
  afrog_scan: 'afrog扫描',
  web_info_hunter: 'WIH信息收集',
  wih: 'WIH信息收集',
  findvhost: 'Host碰撞',
  search_engines: '搜索引擎调用',
  npoc_service_detection: '服务识别',
  poc_run: 'PoC扫描',
  weak_brute: '弱口令爆破',
  cloud_security_scan: '云安全扫描',
  waf_smart_skip: 'WAF智能跳过',
  waf_observe: 'WAF识别观察',
  task_finalize: '任务收尾统计',
  wih_monitor: 'WIH监控',
  wih_domain_update: 'WIH域名更新',
  wih_primary_scan: 'Wih primary scan',
  wih_endpoint_probe: 'Wih endpoint probe',
  wih_endpoint_ai_fill: 'Wih endpoint ai fill',
  wih_urlfinder_extract: 'Wih urlfinder extract',
  wih_page_intel: 'Wih page intel',
  wih_api_doc: 'Wih api doc',
  wih_js_intel: 'Wih js intel',
  wih_urlfinder_sensitive: 'Wih sensitive rescan',
  wih_trufflehog_js: 'Wih trufflehog js',
  wih_url_probe: 'Wih url probe',
};

export function parseTaskServiceElapsedSeconds(rawValue: any): number | null {
  if (rawValue === null || rawValue === undefined) return null;
  if (typeof rawValue === 'number') {
    return Number.isFinite(rawValue) && rawValue >= 0 ? rawValue : null;
  }
  const parsed = Number(String(rawValue).trim());
  if (!Number.isFinite(parsed) || parsed < 0) return null;
  return parsed;
}

export function parseTaskServiceSummaryCount(rawValue: any): number | null {
  if (rawValue === null || rawValue === undefined) return null;
  const parsed = Number(String(rawValue).trim());
  if (!Number.isFinite(parsed) || parsed < 0) return null;
  return Math.floor(parsed);
}

export function getTaskServiceStageLabel(rawName: any, fallback: string): string {
  const text = String(rawName ?? '').trim();
  if (!text) return fallback;
  const normalized = text.toLowerCase();
  return TASK_SERVICE_STAGE_LABEL_MAP[normalized] || fieldLabelMap[normalized] || fieldLabelMap[text] || humanizeField(text);
}

export function buildTaskServiceDurationSummary(row: any): {
  entries: Array<{
    stageKey: string;
    stageName: string;
    elapsedSeconds: number | null;
    elapsedLabel: string;
    detail: string;
    countedInTotal: boolean;
  }>;
  totalStageCount: number;
  totalDurationSeconds: number | null;
  totalDurationLabel: string;
  countedStageCount: number;
  rawTotalDurationSeconds: number | null;
  rawTotalDurationLabel: string;
  dedupApplied: boolean;
  skippedParentStageNames: string[];
} {
  const serviceItems = Array.isArray(row?.service) ? row.service : [];
  const rawServiceSummary = row?.service_summary;
  const serviceSummary = rawServiceSummary && typeof rawServiceSummary === 'object'
    ? rawServiceSummary
    : null;
  const skippedParentStageKeys = Array.isArray(serviceSummary?.skipped_parent_phase)
    ? serviceSummary.skipped_parent_phase
      .map((item: any) => String(item ?? '').trim().toLowerCase())
      .filter(Boolean)
    : [];
  const skippedParentStageKeySet = new Set(skippedParentStageKeys);
  const entries = serviceItems.map((item, index) => {
    const rawStageName = String(item?.name ?? item?.service_name ?? item?.stage ?? item ?? '').trim();
    const stageName = getTaskServiceStageLabel(
      rawStageName,
      `阶段${index + 1}`
    );
    const elapsedSeconds = parseTaskServiceElapsedSeconds(
      item?.elapsed ?? item?.duration ?? item?.cost ?? item?.seconds
    );
    const detail = sanitizeUiMessage(String(item?.detail || item?.message || '').trim(), 240) || '';
    return {
      stageKey: rawStageName.toLowerCase(),
      stageName,
      elapsedSeconds,
      elapsedLabel: elapsedSeconds === null ? '-' : formatDurationSecondsLabel(elapsedSeconds),
      detail,
      countedInTotal: !skippedParentStageKeySet.has(rawStageName.toLowerCase()),
    };
  });
  const entriesWithDuration = entries.filter((item) => item.elapsedSeconds !== null);
  const rawTotalDurationSeconds = entriesWithDuration.length > 0
    ? entriesWithDuration.reduce((sum, item) => sum + Number(item.elapsedSeconds || 0), 0)
    : null;
  const dedupDurationSeconds = parseTaskServiceElapsedSeconds(serviceSummary?.dedup_elapsed);
  const totalStageCount = parseTaskServiceSummaryCount(serviceSummary?.phase_count) ?? entries.length;
  const countedStageCount = parseTaskServiceSummaryCount(serviceSummary?.dedup_phase_count) ?? entriesWithDuration.length;
  const totalDurationSeconds = dedupDurationSeconds ?? rawTotalDurationSeconds;
  const dedupApplied = Boolean(
    dedupDurationSeconds !== null && (
      skippedParentStageKeys.length > 0 ||
      (rawTotalDurationSeconds !== null && Math.abs(rawTotalDurationSeconds - dedupDurationSeconds) >= 0.01) ||
      countedStageCount !== entriesWithDuration.length
    )
  );
  const skippedParentStageNames = skippedParentStageKeys.map((stageKey, index) =>
    getTaskServiceStageLabel(stageKey, `汇总阶段${index + 1}`)
  );

  return {
    entries,
    totalStageCount,
    totalDurationSeconds,
    totalDurationLabel: formatDurationSecondsLabel(totalDurationSeconds),
    countedStageCount,
    rawTotalDurationSeconds,
    rawTotalDurationLabel: formatDurationSecondsLabel(rawTotalDurationSeconds),
    dedupApplied,
    skippedParentStageNames,
  };
}

export function buildTaskExecutionAccountingSummary(row: any, nowMs: number): {
  currentStageName: string;
  currentStageVisible: boolean;
  uncountedStageName: string;
  hasUncountedDuration: boolean;
  uncountedDurationSeconds: number | null;
  uncountedDurationLabel: string;
  note: string;
} {
  const execution = buildTaskExecutionDurationInfo(row, nowMs);
  const serviceSummary = buildTaskServiceDurationSummary(row);
  const rawStatus = String(row?.status ?? '').trim();
  const statusKey = rawStatus.toLowerCase();
  const normalizedStatus = normalizeTaskStatus(rawStatus);
  const runningLike = normalizedStatus === 'running' || normalizedStatus === 'waiting';
  const currentStageVisible = Boolean(
    runningLike &&
    statusKey &&
    statusKey !== 'running' &&
    statusKey !== 'waiting'
  );
  const currentStageName = currentStageVisible
    ? getTaskServiceStageLabel(rawStatus, '当前阶段')
    : '-';
  const uncountedStageName = currentStageVisible
    ? currentStageName
    : runningLike
      ? '当前进行阶段'
      : '任务收尾统计/同步';

  let uncountedDurationSeconds: number | null = null;
  if (execution.durationSeconds !== null) {
    const counted = serviceSummary.totalDurationSeconds;
    if (counted === null) {
      uncountedDurationSeconds = execution.durationSeconds;
    } else {
      uncountedDurationSeconds = Math.max(0, execution.durationSeconds - counted);
    }
  }

  const hasUncountedDuration = Boolean(
    uncountedDurationSeconds !== null && Number.isFinite(uncountedDurationSeconds) && uncountedDurationSeconds >= 1
  );

  let note = '';
  if (hasUncountedDuration && currentStageVisible) {
    note = '该阶段仍在执行，耗时实时计算；阶段完成后自动并入子任务累计耗时。';
  } else if (hasUncountedDuration && runningLike) {
    note = '当前任务仍在执行，耗时实时计算；阶段完成后自动并入子任务累计耗时。';
  } else if (hasUncountedDuration) {
    note = '任务收尾统计或同步仍在执行，该耗时会在流程结束后并入累计。';
  }

  return {
    currentStageName,
    currentStageVisible,
    uncountedStageName,
    hasUncountedDuration,
    uncountedDurationSeconds,
    uncountedDurationLabel: formatDurationSecondsLabel(uncountedDurationSeconds),
    note,
  };
}

export function buildTaskExecutionDurationInfo(row: any, nowMs: number): {
  startText: string;
  endText: string;
  durationSeconds: number | null;
  durationLabel: string;
} {
  const startMs = parseDateTimeToTimestamp(row?.start_time);
  const endMsRaw = parseDateTimeToTimestamp(row?.end_time);
  const startText = formatDateTimeCell(row?.start_time);
  const status = normalizeTaskStatus(row?.status);
  const runningLike = status === 'running' || status === 'waiting';
  const effectiveEndMs = endMsRaw ?? (startMs && runningLike ? nowMs : null);
  const endText = endMsRaw
    ? formatDateTimeCell(row?.end_time)
    : (startMs && runningLike ? '进行中' : formatDateTimeCell(row?.end_time));

  if (!startMs || !effectiveEndMs || effectiveEndMs < startMs) {
    return {
      startText,
      endText,
      durationSeconds: null,
      durationLabel: '-',
    };
  }

  const durationSeconds = Math.floor((effectiveEndMs - startMs) / 1000);
  return {
    startText,
    endText,
    durationSeconds,
    durationLabel: formatDurationSecondsLabel(durationSeconds),
  };
}

export function getTaskProgressPercent(row: any): number {
  const status = String(row?.status || '').toLowerCase();
  if (status === 'done') return 100;
  if (status === 'waiting') return 0;
  if (status === 'error' || status === 'stop') return 100;

  const ratioMatch = status.match(/(\d+)\s*\/\s*(\d+)/);
  if (ratioMatch) {
    const current = Number(ratioMatch[1]);
    const total = Number(ratioMatch[2]);
    if (Number.isFinite(current) && Number.isFinite(total) && total > 0) {
      const ratio = Math.round((current / total) * 100);
      return Math.min(99, Math.max(1, ratio));
    }
  }

  const options = row?.options && typeof row.options === 'object' ? row.options : {};
  const enabledOptionCount = Object.values(options).filter((value) => value === true).length;
  const serviceDoneCount = Array.isArray(row?.service) ? row.service.length : 0;
  const estimatedTotal = Math.max(enabledOptionCount + 2, 4);
  const estimated = Math.round((serviceDoneCount / estimatedTotal) * 100);
  if (status.includes('run') || status.includes('wait') || status.includes('queue') || status.includes('start')) {
    return Math.min(99, Math.max(5, estimated));
  }
  return Math.min(99, Math.max(0, estimated));
}
