import { normalizeValue, normalizeValueNoTruncate } from './format';

export function formatWihEndpointMetric(row: any, column: string): string {
  const rawValue = column === 'status_code'
    ? (row?.status_code ?? row?.response_status)
    : row?.response_size;
  if (rawValue === null || rawValue === undefined || rawValue === '') {
    const rawStatus = row?.status_code ?? row?.response_status;
    const numericStatus = Number(rawStatus);
    if (column === 'response_size' && Number.isFinite(numericStatus) && numericStatus > 0) return '-';
    return '-';
  }

  const numericValue = Number(rawValue);
  if (!Number.isFinite(numericValue)) return normalizeValue(rawValue);

  if (column === 'status_code') {
    return numericValue > 0 ? String(numericValue) : '-';
  }

  const rawStatus = row?.status_code ?? row?.response_status;
  const numericStatus = Number(rawStatus);
  if (numericValue <= 0 && (!Number.isFinite(numericStatus) || numericStatus <= 0)) {
    return '-';
  }
  return String(numericValue);
}

export function buildWihEndpointDetailUrl(row: any): string {
  const rawUrl = normalizeValueNoTruncate(row?.url);
  if (!rawUrl || rawUrl === '-') return '-';

  const methodText = String(row?.method || '').trim().toUpperCase();
  if (methodText !== 'GET' || rawUrl.includes('?')) return rawUrl;

  const requestTemplate = row?.request_template && typeof row.request_template === 'object' ? row.request_template : {};
  const queryString = String(requestTemplate?.query_string || '').trim().replace(/^\?+/, '');
  if (queryString) return `${rawUrl}?${queryString}`;

  const queryObject = requestTemplate?.query && typeof requestTemplate.query === 'object' ? requestTemplate.query : {};
  const queryParams = new URLSearchParams();
  Object.entries(queryObject).forEach(([key, value]) => {
    if (value === null || value === undefined || value === '') return;
    queryParams.append(key, String(value));
  });
  const composedQuery = queryParams.toString();
  return composedQuery ? `${rawUrl}?${composedQuery}` : rawUrl;
}

export function buildWihEndpointRequestPacket(row: any): string {
  const packet = normalizeValueNoTruncate(row?.request_packet);
  if (packet && packet !== '-') return packet;

  const template = row?.request_template && typeof row.request_template === 'object' ? row.request_template : null;
  if (!template) return '-';
  try {
    return JSON.stringify(template, null, 2);
  } catch {
    return normalizeValueNoTruncate(template);
  }
}

export function buildWihEndpointAiFillPacket(row: any): string {
  const packet = normalizeValueNoTruncate(row?.ai_fill_request_packet);
  if (packet && packet !== '-') return packet;

  const template = row?.ai_fill_request_template && typeof row.ai_fill_request_template === 'object'
    ? row.ai_fill_request_template
    : null;
  if (!template) return '-';
  try {
    return JSON.stringify(template, null, 2);
  } catch {
    return normalizeValueNoTruncate(template);
  }
}

export function buildWihEndpointDisplayRequestPacket(row: any): string {
  const aiFillStatus = String(row?.ai_fill_status || '').trim().toLowerCase();
  if (aiFillStatus && !['disabled', 'skipped', 'error'].includes(aiFillStatus)) {
    const aiPacket = buildWihEndpointAiFillPacket(row);
    if (aiPacket && aiPacket !== '-') return aiPacket;
  }
  return buildWihEndpointRequestPacket(row);
}

export function buildWihEndpointResponsePacket(row: any): string {
  const aiPacket = normalizeValueNoTruncate(row?.ai_fill_response_packet);
  if (aiPacket && aiPacket !== '-') return aiPacket;

  const aiSummary = normalizeValueNoTruncate(row?.ai_fill_response_summary);
  if (aiSummary && aiSummary !== '-') return aiSummary;

  const aiFillStatus = String(row?.ai_fill_status || '').trim().toLowerCase();
  const aiFillNote = normalizeValueNoTruncate(row?.ai_fill_note);
  if (
    aiFillNote &&
    aiFillNote !== '-' &&
    ['test_failed', 'error'].includes(aiFillStatus)
  ) {
    return aiFillNote;
  }

  const probePacket = normalizeValueNoTruncate(row?.verification_response_packet);
  if (probePacket && probePacket !== '-') return probePacket;

  const responsePacket = normalizeValueNoTruncate(row?.response_packet);
  if (responsePacket && responsePacket !== '-') return responsePacket;

  const verificationNote = normalizeValueNoTruncate(row?.verification_note);
  if (verificationNote && verificationNote !== '-') return verificationNote;

  return '-';
}

export function formatWihEndpointAiFillStatus(row: any): string {
  const value = String(row?.ai_fill_status || '').trim().toLowerCase();
  const mapping: Record<string, string> = {
    tested: '已测试',
    filled: '已填充',
    test_failed: '测试失败',
    hint_only: '仅提示',
    disabled: '已关闭',
    skipped: '已跳过',
    error: '失败',
  };
  return mapping[value] || '-';
}

export const WIH_SENSITIVE_RECORD_TYPE_SET = new Set([
  'app_key',
  'api_key',
  'access_key',
  'secret_key',
  'client_secret',
  'private_key',
  'authorization',
  'token',
  'jwt',
  'password',
  'passwd',
  'credential',
]);

export const WIH_SENSITIVE_CONTENT_KEYWORDS = [
  'app_key',
  'api_key',
  'access_key',
  'secret_key',
  'client_secret',
  'private_key',
  'authorization: bearer',
  'password',
  'passwd',
  'token',
  'jwt',
];

export function isSensitiveWihRow(row: any): boolean {
  const recordType = String(row?.record_type || '').trim().toLowerCase();
  const content = String(row?.content || '').trim().toLowerCase();
  if (!recordType && !content) return false;
  if (recordType.startsWith('trufflehog_')) return true;
  if (WIH_SENSITIVE_RECORD_TYPE_SET.has(recordType)) return true;
  if (recordType.endsWith('_key') || recordType.endsWith('_token')) return true;
  return WIH_SENSITIVE_CONTENT_KEYWORDS.some((keyword) => content.includes(keyword));
}

export function getWihRecordTypeTagClass(recordType: string, sensitive: boolean): string {
  const normalized = String(recordType || '').trim().toLowerCase();
  if (normalized.startsWith('trufflehog_')) {
    return 'inline-flex items-center rounded-full border border-error/45 bg-error/15 px-2.5 py-1 text-[11px] font-black text-error';
  }
  if (sensitive) {
    return 'inline-flex items-center rounded-full border border-warning/45 bg-warning/15 px-2.5 py-1 text-[11px] font-black text-warning';
  }
  return 'inline-flex items-center rounded-full border border-base-300 bg-base-100/70 px-2.5 py-1 text-[11px] font-semibold text-content-muted';
}
