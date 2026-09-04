import type {ApiRequestOptions, JsonValue} from '../domain/types';

export function buildFilterSignature(filters?: JsonValue): string {
  if (!filters || typeof filters !== 'object') return '[]';
  const entries = Object.entries(filters)
    .filter(([, value]) => value !== undefined)
    .sort((a, b) => a[0].localeCompare(b[0]));
  return JSON.stringify(entries);
}

export const API_BASE = '/api';

export const TOKEN_KEY = 'arl-token';

export const USERNAME_KEY = 'arl-username';

export const ACTIVE_MODULE_KEY = 'arl-active-module';

export function buildUrl(path: string, query?: JsonValue): string {
  const p = path.startsWith('/') ? path : `/${path}`;
  const full = `${API_BASE}${p}`;
  if (!query || Object.keys(query).length === 0) return full;

  const params = new URLSearchParams();
  Object.entries(query).forEach(([key, value]) => {
    if (value === undefined || value === null || value === '') return;
    params.append(key, String(value));
  });

  const qs = params.toString();
  return qs ? `${full}?${qs}` : full;
}

export function toggleTrailingSlash(path: string): string | null {
  if (!path || path === '/') return null;
  if (path.endsWith('/')) {
    return path.slice(0, -1);
  }
  return `${path}/`;
}

export function sanitizeUiMessage(value: any, maxLength = 300): string {
  if (value === null || value === undefined) return '';
  let text = String(value);
  // 统一移除 script/html 标签，避免接口返回原样展示脚本片段。
  text = text.replace(/<script[\s\S]*?>[\s\S]*?<\/script>/gi, ' ');
  text = text.replace(/<\/?[^>]+>/g, ' ');
  text = text.replace(/[\u0000-\u001f\u007f]+/g, ' ');
  text = text.replace(/\s+/g, ' ').trim();
  if (!text) return '';
  if (text.length <= maxLength) return text;
  return `${text.slice(0, maxLength)}...`;
}

export function extractErrorMessage(data: any): string {
  if (!data) return '请求失败';
  if (typeof data === 'string') return sanitizeUiMessage(data) || '请求失败';
  if (Number(data.code) === 401) return '认证失败，请检查用户名密码或重新登录';

  const pickNestedMessage = (obj: any): string => {
    if (!obj || typeof obj !== 'object') return '';
    const directKeys = ['error_message', 'error', 'message', 'msg', 'errmsg', 'errMsg', 'detail'];
    for (const key of directKeys) {
      const value = (obj as Record<string, any>)?.[key];
      if (typeof value === 'string' && value.trim()) {
        const text = sanitizeUiMessage(value);
        if (text) return text;
      }
    }
    if (Array.isArray((obj as Record<string, any>)?.missing_fields) && (obj as Record<string, any>).missing_fields.length > 0) {
      return `缺少配置: ${(obj as Record<string, any>).missing_fields.join(', ')}`;
    }
    return '';
  };

  const nestedSources = [data?.data, data?.detail, data];
  for (const source of nestedSources) {
    const text = pickNestedMessage(source);
    if (text) return text;
  }

  return '请求失败';
}

export function normalizeListData(data: any): {
  items: any[];
  total: number;
  page: number;
  size: number;
} {
  const source = data && data.data && Array.isArray(data.data.items) ? data.data : data;
  const items = Array.isArray(source?.items) ? source.items : [];
  const total = Number(source?.total ?? items.length);
  const page = Number(source?.page ?? 1);
  const size = Number((source?.size ?? items.length) || 20);
  return { items, total, page, size };
}

export function sanitizeFilename(fileName: string): string {
  return fileName.replace(/[\\/:*?"<>|]/g, '_');
}

export function normalizeRowIdValue(value: any): string {
  if (value === undefined || value === null) return '';
  if (typeof value === 'string' || typeof value === 'number') return String(value);
  if (typeof value === 'object') {
    const candidates = ['$oid', '_id', 'id', 'task_id', 'job_id', 'oid'];
    for (const key of candidates) {
      const nested = (value as Record<string, any>)?.[key];
      if (typeof nested === 'string' || typeof nested === 'number') {
        const text = String(nested).trim();
        if (text) return text;
      }
    }
  }
  return '';
}

export async function requestApi(token: string, path: string, options: ApiRequestOptions = {}) {
  const method = options.method ?? 'GET';
  const isGatewayNotReadyStatus = (status: number) => [502, 503, 504].includes(status);
  const backendNotReadyMessage = '系统正在启动中，后端服务尚未就绪，请稍后重试。';
  const buildFetchOptions = (): RequestInit => {
    const headers: Record<string, string> = {};
    if (token) {
      headers.Token = token;
    }

    const fetchOptions: RequestInit = {
      method,
      headers,
      credentials: 'same-origin',
    };

    if (method !== 'GET' && options.body !== undefined) {
      if (options.body instanceof FormData) {
        fetchOptions.body = options.body;
      } else {
        headers['Content-Type'] = 'application/json';
        fetchOptions.body = JSON.stringify(options.body);
      }
    }
    return fetchOptions;
  };

  const performRequestWithFallback = async (): Promise<Response> => {
    const primaryPath = path.startsWith('/') ? path : `/${path}`;
    const fallbackPath = toggleTrailingSlash(primaryPath);
    const primaryUrl = buildUrl(primaryPath, options.query);

    let response = await fetch(primaryUrl, buildFetchOptions());
    if ((response.status === 404 || response.status === 405) && fallbackPath && fallbackPath !== primaryPath) {
      const fallbackUrl = buildUrl(fallbackPath, options.query);
      response = await fetch(fallbackUrl, buildFetchOptions());
    }
    return response;
  };

  const waitBackendReady = async (maxAttempts = 8, intervalMs = 1200): Promise<boolean> => {
    const probeUrl = buildUrl('/');
    for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
      try {
        const probeResp = await fetch(probeUrl, {
          method: 'GET',
          credentials: 'same-origin',
        });
        if (!isGatewayNotReadyStatus(probeResp.status)) {
          return true;
        }
      } catch {
        // ignore probe error and continue retry
      }
      if (attempt < maxAttempts - 1) {
        await sleep(intervalMs);
      }
    }
    return false;
  };

  let response = await performRequestWithFallback();
  if (isGatewayNotReadyStatus(response.status)) {
    const ready = await waitBackendReady();
    if (!ready) {
      throw new Error(backendNotReadyMessage);
    }
    response = await performRequestWithFallback();
    if (isGatewayNotReadyStatus(response.status)) {
      throw new Error(backendNotReadyMessage);
    }
  }

  if (options.download) {
    const contentType = response.headers.get('content-type') || '';

    if (contentType.includes('application/json') || contentType.includes('text/json')) {
      let errJson: any = {};
      try {
        errJson = await response.json();
      } catch {
        errJson = {};
      }

      if (!response.ok || (errJson?.code && Number(errJson.code) !== 200)) {
        throw new Error(extractErrorMessage(errJson) || `下载失败: HTTP ${response.status}`);
      }

      throw new Error('下载失败，服务端未返回文件流');
    }

    if (!response.ok) {
      const fallbackText = await response.text();
      throw new Error(sanitizeUiMessage(fallbackText) || `下载失败: HTTP ${response.status}`);
    }

    const blob = await response.blob();
    const contentDisposition = response.headers.get('content-disposition') || '';
    const match = contentDisposition.match(/filename\*=UTF-8''([^;]+)|filename=([^;]+)/i);
    const rawName = decodeURIComponent((match?.[1] || match?.[2] || 'arl-export.bin').replace(/"/g, '').trim());
    const fileName = sanitizeFilename(rawName);

    const objectUrl = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = objectUrl;
    a.download = fileName;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(objectUrl);

    return { code: 200, message: 'downloaded', data: { fileName } };
  }

  const text = await response.text();
  let data: any = {};
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = { raw: text };
    }
  }

  const handleUnauthorized = () => {
    localStorage.removeItem('arl-token');
    setTimeout(() => {
      window.location.reload();
    }, 1500);
  };

  if (!response.ok) {
    if (response.status === 401 || Number(data?.code) === 401) {
      handleUnauthorized();
    }
    if (typeof data?.raw === 'string' && data.raw) {
      throw new Error(`HTTP ${response.status}: ${sanitizeUiMessage(data.raw)}`);
    }
    throw new Error(`HTTP ${response.status}: ${extractErrorMessage(data)}`);
  }

  if (typeof data?.code === 'number' && data.code !== 200) {
    if (data.code === 401) {
      handleUnauthorized();
    }
    throw new Error(extractErrorMessage(data));
  }

  if (typeof data?.raw === 'string' && data.raw) {
    throw new Error(`接口返回非JSON: ${sanitizeUiMessage(data.raw)}`);
  }

  if (typeof data?.message === 'string') {
    data.message = sanitizeUiMessage(data.message);
  }
  if (typeof data?.error === 'string') {
    data.error = sanitizeUiMessage(data.error);
  }
  if (typeof data?.detail === 'string') {
    data.detail = sanitizeUiMessage(data.detail);
  }

  return data;
}

export function sleep(ms: number) {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}
