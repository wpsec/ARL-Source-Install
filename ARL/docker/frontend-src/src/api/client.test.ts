// API 客户端契约（计划 4 UI 验收·错误态/消息脱敏/trailing-slash 兼容/下载）。
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  buildFilterSignature,
  buildUrl,
  extractErrorMessage,
  normalizeListData,
  normalizeRowIdValue,
  requestApi,
  sanitizeFilename,
  sanitizeUiMessage,
  toggleTrailingSlash,
} from './client';

function makeResponse(status: number, body?: unknown, headers?: Record<string, string>) {
  const text = typeof body === 'string' ? body : body === undefined ? '' : JSON.stringify(body);
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: new Headers(headers ?? {}),
    async text() {
      return text;
    },
    async json() {
      return JSON.parse(text);
    },
    async blob() {
      return new Blob([text]);
    },
  };
}

function mockFetchQueue(responses: Array<ReturnType<typeof makeResponse>>) {
  const calls: Array<{ url: string; init: RequestInit | undefined }> = [];
  let index = 0;
  const fn = vi.fn(async (url: string, init?: RequestInit) => {
    calls.push({ url, init });
    return responses[Math.min(index++, responses.length - 1)];
  });
  vi.stubGlobal('fetch', fn);
  return calls;
}

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe('纯函数', () => {
  it('buildUrl 过滤空值并序列化', () => {
    expect(buildUrl('/host')).toBe('/api/host');
    expect(buildUrl('host', { page: 2, q: '', skip: undefined })).toBe('/api/host?page=2');
  });

  it('toggleTrailingSlash', () => {
    expect(toggleTrailingSlash('/')).toBeNull();
    expect(toggleTrailingSlash('')).toBeNull();
    expect(toggleTrailingSlash('/a')).toBe('/a/');
    expect(toggleTrailingSlash('/a/')).toBe('/a');
  });

  it('buildFilterSignature 键序稳定且忽略 undefined', () => {
    expect(buildFilterSignature()).toBe('[]');
    expect(buildFilterSignature({ b: 1, a: 2, c: undefined })).toBe('[["a",2],["b",1]]');
  });

  it('sanitizeUiMessage 去标签/控制符并截断', () => {
    expect(sanitizeUiMessage('<script>alert(1)</script>hello')).toBe('hello');
    expect(sanitizeUiMessage('<b>bold</b>')).toBe('bold');
    expect(sanitizeUiMessage('line1\nline2')).toBe('line1 line2');
    expect(sanitizeUiMessage('x'.repeat(10), 5)).toBe(`${'x'.repeat(5)}...`);
    expect(sanitizeUiMessage(null)).toBe('');
  });

  it('extractErrorMessage 各错误形态', () => {
    expect(extractErrorMessage(null)).toBe('请求失败');
    expect(extractErrorMessage({ code: 401 })).toBe('认证失败，请检查用户名密码或重新登录');
    expect(extractErrorMessage({ data: { error_message: '内部错' } })).toBe('内部错');
    expect(extractErrorMessage({ missing_fields: ['FOFA', 'KEY'] })).toBe('缺少配置: FOFA, KEY');
    expect(extractErrorMessage('<i>bad</i>')).toBe('bad');
  });

  it('normalizeListData 兼容包裹/裸形态与默认值', () => {
    expect(normalizeListData({ data: { items: [{ id: 1 }], total: 5, page: 2, size: 10 } })).toEqual({
      items: [{ id: 1 }],
      total: 5,
      page: 2,
      size: 10,
    });
    const bare = normalizeListData({ items: [{ id: 1 }, { id: 2 }] });
    expect(bare.total).toBe(2);
    expect(bare.page).toBe(1);
    const empty = normalizeListData({});
    expect(empty.items).toEqual([]);
    expect(empty.size).toBe(20);
  });

  it('normalizeRowIdValue 提取嵌套 id', () => {
    expect(normalizeRowIdValue({ $oid: 'abc' })).toBe('abc');
    expect(normalizeRowIdValue({ id: 7 })).toBe('7');
    expect(normalizeRowIdValue('s')).toBe('s');
    expect(normalizeRowIdValue(null)).toBe('');
    expect(normalizeRowIdValue({ nested: {} })).toBe('');
  });

  it('sanitizeFilename 去路径分隔符', () => {
    expect(sanitizeFilename('a/b:c*?')).toBe('a_b_c__');
  });
});

describe('requestApi', () => {
  it('携带 Token 头并返回业务 payload', async () => {
    const calls = mockFetchQueue([makeResponse(200, { code: 200, data: { items: [] } })]);
    const result = await requestApi('tok-1', '/host', { query: { page: 1 } });
    expect(result.code).toBe(200);
    expect(calls[0].url).toBe('/api/host?page=1');
    expect((calls[0].init!.headers as Record<string, string>).Token).toBe('tok-1');
  });

  it('POST 对象体走 JSON，FormData 不强制 Content-Type', async () => {
    const calls = mockFetchQueue([makeResponse(200, { code: 200 }), makeResponse(200, { code: 200 })]);
    await requestApi('t', '/x', { method: 'POST', body: { a: 1 } });
    expect((calls[0].init!.headers as Record<string, string>)['Content-Type']).toBe('application/json');
    const fd = new FormData();
    fd.set('k', 'v');
    await requestApi('t', '/x', { method: 'POST', body: fd });
    expect((calls[1].init!.headers as Record<string, string>)['Content-Type']).toBeUndefined();
    expect(calls[1].init!.body).toBe(fd);
  });

  it('404 时自动切换 trailing slash 重试', async () => {
    const calls = mockFetchQueue([makeResponse(404, { code: 404 }), makeResponse(200, { code: 200, hit: 'slash' })]);
    const result = await requestApi('t', '/list');
    expect((result as { hit?: string }).hit).toBe('slash');
    expect(calls.map((c) => c.url)).toEqual(['/api/list', '/api/list/']);
  });

  it('HTTP 非 2xx 抛包含状态码与服务端消息的错误', async () => {
    mockFetchQueue([makeResponse(500, { message: '服务器错误' })]);
    await expect(requestApi('t', '/boom')).rejects.toThrow('HTTP 500: 服务器错误');
  });

  it('业务 code 非 200 抛 extractErrorMessage 结果', async () => {
    mockFetchQueue([makeResponse(200, { code: 400, message: '参数错误' })]);
    await expect(requestApi('t', '/bad')).rejects.toThrow('参数错误');
  });

  it('非 JSON 响应以“接口返回非JSON”上抛（错误态可展示）', async () => {
    mockFetchQueue([makeResponse(200, '<html>gateway</html>')]);
    await expect(requestApi('t', '/html')).rejects.toThrow('接口返回非JSON');
  });

  it('502 网关未就绪：探测通过后自动重试一次', async () => {
    const calls = mockFetchQueue([
      makeResponse(502),
      makeResponse(200, { code: 200 }),
      makeResponse(200, { code: 200, data: 'after-ready' }),
    ]);
    const result = await requestApi('t', '/task');
    expect(result.data).toBe('after-ready');
    expect(calls.map((c) => c.url)).toEqual(['/api/task', '/api/', '/api/task']);
  });

  it('401 清除本地 token（reloader 定时器不推进即不触发）', async () => {
    localStorage.setItem('arl-token', 'stale');
    mockFetchQueue([makeResponse(200, { code: 401, message: '登录过期' })]);
    // 401 走 extractErrorMessage 的固定文案（不透传服务端原始 message）。
    await expect(requestApi('stale', '/whoami')).rejects.toThrow('认证失败');
    expect(localStorage.getItem('arl-token')).toBeNull();
  });

  it('download 模式解析文件名并触发浏览器下载', async () => {
    let created = '';
    (URL as unknown as { createObjectURL: (b: unknown) => string }).createObjectURL = vi.fn(() => {
      created = 'blob:mock';
      return created;
    });
    (URL as unknown as { revokeObjectURL: (u: string) => void }).revokeObjectURL = vi.fn();
    mockFetchQueue([
      makeResponse(200, 'csv-data', {
        'content-type': 'text/csv',
        'content-disposition': "attachment; filename*=UTF-8''report%20A.csv",
      }),
    ]);
    const result = await requestApi('t', '/export', { download: true });
    expect(result.data.fileName).toBe('report A.csv');
    expect(created).toBe('blob:mock');
  });

  it('download 模式遇到 JSON 错误体按消息抛出', async () => {
    mockFetchQueue([
      makeResponse(200, { code: 400, message: '导出为空' }, { 'content-type': 'application/json' }),
    ]);
    await expect(requestApi('t', '/export', { download: true })).rejects.toThrow('导出为空');
  });
});
