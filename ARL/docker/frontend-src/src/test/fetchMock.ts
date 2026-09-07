// 页面级测试共享的 fetch mock：默认所有 /api 返回成功空列表，
// 特例路径按前缀覆盖。只记录 URL 与请求头，绝不记录 body（防凭据进断言输出）。
import { vi } from 'vitest';

export type FetchCall = { url: string; method: string; token: string };

export type FetchMockOptions = {
  // key 为 URL 片段（includes 匹配，先匹配先中），value 返回 [status, body]
  routes?: Record<string, [number, unknown]>;
};

export function makeHttpResponse(status: number, body: unknown) {
  const text = JSON.stringify(body);
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: new Headers({ 'content-type': 'application/json' }),
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

export function installFetchMock(options: FetchMockOptions = {}) {
  const calls: FetchCall[] = [];
  const routes = options.routes ?? {};
  vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
    const headers = (init?.headers ?? {}) as Record<string, string>;
    calls.push({ url, method: init?.method ?? 'GET', token: headers.Token ?? '' });
    for (const [fragment, pair] of Object.entries(routes)) {
      if (url.includes(fragment)) {
        return makeHttpResponse(pair[0], pair[1]);
      }
    }
    return makeHttpResponse(200, { code: 200, data: { items: [], total: 0, page: 1, size: 20 } });
  }));
  return calls;
}

export function setViteDefineGlobals() {
  // vitest 不走 vite.config 的 define，登录页引用的版本号需手工挂全局。
  (globalThis as Record<string, unknown>).__ARL_VERSION__ = '0.0-test-page';
}
