#!/usr/bin/env node

/*
 * WIH Playwright runtime driver MVP
 *
 * 说明：
 * - 从 stdin 读取 WIH runtime request
 * - 使用 Playwright 采集页面加载期与少量交互期的 runtime 请求
 * - 输出 endpoints / parameters JSON
 *
 * 前提：
 * - 本脚本仅在本地已安装 playwright 时可运行
 * - 不负责结果最终归一化，WIH 主链路仍会二次过滤与补全
 */

const { URL } = require('url');

const staticAssetPattern = /\.(?:js|css|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|pdf|zip|rar|7z|mp[34]|avi|mov|docx?|xlsx?|pptx?)$/i;

async function readStdin() {
  return await new Promise((resolve, reject) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => {
      data += chunk;
    });
    process.stdin.on('end', () => resolve(data));
    process.stdin.on('error', reject);
  });
}

function safeJsonOutput(payload) {
  process.stdout.write(JSON.stringify(payload));
}

function normalizeNameList(items) {
  return Array.from(new Set(
    (Array.isArray(items) ? items : [])
      .map((item) => String(item || '').trim().toLowerCase())
      .filter(Boolean),
  )).sort();
}

function buildEndpointKey(method, targetUrl, queryKeys = [], bodyKeys = [], bodyKind = '') {
  const parsed = targetUrl instanceof URL ? targetUrl : new URL(String(targetUrl || ''));
  return [
    String(method || 'GET').trim().toUpperCase(),
    String(parsed.origin || '').trim().toLowerCase(),
    String(parsed.pathname || '/').trim() || '/',
    normalizeNameList(queryKeys).join(','),
    String(bodyKind || '').trim().toLowerCase(),
    normalizeNameList(bodyKeys).join(','),
  ].join('|');
}

function inferBodyKind(contentType, bodyText) {
  const loweredType = String(contentType || '').toLowerCase();
  const trimmedBody = String(bodyText || '').trim();
  if (loweredType.includes('graphql')) return 'graphql';
  if (loweredType.includes('application/json')) return 'json';
  if (loweredType.includes('application/x-www-form-urlencoded')) return 'form_urlencoded';
  if (loweredType.includes('multipart/form-data')) return 'multipart';
  if (loweredType.includes('xml')) return 'xml';
  if (trimmedBody.startsWith('{') || trimmedBody.startsWith('[')) return 'json';
  if (trimmedBody.startsWith('<')) return 'xml';
  if (trimmedBody.includes('=') && trimmedBody.includes('&')) return 'form_urlencoded';
  return '';
}

function inferParamType(value) {
  const text = String(value ?? '').trim();
  if (!text) return 'unknown';
  if (text === 'true' || text === 'false') return 'boolean';
  if (/^\d+$/.test(text)) return 'number';
  if (text.startsWith('{') || text.startsWith('[')) return 'object';
  return 'string';
}

function normalizeHeaders(input) {
  const result = {};
  if (!input || typeof input !== 'object') return result;
  for (const [key, value] of Object.entries(input)) {
    const name = String(key || '').trim();
    const text = String(value || '').trim();
    if (!name || !text) continue;
    result[name] = text;
  }
  return result;
}

function normalizeMap(input) {
  const result = {};
  if (!input || typeof input !== 'object') return result;
  for (const [key, value] of Object.entries(input)) {
    const name = String(key || '').trim();
    if (!name) continue;
    result[name] = String(value ?? '').trim() || '<value>';
  }
  return result;
}

function normalizeObjectBody(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return {};
  const result = {};
  const hasGraphQLQuery = typeof input.query === 'string' && /\b(query|mutation|subscription)\b/.test(input.query);
  if (hasGraphQLQuery) {
    result.query = input.query.trim();
    if (input.operationName) {
      result.operationName = String(input.operationName || '').trim();
    }
    if (input.variables && typeof input.variables === 'object' && !Array.isArray(input.variables)) {
      for (const [key, value] of Object.entries(input.variables)) {
        const name = String(key || '').trim();
        if (!name) continue;
        result[name] = typeof value === 'string' ? value : JSON.stringify(value);
      }
      return result;
    }
  }

  for (const [key, value] of Object.entries(input)) {
    const name = String(key || '').trim();
    if (!name) continue;
    if (value === null || value === undefined) {
      result[name] = '<value>';
      continue;
    }
    if (typeof value === 'string') {
      result[name] = value.trim() || '<value>';
      continue;
    }
    if (typeof value === 'number' || typeof value === 'boolean') {
      result[name] = String(value);
      continue;
    }
    result[name] = JSON.stringify(value);
  }
  return result;
}

function parseBodyText(bodyText) {
  const trimmed = String(bodyText || '').trim();
  if (!trimmed) return { bodyKind: '', bodyText: '', body: {} };
  if ((trimmed.startsWith('{') && trimmed.endsWith('}')) || (trimmed.startsWith('[') && trimmed.endsWith(']'))) {
    try {
      const parsed = JSON.parse(trimmed);
      const body = normalizeObjectBody(parsed);
      const bodyKind = inferBodyKind('application/json', trimmed) || (body.query ? 'graphql' : 'json');
      return { bodyKind, bodyText: trimmed, body };
    } catch (error) {
      return { bodyKind: inferBodyKind('', trimmed), bodyText: trimmed, body: {} };
    }
  }
  if (trimmed.includes('=')) {
    const query = {};
    for (const [key, value] of new URLSearchParams(trimmed).entries()) {
      query[key] = value;
    }
    return { bodyKind: 'form_urlencoded', bodyText: trimmed, body: query };
  }
  return { bodyKind: inferBodyKind('', trimmed), bodyText: trimmed, body: {} };
}

function extractParameters(endpointId, endpoint, query, body, headers, bodyKind) {
  const parameters = [];

  for (const [key, value] of Object.entries(query || {})) {
    parameters.push({
      endpoint_id: endpointId,
      param_name: key,
      location: 'query',
      param_type: inferParamType(value),
      example: String(value ?? ''),
    });
  }

  for (const [key, value] of Object.entries(body || {})) {
    parameters.push({
      endpoint_id: endpointId,
      param_name: key,
      location: bodyKind === 'graphql' && key !== 'query' ? 'graphql_variable' : 'body',
      param_type: inferParamType(value),
      example: String(value ?? ''),
    });
  }

  for (const [key, value] of Object.entries(headers || {})) {
    parameters.push({
      endpoint_id: endpointId,
      param_name: key,
      location: 'header',
      param_type: 'string',
      example: String(value ?? ''),
    });
  }

  const pathMatches = String(endpoint.path || '').match(/\{([A-Za-z_][\w.-]{0,63})\}/g) || [];
  for (const item of pathMatches) {
    const name = item.replace(/[{}]/g, '').trim();
    if (!name) continue;
    parameters.push({
      endpoint_id: endpointId,
      param_name: name,
      location: 'path',
      param_type: 'string',
      example: '',
    });
  }

  return parameters;
}

function buildParameterCountKey(endpointKey, location, paramName) {
  return `${String(endpointKey || '').trim()}|${String(location || '').trim().toLowerCase()}|${String(paramName || '').trim().toLowerCase()}`;
}

function incrementParameterCounts(counterMap, endpointKey, query, body, headers, bodyKind) {
  const increase = (location, name) => {
    const paramName = String(name || '').trim();
    if (!paramName) return;
    const counterKey = buildParameterCountKey(endpointKey, location, paramName);
    counterMap.set(counterKey, (counterMap.get(counterKey) || 0) + 1);
  };

  Object.keys(query || {}).forEach((name) => increase('query', name));
  Object.keys(body || {}).forEach((name) => {
    const location = bodyKind === 'graphql' && name !== 'query' ? 'graphql_variable' : 'body';
    increase(location, name);
  });
  Object.keys(headers || {}).forEach((name) => increase('header', name));
}

function shouldCaptureNetworkRequest(request, targetHost) {
  let requestUrl;
  try {
    requestUrl = new URL(String(request.url() || ''));
  } catch (error) {
    return false;
  }

  if (String(requestUrl.hostname || '').toLowerCase() !== String(targetHost || '').toLowerCase()) {
    return false;
  }

  const resourceType = String(request.resourceType() || '').toLowerCase();
  const method = String(request.method() || 'GET').trim().toUpperCase();
  if (resourceType === 'fetch' || resourceType === 'xhr') {
    return true;
  }
  if (resourceType === 'document') {
    return method !== 'GET' || String(requestUrl.search || '').trim() !== '';
  }
  return String(request.postData() || '').trim() !== '';
}

function buildInputSample(name, type) {
  const loweredName = String(name || '').toLowerCase();
  const loweredType = String(type || '').toLowerCase();
  if (loweredType === 'email' || loweredName.includes('mail')) return 'test@example.com';
  if (loweredType === 'tel' || loweredName.includes('phone') || loweredName.includes('mobile')) return '13800138000';
  if (loweredName.includes('page')) return '2';
  if (loweredName.includes('keyword') || loweredName.includes('search') || loweredName.includes('query')) return 'test';
  return 'test';
}

function isDangerousActionText(text) {
  const normalized = String(text || '').toLowerCase().replace(/\s+/g, ' ').trim();
  if (!normalized) return false;
  return /(delete|remove|save|update|submit|create|upload|import|export|pay|logout|登录|提交|删除|保存|修改|新增|创建|上传|导入|支付|退出)/.test(normalized);
}

function isPreferredActionText(text) {
  const normalized = String(text || '').toLowerCase().replace(/\s+/g, ' ').trim();
  if (!normalized) return false;
  return /(search|filter|next|more|tab|query|搜索|查询|筛选|下一页|更多|切换|标签)/.test(normalized);
}

function isPreferredPageText(text) {
  const normalized = String(text || '').toLowerCase().replace(/\s+/g, ' ').trim();
  if (!normalized) return false;
  return /(search|filter|query|list|detail|admin|manage|dashboard|index|home|api|doc|search|查询|筛选|列表|详情|管理|后台|首页|文档)/.test(normalized);
}

function isPreferredFormText(text) {
  const normalized = String(text || '').toLowerCase().replace(/\s+/g, ' ').trim();
  if (!normalized) return false;
  return /(search|filter|query|keyword|查询|搜索|筛选|关键字|检索)/.test(normalized);
}

function normalizeSameHostPageUrl(rawUrl, baseUrl, targetHost) {
  const text = String(rawUrl || '').trim();
  if (!text || text.startsWith('javascript:') || text.startsWith('mailto:') || text.startsWith('tel:')) {
    return '';
  }

  let resolved;
  try {
    resolved = new URL(text, baseUrl);
  } catch (error) {
    return '';
  }

  if (String(resolved.hostname || '').toLowerCase() !== String(targetHost || '').toLowerCase()) {
    return '';
  }
  if (!/^https?:$/i.test(String(resolved.protocol || ''))) {
    return '';
  }
  if (staticAssetPattern.test(String(resolved.pathname || ''))) {
    return '';
  }

  const hashText = String(resolved.hash || '').trim();
  if (hashText && !hashText.startsWith('#/') && !hashText.startsWith('#!/')) {
    resolved.hash = '';
  }
  return resolved.toString();
}

async function extractSameHostPageCandidates(page, baseUrl, targetHost) {
  const rawItems = await page.evaluate(() => {
    const candidates = [];

    const pushCandidate = (url, text = '', tag = '') => {
      const value = String(url || '').trim();
      if (!value) return;
      candidates.push({
        url: value,
        text: String(text || '').trim(),
        tag: String(tag || '').trim().toLowerCase(),
      });
    };

    document.querySelectorAll('a[href]').forEach((element) => {
      pushCandidate(
        element.getAttribute('href') || '',
        element.innerText || element.textContent || '',
        'a',
      );
    });

    document.querySelectorAll('iframe[src]').forEach((element) => {
      pushCandidate(
        element.getAttribute('src') || '',
        element.getAttribute('title') || '',
        'iframe',
      );
    });

    document.querySelectorAll('form[action]').forEach((element) => {
      const method = String(element.getAttribute('method') || 'get').trim().toLowerCase();
      if (method !== '' && method !== 'get') return;
      pushCandidate(
        element.getAttribute('action') || '',
        element.getAttribute('name') || '',
        'form',
      );
    });

    return candidates;
  }).catch(() => []);

  const result = [];
  const seen = new Set();
  for (const item of Array.isArray(rawItems) ? rawItems : []) {
    const normalized = normalizeSameHostPageUrl(item && item.url, baseUrl, targetHost);
    if (!normalized || seen.has(normalized)) continue;
    const text = String((item && item.text) || '').trim();
    const tag = String((item && item.tag) || '').trim().toLowerCase();
    if (isDangerousActionText(text)) continue;
    if (tag === 'a' && text && !isPreferredPageText(text)) continue;
    seen.add(normalized);
    result.push(normalized);
  }
  return result;
}

async function drainRuntimeEvents(page) {
  return await page.evaluate(() => {
    const events = Array.isArray(window.__WIH_RUNTIME_EVENTS__) ? window.__WIH_RUNTIME_EVENTS__.slice(0) : [];
    window.__WIH_RUNTIME_EVENTS__ = [];
    return events;
  }).catch(() => []);
}

async function performLowRiskInteractions(page, maxActions) {
  let used = 0;
  const settle = async () => {
    await page.waitForTimeout(700);
  };

  const fillSelectors = [
    'input[type="search"]',
    'input[name*="search" i]',
    'input[name*="keyword" i]',
    'input[placeholder*="搜索"]',
    'input[placeholder*="search" i]',
  ];
  for (const selector of fillSelectors) {
    const count = await page.locator(selector).count();
    for (let i = 0; i < count && used < maxActions; i += 1) {
      const locator = page.locator(selector).nth(i);
      const visible = await locator.isVisible().catch(() => false);
      const enabled = await locator.isEnabled().catch(() => false);
      if (!visible || !enabled) continue;
      const meta = await locator.evaluate((element) => ({
        name: element.getAttribute('name') || '',
        type: element.getAttribute('type') || '',
      })).catch(() => ({ name: '', type: '' }));
      await locator.fill(buildInputSample(meta.name, meta.type)).catch(() => {});
      await locator.dispatchEvent('input').catch(() => {});
      await locator.dispatchEvent('change').catch(() => {});
      used += 1;
      await settle();
    }
  }

  const selectCount = await page.locator('select:not([disabled])').count();
  for (let i = 0; i < selectCount && used < maxActions; i += 1) {
    const locator = page.locator('select:not([disabled])').nth(i);
    const visible = await locator.isVisible().catch(() => false);
    if (!visible) continue;
    const value = await locator.evaluate((element) => {
      const options = Array.from(element.options || []);
      const candidate = options.find((option) => !option.disabled && String(option.value || '').trim() !== '');
      return candidate ? String(candidate.value) : '';
    }).catch(() => '');
    if (!value) continue;
    await locator.selectOption(value).catch(() => {});
    used += 1;
    await settle();
  }

  const formCount = await page.locator('form').count();
  for (let i = 0; i < formCount && used < maxActions; i += 1) {
    const locator = page.locator('form').nth(i);
    const visible = await locator.isVisible().catch(() => false);
    if (!visible) continue;
    const meta = await locator.evaluate((element) => {
      const text = [
        element.getAttribute('id') || '',
        element.getAttribute('name') || '',
        element.getAttribute('action') || '',
        element.innerText || element.textContent || '',
      ].join(' ');
      const method = String(element.getAttribute('method') || 'get').trim().toLowerCase();
      const hasPassword = element.querySelector('input[type="password"]') !== null;
      const hasFile = element.querySelector('input[type="file"]') !== null;
      const inputCount = element.querySelectorAll('input, select, textarea').length;
      return {
        text,
        method,
        hasPassword,
        hasFile,
        inputCount,
      };
    }).catch(() => ({ text: '', method: 'get', hasPassword: false, hasFile: false, inputCount: 0 }));

    if (meta.hasPassword || meta.hasFile) continue;
    if (meta.inputCount <= 0) continue;
    if (meta.method !== '' && meta.method !== 'get') continue;
    if (!isPreferredFormText(meta.text)) continue;
    if (isDangerousActionText(meta.text)) continue;

    await locator.evaluate((element) => {
      if (typeof element.requestSubmit === 'function') {
        element.requestSubmit();
        return;
      }
      element.submit();
    }).catch(() => {});
    used += 1;
    await settle();
  }

  const tabSelectors = ['[role="tab"]', '[data-tab]', '[aria-controls]'];
  for (const selector of tabSelectors) {
    const count = await page.locator(selector).count();
    for (let i = 0; i < count && used < maxActions; i += 1) {
      const locator = page.locator(selector).nth(i);
      const visible = await locator.isVisible().catch(() => false);
      if (!visible) continue;
      await locator.click({ timeout: 1000 }).catch(() => {});
      used += 1;
      await settle();
    }
  }

  const actionSelectors = ['button', '[role="button"]', 'a[role="button"]', 'a'];
  for (const selector of actionSelectors) {
    const count = await page.locator(selector).count();
    for (let i = 0; i < count && used < maxActions; i += 1) {
      const locator = page.locator(selector).nth(i);
      const visible = await locator.isVisible().catch(() => false);
      const enabled = await locator.isEnabled().catch(() => true);
      if (!visible || !enabled) continue;
      const meta = await locator.evaluate((element) => ({
        text: (element.innerText || element.textContent || '').trim(),
        type: (element.getAttribute('type') || '').trim(),
      })).catch(() => ({ text: '', type: '' }));
      if (!isPreferredActionText(meta.text)) continue;
      if (meta.type.toLowerCase() === 'submit' || isDangerousActionText(meta.text)) continue;
      await locator.click({ timeout: 1000 }).catch(() => {});
      used += 1;
      await settle();
    }
  }

  return used;
}

async function visitPageAndCollect(page, targetPageUrl, targetHost, timeoutMs, actionBudget) {
  try {
    await page.goto(targetPageUrl, { waitUntil: 'domcontentloaded', timeout: timeoutMs });
    await page.waitForTimeout(1200);
  } catch (error) {
    return { events: [], candidates: [], actionsUsed: 0 };
  }

  let actionsUsed = 0;
  if (actionBudget > 0) {
    actionsUsed = await performLowRiskInteractions(page, actionBudget).catch(() => 0);
  }

  const currentPageUrl = String(page.url() || targetPageUrl).trim() || targetPageUrl;
  const [events, candidates] = await Promise.all([
    drainRuntimeEvents(page),
    extractSameHostPageCandidates(page, currentPageUrl, targetHost),
  ]);

  return {
    events: Array.isArray(events) ? events : [],
    candidates: Array.isArray(candidates) ? candidates : [],
    actionsUsed,
  };
}

async function main() {
  let payload = {};
  try {
    const raw = await readStdin();
    payload = raw.trim() ? JSON.parse(raw) : {};
  } catch (error) {
    safeJsonOutput({ endpoints: [], parameters: [], error: 'invalid_request_json' });
    return;
  }

  const targetUrl = String(payload.target_url || '').trim();
  if (!targetUrl) {
    safeJsonOutput({ endpoints: [], parameters: [], error: 'empty_target_url' });
    return;
  }

  let playwright;
  try {
    playwright = require('playwright');
  } catch (error) {
    safeJsonOutput({ endpoints: [], parameters: [], error: 'playwright_not_installed' });
    return;
  }

  let target;
  try {
    target = new URL(targetUrl);
  } catch (error) {
    safeJsonOutput({ endpoints: [], parameters: [], error: 'invalid_target_url' });
    return;
  }

  const maxRequests = Math.max(1, Number(payload.max_requests || 40) || 40);
  const maxPages = Math.max(1, Number(payload.max_pages || 3) || 1);
  const maxActions = Math.max(0, Number(payload.max_actions || 8) || 0);
  const timeoutMs = Math.max(1000, (Number(payload.timeout_sec || 20) || 20) * 1000);
  const defaultHeaders = normalizeHeaders(payload.default_headers);

  const browser = await playwright.chromium.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-dev-shm-usage'],
  });

  const context = await browser.newContext({
    ignoreHTTPSErrors: true,
    extraHTTPHeaders: defaultHeaders,
  });
  const page = await context.newPage();
  const observedRequests = [];
  const maxObservedRequests = Math.max(200, maxRequests * 8);

  const pushObservedRequest = (record) => {
    if (!record || !record.url) return;
    observedRequests.push(record);
    if (observedRequests.length > maxObservedRequests) {
      observedRequests.shift();
    }
  };

  page.on('request', (request) => {
    try {
      if (!shouldCaptureNetworkRequest(request, target.hostname)) {
        return;
      }

      const headers = normalizeHeaders(request.headers());
      const rawBodyText = String(request.postData() || '').trim();
      const bodyInfo = rawBodyText ? parseBodyText(rawBodyText) : { bodyKind: '', bodyText: '', body: {} };
      const contentType = headers['Content-Type'] || headers['content-type'] || '';
      const bodyKind = String(bodyInfo.bodyKind || inferBodyKind(contentType, rawBodyText)).trim();

      pushObservedRequest({
        source: `network_${String(request.resourceType() || 'request').toLowerCase()}`,
        url: request.url(),
        method: String(request.method() || 'GET').toUpperCase(),
        headers,
        bodyKind,
        bodyText: bodyInfo.bodyText || rawBodyText,
        body: normalizeMap(bodyInfo.body),
        trigger: String(page.url() || targetUrl).trim() || targetUrl,
      });
    } catch (error) {
      // 运行时采集以尽量多拿结果为目标，单条请求解析失败时保守跳过。
    }
  });

  await page.addInitScript(() => {
    const events = [];
    const maxStored = 200;

    const normalizeObjectBodyInPage = (input) => {
      if (!input || typeof input !== 'object' || Array.isArray(input)) return {};
      const result = {};
      const hasGraphQLQuery = typeof input.query === 'string' && /\b(query|mutation|subscription)\b/.test(input.query);
      if (hasGraphQLQuery) {
        result.query = input.query.trim();
        if (input.operationName) {
          result.operationName = String(input.operationName || '').trim();
        }
        if (input.variables && typeof input.variables === 'object' && !Array.isArray(input.variables)) {
          for (const [key, value] of Object.entries(input.variables)) {
            const name = String(key || '').trim();
            if (!name) continue;
            result[name] = typeof value === 'string' ? value : JSON.stringify(value);
          }
          return result;
        }
      }

      for (const [key, value] of Object.entries(input)) {
        const name = String(key || '').trim();
        if (!name) continue;
        if (value === null || value === undefined) {
          result[name] = '<value>';
          continue;
        }
        if (typeof value === 'string') {
          result[name] = value.trim() || '<value>';
          continue;
        }
        if (typeof value === 'number' || typeof value === 'boolean') {
          result[name] = String(value);
          continue;
        }
        result[name] = JSON.stringify(value);
      }
      return result;
    };

    const parseBodyTextInPage = (bodyText) => {
      const trimmed = String(bodyText || '').trim();
      if (!trimmed) return { bodyKind: '', bodyText: '', body: {} };
      if ((trimmed.startsWith('{') && trimmed.endsWith('}')) || (trimmed.startsWith('[') && trimmed.endsWith(']'))) {
        try {
          const parsed = JSON.parse(trimmed);
          const body = normalizeObjectBodyInPage(parsed);
          return { bodyKind: body.query ? 'graphql' : 'json', bodyText: trimmed, body };
        } catch (error) {
          return { bodyKind: '', bodyText: trimmed, body: {} };
        }
      }
      if (trimmed.includes('=')) {
        const query = {};
        for (const [key, value] of new URLSearchParams(trimmed).entries()) {
          query[key] = value;
        }
        return { bodyKind: 'form_urlencoded', bodyText: trimmed, body: query };
      }
      return { bodyKind: '', bodyText: trimmed, body: {} };
    };

    const collectHeaders = (sourceHeaders) => {
      const headersObj = {};
      if (!sourceHeaders) return headersObj;
      if (typeof sourceHeaders.forEach === 'function') {
        sourceHeaders.forEach((value, key) => {
          headersObj[String(key)] = String(value);
        });
        return headersObj;
      }
      if (Array.isArray(sourceHeaders)) {
        sourceHeaders.forEach((item) => {
          if (!Array.isArray(item) || item.length < 2) return;
          headersObj[String(item[0])] = String(item[1]);
        });
        return headersObj;
      }
      if (typeof sourceHeaders === 'object') {
        Object.entries(sourceHeaders).forEach(([key, value]) => {
          headersObj[String(key)] = String(value);
        });
      }
      return headersObj;
    };

    const safePush = (record) => {
      if (!record || !record.url) return;
      events.push(record);
      if (events.length > maxStored) events.shift();
      window.__WIH_RUNTIME_EVENTS__ = events;
    };

    const normalizeBody = (body) => {
      if (!body) return { bodyKind: '', bodyText: '', body: {} };
      if (typeof body === 'string') {
        return parseBodyTextInPage(body);
      }
      if (body instanceof URLSearchParams) {
        const query = {};
        for (const [key, value] of body.entries()) query[key] = value;
        return { bodyKind: 'form_urlencoded', bodyText: body.toString(), body: query };
      }
      if (body instanceof FormData) {
        const data = {};
        for (const [key, value] of body.entries()) data[key] = String(value ?? '');
        return { bodyKind: 'multipart', bodyText: '', body: data };
      }
      if (typeof body === 'object') {
        const data = normalizeObjectBodyInPage(body);
        return {
          bodyKind: data.query ? 'graphql' : 'json',
          bodyText: JSON.stringify(body),
          body: data,
        };
      }
      return { bodyKind: '', bodyText: '', body: {} };
    };

    const originalFetch = window.fetch.bind(window);
    window.fetch = async (input, init = {}) => {
      const requestUrl = typeof input === 'string' ? input : (input && input.url) || '';
      const method = String(init.method || (input && input.method) || 'GET').toUpperCase();
      const sourceHeaders = init.headers || (input && input.headers);
      const headersObj = collectHeaders(sourceHeaders);
      const bodyInfo = normalizeBody(init.body);
      safePush({
        source: 'fetch',
        url: requestUrl,
        method,
        headers: headersObj,
        bodyKind: bodyInfo.bodyKind,
        bodyText: bodyInfo.bodyText,
        body: bodyInfo.body,
        trigger: document.location.href,
      });
      return originalFetch(input, init);
    };

    const originalOpen = XMLHttpRequest.prototype.open;
    const originalSetRequestHeader = XMLHttpRequest.prototype.setRequestHeader;
    const originalSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.open = function(method, url) {
      this.__wihMethod = String(method || 'GET').toUpperCase();
      this.__wihUrl = String(url || '');
      this.__wihHeaders = {};
      return originalOpen.apply(this, arguments);
    };
    XMLHttpRequest.prototype.setRequestHeader = function(name, value) {
      if (!this.__wihHeaders) this.__wihHeaders = {};
      this.__wihHeaders[String(name || '')] = String(value || '');
      return originalSetRequestHeader.apply(this, arguments);
    };
    XMLHttpRequest.prototype.send = function(body) {
      const bodyInfo = normalizeBody(body);
      safePush({
        source: 'xhr',
        url: this.__wihUrl || '',
        method: this.__wihMethod || 'GET',
        headers: this.__wihHeaders || {},
        bodyKind: bodyInfo.bodyKind,
        bodyText: bodyInfo.bodyText,
        body: bodyInfo.body,
        trigger: document.location.href,
      });
      return originalSend.apply(this, arguments);
    };

    const originalBeacon = navigator.sendBeacon?.bind(navigator);
    if (originalBeacon) {
      navigator.sendBeacon = (url, data) => {
        const bodyInfo = normalizeBody(data);
        safePush({
          source: 'beacon',
          url: String(url || ''),
          method: 'POST',
          headers: {},
          bodyKind: bodyInfo.bodyKind,
          bodyText: bodyInfo.bodyText,
          body: bodyInfo.body,
          trigger: document.location.href,
        });
        return originalBeacon(url, data);
      };
    }
  });

  const pendingPages = [targetUrl];
  const queuedPages = new Set([targetUrl]);
  const visitedPages = new Set();
  let remainingActions = maxActions;
  const rawEvents = [];

  while (pendingPages.length > 0 && visitedPages.size < maxPages && rawEvents.length < maxRequests * 6) {
    const nextPageUrl = pendingPages.shift();
    queuedPages.delete(nextPageUrl);
    if (!nextPageUrl || visitedPages.has(nextPageUrl)) continue;
    visitedPages.add(nextPageUrl);

    const remainingPageBudget = Math.max(1, maxPages - visitedPages.size + 1);
    const perPageActionBudget = remainingActions > 0
      ? Math.min(remainingActions, Math.max(1, Math.ceil(remainingActions / remainingPageBudget)))
      : 0;

    const visitResult = await visitPageAndCollect(page, nextPageUrl, target.hostname, timeoutMs, perPageActionBudget);
    rawEvents.push(...visitResult.events);
    remainingActions = Math.max(0, remainingActions - visitResult.actionsUsed);

    for (const candidateUrl of visitResult.candidates) {
      if (!candidateUrl || visitedPages.has(candidateUrl) || queuedPages.has(candidateUrl)) continue;
      pendingPages.push(candidateUrl);
      queuedPages.add(candidateUrl);
      if (pendingPages.length + visitedPages.size >= maxPages * 4) break;
    }
  }

  await browser.close();

  const endpointMap = new Map();
  const parameterCountMap = new Map();
  const parameters = [];
  const combinedEvents = [...rawEvents, ...observedRequests];

  for (const event of Array.isArray(combinedEvents) ? combinedEvents : []) {
    if (!event || !event.url) continue;
    if (endpointMap.size >= maxRequests) break;

    let eventUrl;
    try {
      eventUrl = new URL(String(event.url), targetUrl);
    } catch (error) {
      continue;
    }
    if (eventUrl.hostname !== target.hostname) continue;

    const method = String(event.method || 'GET').toUpperCase();
    const headers = normalizeHeaders(event.headers);
    const query = {};
    eventUrl.searchParams.forEach((value, key) => {
      query[key] = value;
    });
    const body = normalizeMap(event.body);
    const bodyText = String(event.bodyText || '').trim();
    const contentType = headers['Content-Type'] || headers['content-type'] || '';
    const bodyKind = String(event.bodyKind || inferBodyKind(contentType, bodyText)).trim();
    const queryKeys = Object.keys(query || {});
    const bodyKeys = Object.keys(body || {});
    const endpointKey = buildEndpointKey(method, eventUrl, queryKeys, bodyKeys, bodyKind);
    incrementParameterCounts(parameterCountMap, endpointKey, query, body, headers, bodyKind);
    const existing = endpointMap.get(endpointKey);
    if (existing) {
      existing.request_template.headers = { ...(existing.request_template.headers || {}), ...headers };
      existing.request_template.query = { ...(existing.request_template.query || {}), ...query };
      existing.request_template.body = { ...(existing.request_template.body || {}), ...body };
      if (!existing.request_template.body_text && bodyText) {
        existing.request_template.body_text = bodyText;
      }
      if (!existing.content_type && contentType) {
        existing.content_type = contentType;
      }
      if (!existing.body_kind && bodyKind) {
        existing.body_kind = bodyKind;
      }
      existing.trigger_context.page = existing.trigger_context.page || String(event.trigger || targetUrl);
      endpointMap.set(endpointKey, existing);
      continue;
    }

    endpointMap.set(endpointKey, {
      endpoint_id: `runtime-${endpointMap.size + 1}`,
      page_url: String(event.trigger || targetUrl),
      url: eventUrl.toString(),
      method,
      content_type: contentType,
      body_kind: bodyKind,
      trigger_context: {
        page: String(event.trigger || targetUrl),
        event: String(event.source || 'runtime'),
        dom_hint: 'playwright_driver',
      },
      request_template: {
        headers,
        query,
        body,
        body_text: bodyText,
      },
    });
  }

  for (const [endpointKey, endpoint] of endpointMap.entries()) {
    const endpointParameters = extractParameters(
      endpoint.endpoint_id,
      endpoint,
      endpoint.request_template.query,
      endpoint.request_template.body,
      endpoint.request_template.headers,
      endpoint.body_kind,
    ).map((parameter) => ({
      ...parameter,
      source: 'runtime',
      source_detail: {
        page_url: String(endpoint.page_url || endpoint.trigger_context?.page || targetUrl),
      },
      confidence: 0.93,
      occurrence_count: parameterCountMap.get(buildParameterCountKey(endpointKey, parameter.location, parameter.param_name)) || 1,
    }));
    parameters.push(...endpointParameters);
  }

  safeJsonOutput({
    endpoints: Array.from(endpointMap.values()),
    parameters,
  });
}

main().catch(() => {
  safeJsonOutput({ endpoints: [], parameters: [], error: 'runtime_driver_unexpected_error' });
});
