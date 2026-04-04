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

const fs = require('fs');
const { URL } = require('url');

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

function buildEndpointKey(method, url) {
  return `${String(method || 'GET').trim().toUpperCase()}|${String(url || '').trim()}`;
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

  await page.addInitScript(() => {
    const events = [];
    const maxStored = 200;

    const safePush = (record) => {
      if (!record || !record.url) return;
      events.push(record);
      if (events.length > maxStored) events.shift();
      window.__WIH_RUNTIME_EVENTS__ = events;
    };

    const normalizeBody = (body) => {
      if (!body) return { bodyKind: '', bodyText: '', body: {} };
      if (typeof body === 'string') {
        return parseBodyText(body);
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
        const data = normalizeObjectBody(body);
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
      const headersObj = {};
      const sourceHeaders = init.headers || (input && input.headers);
      if (sourceHeaders && typeof sourceHeaders.forEach === 'function') {
        sourceHeaders.forEach((value, key) => {
          headersObj[String(key)] = String(value);
        });
      }
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

  try {
    await page.goto(targetUrl, { waitUntil: 'domcontentloaded', timeout: timeoutMs });
    await page.waitForTimeout(1200);
    if (maxActions > 0) {
      await performLowRiskInteractions(page, maxActions);
    }
  } catch (error) {
    await browser.close();
    safeJsonOutput({ endpoints: [], parameters: [], error: 'page_navigation_failed' });
    return;
  }

  const rawEvents = await page.evaluate(() => window.__WIH_RUNTIME_EVENTS__ || []);
  await browser.close();

  const endpointMap = new Map();
  const parameters = [];

  for (const event of Array.isArray(rawEvents) ? rawEvents : []) {
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
    const endpointKey = buildEndpointKey(method, eventUrl.toString());
    if (endpointMap.has(endpointKey)) continue;

    endpointMap.set(endpointKey, {
      endpoint_id: `runtime-${endpointMap.size + 1}`,
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

  for (const endpoint of endpointMap.values()) {
    parameters.push(...extractParameters(
      endpoint.endpoint_id,
      endpoint,
      endpoint.request_template.query,
      endpoint.request_template.body,
      endpoint.request_template.headers,
      endpoint.body_kind,
    ));
  }

  safeJsonOutput({
    endpoints: Array.from(endpointMap.values()),
    parameters,
  });
}

main().catch(() => {
  safeJsonOutput({ endpoints: [], parameters: [], error: 'runtime_driver_unexpected_error' });
});
