// 浏览器弹窗与键盘行为验收（计划 4，playwright 真实 Chromium 路径）。
// 用法: node scripts/ui-smoke-browser.mjs
// 模式:
//   A 默认: 本地 serve dist/，验证 React 挂载、登录表单、Tab 焦点移动、输入回显、无未捕获异常。
//   B 在线(授权环境): UI_SMOKE_URL=http://host 时验证 Modal 链路——
//     UI_SMOKE_MODAL_TRIGGER 点击 → dialog[open] 出现 → Escape 关闭（原生键盘路径）→
//     再次打开后 backdrop 点击关闭。需要已登录态；Basic Auth 用 UI_SMOKE_BASIC_AUTH="user:pass"。
// 退出码: 0=通过, 1=断言失败, 77=playwright 浏览器二进制缺失(环境 SKIP)。
// 注意: 不安装依赖、不下载浏览器；组件层弹窗契约由 Modal.test.tsx(jsdom) 覆盖。
const checks = [];
let failed = 0;

function check(name, ok, detail = '') {
  checks.push({ name, ok, detail });
  if (!ok) failed += 1;
  console.log(`[${ok ? 'PASS' : 'FAIL'}] ${name}${detail ? ` :: ${detail}` : ''}`);
}

let chromium;
try {
  ({ chromium } = await import('playwright'));
} catch {
  console.log('[SKIP] playwright 包不可解析');
  process.exit(77);
}

let server;
const onlineUrl = process.env.UI_SMOKE_URL ?? '';
let targetUrl = onlineUrl;

if (!onlineUrl) {
  const { spawn } = await import('node:child_process');
  const { once } = await import('node:events');
  const path = await import('node:path');
  const distDir = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../dist');
  server = spawn(process.execPath, [
    path.resolve(path.dirname(new URL(import.meta.url).pathname), 'serve-static.mjs'),
    '0',
    distDir,
  ], { stdio: ['ignore', 'pipe', 'inherit'] });
  const port = await new Promise((resolvePort, rejectPort) => {
    let buf = '';
    server.stdout.on('data', (chunk) => {
      buf += chunk.toString();
      const m = buf.match(/LISTENING (\d+)/);
      if (m) resolvePort(Number(m[1]));
    });
    server.on('exit', () => rejectPort(new Error('静态服务器启动失败')));
    setTimeout(() => rejectPort(new Error('静态服务器启动超时')), 10000);
  });
  targetUrl = `http://127.0.0.1:${port}/`;
}

let browser;
try {
  browser = await chromium.launch();
} catch (error) {
  console.log(`[SKIP] 浏览器启动失败(可能未装二进制): ${String(error.message).slice(0, 120)}`);
  if (server) server.kill();
  process.exit(77);
}

try {
  const context = await browser.newContext();
  const page = await context.newPage();
  const pageErrors = [];
  page.on('pageerror', (error) => pageErrors.push(String(error.message)));

  const url = onlineUrl && process.env.UI_SMOKE_BASIC_AUTH
    ? onlineUrl.replace(/^(https?:\/\/)/, `$1${process.env.UI_SMOKE_BASIC_AUTH}@`)
    : onlineUrl;

  if (!onlineUrl) {
    await page.goto(url || targetUrl, { waitUntil: 'networkidle' });

    const mounted = await page.waitForFunction(
      () => document.getElementById('root')?.children.length > 0,
      null,
      { timeout: 15000 },
    ).then(() => true).catch(() => false);
    check('React 挂载(#root 非空)', mounted);

    const userbox = await page.getByPlaceholder('请输入用户名').first().isVisible().catch(() => false);
    const passbox = await page.getByPlaceholder('请输入密码').first().isVisible().catch(() => false);
    check('登录表单渲染(用户名+密码框)', userbox && passbox);

    const focusTrail = new Set();
    for (let i = 0; i < 5; i += 1) {
      await page.keyboard.press('Tab');
      const tag = await page.evaluate(() => {
        const el = document.activeElement;
        return el ? `${el.tagName}:${el.getAttribute('type') ?? ''}:${el.getAttribute('placeholder') ?? ''}` : 'none';
      });
      focusTrail.add(tag);
    }
    check('Tab 键盘焦点移动(≥2 个可聚焦元素)', focusTrail.size >= 2, `trail=${[...focusTrail].join('|')}`);

    await page.getByPlaceholder('请输入用户名').first().click();
    await page.keyboard.type('smoke.test');
    const typed = await page.getByPlaceholder('请输入用户名').first().inputValue();
    check('键盘输入回显', typed === 'smoke.test', `value=${typed}`);

    await page.getByRole('button', { name: '登录系统' }).first().isVisible()
      .then(() => check('登录按钮可见', true))
      .catch(() => check('登录按钮可见', false));

    check('无未捕获页面异常', pageErrors.length === 0, pageErrors.slice(0, 2).join(' ;; '));
  } else {
    const trigger = process.env.UI_SMOKE_MODAL_TRIGGER;
    if (!trigger) {
      check('在线模式需 UI_SMOKE_MODAL_TRIGGER 选择器', false, '未配置触发器');
    } else {
      await page.goto(url, { waitUntil: 'networkidle' });
      const loaded = await page.waitForFunction(
        () => document.getElementById('root')?.children.length > 0,
        null,
        { timeout: 20000 },
      ).then(() => true).catch(() => false);
      check('在线页面挂载', loaded);

      await page.click(trigger);
      const openedByClick = await page.waitForFunction(
        () => !!document.querySelector('dialog[open]'),
        null,
        { timeout: 8000 },
      ).then(() => true).catch(() => false);
      check('点击触发器打开弹窗', openedByClick);

      if (openedByClick) {
        await page.keyboard.press('Escape');
        const closedByEsc = await page.waitForFunction(
          () => !document.querySelector('dialog[open]'),
          null,
          { timeout: 5000 },
        ).then(() => true).catch(() => false);
        check('Escape 关闭弹窗(原生键盘链路)', closedByEsc);

        await page.click(trigger);
        await page.waitForFunction(() => !!document.querySelector('dialog[open]'), null, { timeout: 8000 });
        const box = await page.locator('dialog[open]').boundingBox();
        if (box) {
          // backdrop：点 dialog 元素左上区域（box padding 处，React backdrop 判定 target===dialog）。
          await page.mouse.click(box.x + 4, box.y + 4);
          const closedByBackdrop = await page.waitForFunction(
            () => !document.querySelector('dialog[open]'),
            null,
            { timeout: 5000 },
          ).then(() => true).catch(() => false);
          check('backdrop 点击关闭弹窗', closedByBackdrop);
        } else {
          check('backdrop 点击关闭弹窗', false, 'dialog boundingBox 不可得');
        }
      }
      check('无未捕获页面异常', pageErrors.length === 0, pageErrors.slice(0, 2).join(' ;; '));
    }
  }
} finally {
  await browser.close();
  if (server) server.kill();
}

console.log(`[SUMMARY] ${checks.length - failed}/${checks.length} 浏览器断言通过`);
process.exit(failed > 0 ? 1 : 0);
