import { expect, test as base } from '@playwright/test';

const taskFixture = {
  _id: 'e2e-task',
  name: 'deep-scan-fixture',
  target: 'example.invalid',
  status: 'deep_scan_pending',
  progress: 6,
  options: Object.fromEntries(Array.from({ length: 14 }, (_, index) => [`option_${index}`, true])),
  service: [{ name: 'discovery' }],
  create_time: '2026-10-17 13:00:00',
  start_time: '2026-10-17 13:00:00',
  deep_scan: { status: 'queued', queued_at: '2026-10-17 13:00:00' },
};

const test = base.extend<{ consoleErrors: string[] }>({
  consoleErrors: async ({ page }, use) => {
    const errors: string[] = [];
    page.on('console', (message) => {
      if (message.type() === 'error') errors.push(message.text());
    });
    page.on('pageerror', (error) => errors.push(error.message));
    await use(errors);
    expect(errors).toEqual([]);
  },
});

test.beforeEach(async ({ page }) => {
  await page.addInitScript(() => {
    if (window.location.pathname === '/tasks/login-required/site') return;
    localStorage.setItem('arl-token', 'playwright-fixture-token');
    localStorage.setItem('arl-username', 'ui-review');
  });
  await page.route('**/api/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path !== '/api' && !path.startsWith('/api/')) {
      await route.continue();
      return;
    }

    if (route.request().method() !== 'GET') {
      if (path === '/api/user/login') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ code: 200, data: { token: 'mock-session', username: 'ui-review' } }),
        });
        return;
      }
      await route.fulfill({ status: 403, contentType: 'application/json', body: JSON.stringify({ code: 403 }) });
      return;
    }

    let data: Record<string, unknown> = { items: [], total: 0, page: 1, size: 20 };
    if (path.endsWith('/console/dashboard')) {
      data = {
        stats: {
          task_total: 1,
          active_tasks: 1,
          task_schedule_total: 2,
          asset_scope_total: 4,
          asset_site_total: 8,
          domain_total: 12,
          ip_total: 3,
          service_total: 9,
          url_total: 21,
          vuln_total: 1,
          new_assets_today: 2,
        },
        asset_trend_7d: [{ name: '10-17', assets: 8, vulns: 1 }],
        risk_distribution: [{ name: '高危', value: 1 }],
        recent_logs: [],
        last_updated: '2026-10-18 10:00:00',
      };
    } else if (path.endsWith('/console/queue_metrics')) {
      data = {
        broker_ok: true,
        inspect_ok: true,
        queues: [{
          name: 'arlheavy',
          ready: 692,
          reserved: 4,
          active: 2,
          earliest_queued_at: '2026-10-17 13:00:00',
          earliest_wait_seconds: 49_200,
        }],
      };
    } else if (path.endsWith('/console/recent_logs')) {
      data = { recent_logs: [] };
    } else if (path.endsWith('/task/')) {
      data = { items: [taskFixture], total: 1, page: 1, size: 20 };
    }

    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ code: 200, data }),
    });
  });
});

test('仪表盘在桌面、平板和手机视口保持层级与页面宽度', async ({ page, consoleErrors }, testInfo) => {
  const viewports = [
    { width: 1440, height: 900 },
    { width: 768, height: 1024 },
    { width: 390, height: 844 },
  ];

  for (const viewport of viewports) {
    await page.setViewportSize(viewport);
    await page.goto('/dashboard');
    await expect(page.getByRole('heading', { name: '运行中的任务' })).toBeVisible();
    await expect(page.getByLabel('deep-scan-fixture扫描进度 6%')).toBeVisible();
    await expect(page.getByRole('region', { name: 'Celery 队列状态' })).toBeVisible();
    const dashboardContent = await page.locator('main').innerText();
    expect(dashboardContent.indexOf('运行中的任务')).toBeLessThan(dashboardContent.indexOf('扫描队列'));
    expect(dashboardContent.indexOf('扫描队列')).toBeLessThan(dashboardContent.indexOf('总资产数'));
    const viewportHasNoOverflow = await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth);
    expect(viewportHasNoOverflow).toBe(true);
    await page.screenshot({ path: testInfo.outputPath(`dashboard-${viewport.width}x${viewport.height}.png`), fullPage: true });
  }

  expect(consoleErrors).toEqual([]);
});

test('任务列表查询状态可直接访问并在刷新后恢复', async ({ page, consoleErrors }) => {
  await page.goto('/modules/task?page=2&size=20&status=running');
  await expect(page.getByRole('heading', { name: '任务管理' })).toBeVisible();
  await expect(page.getByLabel('状态：')).toHaveValue('running');
  await expect(page).toHaveURL(/page=2.*size=20.*status=running/);

  await page.reload();
  await expect(page.getByLabel('状态：')).toHaveValue('running');
  await expect(page).toHaveURL(/page=2.*size=20.*status=running/);
  expect(consoleErrors).toEqual([]);
});

test('未登录访问深层链接后登录返回原页面', async ({ page, consoleErrors }) => {
  await page.goto('/tasks/login-required/site');
  await expect(page.getByRole('button', { name: '登录系统' })).toBeVisible();
  await page.getByPlaceholder('请输入用户名').fill('ui-review');
  await page.getByPlaceholder('请输入密码').fill('fixture-password');
  await page.getByRole('button', { name: '登录系统' }).click();

  await expect(page).toHaveURL(/\/tasks\/login-required\/site$/);
  await expect(page.getByRole('heading', { name: '站点' })).toBeVisible();
  expect(consoleErrors).toEqual([]);
});

test('任务、资产与配置页面在常见视口没有页面级横向溢出', async ({ page, consoleErrors }, testInfo) => {
  const viewports = [
    { width: 1440, height: 900 },
    { width: 768, height: 1024 },
    { width: 390, height: 844 },
  ];
  const pages = [
    { path: '/modules/task', heading: '任务管理', name: 'tasks' },
    { path: '/modules/site', heading: '站点', name: 'assets' },
    { path: '/modules/config-console', heading: '配置管理', name: 'config' },
  ];

  for (const viewport of viewports) {
    await page.setViewportSize(viewport);
    for (const target of pages) {
      await page.goto(target.path);
      await expect(page.getByRole('heading', { name: target.heading })).toBeVisible();
      const viewportHasNoOverflow = await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth);
      expect(viewportHasNoOverflow, `${target.path} at ${viewport.width}px`).toBe(true);
      await page.screenshot({
        path: testInfo.outputPath(`${target.name}-${viewport.width}x${viewport.height}.png`),
        fullPage: true,
      });
    }
  }

  expect(consoleErrors).toEqual([]);
});

test('任务详情路由保留任务范围并支持 tab 与浏览器历史', async ({ page, consoleErrors }) => {
  const detailRequest = page.waitForRequest((request) => (
    request.url().includes('/api/site/') && request.url().includes('task_id=e2e-task')
  ));
  await page.goto('/tasks/e2e-task/site');
  await detailRequest;
  await expect(page.getByRole('button', { name: /子域名/ })).toBeVisible();

  await page.getByRole('button', { name: /子域名/ }).click();
  await expect(page).toHaveURL(/\/tasks\/e2e-task\/domain$/);
  await page.goBack();
  await expect(page).toHaveURL(/\/tasks\/e2e-task\/site$/);
  await page.goForward();
  await expect(page).toHaveURL(/\/tasks\/e2e-task\/domain$/);
  expect(consoleErrors).toEqual([]);
});

test('导航、主题切换和窄屏侧栏可用', async ({ page, consoleErrors }) => {
  await page.goto('/dashboard');
  await page.getByRole('button', { name: '资产搜索' }).click();
  await expect(page).toHaveURL(/\/modules\/site$/);
  await page.goBack();
  await expect(page).toHaveURL(/\/dashboard$/);
  await page.getByRole('button', { name: '北欧极光' }).click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'nord');

  await page.setViewportSize({ width: 390, height: 844 });
  const menuButton = page.getByRole('button', { name: '打开导航菜单' });
  await menuButton.focus();
  await expect(menuButton).toBeFocused();
  await page.keyboard.press('Enter');
  const taskNavigationItem = page.getByRole('button', { name: '任务管理', exact: true });
  await expect(taskNavigationItem).toBeVisible();
  await taskNavigationItem.click();
  await expect(page).toHaveURL(/\/modules\/task$/);
  expect(consoleErrors).toEqual([]);
});
