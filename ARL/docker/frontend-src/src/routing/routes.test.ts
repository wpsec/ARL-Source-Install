import { describe, expect, it } from 'vitest';
import { visibleModules } from '../config/modules';
import { buildModuleUrl, resolveModuleRoute } from './routes';

describe('模块路由注册表', () => {
  it('为所有可见模块生成可解析的稳定路由', () => {
    visibleModules.forEach((module) => {
      const url = buildModuleUrl(module.id);
      const parsed = new URL(url, 'https://arl.invalid');
      expect(resolveModuleRoute(parsed.pathname, parsed.search)?.moduleId).toBe(module.id);
    });
  });

  it('任务详情将 task_id 放入路径并保留额外外部筛选', () => {
    const url = buildModuleUrl('site', { task_id: 'task / 1', site: 'example.com' });
    const parsed = new URL(url, 'https://arl.invalid');
    const route = resolveModuleRoute(parsed.pathname, parsed.search);

    expect(parsed.pathname).toBe('/tasks/task%20%2F%201/site');
    expect(route).toEqual({ moduleId: 'site', filters: { site: 'example.com', task_id: 'task / 1' } });
  });

  it('未知模块和无效详情 tab 不匹配路由', () => {
    expect(resolveModuleRoute('/modules/not-a-module')).toBeNull();
    expect(resolveModuleRoute('/tasks/task-1/not-a-tab')).toBeNull();
  });

  it('路由只恢复已知外部筛选字段，不把任意敏感参数写进 URL', () => {
    const url = buildModuleUrl('site', { site: 'example.com', password: 'must-not-appear' });
    expect(url).toBe('/modules/site?x.site=example.com');
    expect(resolveModuleRoute('/modules/site', '?x.site=example.com&x.password=ignored')?.filters)
      .toEqual({ site: 'example.com' });
  });
});
