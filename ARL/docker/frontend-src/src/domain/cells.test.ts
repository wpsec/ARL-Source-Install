import { describe, expect, it } from 'vitest';
import { formatModuleCellValue } from './cells';

describe('formatModuleCellValue 多值字段', () => {
  it('将服务产品、端口和来源统一按行展示', () => {
    expect(formatModuleCellValue('service', 'service_info.product', {
      service_info: [{ product: 'nginx，Apache; Caddy、IIS' }],
    })).toBe('nginx\nApache\nCaddy\nIIS');

    expect(formatModuleCellValue('ip', 'port_info.port_id', {
      port_info: [{ port_id: 80 }, { port_id: 443 }],
    })).toBe('80\n443');

    expect(formatModuleCellValue('domain', 'source', {
      source: 'arl，chaos、fofa',
    })).toBe('arl\nchaos\nfofa');
  });

  it('未知数组字段也按行展示，避免回退为逗号串', () => {
    expect(formatModuleCellValue('site', 'tags', { tags: ['one', 'two'] })).toBe('one\ntwo');
  });
});
