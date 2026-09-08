import { describe, expect, it } from 'vitest';
import { formatModuleCellValue } from './cells';

describe('formatModuleCellValue 多值字段', () => {
  it('将服务产品、端口和来源统一按行展示', () => {
    expect(formatModuleCellValue('service', 'service_info.product', {
      service_info: [{ product: 'nginx, Apache' }],
    })).toBe('nginx\nApache');

    expect(formatModuleCellValue('ip', 'port_info.port_id', {
      port_info: [{ port_id: 80 }, { port_id: 443 }],
    })).toBe('80\n443');

    expect(formatModuleCellValue('domain', 'source', {
      source: 'arl, chaos',
    })).toBe('arl\nchaos');
  });
});
