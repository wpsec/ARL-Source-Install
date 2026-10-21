// done 家族（done/done_pending/done_degraded）前端语义钉——与后端
// TaskFinalizer 终态映射同一契约（计划 2 终态修复轮的 UI 侧对账）。
import { describe, expect, it } from 'vitest';
import {
  buildTaskStatisticSummary,
  getTaskProgressPercent,
  getTaskQueueStatusInfo,
  getTaskStatusSortWeight,
  normalizeTaskStatus,
} from './task';

it('WAF汇总将检测尝试数标为观测主机', () => {
  const summary = buildTaskStatisticSummary({
    statistic: {},
    waf_skip_summary: { detected_host_count: 2, waf_detected_host_count: 0 },
  });

  expect(summary).toContain('观测主机2');
  expect(summary).toContain('识别到WAF主机0');
});

describe('normalizeTaskStatus done family', () => {
  it.each(['done', 'done_pending', 'done_degraded', 'DONE'])(
    '%s 归入完成族',
    (status) => {
      expect(normalizeTaskStatus(status)).toBe('done');
    },
  );

  it('运行/排队/异常状态不误判为完成', () => {
    expect(normalizeTaskStatus('running')).toBe('running');
    expect(normalizeTaskStatus('waiting')).toBe('waiting');
    expect(normalizeTaskStatus('stage 3/9')).toBe('running');
    expect(normalizeTaskStatus('error')).toBe('error');
    expect(normalizeTaskStatus('stop')).toBe('stop');
    expect(normalizeTaskStatus('')).toBe('running');
  });
});

describe('getTaskProgressPercent done family', () => {
  it.each(['done', 'done_pending', 'done_degraded'])(
    '%s 进度按 100 展示（积压/降级证据留在阶段指标）',
    (status) => {
      expect(getTaskProgressPercent({ status })).toBe(100);
    },
  );

  it('running 进度封顶 99 且不低于 5', () => {
    expect(getTaskProgressPercent({ status: 'running', service: [] })).toBeLessThanOrEqual(99);
    expect(getTaskProgressPercent({ status: 'running', service: [] })).toBeGreaterThanOrEqual(5);
  });
});

it('done 家族排序权重一致（列表不分裂）', () => {
  expect(getTaskStatusSortWeight('done_pending')).toBe(getTaskStatusSortWeight('done'));
});

describe('深度扫描队列状态', () => {
  const now = new Date(2026, 9, 18, 3, 0, 0).getTime();

  it('queued 使用 queued_at 显示等待状态和时长', () => {
    const info = getTaskQueueStatusInfo({
      status: 'deep_scan_pending',
      deep_scan: { status: 'queued', queued_at: '2026-10-18 01:30:00' },
    }, now);

    expect(info?.label).toBe('深度扫描排队中');
    expect(info?.detail).toContain('已等待 1小时30分');
    expect(info?.detail).toContain('排队于');
  });

  it('running 使用 started_at 显示扫描状态和时长', () => {
    const info = getTaskQueueStatusInfo({
      status: 'deep_scan_running',
      deep_scan: { status: 'running', started_at: '2026-10-18 02:00:00' },
    }, now);

    expect(info?.label).toBe('深度扫描运行中');
    expect(info?.detail).toContain('已运行 1小时');
    expect(info?.detail).toContain('开始于');
  });

  it.each(['done', 'done_pending', 'done_degraded', 'stop', 'error'])(
    '终态 %s 不显示陈旧的深度扫描状态', (status) => {
      expect(getTaskQueueStatusInfo({
        status,
        deep_scan: { status: 'queued', queued_at: '2026-10-18 01:30:00' },
      }, now)).toBeNull();
    },
  );

  it('深度扫描排队状态不替代发现阶段进度', () => {
    const options = Object.fromEntries(
      Array.from({ length: 14 }, (_, index) => [`option_${index}`, true]),
    );
    expect(getTaskProgressPercent({
      status: 'deep_scan_pending',
      options,
      service: [{ name: 'discovery' }],
      deep_scan: { status: 'queued', queued_at: '2026-10-18 01:30:00' },
    })).toBe(6);
  });
});
