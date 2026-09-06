// done 家族（done/done_pending/done_degraded）前端语义钉——与后端
// TaskFinalizer 终态映射同一契约（计划 2 终态修复轮的 UI 侧对账）。
import { describe, expect, it } from 'vitest';
import {
  getTaskProgressPercent,
  getTaskStatusSortWeight,
  normalizeTaskStatus,
} from './task';

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
