import { describe, expect, it } from 'vitest';
import {
  isLikelyIdColumn,
  normalizeHttpHyperlink,
  normalizeValue,
  normalizeValueNoTruncate,
  truncateMiddleText,
  truncateText,
} from './format';

describe('normalizeHttpHyperlink', () => {
  it('仅放行 http/https 绝对地址，非 URL/占位符返回空', () => {
    expect(normalizeHttpHyperlink('https://example.test/a')).toBe('https://example.test/a');
    expect(normalizeHttpHyperlink('javascript:alert(1)')).toBe('');
    expect(normalizeHttpHyperlink('/relative/path')).toBe('');
    expect(normalizeHttpHyperlink('-')).toBe('');
    expect(normalizeHttpHyperlink(null)).toBe('');
  });
});

describe('truncate helpers', () => {
  it('尾部与中尾截断保留可辨识头尾', () => {
    expect(truncateText('abc', 10)).toBe('abc');
    expect(truncateText('abcdefghijk', 5)).toBe('abcde...');
    const middle = truncateMiddleText('abcdefghijklmnopqrstuvwxyz', 12, 5, 4);
    expect(middle.startsWith('abcde')).toBe(true);
    expect(middle.endsWith('wxyz')).toBe(true);
    expect(middle).toContain('...');
  });
  it('id 列启发式不误伤普通列', () => {
    expect(isLikelyIdColumn('task_id')).toBe(true);
    expect(isLikelyIdColumn('title')).toBe(false);
  });
});

describe('多值展示格式', () => {
  it('数组值统一按行展示，避免长列表挤在一行', () => {
    expect(normalizeValue(['alpha', 'beta'])).toBe('alpha\nbeta');
    expect(normalizeValueNoTruncate(['alpha', 'beta'])).toBe('alpha\nbeta');
  });
});
