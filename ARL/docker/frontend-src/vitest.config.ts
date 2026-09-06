import { defineConfig } from 'vitest/config';

// UI 测试基建（计划 4 收口项，2026-09-06 用户确认选型 vitest + testing-library）。
// 与 vite.config.ts 分离：构建链零感知；jsdom 环境覆盖组件渲染冒烟。
export default defineConfig({
  test: {
    environment: 'jsdom',
    include: ['src/**/*.test.{ts,tsx}'],
  },
});
